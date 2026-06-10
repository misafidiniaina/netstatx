// Fichier eBPF pour compter les octets par "flux" IP.
// Très commenté pour les débutants :
// - Ce programme s'attache en tant que classifier TC (ingress & egress)
// - Il détecte IPv4/IPv6, extrait une adresse (src pour ingress, dst pour egress)
// - Il incrémente un compteur d'octets dans une map BPF par clé (family,direction,addr)

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Clé utilisée pour indexer la map `flows`.
// Pensez-la comme un petit identifiant de "flux" :
// - family: 4 pour IPv4, 6 pour IPv6
// - direction: 0 = ingress (paquet entrant, on regarde la source),
//              1 = egress  (paquet sortant, on regarde la destination)
// - pad: alignement, inutilisé mais nécessaire pour l'alignement mémoire
// - addr: stockage de l'adresse IP. Pour IPv4 on utilise seulement les
//         4 premiers octets, pour IPv6 on utilise les 16 octets complets.
struct flow_key {
    __u8 family;    /* 4 ou 6 */
    __u8 direction; /* 0 = RX, 1 = TX */
    __u8 pad[2];    /* alignement */
    __u8 addr[16];  /* adresse IP (IPv4 dans les 4 premiers octets) */
};

// Map BPF: table de hachage en espace noyau
// - Clé: `struct flow_key`
// - Valeur: `__u64` compteur d'octets
// - max_entries: capacité approximative (131072 entrées)
// Cette map permet au programme eBPF d'enregistrer des compteurs
// consultables depuis l'espace utilisateur (via bpftool, libbpf, etc.).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow_key);
    __type(value, __u64);
} flows SEC(".maps");

static __always_inline int process_packet(
    void *data,
    void *data_end,
    __u8 direction
) {
    /*
     * `data` et `data_end` sont fournis par le kernel et encadrent
     * le buffer du paquet. Avant de caster un pointeur en structure
     * (ethhdr, iphdr...), il faut toujours s'assurer que la mémoire
     * est bien présente entre `data` et `data_end`.
     */
    struct ethhdr *eth = data;
    /*
     * (eth + 1) pointe juste après l'en-tête Ethernet. Si cette adresse
     * dépasse `data_end`, le paquet est trop petit et on ne peut pas lire.
     */
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK; /* paquet incomplet : ne pas manipuler */

    /*
     * Calcul simple de la longueur: `data_end - data` donne le nombre
     * d'octets disponibles pour ce paquet. On l'utilise comme delta
     * à ajouter au compteur de la map.
     */
    __u64 pkt_len = data_end - data;

    /* ---------- Traitement IPv4 ---------- */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        /* ip pointe sur le début de l'en-tête IP juste après Ethernet */
        struct iphdr *ip = (void *)(eth + 1);
        /* vérifier qu'on peut lire l'entier en-tête IP */
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK; /* en-tête IP tronqué */

        /* Préparer la clé pour la map */
        struct flow_key key = {};
        key.family = 4;            /* IPv4 */
        key.direction = direction; /* 0 = ingress, 1 = egress */

        /*
         * Choix de l'adresse utilisée pour agréger les octets:
         * - Pour ingress (paquet entrant), on regarde `saddr` (qui a envoyé)
         * - Pour egress (paquet sortant), on regarde `daddr` (qui reçoit)
         * On copie 4 octets (IPv4) dans `key.addr`.
         */
        if (direction == 0)
            __builtin_memcpy(key.addr, &ip->saddr, 4);
        else
            __builtin_memcpy(key.addr, &ip->daddr, 4);

        /*
         * Regardons si la clé existe déjà dans la map `flows`.
         * - Si oui: on ajoute la longueur du paquet (opération atomique).
         * - Si non: on crée la clé avec la valeur initiale = pkt_len.
         */
        __u64 *val = bpf_map_lookup_elem(&flows, &key);
        if (val)
            __sync_fetch_and_add(val, pkt_len); /* éviter les courses */
        else {
            __u64 init_val = pkt_len;
            bpf_map_update_elem(&flows, &key, &init_val, BPF_ANY);
        }
    }

    /* ---------- Traitement IPv6 (même logique, adresses 16 octets) ---------- */
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return TC_ACT_OK; /* en-tête IPv6 tronqué */

        struct flow_key key = {};
        key.family = 6;
        key.direction = direction;

        /* copier 16 octets d'adresse IPv6 */
        if (direction == 0)
            __builtin_memcpy(key.addr, &ip6->saddr, 16);
        else
            __builtin_memcpy(key.addr, &ip6->daddr, 16);

        __u64 *val = bpf_map_lookup_elem(&flows, &key);
        if (val)
            __sync_fetch_and_add(val, pkt_len);
        else {
            __u64 init_val = pkt_len;
            bpf_map_update_elem(&flows, &key, &init_val, BPF_ANY);
        }
    }

    /*
     * Comportement: le programme n'altère pas le forwarding du paquet.
     * `TC_ACT_OK` signifie « laisser passer ». Si vous vouliez bloquer
     * ou modifier le paquet, il faudrait retourner une autre action.
     */
    return TC_ACT_OK;
}

SEC("classifier/ingress")
int tc_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    return process_packet(data, data_end, 0); // RX
}

SEC("classifier/egress")
int tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    return process_packet(data, data_end, 1); // TX
}

char LICENSE[] SEC("license") = "GPL";