package capture

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Collector struct {
	ingressLink link.Link
	egressLink  link.Link
	objs        *ebpf.Collection
}

//go:embed xdp.o
var xdpObj []byte

func loadSpec() (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(xdpObj))
}

func Start(iface string) (*Collector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := loadSpec()
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}

	objs, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("get interface: %w", err)
	}

	// Attach ingress (RX)
	ingress, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.Programs["tc_ingress"],
		Attach:    ebpf.AttachTCXIngress,
		Interface: ifi.Index,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach ingress: %w", err)
	}

	// Attach egress (TX)
	egress, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.Programs["tc_egress"],
		Attach:    ebpf.AttachTCXEgress,
		Interface: ifi.Index,
	})
	if err != nil {
		ingress.Close()
		objs.Close()
		return nil, fmt.Errorf("attach egress: %w", err)
	}

	return &Collector{
		ingressLink: ingress,
		egressLink:  egress,
		objs:        objs,
	}, nil
}

func (c *Collector) Snapshot() ([]Flow, error) {
	var flows []Flow

	m := c.objs.Maps["flows"]
	iter := m.Iterate()

	var key struct {
		Family    uint8
		Direction uint8
		Pad       [2]uint8
		Addr      [16]byte
	}
	var bytes uint64

	for iter.Next(&key, &bytes) {
		var ip net.IP

		if key.Family == 4 {
			ip = net.IPv4(
				key.Addr[0],
				key.Addr[1],
				key.Addr[2],
				key.Addr[3],
			)
		} else {
			ip = net.IP(key.Addr[:])
		}

		flows = append(flows, Flow{
			IP:        ip,
			Direction: Direction(key.Direction),
			Bytes:     bytes,
		})
	}

	return flows, iter.Err()
}

func (c *Collector) Close() error {
	if c.ingressLink != nil {
		c.ingressLink.Close()
	}
	if c.egressLink != nil {
		c.egressLink.Close()
	}
	if c.objs != nil {
		c.objs.Close()
	}
	return nil
}