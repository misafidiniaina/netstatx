package aggregator

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
)

func StartMapReader(path string, agg *DNSAggregator) error {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return err
	}
	defer m.Close()

	log.Println("DNS reader started")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		it := m.Iterate()

		var key DNSKey
		var value uint64

		for it.Next(&key, &value) {
			agg.Add(key.IP, value)
		}

		if err := it.Err(); err != nil {
			log.Println("iteration error:", err)
		}
	}

	return nil
}