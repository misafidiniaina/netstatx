package aggregator

import "sync"

type DNSAggregator struct {
	mu    sync.Mutex
	count map[uint32]uint64
}

func NewDNSAggregator() *DNSAggregator {
	return &DNSAggregator{
		count: make(map[uint32]uint64),
	}
}

func (d *DNSAggregator) Add(ip uint32, value uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.count[ip] += value
}

func (d *DNSAggregator) Snapshot() map[uint32]uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make(map[uint32]uint64)
	for k, v := range d.count {
		out[k] = v
	}
	return out
}