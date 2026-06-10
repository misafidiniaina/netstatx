package capture

import "net"

type Direction uint8

const (
	RX Direction = iota
	TX
)

type Flow struct {
	IP        net.IP
	Direction Direction
	Bytes     uint64
}
