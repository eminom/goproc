package proc

import (
	"encoding/binary"
	"net"
)

type NetPortInfo struct {
	Name       string
	Pid        uint32
	LocalIP    net.IP
	LocalPort  uint16
	RemoteIP   net.IP
	RemotePort uint16
}

type UDPPortInfo struct {
	Name      string
	Pid       uint32
	LocalIP   net.IP
	LocalPort uint16
}

func fetchBigEndianUint16(v uint32) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(v))
	return binary.LittleEndian.Uint16(b[:])
}

func translateIP(v uint32) net.IP {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return net.IPv4(b[0], b[1], b[2], b[3])
}
