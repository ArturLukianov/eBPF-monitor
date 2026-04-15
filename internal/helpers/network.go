package helpers

import (
	"encoding/binary"
	"net"
)

func BytesToIPv4(data uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, data)
	return ip.String()
}
