//go:build !linux

package resolve

import (
	"errors"
	"net"
)

const rawSrcPort = 666

func openRawUDPv6() (int, error) {
	return -1, errors.New("--rand-src-ipv6 is only supported on Linux")
}

func closeRawFD(fd int) {}

func setRawRecvBuffer(fd, n int) error { return nil }

func setRawSendBuffer(fd, n int) error { return nil }

func writeRawUDPv6(fd int, src, dst net.IP, sport, dport uint16, payload []byte) error {
	return errors.New("--rand-src-ipv6 is only supported on Linux")
}

func readRawUDPv6(fd int, buf []byte) ([]byte, *net.UDPAddr, error) {
	return nil, nil, errors.New("--rand-src-ipv6 is only supported on Linux")
}
