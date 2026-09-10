//go:build linux

package resolve

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

const rawSrcPort = 666 // massdns hard-coded UDP source port for HDRINCL sends

// openRawUDPv6 creates a SOCK_RAW IPPROTO_UDP socket with IPV6_HDRINCL so we can
// forge the IPv6 source address (massdns --rand-src-ipv6). Requires CAP_NET_RAW.
func openRawUDPv6() (int, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_UDP)
	if err != nil {
		return -1, fmt.Errorf("raw ipv6 udp socket: %w (need CAP_NET_RAW?)", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("IPV6_HDRINCL: %w", err)
	}
	return fd, nil
}

func closeRawFD(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

func setRawRecvBuffer(fd, n int) error {
	if fd < 0 || n <= 0 {
		return nil
	}
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, n)
}

func setRawSendBuffer(fd, n int) error {
	if fd < 0 || n <= 0 {
		return nil
	}
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, n)
}

// writeRawUDPv6 writes an IPv6+UDP+payload datagram with an explicit source
// address via a HDRINCL raw socket. sport is typically a fixed ephemeral-ish
// port (massdns uses 666).
func writeRawUDPv6(fd int, src, dst net.IP, sport, dport uint16, payload []byte) error {
	src16 := src.To16()
	dst16 := dst.To16()
	if src16 == nil || dst16 == nil {
		return errors.New("raw send requires IPv6 addresses")
	}
	udpLen := 8 + len(payload)
	total := 40 + udpLen
	buf := make([]byte, total)

	// Build a buffer laid out so the IPv6 UDP pseudo-header checksum can be
	// computed in place (same trick as massdns write_raw_header), then fix the
	// real IPv6 header fields.
	binary.BigEndian.PutUint16(buf[4:6], uint16(udpLen))
	buf[6] = 0
	buf[7] = unix.IPPROTO_UDP // temp: next-header slot holds protocol for checksum
	copy(buf[8:24], src16)
	copy(buf[24:40], dst16)
	binary.BigEndian.PutUint16(buf[40:42], sport)
	binary.BigEndian.PutUint16(buf[42:44], dport)
	binary.BigEndian.PutUint16(buf[44:46], uint16(udpLen))
	binary.BigEndian.PutUint16(buf[46:48], 0)
	copy(buf[48:], payload)
	sum := ipChecksum(buf)
	binary.BigEndian.PutUint16(buf[46:48], sum)

	buf[0] = 0x60 // version 6
	buf[1], buf[2], buf[3] = 0, 0, 0
	buf[6] = unix.IPPROTO_UDP
	buf[7] = 255

	sa := &unix.SockaddrInet6{}
	copy(sa.Addr[:], dst16)
	// Raw IPv6 sendto rejects non-zero ports on some kernels (same as massdns).
	return unix.Sendto(fd, buf, 0, sa)
}

// readRawUDPv6 reads from a raw IPv6 UDP socket. On Linux the datagram starts
// with the 8-byte UDP header; we strip it and recover the source port.
func readRawUDPv6(fd int, buf []byte) (payload []byte, addr *net.UDPAddr, err error) {
	n, from, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, nil, err
		}
		return nil, nil, err
	}
	if n < 8 {
		return nil, nil, errors.New("short raw udp read")
	}
	sport := binary.BigEndian.Uint16(buf[0:2])
	ip := net.IPv6zero
	if sa6, ok := from.(*unix.SockaddrInet6); ok {
		ip = make(net.IP, 16)
		copy(ip, sa6.Addr[:])
	}
	return buf[8:n], &net.UDPAddr{IP: ip, Port: int(sport)}, nil
}

// ipChecksum computes the Internet checksum over buf (as used for IPv6 UDP).
func ipChecksum(buf []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(buf); i += 2 {
		sum += uint32(buf[i])<<8 | uint32(buf[i+1])
	}
	if len(buf)%2 == 1 {
		sum += uint32(buf[len(buf)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}