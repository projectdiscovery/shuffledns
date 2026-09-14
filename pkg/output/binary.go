package output

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

// massdns binary format (see massdns binfile_write_head / OUTPUT_BINARY).
//
// The file is platform-descriptive: a header records native sizes/offsets so
// readers such as scripts/dnsparse.py can parse records written by this writer.
// We emit a stable, documented layout that matches common Linux sockaddr field
// offsets so files are interchangeable with Linux massdns when written there.

const (
	binaryVersion       = uint32(0)
	binarySockaddrSize  = 128
	binaryFamilyOffset  = 0
	binaryFamilySize    = 2
	binaryPortSize      = 2
	binaryTimeSize      = 8
	binarySizeTSize     = 8
	binaryAFInet        = uint16(2)  // AF_INET on Linux
	binaryAFInet6       = uint16(10) // AF_INET6 on Linux
	binarySinAddrOff    = 4
	binarySinPortOff    = 2
	binarySin6AddrOff   = 8
	binarySin6PortOff   = 2
)

func writeBinaryHeader(w io.Writer) error {
	ne := binary.NativeEndian
	if _, err := w.Write([]byte("massdns\x00")); err != nil {
		return err
	}
	if err := binary.Write(w, ne, uint32(0x12345678)); err != nil {
		return err
	}
	if err := binary.Write(w, ne, binaryVersion); err != nil {
		return err
	}
	if _, err := w.Write([]byte{byte(binarySizeTSize)}); err != nil {
		return err
	}
	fields := []uint64{
		binaryTimeSize,
		binarySockaddrSize,
		binaryFamilyOffset,
		binaryFamilySize,
		binaryPortSize,
	}
	for _, v := range fields {
		if err := binary.Write(w, ne, v); err != nil {
			return err
		}
	}
	if err := binary.Write(w, ne, binaryAFInet); err != nil {
		return err
	}
	if err := binary.Write(w, ne, uint64(binarySinAddrOff)); err != nil {
		return err
	}
	if err := binary.Write(w, ne, uint64(binarySinPortOff)); err != nil {
		return err
	}
	if err := binary.Write(w, ne, binaryAFInet6); err != nil {
		return err
	}
	if err := binary.Write(w, ne, uint64(binarySin6AddrOff)); err != nil {
		return err
	}
	if err := binary.Write(w, ne, uint64(binarySin6PortOff)); err != nil {
		return err
	}
	return nil
}

func writeBinaryRecord(w io.Writer, r resolve.Result) error {
	if r.Msg == nil {
		return nil
	}
	raw, err := r.Msg.Pack()
	if err != nil {
		return err
	}
	if len(raw) > 0xffff {
		return fmt.Errorf("dns message too large for binary format: %d", len(raw))
	}

	ts := r.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	ne := binary.NativeEndian
	if err := binary.Write(w, ne, uint64(ts.Unix())); err != nil {
		return err
	}

	var ss [binarySockaddrSize]byte
	host, portStr, splitErr := net.SplitHostPort(r.Resolver)
	if splitErr != nil {
		host = r.Resolver
	}
	port := uint16(53)
	if portStr != "" {
		if p, convErr := strconv.Atoi(portStr); convErr == nil && p > 0 && p < 65536 {
			port = uint16(p)
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			ne.PutUint16(ss[binaryFamilyOffset:], binaryAFInet)
			binary.BigEndian.PutUint16(ss[binarySinPortOff:], port)
			copy(ss[binarySinAddrOff:], v4)
		} else {
			ne.PutUint16(ss[binaryFamilyOffset:], binaryAFInet6)
			binary.BigEndian.PutUint16(ss[binarySin6PortOff:], port)
			copy(ss[binarySin6AddrOff:], ip.To16())
		}
	}
	if _, err := w.Write(ss[:]); err != nil {
		return err
	}
	if err := binary.Write(w, ne, uint16(len(raw))); err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}
