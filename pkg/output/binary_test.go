package output

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestBinaryOutputRoundTripHeaderAndRecord(t *testing.T) {
	r := sampleResult()
	r.Timestamp = time.Unix(1513458347, 0)
	r.Resolver = "192.0.2.1:53"

	var buf bytes.Buffer
	w, err := NewWriterWithConfig(&buf, Config{Format: "B"})
	require.NoError(t, err)
	require.NoError(t, w.Write(r))
	require.NoError(t, w.Flush())

	data := buf.Bytes()
	require.True(t, bytes.HasPrefix(data, []byte("massdns\x00")))

	// magic(8) + endian(4) + version(4) + size_len(1) = 17
	off := 8
	require.Equal(t, uint32(0x12345678), binary.NativeEndian.Uint32(data[off:off+4]))
	off += 4
	require.Equal(t, uint32(0), binary.NativeEndian.Uint32(data[off:off+4]))
	off += 4
	require.Equal(t, byte(8), data[off])
	off++

	// skip descriptive sizes/offsets (5*8 + family/offsets…)
	// After size_len: time, sockaddr, family_off, family_size, port_size (5 uint64)
	off += 5 * 8
	// family_inet (2) + sin_addr_off (8) + sin_port_off (8)
	off += 2 + 8 + 8
	// family_inet6 (2) + sin6_addr_off (8) + sin6_port_off (8)
	off += 2 + 8 + 8

	// record: time(8) + sockaddr(128) + len(2) + payload
	require.Greater(t, len(data), off+8+128+2)
	ts := binary.NativeEndian.Uint64(data[off : off+8])
	require.Equal(t, uint64(1513458347), ts)
	off += 8
	ss := data[off : off+128]
	off += 128
	require.Equal(t, binaryAFInet, binary.NativeEndian.Uint16(ss[0:2]))
	require.Equal(t, uint16(53), binary.BigEndian.Uint16(ss[binarySinPortOff:binarySinPortOff+2]))
	require.Equal(t, netIPv4(192, 0, 2, 1), ss[binarySinAddrOff:binarySinAddrOff+4])

	msgLen := binary.NativeEndian.Uint16(data[off : off+2])
	off += 2
	raw := data[off : off+int(msgLen)]
	msg := new(dns.Msg)
	require.NoError(t, msg.Unpack(raw))
	require.Equal(t, "example.com.", msg.Question[0].Name)
}

func netIPv4(a, b, c, d byte) []byte { return []byte{a, b, c, d} }

func TestParseFormatBinary(t *testing.T) {
	f, err := ParseFormat("B")
	require.NoError(t, err)
	require.Equal(t, modeBinary, f.mode)
}
