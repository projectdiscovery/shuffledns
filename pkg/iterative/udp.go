package iterative

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// udpExchanger performs authoritative queries over a single reused, unconnected
// UDP socket (the client-side equivalent of zdns's socket reuse: one socket per
// worker, reused for every destination, avoiding per-query socket setup). It
// verifies the reply's source address and transaction id, and falls back to TCP
// on truncation.
type udpExchanger struct {
	opts *Options
	conn *net.UDPConn
	buf  []byte
}

func newUDPExchanger(opts *Options) (exchanger, error) {
	network := "udp4"
	if opts.IPv6 {
		network = "udp"
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(4 * 1024 * 1024)
	_ = conn.SetWriteBuffer(4 * 1024 * 1024)
	return &udpExchanger{opts: opts, conn: conn, buf: make([]byte, 64*1024)}, nil
}

func (u *udpExchanger) close() {
	if u.conn != nil {
		_ = u.conn.Close()
	}
}

func (u *udpExchanger) exchange(ctx context.Context, server netip.AddrPort, msg *dns.Msg) (*dns.Msg, error) {
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	dst := net.UDPAddrFromAddrPort(server)

	for attempt := 0; attempt <= u.opts.Retries; attempt++ {
		deadline := time.Now().Add(u.opts.Timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if _, err := u.conn.WriteToUDP(packed, dst); err != nil {
			return nil, err
		}
		_ = u.conn.SetReadDeadline(deadline)

		// read until a matching reply arrives or the deadline expires; stray
		// or spoofed packets (wrong source / id / question) are ignored.
		for {
			n, from, rerr := u.conn.ReadFromUDP(u.buf)
			if rerr != nil {
				if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
					break // retransmit
				}
				return nil, rerr
			}
			// On a dual-stack ("udp") socket an IPv4 server's reply arrives as a
			// 4-in-6 address, so compare against the unmapped form; otherwise every
			// IPv4 response is dropped when IPv6 mode is enabled.
			fromAP := from.AddrPort()
			fromNorm := netip.AddrPortFrom(fromAP.Addr().Unmap(), fromAP.Port())
			if !fromNorm.Addr().IsValid() || fromNorm != server {
				continue // source-address verification (anti off-path spoofing)
			}
			resp := new(dns.Msg)
			if resp.Unpack(u.buf[:n]) != nil {
				continue
			}
			if resp.Id != msg.Id || !sameQuestion(resp, msg) {
				continue
			}
			if resp.Truncated && !u.opts.DisableTCPFallback {
				if tcp, terr := u.exchangeTCP(ctx, server, msg); terr == nil {
					return tcp, nil
				}
			}
			return resp, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return nil, errTimeout
}

func (u *udpExchanger) exchangeTCP(ctx context.Context, server netip.AddrPort, msg *dns.Msg) (*dns.Msg, error) {
	d := net.Dialer{Timeout: u.opts.Timeout}
	conn, err := d.DialContext(ctx, "tcp", server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	co := &dns.Conn{Conn: conn}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(u.opts.Timeout))
	}
	if err := co.WriteMsg(msg); err != nil {
		return nil, err
	}
	return co.ReadMsg()
}

var errTimeout = errors.New("iterative: query timed out")

func sameQuestion(a, b *dns.Msg) bool {
	if len(a.Question) != 1 || len(b.Question) != 1 {
		return false
	}
	qa, qb := a.Question[0], b.Question[0]
	return qa.Qtype == qb.Qtype && qa.Qclass == qb.Qclass && canonical(qa.Name) == canonical(qb.Name)
}
