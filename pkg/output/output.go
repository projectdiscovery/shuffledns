// Package output renders resolver results in massdns-compatible output formats.
//
// It mirrors the massdns -o flag: a format string whose first recognized
// major letter selects the mode (S simple, F full, L list, J ndjson) and whose
// remaining letters toggle mode-specific options. The goal is drop-in parity so
// existing massdns post-processing pipelines keep working against the native
// resolver.
//
// Supported major modes:
//
//	S - simple text  (default; "name. TYPE data" per record, the form shuffledns parses)
//	F - full text    (dig-like packet dump with ;; Server/Size/Unix time header)
//	L - domain list  (tab-separated query/type/data, one record per line)
//	J - ndjson       (one JSON object per reply)
//	B - binary       (massdns binary packet stream; readable by dnsparse.py)
package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

type mode int

const (
	modeSimple mode = iota
	modeFull
	modeList
	modeNDJSON
	modeBinary
)

// Format is a parsed massdns -o specification.
type Format struct {
	mode mode

	// simple-mode section selectors
	answer     bool // n
	authority  bool // u
	additional bool // d

	// simple-mode modifiers
	ttlClass    bool // t: include TTL and class
	question    bool // q: print the question line
	meta        bool // r: prepend resolver, unix ts and rcode to the question
	sepReplies  bool // l: blank line between replies
	matchQ      bool // m: only records whose owner matches the question name
	indent      bool // i: indent reply records by a tab
	sepSections bool // s: blank line between sections

	listIncludeEmpty bool // 0 (list mode): include NOERROR replies without answers
	ndjsonFailures   bool // e (ndjson mode): emit a record for terminal failures
}

// ParseFormat parses a massdns-style format string (e.g. "Snl", "F", "J").
// An empty string defaults to simple answer-record output ("Sn").
func ParseFormat(spec string) (*Format, error) {
	f := &Format{mode: modeSimple}
	modeSet := false
	for _, r := range spec {
		switch r {
		case 'S':
			f.mode, modeSet = modeSimple, true
		case 'F':
			f.mode, modeSet = modeFull, true
		case 'L':
			f.mode, modeSet = modeList, true
		case 'J':
			f.mode, modeSet = modeNDJSON, true
		case 'B':
			f.mode, modeSet = modeBinary, true
		case 'n':
			f.answer = true
		case 'u':
			f.authority = true
		case 'd':
			f.additional = true
		case 't':
			f.ttlClass = true
		case 'q':
			f.question = true
		case 'r':
			f.meta = true
		case 'l':
			f.sepReplies = true
		case 'm':
			f.matchQ = true
		case 'i':
			f.indent = true
		case 's':
			f.sepSections = true
		case '0':
			f.listIncludeEmpty = true
		case 'e':
			f.ndjsonFailures = true
		case ' ', '\t':
			// ignore separators
		default:
			return nil, fmt.Errorf("unknown output flag %q", string(r))
		}
	}
	_ = modeSet
	// Simple mode with no explicit section defaults to the answer section, which
	// matches plain `-o S`.
	if f.mode == modeSimple && !f.answer && !f.authority && !f.additional {
		f.answer = true
	}
	return f, nil
}

// EmitsFailures reports whether terminal (post-retry) failures should be handed
// to WriteFailure. Only ndjson with the 'e' flag records them.
func (f *Format) EmitsFailures() bool { return f.mode == modeNDJSON && f.ndjsonFailures }

// Config bundles a format spec with response-filtering options. It is the
// SDK-friendly way to build a Writer with massdns --filter/--ignore semantics
// and the "only the queried record type" behaviour (massdns issue #1).
type Config struct {
	// Format is the massdns-style -o spec (see ParseFormat). Empty = "Sn".
	Format string
	// FilterRcodes, when non-empty, restricts output to replies whose response
	// code is in the set (massdns --filter). Names are response-code strings or
	// numbers, e.g. "NOERROR", "NXDOMAIN", "3".
	FilterRcodes []string
	// IgnoreRcodes drops replies whose response code is in the set (massdns
	// --ignore). Applied after FilterRcodes.
	IgnoreRcodes []string
	// OnlyQueryType emits only answer records whose type matches the queried
	// type, dropping CNAME/glue chains from the output (massdns issue #1).
	OnlyQueryType bool
	// FlushEach flushes after every written reply (massdns --flush).
	FlushEach bool
}

// rcodeValue resolves a response-code name or number to its numeric value.
func rcodeValue(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if v, ok := dns.StringToRcode[strings.ToUpper(s)]; ok {
		return v, true
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n, true
	}
	return 0, false
}

func rcodeSet(names []string) (map[int]struct{}, error) {
	if len(names) == 0 {
		return nil, nil
	}
	set := make(map[int]struct{}, len(names))
	for _, n := range names {
		v, ok := rcodeValue(n)
		if !ok {
			return nil, fmt.Errorf("invalid response code %q", n)
		}
		set[v] = struct{}{}
	}
	return set, nil
}

// Writer renders results to an underlying writer. It is safe for concurrent use
// (the resolver delivers results from multiple goroutines).
type Writer struct {
	mu sync.Mutex
	bw *bufio.Writer
	f  *Format

	filter    map[int]struct{} // only these rcodes (nil = all)
	ignore    map[int]struct{} // drop these rcodes
	onlyQType bool             // emit only answer records matching the question type
	flushEach bool
	binHeader bool // binary mode header already written
}

// NewWriter builds a Writer for the given format spec.
func NewWriter(w io.Writer, spec string) (*Writer, error) {
	return NewWriterWithConfig(w, Config{Format: spec})
}

// NewWriterWithConfig builds a Writer from a full Config (format + filters).
func NewWriterWithConfig(w io.Writer, cfg Config) (*Writer, error) {
	f, err := ParseFormat(cfg.Format)
	if err != nil {
		return nil, err
	}
	filter, err := rcodeSet(cfg.FilterRcodes)
	if err != nil {
		return nil, err
	}
	ignore, err := rcodeSet(cfg.IgnoreRcodes)
	if err != nil {
		return nil, err
	}
	return &Writer{
		bw:        bufio.NewWriterSize(w, 64*1024),
		f:         f,
		filter:    filter,
		ignore:    ignore,
		onlyQType: cfg.OnlyQueryType,
		flushEach: cfg.FlushEach,
	}, nil
}

// suppressed reports whether a reply with the given rcode should be dropped by
// the configured --filter/--ignore sets.
func (w *Writer) suppressed(rcode int) bool {
	if w.filter != nil {
		if _, ok := w.filter[rcode]; !ok {
			return true
		}
	}
	if w.ignore != nil {
		if _, ok := w.ignore[rcode]; ok {
			return true
		}
	}
	return false
}

// Flush flushes buffered output.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bw.Flush()
}

// Write renders a single result.
func (w *Writer) Write(r resolve.Result) error {
	if w.suppressed(r.Rcode) {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	switch w.f.mode {
	case modeSimple:
		err = w.writeSimple(r)
	case modeFull:
		err = w.writeFull(r)
	case modeList:
		err = w.writeList(r)
	case modeNDJSON:
		err = w.writeNDJSON(r)
	case modeBinary:
		err = w.writeBinary(r)
	}
	if err == nil && w.flushEach {
		err = w.bw.Flush()
	}
	return err
}

func (w *Writer) writeBinary(r resolve.Result) error {
	if !w.binHeader {
		if err := writeBinaryHeader(w.bw); err != nil {
			return err
		}
		w.binHeader = true
	}
	return writeBinaryRecord(w.bw, r)
}

// answerRecords returns the answer section, optionally filtered to records whose
// type matches the queried type (the OnlyQueryType behaviour).
func (w *Writer) answerRecords(r resolve.Result) []dns.RR {
	if r.Msg == nil {
		return nil
	}
	if !w.onlyQType {
		return r.Msg.Answer
	}
	out := make([]dns.RR, 0, len(r.Msg.Answer))
	for _, rr := range r.Msg.Answer {
		if rr.Header().Rrtype == r.Type {
			out = append(out, rr)
		}
	}
	return out
}

// WriteFailure records a terminal query failure (ndjson 'e' flag only).
func (w *Writer) WriteFailure(name string, qtype uint16, reason string) error {
	if !w.f.EmitsFailures() {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	rec := jsonReply{
		Name:   dns.Fqdn(name),
		Type:   typeString(qtype),
		Class:  "IN",
		Status: "ERROR",
		Error:  reason,
	}
	return w.encodeJSON(rec)
}

// ---- simple ----

func (w *Writer) writeSimple(r resolve.Result) error {
	qname := questionName(r)

	if w.f.meta {
		// resolver, unix timestamp and rcode prepended to the question
		fmt.Fprintf(w.bw, "%s %d %s %s %s %s\n",
			emptyDash(r.Resolver), r.Timestamp.Unix(), rcodeString(r.Rcode),
			qname, "IN", typeString(r.Type))
	} else if w.f.question {
		fmt.Fprintf(w.bw, "%s %s %s\n", qname, "IN", typeString(r.Type))
	}

	wrote := false
	emit := func(rrs []dns.RR) error {
		if w.f.sepSections && wrote && len(rrs) > 0 {
			if err := w.bw.WriteByte('\n'); err != nil {
				return err
			}
		}
		for _, rr := range rrs {
			if w.f.matchQ && !strings.EqualFold(rr.Header().Name, qname) {
				continue
			}
			if w.f.indent {
				if err := w.bw.WriteByte('\t'); err != nil {
					return err
				}
			}
			if _, err := w.bw.WriteString(w.simpleLine(rr)); err != nil {
				return err
			}
			wrote = true
		}
		return nil
	}

	if r.Msg != nil {
		if w.f.answer {
			if err := emit(w.answerRecords(r)); err != nil {
				return err
			}
		}
		if w.f.authority {
			if err := emit(r.Msg.Ns); err != nil {
				return err
			}
		}
		if w.f.additional {
			if err := emit(filterOPT(r.Msg.Extra)); err != nil {
				return err
			}
		}
	}

	// 'l': separate replies with a blank line (the classic -o Snl form).
	if w.f.sepReplies {
		if err := w.bw.WriteByte('\n'); err != nil {
			return err
		}
	}
	return nil
}

// simpleLine renders one RR as "name TYPE data" (or "name TTL CLASS TYPE data"
// with the 't' flag), terminated by a newline.
func (w *Writer) simpleLine(rr dns.RR) string {
	h := rr.Header()
	data := rdata(rr)
	if w.f.ttlClass {
		return fmt.Sprintf("%s %d %s %s %s\n", h.Name, h.Ttl, classString(h.Class), typeString(h.Rrtype), data)
	}
	return fmt.Sprintf("%s %s %s\n", h.Name, typeString(h.Rrtype), data)
}

// ---- full ----

func (w *Writer) writeFull(r resolve.Result) error {
	size := 0
	body := ""
	if r.Msg != nil {
		size = r.Msg.Len()
		body = r.Msg.String()
	}
	fmt.Fprintf(w.bw, ";; Server: %s\n;; Size: %d\n;; Unix time: %d\n%s\n\n",
		emptyDash(r.Resolver), size, r.Timestamp.Unix(), body)
	return nil
}

// ---- list ----

func (w *Writer) writeList(r resolve.Result) error {
	if r.Msg == nil {
		return nil
	}
	qname := questionName(r)
	answers := w.answerRecords(r)
	if len(answers) == 0 {
		if w.f.listIncludeEmpty && r.Rcode == dns.RcodeSuccess {
			fmt.Fprintf(w.bw, "%s\n", strings.TrimSuffix(qname, "."))
		}
		return nil
	}
	for _, rr := range answers {
		h := rr.Header()
		fmt.Fprintf(w.bw, "%s\t%s\t%s\n",
			strings.TrimSuffix(h.Name, "."), typeString(h.Rrtype), rdata(rr))
	}
	return nil
}

// ---- ndjson ----

type jsonRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

type jsonData struct {
	Answers     []jsonRecord `json:"answers"`
	Authorities []jsonRecord `json:"authorities,omitempty"`
	Additionals []jsonRecord `json:"additionals,omitempty"`
}

type jsonReply struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Class    string   `json:"class"`
	Status   string   `json:"status"`
	RxTs     int64    `json:"rx_ts,omitempty"`
	Resolver string   `json:"resolver,omitempty"`
	Flags    []string `json:"flags,omitempty"`
	Data     jsonData `json:"data"`
	Error    string   `json:"error,omitempty"`
}

func (w *Writer) writeNDJSON(r resolve.Result) error {
	rec := jsonReply{
		Name:     questionName(r),
		Type:     typeString(r.Type),
		Class:    "IN",
		Status:   rcodeString(r.Rcode),
		Resolver: r.Resolver,
	}
	if !r.Timestamp.IsZero() {
		rec.RxTs = r.Timestamp.Unix()
	}
	if r.Msg != nil {
		rec.Flags = msgFlags(r.Msg)
		rec.Data.Answers = jsonRecords(w.answerRecords(r))
		rec.Data.Authorities = jsonRecords(r.Msg.Ns)
		rec.Data.Additionals = jsonRecords(filterOPT(r.Msg.Extra))
	}
	if rec.Data.Answers == nil {
		rec.Data.Answers = []jsonRecord{}
	}
	return w.encodeJSON(rec)
}

func (w *Writer) encodeJSON(rec jsonReply) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if _, err := w.bw.Write(b); err != nil {
		return err
	}
	return w.bw.WriteByte('\n')
}

func jsonRecords(rrs []dns.RR) []jsonRecord {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]jsonRecord, 0, len(rrs))
	for _, rr := range rrs {
		h := rr.Header()
		out = append(out, jsonRecord{
			Name:  h.Name,
			Type:  typeString(h.Rrtype),
			Class: classString(h.Class),
			TTL:   h.Ttl,
			Data:  rdata(rr),
		})
	}
	return out
}

// ---- helpers ----

// rdata returns the record-specific data portion of an RR (everything after the
// "name ttl class type" header that miekg/dns prints).
func rdata(rr dns.RR) string {
	full := rr.String()
	header := rr.Header().String()
	return strings.TrimPrefix(full, header)
}

// filterOPT drops EDNS0 OPT pseudo-records from the additional section; they are
// transport metadata, not answer data, and massdns does not print them.
func filterOPT(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := rrs[:0:0]
	for _, rr := range rrs {
		if _, ok := rr.(*dns.OPT); ok {
			continue
		}
		out = append(out, rr)
	}
	return out
}

func msgFlags(m *dns.Msg) []string {
	var f []string
	if m.Response {
		f = append(f, "qr")
	}
	if m.Authoritative {
		f = append(f, "aa")
	}
	if m.Truncated {
		f = append(f, "tc")
	}
	if m.RecursionDesired {
		f = append(f, "rd")
	}
	if m.RecursionAvailable {
		f = append(f, "ra")
	}
	if m.AuthenticatedData {
		f = append(f, "ad")
	}
	if m.CheckingDisabled {
		f = append(f, "cd")
	}
	return f
}

// questionName returns the query name with a trailing dot (massdns convention).
func questionName(r resolve.Result) string {
	if r.Msg != nil && len(r.Msg.Question) > 0 {
		return r.Msg.Question[0].Name
	}
	return dns.Fqdn(r.Name)
}

func typeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

func classString(c uint16) string {
	if s, ok := dns.ClassToString[c]; ok {
		return s
	}
	return fmt.Sprintf("CLASS%d", c)
}

func rcodeString(rc int) string {
	if s, ok := dns.RcodeToString[rc]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", rc)
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
