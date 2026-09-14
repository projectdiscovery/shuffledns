package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/shuffledns/pkg/parser"
	"github.com/projectdiscovery/shuffledns/pkg/resolve"
)

// sampleResult builds a resolve.Result with a fully populated *dns.Msg for
// example.com -> 93.184.216.34 (A) with an authority NS record.
func sampleResult() resolve.Result {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.Response = true
	m.RecursionDesired = true
	m.RecursionAvailable = true
	a, _ := dns.NewRR("example.com. 45929 IN A 93.184.216.34")
	m.Answer = []dns.RR{a}
	ns, _ := dns.NewRR("example.com. 24852 IN NS a.iana-servers.net.")
	m.Ns = []dns.RR{ns}

	return resolve.Result{
		Name:      "example.com",
		Type:      dns.TypeA,
		Rcode:     dns.RcodeSuccess,
		A:         []string{"93.184.216.34"},
		Resolver:  "192.0.2.1:53",
		Msg:       m,
		Timestamp: time.Unix(1513458347, 0),
	}
}

func render(t *testing.T, spec string, r resolve.Result) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, spec)
	if err != nil {
		t.Fatalf("NewWriter(%q): %v", spec, err)
	}
	if err := w.Write(r); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	return buf.String()
}

func TestSimpleDefault(t *testing.T) {
	got := render(t, "S", sampleResult())
	want := "example.com. A 93.184.216.34\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSimpleSnlRoundTripsThroughParser(t *testing.T) {
	// The classic massdns -o Snl form must be consumable by pkg/parser.
	got := render(t, "Snl", sampleResult())
	if !strings.HasSuffix(got, "\n\n") {
		t.Fatalf("Snl should end replies with a blank line: %q", got)
	}

	var domain string
	var ips []string
	err := parser.ParseReader(strings.NewReader(got), func(d string, ip []string) error {
		domain = d
		ips = ip
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if domain != "example.com" {
		t.Fatalf("parser domain: got %q", domain)
	}
	if len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Fatalf("parser ips: got %v", ips)
	}
}

func TestSimpleTTLClass(t *testing.T) {
	got := render(t, "St", sampleResult())
	want := "example.com. 45929 IN A 93.184.216.34\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestSimpleQuestionAndAuthority(t *testing.T) {
	got := render(t, "Snuq", sampleResult())
	if !strings.Contains(got, "example.com. IN A\n") {
		t.Fatalf("missing question line: %q", got)
	}
	if !strings.Contains(got, "example.com. A 93.184.216.34\n") {
		t.Fatalf("missing answer: %q", got)
	}
	if !strings.Contains(got, "example.com. NS a.iana-servers.net.\n") {
		t.Fatalf("missing authority: %q", got)
	}
}

func TestSimpleMeta(t *testing.T) {
	got := render(t, "Snr", sampleResult())
	if !strings.HasPrefix(got, "192.0.2.1:53 1513458347 NOERROR example.com. IN A\n") {
		t.Fatalf("meta prefix wrong: %q", got)
	}
}

func TestFull(t *testing.T) {
	got := render(t, "F", sampleResult())
	for _, want := range []string{
		";; Server: 192.0.2.1:53",
		";; Unix time: 1513458347",
		"ANSWER SECTION",
		"93.184.216.34",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("full output missing %q in:\n%s", want, got)
		}
	}
}

func TestList(t *testing.T) {
	got := render(t, "L", sampleResult())
	want := "example.com\tA\t93.184.216.34\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestNDJSON(t *testing.T) {
	got := render(t, "J", sampleResult())
	var rec struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Class    string `json:"class"`
		Status   string `json:"status"`
		Resolver string `json:"resolver"`
		RxTs     int64  `json:"rx_ts"`
		Data     struct {
			Answers []struct {
				Name string `json:"name"`
				Type string `json:"type"`
				TTL  uint32 `json:"ttl"`
				Data string `json:"data"`
			} `json:"answers"`
		} `json:"data"`
		Flags []string `json:"flags"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(got)), &rec); err != nil {
		t.Fatalf("invalid ndjson %q: %v", got, err)
	}
	if rec.Name != "example.com." || rec.Type != "A" || rec.Status != "NOERROR" {
		t.Fatalf("bad header fields: %+v", rec)
	}
	if rec.Resolver != "192.0.2.1:53" || rec.RxTs != 1513458347 {
		t.Fatalf("bad meta: %+v", rec)
	}
	if len(rec.Data.Answers) != 1 || rec.Data.Answers[0].Data != "93.184.216.34" || rec.Data.Answers[0].TTL != 45929 {
		t.Fatalf("bad answers: %+v", rec.Data.Answers)
	}
}

func TestNDJSONFailure(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, "Je")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFailure("dead.example.com", dns.TypeA, "resolution failed"); err != nil {
		t.Fatal(err)
	}
	_ = w.Flush()
	if !strings.Contains(buf.String(), `"status":"ERROR"`) || !strings.Contains(buf.String(), "dead.example.com.") {
		t.Fatalf("bad failure record: %q", buf.String())
	}

	// without 'e', failures are suppressed
	var buf2 bytes.Buffer
	w2, _ := NewWriter(&buf2, "J")
	_ = w2.WriteFailure("dead.example.com", dns.TypeA, "x")
	_ = w2.Flush()
	if buf2.Len() != 0 {
		t.Fatalf("expected no failure output without 'e', got %q", buf2.String())
	}
}

func renderCfg(t *testing.T, cfg Config, r resolve.Result) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriterWithConfig(&buf, cfg)
	if err != nil {
		t.Fatalf("NewWriterWithConfig: %v", err)
	}
	if err := w.Write(r); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = w.Flush()
	return buf.String()
}

func TestFilterRcode(t *testing.T) {
	r := sampleResult() // NOERROR
	// only NXDOMAIN allowed -> NOERROR reply suppressed
	if got := renderCfg(t, Config{Format: "S", FilterRcodes: []string{"NXDOMAIN"}}, r); got != "" {
		t.Fatalf("expected suppression, got %q", got)
	}
	// NOERROR allowed -> emitted
	if got := renderCfg(t, Config{Format: "S", FilterRcodes: []string{"NOERROR"}}, r); got == "" {
		t.Fatal("expected output for allowed rcode")
	}
}

func TestIgnoreRcode(t *testing.T) {
	r := sampleResult() // NOERROR
	if got := renderCfg(t, Config{Format: "S", IgnoreRcodes: []string{"NOERROR"}}, r); got != "" {
		t.Fatalf("expected NOERROR to be ignored, got %q", got)
	}
}

func TestOnlyQueryType(t *testing.T) {
	// build a result whose answer has a CNAME plus the queried A record
	m := new(dns.Msg)
	m.SetQuestion("www.example.com.", dns.TypeA)
	cname, _ := dns.NewRR("www.example.com. 300 IN CNAME example.com.")
	a, _ := dns.NewRR("example.com. 300 IN A 93.184.216.34")
	m.Answer = []dns.RR{cname, a}
	r := resolve.Result{Name: "www.example.com", Type: dns.TypeA, Rcode: dns.RcodeSuccess, Msg: m}

	full := renderCfg(t, Config{Format: "S"}, r)
	if !strings.Contains(full, "CNAME") {
		t.Fatalf("expected CNAME in unfiltered output: %q", full)
	}
	only := renderCfg(t, Config{Format: "S", OnlyQueryType: true}, r)
	if strings.Contains(only, "CNAME") {
		t.Fatalf("only-type output should drop CNAME: %q", only)
	}
	if !strings.Contains(only, "A 93.184.216.34") {
		t.Fatalf("only-type output should keep the A record: %q", only)
	}
}

func TestInvalidRcodeConfig(t *testing.T) {
	var buf bytes.Buffer
	if _, err := NewWriterWithConfig(&buf, Config{Format: "S", FilterRcodes: []string{"BOGUS"}}); err == nil {
		t.Fatal("expected error for invalid rcode name")
	}
}

func TestUnknownFlag(t *testing.T) {
	if _, err := ParseFormat("SZ"); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}
