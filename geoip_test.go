package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func writeSet(t *testing.T, body string) *ipSet {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.txt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := parseIPSet(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestParseIPSetAndMatch(t *testing.T) {
	s := writeSet(t, "# test\n10.0.0.0/8\n203.0.113.7\n8.8.8.0/24\n2001:db8::/32\n")
	if s.Entries != 3 {
		t.Fatalf("Entries = %d, want 3", s.Entries)
	}
	if s.SkippedV6 != 1 {
		t.Fatalf("SkippedV6 = %d, want 1", s.SkippedV6)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"9.255.255.255", false},
		{"11.0.0.0", false},
		{"203.0.113.7", true},
		{"203.0.113.8", false},
		{"8.8.8.8", true},
		{"2001:db8::1", false}, // IPv6 не поддержан — ожидаемо false
	}
	for _, c := range cases {
		if got := s.match(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("match(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestParseIPSetMergesOverlaps(t *testing.T) {
	s := writeSet(t, "10.0.0.0/24\n10.0.0.128/25\n10.0.1.0/24\n")
	if len(s.Ranges) != 1 {
		t.Fatalf("диапазоны не слились: %+v", s.Ranges)
	}
	if s.Ranges[0].lo != ip4ToU32(net.ParseIP("10.0.0.0")) || s.Ranges[0].hi != ip4ToU32(net.ParseIP("10.0.1.255")) {
		t.Fatalf("неверный слитый диапазон: %+v", s.Ranges[0])
	}
}

func TestParseIPSetRejectsGarbage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.txt")
	if err := os.WriteFile(p, []byte("10.0.0.0/33\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := parseIPSet(p); err == nil {
		t.Fatal("битый CIDR должен быть ошибкой")
	}
}

func TestApplyAnswerGeoip(t *testing.T) {
	s := writeSet(t, "140.82.0.0/16\n")
	cfg := &Config{geoip: map[string]*ipSet{"blocked": s}}

	mk := func(ip string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("x.example.", dns.TypeA)
		m.Response = true
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(ip),
		})
		return m
	}

	// попал в набор -> nxdomain, ответ очищен
	cfg.AnswerGeoip = []AnswerRule{{Set: "blocked", Action: "nxdomain"}}
	m := mk("140.82.121.3")
	if !cfg.applyAnswerGeoip(m) {
		t.Fatal("ожидалось срабатывание фильтра")
	}
	if m.Rcode != dns.RcodeNameError || len(m.Answer) != 0 {
		t.Fatalf("rcode=%d answer=%d, want NXDOMAIN/0", m.Rcode, len(m.Answer))
	}

	// refused
	cfg.AnswerGeoip = []AnswerRule{{Set: "blocked", Action: "refused"}}
	m = mk("140.82.121.3")
	cfg.applyAnswerGeoip(m)
	if m.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode=%d, want REFUSED", m.Rcode)
	}

	// не попал -> без изменений
	cfg.AnswerGeoip = []AnswerRule{{Set: "blocked", Action: "nxdomain"}}
	m = mk("93.184.216.34")
	if cfg.applyAnswerGeoip(m) {
		t.Fatal("фильтр не должен срабатывать")
	}
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("ответ изменён без причины: rcode=%d answer=%d", m.Rcode, len(m.Answer))
	}
}
