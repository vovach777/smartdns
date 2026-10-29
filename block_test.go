package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Апстрим-заглушка: не ходит в сеть, сразу отдаёт заданный код.
func TestBlockUpstream(t *testing.T) {
	cases := []struct {
		spec string
		want int
	}{
		{"refuse", dns.RcodeRefused},
		{"refused", dns.RcodeRefused},
		{"nxdomain", dns.RcodeNameError},
		{"nx", dns.RcodeNameError},
		{"noerror", dns.RcodeSuccess},
	}
	for _, c := range cases {
		u, err := newUpstream("blocked", c.spec, time.Second, "", boot{})
		if err != nil {
			t.Fatalf("%s: %v", c.spec, err)
		}
		if !u.block {
			t.Fatalf("%s: не заглушка", c.spec)
		}
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn("ads.example.org"), dns.TypeA)
		m, err := u.exchange(q, "udp")
		if err != nil {
			t.Fatalf("%s: %v", c.spec, err)
		}
		if m == nil || m.Rcode != c.want {
			t.Fatalf("%s: код %v, ждали %v", c.spec, m.Rcode, c.want)
		}
		if len(m.Answer) != 0 {
			t.Fatalf("%s: в ответе есть записи: %v", c.spec, m.Answer)
		}
		if m.Question[0].Name != "ads.example.org." {
			t.Fatalf("%s: вопрос не сохранён: %v", c.spec, m.Question)
		}
	}
}

// Обычный апстрим заглушкой не считается: NOERROR — это код 0.
func TestBlockUpstreamOrdinary(t *testing.T) {
	u, err := newUpstream("cf", "1.1.1.1", time.Second, "", boot{})
	if err != nil {
		t.Fatal(err)
	}
	if u.block {
		t.Fatal("1.1.1.1 принят за заглушку")
	}
}
