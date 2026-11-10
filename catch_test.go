package main

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testRR — запись с правильным именем и типом по адресу.
func testRR(name, ip string, ttl uint32) dns.RR {
	hdr := dns.RR_Header{Name: dns.Fqdn(name), Class: dns.ClassINET, Ttl: ttl}
	v := net.ParseIP(ip)
	if v4 := v.To4(); v4 != nil {
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: v4}
	}
	hdr.Rrtype = dns.TypeAAAA
	return &dns.AAAA{Hdr: hdr, AAAA: v}
}

// startTestDNS поднимает локальный UDP-резолвер, который отдаёт заранее
// заданные ответы по имени. Адрес — 127.0.0.1:<эфемерный порт>.
func startTestDNS(t *testing.T, answers map[string][]dns.RR) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("слушатель: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		if len(r.Question) > 0 {
			q := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, "."))
			for _, rr := range answers[q] {
				m.Answer = append(m.Answer, dns.Copy(rr))
			}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// testCatchApp собирает живое приложение без чтения файлов конфига.
func testCatchApp(t *testing.T, servers map[string]string, routes []Route, catches []CatchRule, ipv6 bool) *App {
	t.Helper()
	cfg := defaultConfig()
	cfg.IPv6 = ipv6
	cfg.Servers = servers
	cfg.Routes = routes
	cfg.Catches = catches
	cfg.timeoutDur = time.Second
	if err := cfg.prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	a, err := NewApp(&cfg)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	return a
}

func TestCatchMatch(t *testing.T) {
	cfg := defaultConfig()
	cfg.Catches = []CatchRule{
		{Name: "zero", Match: []string{"0.0.0.1", "0.0.0.0"}},
		{Name: "doc", Match: []string{"198.51.100.0/24"}},
		{Name: "v6", Match: []string{"2001:db8::/32"}},
	}
	if err := cfg.prepareCatches(); err != nil {
		t.Fatal(err)
	}
	mk := func(rrs ...dns.RR) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("www.example.", dns.TypeA)
		m.Answer = rrs
		return m
	}
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
		Target: "target.example.",
	}
	cases := []struct {
		name string
		msg  *dns.Msg
		want string
	}{
		{"точный адрес", mk(testRR("www.example.", "0.0.0.1", 60)), "zero"},
		{"CIDR", mk(testRR("www.example.", "198.51.100.7", 60)), "doc"},
		{"IPv6", mk(testRR("www.example.", "2001:db8::5", 60)), "v6"},
		{"CNAME + A", mk(cname, testRR("target.example.", "0.0.0.1", 60)), "zero"},
		{"мимо", mk(testRR("www.example.", "203.0.113.9", 60)), ""},
	}
	for _, c := range cases {
		got := ""
		if r, _ := cfg.catchMatch(c.msg, nil); r != nil {
			got = r.Name
		}
		if got != c.want {
			t.Errorf("%s: правило %q, ждали %q", c.name, got, c.want)
		}
	}
}

// Правило срабатывает не больше раза за запрос — это и есть защита от петли.
func TestCatchUsedGuard(t *testing.T) {
	cfg := defaultConfig()
	cfg.Catches = []CatchRule{{Name: "zero", Match: []string{"0.0.0.1"}}}
	if err := cfg.prepareCatches(); err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	m.SetQuestion("www.example.", dns.TypeA)
	m.Answer = []dns.RR{testRR("www.example.", "0.0.0.1", 60)}

	used := map[string]bool{}
	if r, _ := cfg.catchMatch(m, used); r == nil {
		t.Fatal("первый раз правило не сработало")
	}
	used["zero"] = true
	if r, _ := cfg.catchMatch(m, used); r != nil {
		t.Fatalf("второй раз сработало правило %q", r.Name)
	}
}

func TestCatchPrepare(t *testing.T) {
	cfg := defaultConfig()
	cfg.Catches = []CatchRule{{Match: []string{"0.0.0.1"}}}
	if err := cfg.prepareCatches(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Catches[0].Name; got != "catch#1" {
		t.Fatalf("имя по умолчанию %q, ждали catch#1", got)
	}

	bad := defaultConfig()
	bad.Catches = []CatchRule{{Match: []string{"не-адрес"}}}
	if err := bad.prepareCatches(); err == nil {
		t.Fatal("ждали ошибку на не-адресе")
	}
}

func TestCatchValidation(t *testing.T) {
	base := func() *Config {
		cfg := defaultConfig()
		cfg.Servers = map[string]string{"q9": "9.9.9.9", "cf": "1.1.1.1"}
		cfg.Routes = []Route{{Match: []string{"*"}, Chain: []string{"q9"}}}
		return &cfg
	}
	cases := []struct {
		name string
		rule CatchRule
		want string
	}{
		{"пустой chain", CatchRule{Name: "a", Match: []string{"0.0.0.1"}}, "пустой chain"},
		{"неизвестный сервер", CatchRule{Name: "a", Match: []string{"0.0.0.1"}, Chain: []string{"нет"}}, "неизвестный сервер"},
		{"без матча", CatchRule{Name: "a", Chain: []string{"q9"}}, "нужен match или set"},
	}
	for _, c := range cases {
		cfg := base()
		cfg.Catches = []CatchRule{c.rule}
		if err := cfg.prepare(); err != nil {
			t.Fatalf("%s: prepare: %v", c.name, err)
		}
		err := cfg.validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: ошибка %v, ждали %q", c.name, err, c.want)
		}
	}

	cfg := base()
	cfg.Catches = []CatchRule{
		{Name: "dup", Match: []string{"0.0.0.1"}, Chain: []string{"q9"}},
		{Name: "dup", Match: []string{"0.0.0.2"}, Chain: []string{"q9"}},
	}
	if err := cfg.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "повторяется") {
		t.Fatalf("дубль имени: ошибка %v", err)
	}
}

// Сквозной сценарий: первый сервер отдаёт 0.0.0.1, правило переспрашивает
// второй, и годный ответ попадает в кэш.
func TestCatchRetryCachesGoodAnswer(t *testing.T) {
	badAddr := startTestDNS(t, map[string][]dns.RR{
		"blocked.example": {testRR("blocked.example.", "0.0.0.1", 300)},
	})
	goodAddr := startTestDNS(t, map[string][]dns.RR{
		"blocked.example": {testRR("blocked.example.", "203.0.113.7", 300)},
	})
	a := testCatchApp(t,
		map[string]string{"bad": badAddr, "good": goodAddr},
		[]Route{{Match: []string{"*"}, Chain: []string{"bad"}}},
		[]CatchRule{{Name: "ads-zero", Match: []string{"0.0.0.1"}, Chain: []string{"good"}}},
		false,
	)

	q := new(dns.Msg)
	q.SetQuestion("blocked.example.", dns.TypeA)
	resp := a.resolveQuery(q, "udp")
	if resp == nil {
		t.Fatal("ответа нет")
	}
	if got := answerIP(resp, dns.TypeA); got != "203.0.113.7" {
		t.Fatalf("ответ %q, ждали 203.0.113.7", got)
	}

	hit := a.cache.Get(CacheKey("blocked.example", dns.TypeA))
	if hit == nil {
		t.Fatal("пойманный ответ не закэширован")
	}
	if got := answerIP(hit, dns.TypeA); got != "203.0.113.7" {
		t.Fatalf("в кэше %q, ждали 203.0.113.7", got)
	}
}

// Правило, ведущее обратно на тот же сервер, не должно зацикливаться:
// второй раз оно не срабатывает, поганый ответ отдаётся как есть и не
// кэшируется.
func TestCatchLoopTerminates(t *testing.T) {
	badAddr := startTestDNS(t, map[string][]dns.RR{
		"loop.example": {testRR("loop.example.", "0.0.0.1", 300)},
	})
	a := testCatchApp(t,
		map[string]string{"bad": badAddr},
		[]Route{{Match: []string{"*"}, Chain: []string{"bad"}}},
		[]CatchRule{{Name: "self", Match: []string{"0.0.0.1"}, Chain: []string{"bad"}}},
		false,
	)

	q := new(dns.Msg)
	q.SetQuestion("loop.example.", dns.TypeA)
	done := make(chan *dns.Msg, 1)
	go func() { done <- a.resolveQuery(q, "udp") }()
	select {
	case resp := <-done:
		if resp == nil {
			t.Fatal("ответа нет")
		}
		if got := answerIP(resp, dns.TypeA); got != "0.0.0.1" {
			t.Fatalf("ответ %q, ждали 0.0.0.1", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("похоже на петлю: ответа нет за 5 с")
	}
	if hit := a.cache.Get(CacheKey("loop.example", dns.TypeA)); hit != nil {
		t.Fatal("поганый ответ попал в кэш")
	}
}

// Переспрос, который никого не дождался, не превращает правило в фильтр:
// возвращается исходный ответ, как будто правила не было.
func TestCatchRetryFailureKeepsOriginal(t *testing.T) {
	origAddr := startTestDNS(t, map[string][]dns.RR{
		"soft.example": {testRR("soft.example.", "203.0.113.9", 300)},
	})
	deadAddr := startTestDNS(t, map[string][]dns.RR{})
	a := testCatchApp(t,
		map[string]string{"orig": origAddr, "dead": deadAddr},
		[]Route{{Match: []string{"*"}, Chain: []string{"orig"}}},
		[]CatchRule{{Name: "soft", Match: []string{"203.0.113.9"}, Chain: []string{"dead"}}},
		false,
	)

	q := new(dns.Msg)
	q.SetQuestion("soft.example.", dns.TypeA)
	resp := a.resolveQuery(q, "udp")
	if resp == nil {
		t.Fatal("ответа нет")
	}
	if got := answerIP(resp, dns.TypeA); got != "203.0.113.9" {
		t.Fatalf("ответ %q, ждали исходный 203.0.113.9", got)
	}
}

// Набор из catches обязан попасть в список ссылок: иначе в режиме единого
// .dat категория не вытащится и правило молча не сработает.
func TestReferencedSetsIncludesCatches(t *testing.T) {
	cfg := defaultConfig()
	cfg.Geo = Geo{Sources: []GeoSource{{
		Name:    "t",
		Geosite: []string{"https://t/{name}"},
		Geoip:   []string{"https://t/{name}"},
	}}}
	if err := cfg.prepareGeo(); err != nil {
		t.Fatal(err)
	}
	cfg.AnswerGeoip = []AnswerRule{{Set: "blocked", Action: "nxdomain"}}
	cfg.Catches = []CatchRule{{Name: "ru", Set: "RU-BLOCKED", Chain: []string{"q9"}}}
	cfg.geoip = map[string]*ipSet{}

	got := cfg.referencedRefs()
	if !got["geoip"]["t"]["blocked"] {
		t.Error("потерян набор из answer_geoip")
	}
	if !got["geoip"]["t"]["ru-blocked"] {
		t.Error("потерян набор из catches")
	}
}

// IPv6-адрес в ответе тоже ловится, если IPv6 не вырезан.
func TestCatchIPv6(t *testing.T) {
	badAddr := startTestDNS(t, map[string][]dns.RR{
		"v6.example": {testRR("v6.example.", "2001:db8::1", 300)},
	})
	goodAddr := startTestDNS(t, map[string][]dns.RR{
		"v6.example": {testRR("v6.example.", "2001:db8::2", 300)},
	})
	a := testCatchApp(t,
		map[string]string{"bad": badAddr, "good": goodAddr},
		[]Route{{Match: []string{"*"}, Chain: []string{"bad"}}},
		[]CatchRule{{Name: "v6", Match: []string{"2001:db8::1"}, Chain: []string{"good"}}},
		true,
	)

	q := new(dns.Msg)
	q.SetQuestion("v6.example.", dns.TypeAAAA)
	resp := a.resolveQuery(q, "udp")
	if resp == nil {
		t.Fatal("ответа нет")
	}
	if got := answerIP(resp, dns.TypeAAAA); got != "2001:db8::2" {
		t.Fatalf("ответ %q, ждали 2001:db8::2", got)
	}
}
