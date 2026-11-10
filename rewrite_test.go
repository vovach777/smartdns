package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testApp собирает приложение из готового конфига (для тестов rewrite).
func testApp(t *testing.T, cfg *Config) *App {
	t.Helper()
	if err := cfg.prepare(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	a, err := NewApp(cfg)
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	return a
}

func TestRewritePrepare(t *testing.T) {
	cfg := defaultConfig()
	cfg.Rewrite = map[string]string{"WorkBuddy.CH.": "WorkBuddy.AI."}
	if err := cfg.prepare(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.rewrites["workbuddy.ch"]; got != "workbuddy.ai" {
		t.Fatalf("нормализация: %q, ждали workbuddy.ai", got)
	}

	bad := []map[string]string{
		{"a.example": "1.2.3.4"},     // IP — это hosts
		{"a.example": "a.example"},   // сам на себя
		{"a.example": ""},            // пусто
		{"*.a.example": "b.example"}, // шаблоны не поддерживаем
	}
	for _, m := range bad {
		c := defaultConfig()
		c.Rewrite = m
		if err := c.prepare(); err == nil {
			t.Errorf("%v: ждали ошибку", m)
		}
	}
}

// Запрос за workbuddy.ch уходит апстриму уже как workbuddy.ai, а ответ
// возвращается под исходным именем — без CNAME и без второго запроса.
func TestRewritePatchesName(t *testing.T) {
	addr := startTestDNS(t, map[string][]dns.RR{
		"workbuddy.ai": {testRR("workbuddy.ai.", "203.0.113.10", 300)},
		"workbuddy.ch": {testRR("workbuddy.ch.", "203.0.113.99", 300)}, // ловушка
	})
	cfg := defaultConfig()
	cfg.Servers = map[string]string{"q9": addr}
	cfg.Routes = []Route{{Match: []string{"*"}, Chain: []string{"q9"}}}
	cfg.Rewrite = map[string]string{"workbuddy.ch": "workbuddy.ai"}
	cfg.timeoutDur = time.Second
	a := testApp(t, &cfg)

	q := new(dns.Msg)
	q.SetQuestion("workbuddy.ch.", dns.TypeA)
	resp := a.resolveQuery(q, "udp")
	if resp == nil {
		t.Fatal("ответа нет")
	}
	if got := answerIP(resp, dns.TypeA); got != "203.0.113.10" {
		t.Fatalf("ответ %q, ждали адрес workbuddy.ai (203.0.113.10)", got)
	}
	if len(resp.Question) == 0 || resp.Question[0].Name != "workbuddy.ch." {
		t.Fatalf("вопрос в ответе %v, ждали workbuddy.ch.", resp.Question)
	}
	if len(resp.Answer) == 0 || resp.Answer[0].Header().Name != "workbuddy.ch." {
		t.Fatalf("владелец записи %v, ждали workbuddy.ch.", resp.Answer)
	}
	if hit := a.cache.Get(CacheKey("workbuddy.ch", dns.TypeA)); hit == nil {
		t.Fatal("ответ не закэширован под исходным именем")
	}
}

// Маршрут выбирается по целевому имени: workbuddy.ai идёт своей цепочкой,
// а не той, что была бы у workbuddy.ch.
func TestRewriteUsesTargetRoute(t *testing.T) {
	badAddr := startTestDNS(t, map[string][]dns.RR{
		"workbuddy.ai": {testRR("workbuddy.ai.", "203.0.113.99", 300)},
	})
	goodAddr := startTestDNS(t, map[string][]dns.RR{
		"workbuddy.ai": {testRR("workbuddy.ai.", "203.0.113.10", 300)},
	})
	cfg := defaultConfig()
	cfg.Servers = map[string]string{"bad": badAddr, "good": goodAddr}
	cfg.Routes = []Route{
		{Match: []string{"workbuddy.ai"}, Chain: []string{"good"}},
		{Match: []string{"*"}, Chain: []string{"bad"}},
	}
	cfg.Rewrite = map[string]string{"workbuddy.ch": "workbuddy.ai"}
	cfg.timeoutDur = time.Second
	a := testApp(t, &cfg)

	q := new(dns.Msg)
	q.SetQuestion("workbuddy.ch.", dns.TypeA)
	resp := a.resolveQuery(q, "udp")
	if got := answerIP(resp, dns.TypeA); got != "203.0.113.10" {
		t.Fatalf("ответ %q, ждали 203.0.113.10 из цепочки workbuddy.ai", got)
	}
}

// Патч имени работает и для AAAA.
func TestRewriteIPv6(t *testing.T) {
	addr := startTestDNS(t, map[string][]dns.RR{
		"v6.ai": {testRR("v6.ai.", "2001:db8::10", 300)},
		"v6.ch": {testRR("v6.ch.", "2001:db8::99", 300)},
	})
	cfg := defaultConfig()
	cfg.IPv6 = true
	cfg.Servers = map[string]string{"q9": addr}
	cfg.Routes = []Route{{Match: []string{"*"}, Chain: []string{"q9"}}}
	cfg.Rewrite = map[string]string{"v6.ch": "v6.ai"}
	cfg.timeoutDur = time.Second
	a := testApp(t, &cfg)

	q := new(dns.Msg)
	q.SetQuestion("v6.ch.", dns.TypeAAAA)
	resp := a.resolveQuery(q, "udp")
	if got := answerIP(resp, dns.TypeAAAA); got != "2001:db8::10" {
		t.Fatalf("ответ %q, ждали 2001:db8::10", got)
	}
}
