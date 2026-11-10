package main

import (
	"net/http"
	"net/url"
	"testing"
)

func TestParseProxySpec(t *testing.T) {
	// пусто — не задан
	s, err := parseProxySpec("")
	if err != nil || s.mode != proxyNone {
		t.Fatalf("пустой proxy: %v %v", s, err)
	}

	// direct / env-синонимы
	for _, v := range []string{"direct", "Direct"} {
		if s, err := parseProxySpec(v); err != nil || s.mode != proxyDirect {
			t.Fatalf("%q: ждали direct, получили %v (%v)", v, s, err)
		}
	}
	for _, v := range []string{"env", "yes", "true", "ENV", "Yes"} {
		if s, err := parseProxySpec(v); err != nil || s.mode != proxyEnv {
			t.Fatalf("%q: ждали env, получили %v (%v)", v, s, err)
		}
	}

	// URL с поддерживаемыми схемами, включая учётные данные
	for _, v := range []string{
		"socks5://127.0.0.1:10808",
		"socks5h://127.0.0.1:10808",
		"http://127.0.0.1:10801",
		"https://user:pass@proxy.example.com:3128",
	} {
		s, err := parseProxySpec(v)
		if err != nil || s.mode != proxyURL || s.url == nil {
			t.Fatalf("%q: URL не разобран: %v (%v)", v, s, err)
		}
	}

	// мусор — ошибка, а не молчаливое «напрямую»
	for _, v := range []string{
		"sock5://127.0.0.1:10808", // опечатка: нет схемы socks5
		"ftp://127.0.0.1:21",
		"127.0.0.1:10808", // без схемы
		"socks5://",       // без хоста
		"://",
	} {
		if _, err := parseProxySpec(v); err == nil {
			t.Errorf("%q: ожидалась ошибка", v)
		}
	}
}

func TestGeoProxyFunc(t *testing.T) {
	req := func() *http.Request {
		return &http.Request{URL: &url.URL{Scheme: "https", Host: "raw.githubusercontent.com"}}
	}
	proxyOf := func(cfg *Config) func(*http.Request) (*url.URL, error) {
		return geoProxyFunc(cfg)
	}

	// фиксированный URL — транспорт его отдаёт
	c := defaultConfig()
	c.Proxy = "socks5://127.0.0.1:10808"
	if err := c.prepareProxy(); err != nil {
		t.Fatal(err)
	}
	if u, err := proxyOf(&c)(req()); err != nil || u == nil || u.Scheme != "socks5" || u.Host != "127.0.0.1:10808" {
		t.Fatalf("верхний proxy не применился: %v (%v)", u, err)
	}

	// geo.proxy перекрывает верхний
	c.Geo.Proxy = "http://127.0.0.1:10801"
	if err := c.prepareGeo(); err != nil {
		t.Fatal(err)
	}
	if u, err := proxyOf(&c)(req()); err != nil || u == nil || u.Scheme != "http" || u.Host != "127.0.0.1:10801" {
		t.Fatalf("geo.proxy не перекрыл верхний: %v (%v)", u, err)
	}

	// geo.proxy: direct перекрывает верхний прокси — качаем напрямую
	c.Geo.Proxy = "direct"
	if err := c.prepareGeo(); err != nil {
		t.Fatal(err)
	}
	if fn := geoProxyFunc(&c); fn != nil {
		t.Fatal("direct должен отключить прокси")
	}

	// env — транспорт читает окружение
	c2 := defaultConfig()
	c2.Proxy = "env"
	if err := c2.prepareProxy(); err != nil {
		t.Fatal(err)
	}
	if fn := geoProxyFunc(&c2); fn == nil {
		t.Fatal("proxy: env, а транспорт окружение не использует")
	} else if u, err := fn(req()); err != nil || u == nil {
		t.Fatalf("env: %v (%v)", u, err)
	}

	// пусто — напрямую
	c3 := defaultConfig()
	if fn := geoProxyFunc(&c3); fn != nil {
		t.Fatal("без proxy качаем напрямую, а транспорт что-то подставил")
	}
}

func TestTransportWiresProxy(t *testing.T) {
	c := defaultConfig()
	c.Proxy = "socks5://127.0.0.1:10808"
	if err := c.prepareProxy(); err != nil {
		t.Fatal(err)
	}
	f := newGeoFetcher(&c)
	tr, ok := f.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("транспорт не http.Transport")
	}
	if tr.Proxy == nil {
		t.Fatal("proxy задан, а транспорт его не использует")
	}
	u, err := tr.Proxy(&http.Request{URL: &url.URL{Scheme: "https", Host: "raw.githubusercontent.com"}})
	if err != nil || u == nil || u.Host != "127.0.0.1:10808" {
		t.Fatalf("не тот прокси: %v (%v)", u, err)
	}
}
