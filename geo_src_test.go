package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func srcCfg() *Config {
	c := defaultConfig()
	c.Geo = Geo{Sources: []GeoSource{
		{Name: "hagezi", Geosite: []string{"https://h/{name}.txt"}},
		{Name: "rf", Geosite: []string{"https://rf/{name}.txt"}, Geoip: []string{"https://rf/{name}.txt"}},
	}}
	return &c
}

func TestPrepareGeoValidation(t *testing.T) {
	bad := []struct {
		name string
		mk   func(*Config)
		want string
	}{
		{"нет имени", func(c *Config) { c.Geo.Sources[0].Name = "" }, "нужно имя"},
		{"дубль", func(c *Config) { c.Geo.Sources[1].Name = "hagezi" }, "дважды"},
		{"нет url", func(c *Config) { c.Geo.Sources[0].Geosite = nil }, "ни один URL"},
		{"схема", func(c *Config) { c.Geo.Sources[0].Geosite = []string{"ftp://h/{name}.txt"} }, "http"},
		{"смешаны режимы", func(c *Config) { c.Geo.Sources[0].Geosite = []string{"https://h/{name}.txt", "https://h/all.txt"} }, "смешаны"},
		{"кэш дважды", func(c *Config) { c.GeoCacheDir = "C:\\x"; c.Geo.CacheDir = "C:\\y" }, "оставь один"},
	}
	for _, tc := range bad {
		c := srcCfg()
		tc.mk(c)
		err := c.prepareGeo()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ждали ошибку с %q, получили %v", tc.name, tc.want, err)
		}
	}

	// валидный конфиг проходит
	c := srcCfg()
	if err := c.prepareGeo(); err != nil {
		t.Fatalf("валидный конфиг не прошёл: %v", err)
	}
	if c.geoSrcs[0].name != "hagezi" || c.geoSrcs[1].name != "rf" {
		t.Error("порядок источников потерян")
	}
}

func TestGeoRefValidation(t *testing.T) {
	bad := []struct {
		name string
		mk   func(*Config)
		want string
	}{
		{"нет источника", func(c *Config) { c.Routes[0].Match = []string{"geosite@nope:pro"} }, "нет источника"},
		{"нет вида", func(c *Config) {
			c.Geo.Sources[0].Geosite = nil
			c.Geo.Sources[0].Geoip = []string{"https://h/{name}.txt"}
			c.Geo.Sources[1].Geosite = nil
		}, "нет ни одного источника с geosite"},
		{"кривая ссылка", func(c *Config) { c.Routes[0].Match = []string{"geosite@hagezi"} }, "источник:имя"},
		{"set нет источника", func(c *Config) { c.AnswerGeoip[0].Set = "nope@blocked" }, "нет источника"},
		{"set кривая", func(c *Config) { c.Catches[0].Set = "a@b@c" }, "источник@имя"},
	}
	for _, tc := range bad {
		c := srcCfg()
		// первый источник без geosite не бывает — ломаем по сценарию
		if tc.name == "нет вида" {
			c.Geo.Sources[0].Geosite = nil
		}
		c.Servers = map[string]string{"s": "127.0.0.1:53"}
		c.Routes = []Route{{Match: []string{"geosite:pro"}, Chain: []string{"s"}}}
		c.AnswerGeoip = []AnswerRule{{Set: "blocked", Action: "nxdomain"}}
		c.Catches = []CatchRule{{Name: "c", Set: "blocked", Chain: []string{"s"}}}
		tc.mk(c)
		err := c.prepareGeo()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: ждали ошибку с %q, получили %v", tc.name, tc.want, err)
		}
	}

	// корректные ссылки проходят, включая неймспейс
	c := srcCfg()
	c.Servers = map[string]string{"s": "127.0.0.1:53"}
	c.Routes = []Route{{Match: []string{"geosite@hagezi:pro", "geosite:pro"}, Chain: []string{"s"}}}
	c.AnswerGeoip = []AnswerRule{{Set: "rf@blocked", Action: "nxdomain"}}
	if err := c.prepareGeo(); err != nil {
		t.Fatalf("валидные ссылки не прошли: %v", err)
	}
}

// Ссылка без неймспейса — первый источник, объявивший вид; с неймспейсом —
// ровно тот, что назван.
func TestGeoFirstSourceResolution(t *testing.T) {
	c := srcCfg()
	if err := c.prepareGeo(); err != nil {
		t.Fatal(err)
	}
	c.Servers = map[string]string{"a": "127.0.0.1:1", "b": "127.0.0.1:2"}
	c.Routes = []Route{
		{Match: []string{"geosite:pro"}, Chain: []string{"a"}},
		{Match: []string{"geosite@rf:pro"}, Chain: []string{"b"}},
	}
	c.geosite = map[string]*domainSet{}
	h := &domainSet{Name: "pro", Full: map[string]bool{}, suffixes: []string{"hagezi.example"}}
	r := &domainSet{Name: "pro", Full: map[string]bool{}, suffixes: []string{"rf.example"}}
	c.geosite[geoKey("hagezi", "pro")] = h
	c.geosite[geoKey("rf", "pro")] = r

	// без неймспейса матчится только первый источник
	if !c.geositeMatch("pro", "x.hagezi.example") {
		t.Error("первый источник должен матчить свой набор")
	}
	if c.geositeMatch("pro", "x.rf.example") {
		t.Error("первый источник не должен матчить чужой набор")
	}
	// неймспейс — свой источник, и только он
	if !c.geositeMatchIn("rf", "pro", "x.rf.example") {
		t.Error("geosite@rf:pro не сматчил свой набор")
	}
	if c.geositeMatchIn("rf", "pro", "x.hagezi.example") {
		t.Error("geosite@rf:pro сматчил чужой набор")
	}
	// маршруты: hagezi.example → a (первое правило), rf.example → b (второе)
	if got := c.routeFor("x.hagezi.example"); len(got) != 1 || got[0] != "a" {
		t.Errorf("x.hagezi.example -> %v, want [a]", got)
	}
	if got := c.routeFor("x.rf.example"); len(got) != 1 || got[0] != "b" {
		t.Errorf("x.rf.example -> %v, want [b]", got)
	}
}

// Зеркала: первый URL отдаёт 500 — берём со второго.
func TestMirrorFallback(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "*.doubleclick.net\n")
	}))
	defer good.Close()

	dir := t.TempDir()
	c := &Config{GeoCacheDir: dir}
	c.Geo = Geo{Sources: []GeoSource{{Name: "t", Geosite: []string{bad.URL + "/{name}.txt", good.URL + "/{name}.txt"}}}}
	if err := c.prepareGeo(); err != nil {
		t.Fatal(err)
	}
	c.geosite = map[string]*domainSet{}
	c.geoip = map[string]*ipSet{}
	f := newGeoFetcher(c)
	src := c.geoSrc("t")

	if err := f.download("geosite", src, "pro"); err != nil {
		t.Fatalf("фолбэк на зеркало не сработал: %v", err)
	}
	data, err := os.ReadFile(f.cachePath("geosite", src, "pro"))
	if err != nil || !strings.Contains(string(data), "doubleclick.net") {
		t.Fatalf("кэш не записан: %v %q", err, data)
	}
	if err := f.loadFromCache("geosite", src, "pro"); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	set := c.peekGeositeKey("t", "pro")
	if set == nil || !set.match("ad.doubleclick.net") {
		t.Error("набор с зеркала не применился")
	}
}

// Локальные каталоги работают как псевдо-источник dir для ссылок без неймспейса.
func TestGeoDirPseudoSource(t *testing.T) {
	dir := t.TempDir()
	gsDir := filepath.Join(dir, "geosite")
	if err := os.MkdirAll(gsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gsDir, "cn.txt"), []byte("domain:example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := defaultConfig()
	c.GeositeDir = gsDir
	if err := c.loadGeosite(); err != nil {
		t.Fatal(err)
	}
	if set := c.resolveGeoSrc("geosite", ""); set == nil || set.name != geoDirSrc {
		t.Fatalf("псевдо-источник dir не подставился: %v", set)
	}
	if got := c.geositeMatch("cn", "www.example.com"); !got {
		t.Error("набор из geosite_dir не сматчился через ссылку без неймспейса")
	}
}
