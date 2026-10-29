package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestParseDomainSetAndMatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cn.txt")
	body := "# комментарий\n" +
		"domain:example.com\n" +
		"full:only.example.org\n" +
		"plain.net\n" +
		"\n" +
		"  spaced.io  \n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := parseDomainSet(path)
	if err != nil {
		t.Fatal(err)
	}
	if set.Entries != 4 {
		t.Fatalf("Entries = %d, want 4", set.Entries)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"a.b.example.com", true},
		{"badexample.com", false},     // не суффикс по границе точки
		{"only.example.org", true},    // full
		{"x.only.example.org", false}, // full не про поддомены
		{"plain.net", true},
		{"sub.plain.net", true},
		{"spaced.io", true},
		{"other.dev", false},
	}
	for _, c := range cases {
		if got := set.match(c.host); got != c.want {
			t.Errorf("match(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestRouteForGeosite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cn.txt"), []byte("domain:example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.GeositeDir = dir
	cfg.Servers = map[string]string{"a": "127.0.0.1:1", "b": "127.0.0.1:2"}
	cfg.Routes = []Route{
		{Match: []string{"geosite:cn"}, Chain: []string{"a"}},
		{Match: []string{"*"}, Chain: []string{"b"}},
	}
	if err := cfg.loadGeosite(); err != nil {
		t.Fatal(err)
	}
	if got := cfg.routeFor("www.example.com"); len(got) != 1 || got[0] != "a" {
		t.Errorf("www.example.com -> %v, want [a]", got)
	}
	if got := cfg.routeFor("example.org"); len(got) != 1 || got[0] != "b" {
		t.Errorf("example.org -> %v, want [b]", got)
	}
}

func TestParseDomainSetRejectsRegexp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(path, []byte("regexp:^ads\\.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := parseDomainSet(path); err == nil {
		t.Fatal("regexp: должен быть ошибкой, а не тихо игнорироваться")
	}
}

func BenchmarkDomainSetMatch(b *testing.B) {
	const n = 300000
	set := &domainSet{Full: map[string]bool{}}
	suf := make([]string, 0, n)
	cats := []string{"cn", "ads", "google", "private", "ru"}
	for i := 0; i < n; i++ {
		suf = append(suf, fmt.Sprintf("host%d.%s.example", i, cats[i%len(cats)]))
	}
	sort.Strings(suf)
	set.suffixes = suf
	names := make([]string, 1024)
	for i := range names {
		names[i] = fmt.Sprintf("x%d.cn.example", (i*7919)%n)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		set.match(names[i%len(names)])
	}
}
