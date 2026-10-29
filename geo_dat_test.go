package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// ---- минимальный protobuf-энкодер для тестовых .dat ----

func pbVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func pbKey(field, wire int) []byte { return pbVarint(uint64(field<<3 | wire)) }

func pbBytes(field int, b []byte) []byte {
	out := pbKey(field, 2)
	out = append(out, pbVarint(uint64(len(b)))...)
	return append(out, b...)
}

func pbInt(field int, v uint64) []byte {
	return append(pbKey(field, 0), pbVarint(v)...)
}

func geositeEntry(code string, doms ...struct {
	typ int
	val string
}) []byte {
	entry := pbBytes(1, []byte(code))
	for _, d := range doms {
		var dom []byte
		dom = append(dom, pbInt(1, uint64(d.typ))...)
		dom = append(dom, pbBytes(2, []byte(d.val))...)
		entry = append(entry, pbBytes(2, dom)...)
	}
	return pbBytes(1, entry)
}

func TestExtractGeosite(t *testing.T) {
	type d = struct {
		typ int
		val string
	}
	var data []byte
	data = append(data, geositeEntry("CATEGORY-ADS-ALL",
		d{2, "doubleclick.net"},
		d{3, "ads.example.com"},
		d{1, "^re[0-9]+\\.example\\.org$"},
	)...)
	data = append(data, geositeEntry("RU", d{2, "yandex.ru"})...)

	all, err := extractGeosite(data, map[string]bool{"category-ads-all": true, "ru": true})
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("категорий: %d, ждали 2", len(all))
	}
	ads := all["category-ads-all"]
	if ads == nil {
		t.Fatal("нет category-ads-all")
	}
	if !ads.match("doubleclick.net") || !ads.match("a.b.doubleclick.net") {
		t.Error("суффикс doubleclick.net не сработал")
	}
	if ads.match("ads.example.com.evil.tld") {
		t.Error("full-запись не должна совпадать как суффикс")
	}
	if ads.SkippedUnsupported != 1 {
		t.Errorf("regex не посчитан: %d", ads.SkippedUnsupported)
	}
	// берём только запрошенное
	only, err := extractGeosite(data, map[string]bool{"ru": true})
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(only) != 1 || only["ru"] == nil {
		t.Fatalf("выбралось лишнее: %v", len(only))
	}
}

func TestExtractGeoip(t *testing.T) {
	cidr := func(ip []byte, prefix uint64) []byte {
		var c []byte
		c = append(c, pbBytes(1, ip)...)
		c = append(c, pbInt(2, prefix)...)
		return pbBytes(2, c)
	}
	var ru []byte
	ru = append(ru, pbBytes(1, []byte("RU"))...)
	ru = append(ru, cidr([]byte{5, 8, 0, 0}, 16)...)
	ru = append(ru, cidr([]byte{5, 8, 128, 0}, 17)...) // примыкает — склеится
	ru = append(ru, cidr([]byte{77, 88, 0, 0}, 16)...)
	// IPv6 — мимо
	ru = append(ru, cidr(make([]byte, 16), 32)...)

	var de []byte
	de = append(de, pbBytes(1, []byte("DE"))...)
	de = append(de, cidr([]byte{1, 2, 3, 0}, 24)...)

	var data []byte
	data = append(data, pbBytes(1, ru)...)
	data = append(data, pbBytes(1, de)...)

	sets, err := extractGeoip(data, map[string]bool{"ru": true})
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	set := sets["ru"]
	if set == nil {
		t.Fatal("нет набора ru")
	}
	if len(set.Ranges) != 2 {
		t.Fatalf("диапазонов: %d, ждали 2 (склейка 5.8.0.0/16 + 5.8.128.0/17)", len(set.Ranges))
	}
	if set.SkippedV6 != 1 {
		t.Errorf("IPv6 не посчитан: %d", set.SkippedV6)
	}
	if !set.match(net.IP{5, 8, 200, 1}) {
		t.Error("5.8.200.1 должен быть в наборе")
	}
	if set.match(net.IP{5, 9, 0, 1}) {
		t.Error("5.9.0.1 не должен быть в наборе")
	}
}

func TestLooksBinary(t *testing.T) {
	if looksBinary([]byte("domain:example.org\nfull:a.example\n")) {
		t.Error("текст опознан как бинарь")
	}
	if !looksBinary([]byte{0x0a, 0x02, 'r', 'u'}) {
		t.Error("protobuf не опознан")
	}
	if looksBinary(nil) {
		t.Error("пустой файл — не бинарь")
	}
}

// .dat в поштучном режиме ({name}.dat): файл из кэша разбирается как protobuf.
func TestPerNameDat(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{GeositeURL: "https://x/{name}.dat", GeoipURL: "https://x/{name}.dat", GeoCacheDir: dir}
	cfg.geosite = map[string]*domainSet{}
	cfg.geoip = map[string]*ipSet{}
	cfg.fetch = newGeoFetcher(cfg)

	type d = struct {
		typ int
		val string
	}
	site := geositeEntry("RU", d{2, "yandex.ru"}, d{3, "mail.yandex.ru"})
	path := cfg.fetch.cachePath("geosite", "ru")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, site, 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := cfg.fetch.buildDomainSet("ru", map[string]bool{}, 0)
	if err != nil {
		t.Fatalf("поштучный .dat: %v", err)
	}
	if set == nil || !set.match("yandex.ru") || !set.match("www.yandex.ru") {
		t.Fatalf("набор не собран: %+v", set)
	}

	cidr := func(ip []byte, prefix uint64) []byte {
		var c []byte
		c = append(c, pbBytes(1, ip)...)
		c = append(c, pbInt(2, prefix)...)
		return pbBytes(2, c)
	}
	var entry []byte
	entry = append(entry, pbBytes(1, []byte("RU"))...)
	entry = append(entry, cidr([]byte{5, 8, 0, 0}, 16)...)
	ipPath := cfg.fetch.cachePath("geoip", "ru")
	if err := os.MkdirAll(filepath.Dir(ipPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ipPath, pbBytes(1, entry), 0o644); err != nil {
		t.Fatal(err)
	}
	ipSet, err := cfg.fetch.buildIPSet("ru", map[string]bool{}, 0)
	if err != nil {
		t.Fatalf("поштучный geoip .dat: %v", err)
	}
	if ipSet == nil || !ipSet.match(net.IP{5, 8, 1, 2}) {
		t.Fatalf("адресный набор не собран: %+v", ipSet)
	}

	// файл есть, но категории в нём нет — внятная ошибка, а не пустой набор
	other := cfg.fetch.cachePath("geosite", "de")
	if err := os.WriteFile(other, site, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.fetch.buildDomainSet("de", map[string]bool{}, 0); err == nil {
		t.Error("ждали ошибку про отсутствующую категорию")
	}
}

func TestIsDatMode(t *testing.T) {
	cfg := &Config{GeositeURL: "https://x/geosite.dat", GeoipURL: "https://x/{name}.zone"}
	f := newGeoFetcher(cfg)
	if !f.isDatMode("geosite") {
		t.Error("geosite без {name} — это .dat")
	}
	if f.isDatMode("geoip") {
		t.Error("geoip с {name} — поштучный режим")
	}
}
