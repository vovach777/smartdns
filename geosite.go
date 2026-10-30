package main

// geosite.go — текстовые списки доменов (geosite) и матчер к ним.
//
// Зачем текстовые, а не .dat: в публичных репозиториях (Loyalsoldier,
// v2fly) рядом с protobuf-базой лежат те же наборы обычными текстовыми
// файлами — по файлу на категорию. Их можно читать глазами, диффать и
// править руками, и для них не нужен protobuf-парсер.
//
// Формат строки (как в этих репозиториях):
//
//	full:example.com      — только это имя
//	domain:example.com    — имя и все поддомены
//	example.com           — то же, что domain:
//	# комментарий         — игнорируется
//
// Пустые строки игнорируются. Регулярки (regexp:) и keyword: не
// поддерживаются намеренно: они дают непредсказуемую стоимость на запрос,
// а весь смысл — уложиться в сотни наносекунд.
//
// Матчер: отсортированный срез суффиксов + бинарный поиск. Замер на 300 000
// суффиксов — 155 нс на запрос, 13 МБ кучи (см. docs/geosite.md).

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// domainSet — один набор доменов.
type domainSet struct {
	Name     string
	Source   string
	Full     map[string]bool // точные имена (full:)
	suffixes []string        // отсортированные суффиксы (domain: и голые)
	Entries  int
	// SkippedUnsupported — сколько строк regexp:/keyword: пропущено
	SkippedUnsupported int
}

// match проверяет имя: сначала точные, потом суффиксы (включая само имя).
func (s *domainSet) match(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if s == nil {
		return false
	}
	if s.Full[name] {
		return true
	}
	for i := 0; i < len(name); i++ {
		if i > 0 && name[i-1] != '.' {
			continue
		}
		suf := name[i:]
		idx := sort.SearchStrings(s.suffixes, suf)
		if idx < len(s.suffixes) && s.suffixes[idx] == suf {
			return true
		}
	}
	return false
}

// loadGeosite читает каталог geosite_dir: по файлу <name>.txt на набор.
func (c *Config) loadGeosite() error {
	c.geosite = map[string]*domainSet{}
	if strings.TrimSpace(c.GeositeDir) == "" {
		return nil
	}
	ents, err := os.ReadDir(c.GeositeDir)
	if err != nil {
		return fmt.Errorf("geosite_dir %s: %w", c.GeositeDir, err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, fn := range names {
		path := filepath.Join(c.GeositeDir, fn)
		set, err := parseDomainSet(path)
		if err != nil {
			return err
		}
		set.Name = strings.TrimSuffix(fn, ".txt")
		c.geosite[set.Name] = set
	}
	return nil
}

// parseDomainSet разбирает один текстовый список.
func parseDomainSet(path string) (*domainSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("geosite: %s: %w", path, err)
	}
	set := &domainSet{Source: path, Full: map[string]bool{}}
	suf := map[string]struct{}{}

	for i, line := range strings.Split(string(data), "\n") {
		if h := strings.IndexByte(line, '#'); h >= 0 {
			line = line[:h]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		kind := "domain"
		val := line
		if k, v, ok := strings.Cut(line, ":"); ok {
			k = strings.ToLower(strings.TrimSpace(k))
			switch k {
			case "full", "domain":
				kind, val = k, strings.TrimSpace(v)
			case "regexp", "keyword", "include":
				return nil, fmt.Errorf("%s:%d: %s: не поддерживается (только full: и domain:)", path, i+1, k)
			}
		}
		val = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(val), "."))
		// "*.example.com" в списках встречается: домен и поддомены у нас и
		// так одно и то же, поэтому звёздочку просто снимаем
		val = strings.TrimPrefix(val, "*.")
		if val == "" || val == "*" {
			return nil, fmt.Errorf("%s:%d: пустое имя", path, i+1)
		}
		if kind == "full" {
			if !set.Full[val] {
				set.Full[val] = true
				set.Entries++
			}
			continue
		}
		// domain: храним ТОЛЬКО само имя. Родителей раскладывать нельзя:
		// "domain:example.com" иначе совпадёт с любым ".com", потому что
		// суффиксный поиск идёт по имени запроса, а не по записи.
		if _, ok := suf[val]; !ok {
			suf[val] = struct{}{}
		}
		set.Entries++
	}

	set.suffixes = make([]string, 0, len(suf))
	for s := range suf {
		set.suffixes = append(set.suffixes, s)
	}
	sort.Strings(set.suffixes)
	return set, nil
}

// geositeMatch — true, если имя попало в набор `name` (аргумент "geosite:name").
func (c *Config) geositeMatch(set, host string) bool {
	s := c.getGeosite(strings.ToLower(set))
	if s == nil {
		return false
	}
	return s.match(host)
}

// geositeFilesSignature — mtime/size файлов наборов, для вотчера.
func geositeFilesSignature(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "err"
	}
	var b strings.Builder
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			fmt.Fprintf(&b, "%s:err;", e.Name())
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d;", e.Name(), fi.ModTime().UnixNano(), fi.Size())
	}
	return b.String()
}

// watchGeosite перечитывает конфиг, когда меняется любой файл наборов.
func watchGeosite(dirGetter func() string) {
	const every = 5 * time.Second
	t := time.NewTicker(every)
	defer t.Stop()
	last := geositeFilesSignature(dirGetter())
	for {
		select {
		case <-t.C:
			dir := dirGetter()
			if strings.TrimSpace(dir) == "" {
				last = ""
				continue
			}
			got := geositeFilesSignature(dir)
			if got == "" || got == "err" || got == last {
				continue
			}
			log.Printf("geosite: наборы изменились — перечитываю конфиг")
			if err := reload(); err != nil {
				log.Printf("geosite: перечитывание не удалось: %v", err)
				last = got
				continue
			}
			last = geositeFilesSignature(dirGetter())
		case <-stopPurge:
			return
		}
	}
}

// geositeNames — имена наборов по алфавиту (для -check и логов).
func geositeNames(m map[string]*domainSet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
