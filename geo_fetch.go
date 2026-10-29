package main

// geo_fetch.go — загрузка наборов по URL: лениво, с кэшем на диске и
// обновлением в полночь.
//
// Почему лениво: список `geosite:cn` из v2fly — это дерево include:'ов на
// сотни килобайт. Тянуть все наборы на старте бессмысленно: в routes
// упомянуты единицы. Набор скачивается при первом обращении правила к нему
// (это и есть «использование») и больше не трогается до полуночи.
//
// Почему фоном: запрос DNS не должен ждать сеть. Первый запрос к ещё не
// загруженному набору просто не совпадёт с правилом (пойдёт по общему "*"),
// а загрузка идёт в горутине; следующие запросы уже увидят набор.
//
// Кэш: <geo_cache_dir>/geosite/<name>.txt и .../geoip/<name>.txt.
// Файл пишется атомарно (tmp + rename), поэтому оборванная загрузка не
// оставляет половину списка.

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// defaultGeoCache — кэш гео-баз во временном каталоге ОС (/tmp/smartdns).
// Наборы всё равно перекачиваются (ленивая загрузка + полночное обновление),
// так что переживать перезагрузку /tmp им не обязательно.
var defaultGeoCache = filepath.Join(os.TempDir(), "smartdns")

const (
	// источники по умолчанию — те, с которых наборы и брались
	// По умолчанию — российские базы v2ray-формата (.dat, всегда последняя
	// версия в ветке release). Без {name}: файл скачивается целиком, из него
	// берутся только упомянутые в правилах категории.
	defaultGeositeURL = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat"
	defaultGeoipURL   = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat"

	geoDialTimeout     = 15 * time.Second // установка соединения
	geoDownloadTimeout = 10 * time.Minute // тело: .dat бывает 70 МБ
	geoMaxInclude      = 6                // глубина include:
)

type geoFetcher struct {
	cfg      *Config
	mu       sync.Mutex
	inflight map[string]bool // "geosite:cn" — чтобы не качать одно и то же дважды
	failed   map[string]bool // 404 и прочие отказы: не долбить повторно
	client   *http.Client
}

func newGeoFetcher(cfg *Config) *geoFetcher {
	return &geoFetcher{
		cfg:      cfg,
		inflight: map[string]bool{},
		failed:   map[string]bool{},
		client: &http.Client{
			Timeout: geoDownloadTimeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: geoDialTimeout}).DialContext,
				// соединение переиспользуем: наборов за сессию единицы
				MaxIdleConnsPerHost: 2,
			},
		},
	}
}

func (f *geoFetcher) urlFor(kind, name string) string {
	tpl := f.cfg.GeositeURL
	if kind == "geoip" {
		tpl = f.cfg.GeoipURL
	}
	if strings.TrimSpace(tpl) == "" {
		return ""
	}
	return strings.ReplaceAll(tpl, "{name}", name)
}

// looksBinary — бинарный ли файл. Текстовые списки (v2fly, ipdeny) — обычный
// текст; protobuf начинается с ключа поля (0x0a) и байта длины, т.е. сразу
// содержит управляющие символы.
func looksBinary(b []byte) bool {
	n := len(b)
	if n > 512 {
		n = 512
	}
	for _, c := range b[:n] {
		if c == 0 || c < 0x09 || (c > 0x0d && c < 0x20) {
			return true
		}
	}
	return false
}

// isDatMode — источник задан без {name}, значит это единый .dat-файл.
func (f *geoFetcher) isDatMode(kind string) bool {
	tpl := f.cfg.GeositeURL
	if kind == "geoip" {
		tpl = f.cfg.GeoipURL
	}
	return strings.TrimSpace(tpl) != "" && !strings.Contains(tpl, "{name}")
}

func (f *geoFetcher) datPath(kind string) string {
	return filepath.Join(f.cfg.GeoCacheDir, kind+".dat")
}

func (f *geoFetcher) cachePath(kind, name string) string {
	return filepath.Join(f.cfg.GeoCacheDir, kind, name+".txt")
}

// ensure запускает фоновую загрузку набора, если его ещё нет.
func (f *geoFetcher) ensure(kind, name string) {
	if f == nil || strings.TrimSpace(f.cfg.GeoCacheDir) == "" {
		return
	}
	if f.urlFor(kind, name) == "" {
		return
	}
	if f.isDatMode(kind) {
		key := kind + ":*"
		f.mu.Lock()
		if f.failed[key] || f.inflight[key] {
			f.mu.Unlock()
			return
		}
		f.inflight[key] = true
		f.mu.Unlock()
		go func() {
			defer func() {
				f.mu.Lock()
				delete(f.inflight, key)
				f.mu.Unlock()
			}()
			// один .dat за раз: иначе два потока качают и переименовывают
			// один и тот же файл
			geoDatMu.Lock()
			defer geoDatMu.Unlock()
			if _, err := os.Stat(f.datPath(kind)); err != nil {
				if err := f.downloadDat(kind); err != nil {
					if permanentGeoError(err) {
						f.mu.Lock()
						f.failed[key] = true
						f.mu.Unlock()
					}
					log.Printf("гео: %s.dat — загрузка не удалась: %v", kind, err)
					return
				}
			}
			f.extractWanted(kind, true)
		}()
		return
	}

	key := kind + ":" + name
	f.mu.Lock()
	if f.failed[key] || f.inflight[key] {
		f.mu.Unlock()
		return
	}
	f.inflight[key] = true
	f.mu.Unlock()

	go func() {
		defer func() {
			f.mu.Lock()
			delete(f.inflight, key)
			f.mu.Unlock()
		}()
		if err := f.download(kind, name); err != nil {
			if permanentGeoError(err) {
				f.mu.Lock()
				f.failed[key] = true
				f.mu.Unlock()
			}
			log.Printf("гео: %s:%s — загрузка не удалась: %v", kind, name, err)
			return
		}
		if err := f.loadFromCache(kind, name); err != nil {
			log.Printf("гео: %s:%s — разбор кэша не удался: %v", kind, name, err)
			return
		}
		log.Printf("гео: %s:%s загружен по URL и применён", kind, name)
		// включённый набор мог приехать позже родителя — пересобираем загруженные
		f.rebuildLoaded()
	}()
}

// download скачивает набор в кэш (атомарно).
func (f *geoFetcher) download(kind, name string) error {
	u := f.urlFor(kind, name)
	if u == "" {
		return fmt.Errorf("URL для %s не задан", kind)
	}
	resp, err := f.client.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{code: resp.StatusCode, url: u}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	dst := f.cachePath(kind, name)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// loadFromCache читает скачанный набор (и его include:) и ставит в конфиг.
func (f *geoFetcher) loadFromCache(kind, name string) error {
	seen := map[string]bool{}
	switch kind {
	case "geosite":
		set, err := f.buildDomainSet(name, seen, 0)
		if err != nil {
			return err
		}
		f.cfg.setGeosite(name, set)
	case "geoip":
		set, err := f.buildIPSet(name, seen, 0)
		if err != nil {
			return err
		}
		f.cfg.setGeoip(name, set)
	default:
		return fmt.Errorf("неизвестный вид набора %q", kind)
	}
	return nil
}

// buildDomainSet собирает набор из кэша, разворачивая include:.
func (f *geoFetcher) buildDomainSet(name string, seen map[string]bool, depth int) (*domainSet, error) {
	if depth > geoMaxInclude {
		return nil, fmt.Errorf("%s: слишком глубокая вложенность include:", name)
	}
	if seen[name] {
		return &domainSet{Name: name, Full: map[string]bool{}}, nil // циклы просто пропускаем
	}
	seen[name] = true

	path := f.cachePath("geosite", name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// докачиваем включённый набор и продолжаем без него в этот раз
			f.ensure("geosite", name)
		}
		return &domainSet{Name: name, Full: map[string]bool{}}, nil
	}
	// .dat в поштучном режиме ({name}.dat): внутри protobuf одной категории
	if looksBinary(data) {
		sets, err := extractGeosite(data, map[string]bool{name: true})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if set := sets[name]; set != nil {
			set.Source = path
			return set, nil
		}
		return nil, fmt.Errorf("%s: в файле нет категории %q", path, name)
	}

	set := &domainSet{Name: name, Source: path, Full: map[string]bool{}}
	// v2fly дописывает атрибуты: "name @ads", "include:x @attr".
	// Мы их не фильтруем — берём запись целиком, атрибут отрезаем.
	stripAttrs := func(v string) string {
		if i := strings.Index(v, " @"); i >= 0 {
			v = v[:i]
		}
		return strings.TrimSpace(v)
	}
	suf := map[string]struct{}{}

	for _, line := range strings.Split(string(data), "\n") {
		if h := strings.IndexByte(line, '#'); h >= 0 {
			line = line[:h]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if ok {
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "include":
				inc := strings.ToLower(stripAttrs(val))
				if inc == "" || seen[inc] {
					continue
				}
				if _, err := os.Stat(f.cachePath("geosite", inc)); err != nil {
					f.ensure("geosite", inc)
					continue
				}
				sub, err := f.buildDomainSet(inc, seen, depth+1)
				if err != nil || sub == nil {
					continue
				}
				for k := range sub.Full {
					if !set.Full[k] {
						set.Full[k] = true
						set.Entries++
					}
				}
				for _, s := range sub.suffixes {
					suf[s] = struct{}{}
				}
				set.SkippedUnsupported += sub.SkippedUnsupported
				continue
			case "regexp", "keyword":
				set.SkippedUnsupported++
				continue
			case "full":
				v := strings.ToLower(strings.TrimSuffix(stripAttrs(val), "."))
				if v != "" && !set.Full[v] {
					set.Full[v] = true
					set.Entries++
				}
				continue
			case "domain":
				v := strings.ToLower(strings.TrimSuffix(stripAttrs(val), "."))
				if v != "" {
					suf[v] = struct{}{}
					set.Entries++
				}
				continue
			}
		}
		v := strings.ToLower(strings.TrimSuffix(stripAttrs(line), "."))
		if v != "" {
			suf[v] = struct{}{}
			set.Entries++
		}
	}
	set.suffixes = make([]string, 0, len(suf))
	for s := range suf {
		set.suffixes = append(set.suffixes, s)
	}
	sort.Strings(set.suffixes)
	return set, nil
}

// buildIPSet собирает адресный набор из кэша.
func (f *geoFetcher) buildIPSet(name string, seen map[string]bool, depth int) (*ipSet, error) {
	if depth > geoMaxInclude || seen[name] {
		return &ipSet{Name: name}, nil
	}
	seen[name] = true
	path := f.cachePath("geoip", name)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			f.ensure("geoip", name)
		}
		return &ipSet{Name: name}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if looksBinary(data) {
		sets, err := extractGeoip(data, map[string]bool{name: true})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if set := sets[name]; set != nil {
			set.Source = path
			return set, nil
		}
		return nil, fmt.Errorf("%s: в файле нет категории %q", path, name)
	}
	set, err := parseIPSetData(data, path)
	if err != nil {
		return nil, err
	}
	set.Name = name
	return set, nil
}

// refreshReferenced перекачивает все уже загруженные наборы (полночь).
func (f *geoFetcher) refreshReferenced() {
	for _, kind := range []string{"geosite", "geoip"} {
		if f.isDatMode(kind) {
			f.refreshDat(kind)
		}
	}
	site, ip := f.cfg.loadedSets()
	if f.isDatMode("geosite") {
		site = nil
	}
	if f.isDatMode("geoip") {
		ip = nil
	}
	for _, n := range site {
		if err := f.download("geosite", n); err != nil {
			log.Printf("гео: geosite:%s — обновление не удалось: %v", n, err)
			continue
		}
		if err := f.loadFromCache("geosite", n); err != nil {
			log.Printf("гео: geosite:%s — разбор после обновления: %v", n, err)
		}
	}
	for _, n := range ip {
		if err := f.download("geoip", n); err != nil {
			log.Printf("гео: geoip:%s — обновление не удалось: %v", n, err)
			continue
		}
		if err := f.loadFromCache("geoip", n); err != nil {
			log.Printf("гео: geoip:%s — разбор после обновления: %v", n, err)
		}
	}
}

// watchMidnight — обновление раз в сутки, в 00:00 локального времени.
func watchMidnight(get func() *geoFetcher) {
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		select {
		case <-time.After(time.Until(next)):
			f := get()
			if f == nil {
				continue
			}
			log.Printf("гео: полночь — обновляю загруженные наборы")
			f.refreshReferenced()
		case <-stopPurge:
			return
		}
	}
}

// ---- доступ к наборам из конфига (карты наполняются фоном) ----

func (c *Config) getGeosite(name string) *domainSet {
	c.geoMu.RLock()
	set := c.geosite[name]
	c.geoMu.RUnlock()
	if set == nil && c.fetch != nil {
		c.fetch.ensure("geosite", name)
	}
	return set
}

func (c *Config) getGeoip(name string) *ipSet {
	c.geoMu.RLock()
	set := c.geoip[name]
	c.geoMu.RUnlock()
	if set == nil && c.fetch != nil {
		c.fetch.ensure("geoip", name)
	}
	return set
}

func (c *Config) setGeosite(name string, set *domainSet) {
	c.geoMu.Lock()
	c.geosite[name] = set
	c.geoMu.Unlock()
}

func (c *Config) setGeoip(name string, set *ipSet) {
	c.geoMu.Lock()
	c.geoip[name] = set
	c.geoMu.Unlock()
}

// loadedSets — какие наборы уже загружены (для полуночного обновления).
func (c *Config) loadedSets() (site, ip []string) {
	c.geoMu.RLock()
	defer c.geoMu.RUnlock()
	for k := range c.geosite {
		site = append(site, k)
	}
	for k := range c.geoip {
		ip = append(ip, k)
	}
	sort.Strings(site)
	sort.Strings(ip)
	return
}

// geoDatMu сериализует скачивание+разбор единого .dat на весь процесс:
// наборы общие для всех Config, параллельный разбор 70 МБ бессмыслен.
var geoDatMu sync.Mutex

// prefetchReferenced — наборы, на которые ссылаются правила, тянем фоном
// (сам DNS-запрос сеть не ждёт).
func (c *Config) prefetchReferenced() {
	if c.fetch == nil {
		return
	}
	for _, r := range c.Routes {
		for _, m := range r.Match {
			if set, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(m)), "geosite:"); ok {
				if _, loaded := c.geosite[set]; !loaded {
					c.fetch.ensure("geosite", set)
				}
			}
		}
	}
	for _, r := range c.AnswerGeoip {
		set := strings.ToLower(strings.TrimSpace(r.Set))
		if _, loaded := c.geoip[set]; !loaded {
			c.fetch.ensure("geoip", set)
		}
	}
}

// rebuildLoaded пересобирает уже установленные наборы из кэша. Нужен, когда
// include: приезжает позже родителя: иначе родитель остался бы собранным по
// неполным данным до следующего рестарта.
func (f *geoFetcher) rebuildLoaded() {
	site, ip := f.cfg.loadedSets()
	for _, n := range site {
		set, err := f.buildDomainSet(n, map[string]bool{}, 0)
		if err == nil && set != nil && set.Entries > 0 {
			f.cfg.setGeosite(n, set)
		}
	}
	for _, n := range ip {
		set, err := f.buildIPSet(n, map[string]bool{}, 0)
		if err == nil && set != nil && len(set.Ranges) > 0 {
			f.cfg.setGeoip(n, set)
		}
	}
}

// downloadDat качает единый .dat в кэш (атомарно).
func (f *geoFetcher) downloadDat(kind string) error {
	tpl := f.cfg.GeositeURL
	if kind == "geoip" {
		tpl = f.cfg.GeoipURL
	}
	if tpl == "" {
		return fmt.Errorf("URL для %s не задан", kind)
	}
	resp, err := f.client.Get(tpl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{code: resp.StatusCode, url: tpl}
	}
	dst := f.datPath(kind)
	if _, err := os.Stat(dst); err == nil {
		return nil // уже скачано другим потоком
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, io.LimitReader(resp.Body, 512<<20)); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		if _, statErr := os.Stat(dst); statErr == nil {
			os.Remove(tmp)
			return nil
		}
		return err
	}
	return nil
}

// extractWanted разбирает .dat один раз и ставит все нужные категории.
func (f *geoFetcher) extractWanted(kind string, onlyMissing bool) {
	all := f.cfg.referencedSets(kind)
	// разбираем только те, которых ещё нет: повторный вызов (второй поток,
	// перечитывание) не должен заново парсить 70 МБ
	want := map[string]bool{}
	for n := range all {
		if !onlyMissing {
			want[n] = true
			continue
		}
		if kind == "geosite" && f.cfg.peekGeosite(n) == nil {
			want[n] = true
		}
		if kind == "geoip" && f.cfg.peekGeoip(n) == nil {
			want[n] = true
		}
	}
	if len(want) == 0 {
		return
	}
	data, err := os.ReadFile(f.datPath(kind))
	if err != nil {
		log.Printf("гео: %s.dat — чтение кэша: %v", kind, err)
		return
	}
	switch kind {
	case "geosite":
		sets, err := extractGeosite(data, want)
		if err != nil {
			log.Printf("гео: geosite.dat — разбор: %v", err)
			return
		}
		for n, s := range sets {
			s.Source = f.datPath(kind)
			f.cfg.setGeosite(n, s)
		}
		log.Printf("гео: geosite.dat — применено категорий: %d из %d запрошенных", len(sets), len(want))
	case "geoip":
		sets, err := extractGeoip(data, want)
		if err != nil {
			log.Printf("гео: geoip.dat — разбор: %v", err)
			return
		}
		for n, s := range sets {
			s.Source = f.datPath(kind)
			f.cfg.setGeoip(n, s)
		}
		log.Printf("гео: geoip.dat — применено категорий: %d из %d запрошенных", len(sets), len(want))
	}
}

// referencedSets — имена наборов этого вида, упомянутые в правилах.
func (c *Config) referencedSets(kind string) map[string]bool {
	out := map[string]bool{}
	c.geoMu.RLock()
	defer c.geoMu.RUnlock()
	if kind == "geosite" {
		for _, r := range c.Routes {
			for _, m := range r.Match {
				if set, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(m)), "geosite:"); ok {
					out[set] = true
				}
			}
		}
		for n := range c.geosite {
			out[n] = true
		}
		return out
	}
	for _, r := range c.AnswerGeoip {
		out[strings.ToLower(strings.TrimSpace(r.Set))] = true
	}
	for n := range c.geoip {
		out[n] = true
	}
	return out
}

// permanentGeoError — «нет такого набора» (404/403/410) запоминаем, а сетевые
// таймауты — нет: следующий запрос попробует снова.
func permanentGeoError(err error) bool {
	var se *httpStatusError
	if errors.As(err, &se) {
		switch se.code {
		case http.StatusNotFound, http.StatusForbidden, http.StatusGone:
			return true
		}
	}
	return false
}

type httpStatusError struct {
	code int
	url  string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("HTTP %d от %s", e.code, e.url)
}

// peekGeosite / peekGeoip — чтение без ленивой загрузки (для внутренних
// проверок: getGeosite на промахе запускает скачивание, здесь это лишнее).
func (c *Config) peekGeosite(name string) *domainSet {
	c.geoMu.RLock()
	defer c.geoMu.RUnlock()
	return c.geosite[name]
}

func (c *Config) peekGeoip(name string) *ipSet {
	c.geoMu.RLock()
	defer c.geoMu.RUnlock()
	return c.geoip[name]
}

// refreshDat — полночное обновление единого .dat: файл перекачивается целиком,
// затем нужные категории разбираются заново (наборы подменяются на месте).
func (f *geoFetcher) refreshDat(kind string) {
	geoDatMu.Lock()
	defer geoDatMu.Unlock()
	os.Remove(f.datPath(kind))
	if err := f.downloadDat(kind); err != nil {
		log.Printf("гео: %s.dat — обновление не удалось: %v", kind, err)
		return
	}
	f.extractWanted(kind, false)
	log.Printf("гео: %s.dat — обновлён", kind)
}
