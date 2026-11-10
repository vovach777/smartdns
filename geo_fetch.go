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
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
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
	geoDialTimeout     = 15 * time.Second // установка соединения
	geoDownloadTimeout = 10 * time.Minute // тело: .dat бывает 70 МБ
	geoMaxInclude      = 6                // глубина include:
	geoDirSrc          = "dir"            // псевдо-источник: geosite_dir/geoip_dir
)

type geoFetcher struct {
	cfg      *Config
	mu       sync.Mutex
	inflight map[string]bool      // "geosite:cn" — чтобы не качать одно и то же дважды
	failed   map[string]bool      // 404 и прочие отказы: не долбить повторно
	retryAt  map[string]time.Time // сетевой сбой: пауза перед повтором
	client   *http.Client
}

func newGeoFetcher(cfg *Config) *geoFetcher {
	return &geoFetcher{
		cfg:      cfg,
		inflight: map[string]bool{},
		failed:   map[string]bool{},
		retryAt:  map[string]time.Time{},
		client: &http.Client{
			Timeout: geoDownloadTimeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: geoDialTimeout}).DialContext,
				// соединение переиспользуем: наборов за сессию единицы
				MaxIdleConnsPerHost: 2,
				// proxy: … — качаем через него; пусто — напрямую.
				Proxy: geoProxyFunc(cfg),
			},
		},
	}
}

// geoProxyFunc — транспорт прокси для скачивания гео-списков. geo.proxy
// перекрывает верхний proxy:. direct — напрямую, env — окружение, URL —
// фиксированный адрес, не задано — напрямую (Proxy: nil — системные настройки
// http.Client по умолчанию не читает).
func geoProxyFunc(cfg *Config) func(*http.Request) (*url.URL, error) {
	if cfg == nil {
		return nil
	}
	spec := cfg.proxy
	if cfg.geoProxy.mode != proxyNone {
		spec = cfg.geoProxy
	}
	switch spec.mode {
	case proxyDirect:
		return nil
	case proxyEnv:
		return http.ProxyFromEnvironment
	case proxyURL:
		return http.ProxyURL(spec.url)
	}
	return nil
}

// urlsFor — URL-шаблоны источника для вида, с подставленным {name}.
// Пусто — у источника нет этого вида либо это единый .dat.
func (f *geoFetcher) urlsFor(kind string, src *geoSourceResolved, name string) []string {
	if src == nil || src.datMode(kind) {
		return nil
	}
	tpls := src.geosite
	if kind == "geoip" {
		tpls = src.geoip
	}
	out := make([]string, 0, len(tpls))
	for _, t := range tpls {
		out = append(out, strings.ReplaceAll(t, "{name}", name))
	}
	return out
}

func (f *geoFetcher) datPath(kind string, src *geoSourceResolved) string {
	return filepath.Join(f.cfg.GeoCacheDir, kind, src.name+".dat")
}

func (f *geoFetcher) cachePath(kind string, src *geoSourceResolved, name string) string {
	return filepath.Join(f.cfg.GeoCacheDir, kind, src.name, name+".txt")
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

// ensure запускает фоновую загрузку набора, если его ещё нет.
// dat-режим источника: качается единый .dat, из него — нужные категории.
func (f *geoFetcher) ensure(kind string, src *geoSourceResolved, name string) {
	if f == nil || src == nil || src.name == geoDirSrc ||
		strings.TrimSpace(f.cfg.GeoCacheDir) == "" {
		return
	}
	f.cleanCache()
	if src.datMode(kind) {
		key := kind + "@" + src.name + ":*"
		f.mu.Lock()
		if f.failed[key] || f.inflight[key] {
			f.mu.Unlock()
			return
		}
		if t, ok := f.retryAt[key]; ok && time.Now().Before(t) {
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
			if _, err := os.Stat(f.datPath(kind, src)); err != nil {
				if err := f.downloadDat(kind, src); err != nil {
					if permanentGeoError(err) {
						f.mu.Lock()
						f.failed[key] = true
						f.mu.Unlock()
					} else {
						f.backoff(key)
					}
					log.Printf("гео: %s@%s.dat — загрузка не удалась: %v", kind, src.name, err)
					return
				}
			}
			f.extractWanted(kind, src, true)
		}()
		return
	}
	if len(f.urlsFor(kind, src, name)) == 0 {
		return
	}

	key := kind + "@" + src.name + ":" + name
	f.mu.Lock()
	if f.failed[key] || f.inflight[key] {
		f.mu.Unlock()
		return
	}
	if t, ok := f.retryAt[key]; ok && time.Now().Before(t) {
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
		// кэш уже есть — сразу пускаем его в дело: работает и без сети,
		// а свежую версию подтягиваем следом
		cached := false
		if _, err := os.Stat(f.cachePath(kind, src, name)); err == nil {
			if err := f.loadFromCache(kind, src, name); err == nil {
				cached = true
				log.Printf("гео: %s@%s:%s взят из кэша", kind, src.name, name)
				f.rebuildLoaded()
			}
		}
		if err := f.download(kind, src, name); err != nil {
			if permanentGeoError(err) {
				f.mu.Lock()
				f.failed[key] = true
				f.mu.Unlock()
			} else {
				f.backoff(key)
			}
			if !cached {
				log.Printf("гео: %s@%s:%s — загрузка не удалась: %v", kind, src.name, name, err)
			}
			return
		}
		if err := f.loadFromCache(kind, src, name); err != nil {
			log.Printf("гео: %s@%s:%s — разбор кэша не удался: %v", kind, src.name, name, err)
			return
		}
		log.Printf("гео: %s@%s:%s загружен по URL и применён", kind, src.name, name)
		// включённый набор мог приехать позже родителя — пересобираем загруженные
		f.rebuildLoaded()
	}()
}

// download скачивает набор в кэш (атомарно), перебирая зеркала источника.
func (f *geoFetcher) download(kind string, src *geoSourceResolved, name string) error {
	urls := f.urlsFor(kind, src, name)
	if len(urls) == 0 {
		return fmt.Errorf("URL для %s@%s не задан", kind, src.name)
	}
	var body []byte
	var lastErr error
	for _, u := range urls {
		resp, err := f.client.Get(u)
		if err != nil {
			lastErr = err
			continue // зеркало недоступно — пробуем следующее
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = &httpStatusError{code: resp.StatusCode, url: u}
			continue
		}
		body, err = io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return lastErr
	}
	dst := f.cachePath(kind, src, name)
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
func (f *geoFetcher) loadFromCache(kind string, src *geoSourceResolved, name string) error {
	seen := map[string]bool{}
	switch kind {
	case "geosite":
		set, err := f.buildDomainSet(src, name, seen, 0)
		if err != nil {
			return err
		}
		f.cfg.setGeosite(src.name, name, set)
	case "geoip":
		set, err := f.buildIPSet(src, name, seen, 0)
		if err != nil {
			return err
		}
		f.cfg.setGeoip(src.name, name, set)
	default:
		return fmt.Errorf("неизвестный вид набора %q", kind)
	}
	return nil
}

// buildDomainSet собирает набор из кэша, разворачивая include:.
// include: резолвится внутри ТОГО ЖЕ источника.
func (f *geoFetcher) buildDomainSet(src *geoSourceResolved, name string, seen map[string]bool, depth int) (*domainSet, error) {
	if depth > geoMaxInclude {
		return nil, fmt.Errorf("%s: слишком глубокая вложенность include:", name)
	}
	key := geoKey(src.name, name)
	if seen[key] {
		return &domainSet{Name: name, Full: map[string]bool{}}, nil // циклы просто пропускаем
	}
	seen[key] = true

	path := f.cachePath("geosite", src, name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// докачиваем включённый набор и продолжаем без него в этот раз
			f.ensure("geosite", src, name)
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
				if inc == "" || seen[geoKey(src.name, inc)] {
					continue
				}
				if _, err := os.Stat(f.cachePath("geosite", src, inc)); err != nil {
					f.ensure("geosite", src, inc)
					continue
				}
				sub, err := f.buildDomainSet(src, inc, seen, depth+1)
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
				v := strings.ToLower(stripWildcard(strings.TrimSuffix(stripAttrs(val), ".")))
				if v != "" && !set.Full[v] {
					set.Full[v] = true
					set.Entries++
				}
				continue
			case "domain":
				v := strings.ToLower(stripWildcard(strings.TrimSuffix(stripAttrs(val), ".")))
				if v != "" {
					suf[v] = struct{}{}
					set.Entries++
				}
				continue
			}
		}
		v := strings.ToLower(stripWildcard(strings.TrimSuffix(stripAttrs(line), ".")))
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
func (f *geoFetcher) buildIPSet(src *geoSourceResolved, name string, seen map[string]bool, depth int) (*ipSet, error) {
	if depth > geoMaxInclude || seen[geoKey(src.name, name)] {
		return &ipSet{Name: name}, nil
	}
	seen[geoKey(src.name, name)] = true
	path := f.cachePath("geoip", src, name)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			f.ensure("geoip", src, name)
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
// dat-источники: файл целиком + пере extraction; поштучные: каждый набор.
func (f *geoFetcher) refreshReferenced() {
	refs := f.cfg.referencedRefs()
	loaded := f.cfg.loadedSetKeys()

	// 1. dat-источники: перекачиваем файл целиком (если он кому-то нужен)
	for _, src := range f.cfg.geoSrcs {
		for _, kind := range []string{"geosite", "geoip"} {
			if src.datMode(kind) && (len(refs[kind][src.name]) > 0 || loaded[kind][src.name]) {
				f.refreshDat(kind, src)
			}
		}
	}

	// 2. поштучные наборы: каждый уже загруженный перекачиваем
	for kind, srcs := range loaded {
		for srcName := range srcs {
			if srcName == geoDirSrc {
				continue // локальный каталог — обновляет вотчер, не сеть
			}
			src := f.cfg.geoSrc(srcName)
			if src == nil || src.datMode(kind) {
				continue // dat-наборы перезагружаются целиком выше
			}
			if err := f.download(kind, src, srcName2Name(srcName)); err != nil {
				log.Printf("гео: %s@%s — обновление не удалось: %v", kind, srcName, err)
				continue
			}
			if err := f.loadFromCache(kind, src, srcName2Name(srcName)); err != nil {
				log.Printf("гео: %s@%s — разбор после обновления: %v", kind, srcName, err)
			}
		}
	}
}

// srcName2Name — из ключа "источник/имя" обратно в имя.
func srcName2Name(key string) string {
	if i := strings.IndexByte(key, '/'); i >= 0 {
		return key[i+1:]
	}
	return key
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

// getGeositeKey / getGeoipKey — набор по ключу "источник/имя"; на промахе
// запускают докачку (кроме локального псевдо-источника dir).
func (c *Config) getGeositeKey(src, name string) *domainSet {
	key := geoKey(src, name)
	c.geoMu.RLock()
	set := c.geosite[key]
	c.geoMu.RUnlock()
	if set == nil && c.fetch != nil {
		if s := c.geoSrc(src); s != nil {
			c.fetch.ensure("geosite", s, name)
		}
	}
	return set
}

func (c *Config) getGeoipKey(src, name string) *ipSet {
	key := geoKey(src, name)
	c.geoMu.RLock()
	set := c.geoip[key]
	c.geoMu.RUnlock()
	if set == nil && c.fetch != nil {
		if s := c.geoSrc(src); s != nil {
			c.fetch.ensure("geoip", s, name)
		}
	}
	return set
}

// geoipSetRef — набор по ссылке из правил: "rf@ru-blocked" или "ru-blocked"
// (первый источник с geoip, в конце — локальный geoip_dir).
func (c *Config) geoipSetRef(ref string) *ipSet {
	src, name, err := parseGeoSetRef(ref)
	if err != nil {
		return nil
	}
	s := c.resolveGeoSrc("geoip", src)
	if s == nil {
		return nil
	}
	return c.getGeoipKey(s.name, name)
}

func (c *Config) setGeosite(src, name string, set *domainSet) {
	c.geoMu.Lock()
	c.geosite[geoKey(src, name)] = set
	c.geoMu.Unlock()
	flushDNSCache()
}

func (c *Config) setGeoip(src, name string, set *ipSet) {
	c.geoMu.Lock()
	c.geoip[geoKey(src, name)] = set
	c.geoMu.Unlock()
	flushDNSCache()
}

// flushDNSCache выбрасывает ответы, выданные до появления набора: пока он
// качался, правило не совпадало и домен успел закэшироваться по общему "*".
// Без сброса реклама продолжила бы резолвиться ещё TTL записи.
func flushDNSCache() {
	if a := app; a != nil {
		a.FlushCache()
	}
}

// loadedSetKeys — какие наборы уже загружены, по видам и источникам
// (для полуночного обновления). Ключи карт c.geosite/c.geoip — "источник/имя".
func (c *Config) loadedSetKeys() map[string]map[string]bool {
	out := map[string]map[string]bool{"geosite": {}, "geoip": {}}
	c.geoMu.RLock()
	defer c.geoMu.RUnlock()
	for k := range c.geosite {
		src, _ := splitGeoKey(k)
		out["geosite"][src] = true
	}
	for k := range c.geoip {
		src, _ := splitGeoKey(k)
		out["geoip"][src] = true
	}
	return out
}

// splitGeoKey — "источник/имя" → (источник, имя).
func splitGeoKey(key string) (string, string) {
	if i := strings.IndexByte(key, '/'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return "", key
}

var geoCleanOnce sync.Once

// geoDatMu сериализует скачивание+разбор единого .dat на весь процесс:
// наборы общие для всех Config, параллельный разбор 70 МБ бессмыслен.
var geoDatMu sync.Mutex

// prefetchReferenced — наборы, на которые ссылаются правила, тянем фоном
// (сам DNS-запрос сеть не ждёт).
func (c *Config) prefetchReferenced() {
	if c.fetch == nil {
		return
	}
	refs := c.referencedRefs()
	for kind, srcs := range refs {
		for srcName, names := range srcs {
			if srcName == geoDirSrc {
				continue // локальный каталог, качать нечего
			}
			src := c.geoSrc(srcName)
			if src == nil {
				continue // невалидные ссылки отсеял prepareGeo
			}
			for name := range names {
				var loaded bool
				c.geoMu.RLock()
				if kind == "geosite" {
					loaded = c.geosite[geoKey(srcName, name)] != nil
				} else {
					loaded = c.geoip[geoKey(srcName, name)] != nil
				}
				c.geoMu.RUnlock()
				if !loaded {
					c.fetch.ensure(kind, src, name)
				}
			}
		}
	}
}

// rebuildLoaded пересобирает уже установленные наборы из кэша. Нужен, когда
// include: приезжает позже родителя: иначе родитель остался бы собранным по
// неполным данным до следующего рестарта.
func (f *geoFetcher) rebuildLoaded() {
	c := f.cfg
	c.geoMu.RLock()
	keys := make([]string, 0, len(c.geosite)+len(c.geoip))
	for k := range c.geosite {
		keys = append(keys, "geosite|"+k)
	}
	for k := range c.geoip {
		keys = append(keys, "geoip|"+k)
	}
	c.geoMu.RUnlock()
	for _, k := range keys {
		kind, srcName, name := splitKindKey(k)
		if srcName == geoDirSrc {
			continue // локальные наборы пересобирает вотчер каталога
		}
		src := c.geoSrc(srcName)
		if src == nil {
			continue
		}
		if kind == "geosite" {
			set, err := f.buildDomainSet(src, name, map[string]bool{}, 0)
			if err == nil && set != nil && set.Entries > 0 {
				c.setGeosite(srcName, name, set)
			}
			continue
		}
		set, err := f.buildIPSet(src, name, map[string]bool{}, 0)
		if err == nil && set != nil && len(set.Ranges) > 0 {
			c.setGeoip(srcName, name, set)
		}
	}
}

// splitKindKey — "geosite|источник/имя" → (geosite, источник, имя).
func splitKindKey(k string) (string, string, string) {
	kind, rest, _ := strings.Cut(k, "|")
	src, name := splitGeoKey(rest)
	return kind, src, name
}

// downloadDat качает единый .dat источника в кэш (атомарно), перебирая
// зеркала.
func (f *geoFetcher) downloadDat(kind string, src *geoSourceResolved) error {
	tpls := src.geosite
	if kind == "geoip" {
		tpls = src.geoip
	}
	if len(tpls) == 0 {
		return fmt.Errorf("URL для %s@%s не задан", kind, src.name)
	}
	var lastErr error
	for _, tpl := range tpls {
		resp, err := f.client.Get(tpl)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = &httpStatusError{code: resp.StatusCode, url: tpl}
			continue
		}
		dst := f.datPath(kind, src)
		if _, err := os.Stat(dst); err == nil {
			resp.Body.Close()
			return nil // уже скачано другим потоком
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			resp.Body.Close()
			return err
		}
		tmp := dst + ".tmp"
		out, err := os.Create(tmp)
		if err != nil {
			resp.Body.Close()
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(resp.Body, 512<<20)); err != nil {
			out.Close()
			resp.Body.Close()
			lastErr = err
			continue
		}
		if err := out.Close(); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()
		if err := os.Rename(tmp, dst); err != nil {
			if _, statErr := os.Stat(dst); statErr == nil {
				os.Remove(tmp)
				return nil
			}
			return err
		}
		return nil
	}
	return lastErr
}

// extractWanted разбирает единый .dat источника один раз и ставит все
// нужные категории этого источника.
func (f *geoFetcher) extractWanted(kind string, src *geoSourceResolved, onlyMissing bool) {
	all := f.cfg.referencedRefs()[kind][src.name]
	// разбираем только те, которых ещё нет: повторный вызов (второй поток,
	// перечитывание) не должен заново парсить 70 МБ
	want := map[string]bool{}
	for n := range all {
		if !onlyMissing {
			want[n] = true
			continue
		}
		if kind == "geosite" && f.cfg.peekGeositeKey(src.name, n) == nil {
			want[n] = true
		}
		if kind == "geoip" && f.cfg.peekGeoipKey(src.name, n) == nil {
			want[n] = true
		}
	}
	if len(want) == 0 {
		return
	}
	data, err := os.ReadFile(f.datPath(kind, src))
	if err != nil {
		log.Printf("гео: %s@%s.dat — чтение кэша: %v", kind, src.name, err)
		return
	}
	switch kind {
	case "geosite":
		sets, err := extractGeosite(data, want)
		if err != nil {
			log.Printf("гео: geosite@%s — разбор: %v", src.name, err)
			return
		}
		for n, s := range sets {
			s.Source = f.datPath(kind, src)
			f.cfg.setGeosite(src.name, n, s)
		}
		log.Printf("гео: geosite@%s — применено категорий: %d из %d запрошенных", src.name, len(sets), len(want))
	case "geoip":
		sets, err := extractGeoip(data, want)
		if err != nil {
			log.Printf("гео: geoip@%s — разбор: %v", src.name, err)
			return
		}
		for n, s := range sets {
			s.Source = f.datPath(kind, src)
			f.cfg.setGeoip(src.name, n, s)
		}
		log.Printf("гео: geoip@%s — применено категорий: %d из %d запрошенных", src.name, len(sets), len(want))
	}
}

// referencedRefs — наборы этого вида, упомянутые в правилах: вид → источник
// → имена. Ссылки без неймспейса резолвятся в первый источник, объявивший
// вид (или в локальный каталог-псевдоисточник dir).
func (c *Config) referencedRefs() map[string]map[string]map[string]bool {
	out := map[string]map[string]map[string]bool{"geosite": {}, "geoip": {}}
	c.geoMu.RLock()
	defer c.geoMu.RUnlock()
	for _, r := range c.Routes {
		for _, m := range r.Match {
			m = strings.ToLower(strings.TrimSpace(m))
			switch {
			case strings.HasPrefix(m, "geosite@"):
				src, nm, err := splitGeoKindRef(strings.TrimPrefix(m, "geosite@"))
				if err != nil {
					continue
				}
				if out["geosite"][src] == nil {
					out["geosite"][src] = map[string]bool{}
				}
				out["geosite"][src][nm] = true
			case strings.HasPrefix(m, "geosite:"):
				nm := strings.TrimPrefix(m, "geosite:")
				if s := c.resolveGeoSrc("geosite", ""); s != nil {
					if out["geosite"][s.name] == nil {
						out["geosite"][s.name] = map[string]bool{}
					}
					out["geosite"][s.name][nm] = true
				}
			}
		}
	}
	for _, r := range c.AnswerGeoip {
		src, nm, err := parseGeoSetRef(r.Set)
		if err != nil {
			continue
		}
		if s := c.resolveGeoSrc("geoip", src); s != nil {
			if out["geoip"][s.name] == nil {
				out["geoip"][s.name] = map[string]bool{}
			}
			out["geoip"][s.name][nm] = true
		}
	}
	// Наборы из catches — тоже ссылки: без них extractWanted в режиме
	// единого .dat не вытащит категорию, и правило молча не сработает.
	for _, r := range c.Catches {
		if strings.TrimSpace(r.Set) == "" {
			continue
		}
		src, nm, err := parseGeoSetRef(r.Set)
		if err != nil {
			continue
		}
		if s := c.resolveGeoSrc("geoip", src); s != nil {
			if out["geoip"][s.name] == nil {
				out["geoip"][s.name] = map[string]bool{}
			}
			out["geoip"][s.name][nm] = true
		}
	}
	// уже загруженные — их тоже надо обновлять (и dat-режиму не терять)
	for k := range c.geosite {
		src, name := splitGeoKey(k)
		if out["geosite"][src] == nil {
			out["geosite"][src] = map[string]bool{}
		}
		out["geosite"][src][name] = true
	}
	for k := range c.geoip {
		src, name := splitGeoKey(k)
		if out["geoip"][src] == nil {
			out["geoip"][src] = map[string]bool{}
		}
		out["geoip"][src][name] = true
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

// peekGeositeKey / peekGeoipKey — чтение без ленивой загрузки (для внутренних
// проверок: getGeositeKey на промахе запускает скачивание, здесь это лишнее).
func (c *Config) peekGeositeKey(src, name string) *domainSet {
	c.geoMu.RLock()
	defer c.geoMu.RUnlock()
	return c.geosite[geoKey(src, name)]
}

func (c *Config) peekGeoipKey(src, name string) *ipSet {
	c.geoMu.RLock()
	defer c.geoMu.RUnlock()
	return c.geoip[geoKey(src, name)]
}

// refreshDat — полночное обновление единого .dat источника: файл
// перекачивается целиком, затем нужные категории разбираются заново
// (наборы подменяются на месте).
func (f *geoFetcher) refreshDat(kind string, src *geoSourceResolved) {
	geoDatMu.Lock()
	defer geoDatMu.Unlock()
	os.Remove(f.datPath(kind, src))
	if err := f.downloadDat(kind, src); err != nil {
		log.Printf("гео: %s@%s.dat — обновление не удалось: %v", kind, src.name, err)
		return
	}
	f.extractWanted(kind, src, false)
	log.Printf("гео: %s@%s.dat — обновлён", kind, src.name)
}

// cleanCache убирает недокачанные файлы (*.tmp), оставшиеся после падения или
// убитого процесса. Свежие не трогаем: их может писать параллельная загрузка.
// Выполняется один раз за запуск, при первом обращении к кэшу.
func (f *geoFetcher) cleanCache() {
	geoCleanOnce.Do(func() {
		cutoff := time.Now().Add(-time.Hour)
		filepath.WalkDir(f.cfg.GeoCacheDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".tmp") {
				return nil
			}
			if info, statErr := d.Info(); statErr == nil && info.ModTime().Before(cutoff) {
				if os.Remove(path) == nil {
					log.Printf("гео: убран недокачанный файл %s", path)
				}
			}
			return nil
		})
	})
}

// geoRetryPause — пауза после сетевого сбоя: без неё каждый запрос к набору
// заново дёргал бы сеть.
const geoRetryPause = time.Minute

func (f *geoFetcher) backoff(key string) {
	f.mu.Lock()
	f.retryAt[key] = time.Now().Add(geoRetryPause)
	f.mu.Unlock()
}

// stripWildcard убирает ведущее "*.": в наших наборах "домен и поддомены"
// выражается самим именем, звёздочка только путала бы (суффикс "*.x" не
// совпадёт никогда).
func stripWildcard(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "*.")
}
