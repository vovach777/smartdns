package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// Route — цепочка серверов для группы имён. Первое совпадение выигрывает.
// chain перебирается по порядку: первый сервер, чей ответ не отбракован,
// и есть ответ. Поэтому "умный" сервер ставят первым, чистый — вторым.
type Route struct {
	Match []string `yaml:"match"`
	Chain []string `yaml:"chain"`
}

type RejectConfig struct {
	// Сети, наличие которых в ответе считается мусором.
	Networks []string `yaml:"networks"`
	// NOERROR без единой A-записи — тоже мусор.
	EmptyA bool `yaml:"empty_a"`
	// Коды ответа, которые считаются мусором (имена или числа).
	Rcodes []string `yaml:"rcodes"`
}

// DotConfig — слушатель DNS-over-TLS: то, куда стучится клиент (tls://...).
type DotConfig struct {
	Listen string `yaml:"listen"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
	// Named — сертификаты по SNI. Если клиент не назвал имя (стучится по
	// IP) или назвал IP — отдаётся основной cert/key.
	Named []DotNamed `yaml:"named"`
}

// dotListeners — список DoT-слушателей. Понимает и старый вид (один
// объект), и новый (список): несколько слушателей нужны, когда на разных
// ПОРТАХ нужны разные сертификаты.
//
// Когда порт один, а сертификатов нужно два — по имени и по IP, —
// используются named-сертификаты (см. DotNamed): выбор по SNI. Это
// следствие правил Let's Encrypt: один сертификат не бывает одновременно
// с CN и с IP — shortlived разрешает IP, но оставляет subject пустым
// (на нём падают клиенты на GnuTLS), классический кладёт CN, но IP
// запрещает. Поэтому «по имени» и «по адресу» обслуживаются разными
// сертификатами на одном порту.
//
// DotNamed — дополнительный сертификат, который отдаём только тем, кто
// назвал это имя в SNI. Клиент по IP (Go не шлёт SNI для IP-литералов)
// получает основной cert/key.
type DotNamed struct {
	ServerName string `yaml:"server_name"`
	Cert       string `yaml:"cert"`
	Key        string `yaml:"key"`
}

type dotListeners []DotConfig

func (d *dotListeners) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.SequenceNode:
		var l []DotConfig
		if err := n.Decode(&l); err != nil {
			return err
		}
		*d = l
		return nil
	case yaml.MappingNode:
		var one DotConfig
		if err := n.Decode(&one); err != nil {
			return err
		}
		*d = []DotConfig{one}
		return nil
	}
	return fmt.Errorf("dot: ожидается объект или список объектов")
}

// listenAddrs — адреса обычного (UDP+TCP) DNS. Понимает и строку, и
// список: одного адреса мало, когда кроме локального слушателя для
// sing-box нужен ещё и публичный 53-й порт.
type listenAddrs []string

func (l *listenAddrs) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		*l = []string{s}
		return nil
	case yaml.SequenceNode:
		var ss []string
		if err := n.Decode(&ss); err != nil {
			return err
		}
		*l = ss
		return nil
	}
	return fmt.Errorf("listen: ожидается адрес или список адресов")
}

// String — для логов: адреса через запятую.
func (l listenAddrs) String() string {
	return strings.Join(l, ", ")
}

type CacheConfig struct {
	Enabled     bool `yaml:"enabled"`
	MaxEntries  int  `yaml:"max_entries"`
	MinTTL      int  `yaml:"min_ttl"`
	MaxTTL      int  `yaml:"max_ttl"`
	NegativeTTL int  `yaml:"negative_ttl"`
}

type Config struct {
	Listen listenAddrs `yaml:"listen"`
	// false (по умолчанию) — IPv6 вырезается. true — пропускать как есть.
	IPv6    bool   `yaml:"ipv6"`
	Timeout string `yaml:"timeout"`
	// Путь к лог-файлу. Пусто — писать в консоль.
	Log     string       `yaml:"log"`
	Verbose bool         `yaml:"verbose"`
	Reject  RejectConfig `yaml:"reject"`
	Cache   CacheConfig  `yaml:"cache"`
	Dot     dotListeners `yaml:"dot"`
	// Doh — слушатели DNS-over-HTTPS (RFC 8484). Тот же формат, что у dot:
	// listen + cert + key. Путь фиксированный — /dns-query.
	Doh dotListeners `yaml:"doh"`
	// Warm — как часто прогревать каналы до апстримов ("5s", "30s").
	// Пусто или 0 — не прогревать: каждый запрос сам открывает соединение.
	// WarmName — чем прогревать (любое заведомо резолвящееся имя).
	// WarmServers — если задан, греем только эти апстримы. Полезно, когда
	// за прокси сидит лишь часть из них: остальные и так отвечают быстро,
	// и долбить их холостыми запросами незачем.
	Warm        string   `yaml:"warm"`
	WarmName    string   `yaml:"warm_name"`
	WarmServers []string `yaml:"warm_servers"`
	// Prefetch — тратить холостые запросы прогрева на актуализацию кэша:
	// переспрашивать записи, которым осталось жить меньше двух интервалов.
	Prefetch bool `yaml:"prefetch"`
	// Bootstrap — откуда брать адреса апстримов, заданных именем.
	// Два вида на один ключ:
	//   bootstrap: 1.1.1.1                  — один резолвер на все имена
	//   bootstrap: {dns.quad9.net: 9.9.9.9} — имя прибито к адресу гвоздём
	// Зачем: когда наш сервер стоит системным (клиенты на 127.0.0.1:53),
	// «резолвить через систему» значит спросить самих себя. Апстримам,
	// заданным IP-литералом, бутстрап не нужен вовсе.
	Bootstrap BootstrapSpec `yaml:"bootstrap"`
	// BootstrapDNS — резолвер для имён без привязки. Нужен в паре с
	// картой: bootstrap в виде карты места для резолвера не оставляет.
	BootstrapDNS string            `yaml:"bootstrap_dns"`
	Servers      map[string]string `yaml:"servers"`
	Hosts        map[string]string `yaml:"hosts"`
	// HostsFiles — файлы (или каталоги с файлами) в формате /etc/hosts.
	// Записи подмешиваются к hosts: явные записи из секции hosts главнее,
	// внутри файлов первое вхождение выигрывает. Изменение файла на диске
	// подхватывается само (опрос раз в 5 с), SIGHUP перечитывает всё сразу.
	HostsFiles []string `yaml:"hosts_files"`
	// GeositeDir — каталог текстовых списков доменов, по файлу на набор
	// (<name>.txt). В routes матчится как "geosite:<name>". Формат строк:
	// full:name, domain:name, просто name (= domain:), '#' — комментарий.
	GeositeDir string `yaml:"geosite_dir"`
	// GeoipDir — каталог адресных наборов (по файлу <name>.txt на набор,
	// строки — CIDR или отдельные IPv4).
	GeoipDir string `yaml:"geoip_dir"`
	// AnswerGeoip — фильтр ГОТОВОГО ответа по адресным наборам: не меняет
	// маршрут и не делает повторных запросов, только переписывает ответ.
	AnswerGeoip []AnswerRule `yaml:"answer_geoip"`
	// GeoCacheDir — куда складывать скачанные наборы.
	GeoCacheDir string `yaml:"geo_cache_dir"`
	// Proxy — прокси для скачивания гео-списков: URL (http://, https://,
	// socks5://, socks5h://) или "env"/"yes" — переменные окружения
	// HTTP(S)_PROXY. Касается только скачивания, не апстримов. Пусто —
	// качать напрямую.
	Proxy string `yaml:"proxy"`
	// Geo — структурированная секция гео-списков: именованные источники
	// с URL-шаблонами, прокси и кэш. Плоские geosite_url/geoip_url убраны.
	Geo    Geo     `yaml:"geo"`
	Routes []Route `yaml:"routes"`
	// Catches — отлов по адресу в готовом ответе: если адрес попал под
	// правило, запрос переспрашивается другой цепочкой. Это НЕ routes:
	// маршрут выбирается по имени до запроса, а адрес появляется после.
	Catches []CatchRule `yaml:"catches"`
	// Rewrite — простой патч имени: запрос за одним именем разрешается как
	// другое имя. Одна подмена, без CNAME и без второго запроса клиента;
	// ответ возвращается под исходным именем. Значение — домен, не IP
	// (для IP есть hosts).
	Rewrite map[string]string `yaml:"rewrite"`

	// BindDevices — имя апстрима -> сетевой интерфейс (SO_BINDTODEVICE).
	// Апстрим тогда выходит через указанный интерфейс независимо от
	// policy-routing'а: правильный примитив для привязки апстрима к
	// туннелю вместо гвоздей вида "ip rule to 1.1.1.1".
	BindDevices map[string]string `yaml:"bind_devices"`

	// вычисляемое
	timeoutDur   time.Duration
	warmDur      time.Duration
	warmServers  map[string]bool
	rejectNets   []net.IPNet
	rejectRcodes map[int]bool
	rewrites map[string]string // нормализованные пары rewrite
	proxy    proxySpec         // верхний proxy: (для скачивания гео)
	geoProxy proxySpec         // geo.proxy — перекрывает верхний

	geoSrcs []*geoSourceResolved // geo.sources по порядку объявления
	boot         boot              // бутстрап: резолвер + прибитые адреса

	// что прочитано из hosts_files: для логов и -check
	hostsFiles []hostsFileStat
	// наборы geosite: имя -> матчер
	geosite map[string]*domainSet
	// наборы geoip: имя -> диапазоны
	geoip map[string]*ipSet
	// geoMu защищает geosite/geoip: их наполняет фоновая загрузка
	geoMu sync.RWMutex
	// fetch — ленивая загрузка наборов по URL
	fetch *geoFetcher
}

// AnswerRule — одно правило фильтра ответа по адресному набору.
type AnswerRule struct {
	Set    string `yaml:"set"`    // имя набора из geoip_dir
	Action string `yaml:"action"` // nxdomain | refused | noerror
}

// BootstrapSpec — значение ключа bootstrap: либо адрес резолвера, либо
// карта «имя апстрима -> адрес». Один ключ на два вида, потому что оба
// отвечают на один вопрос («откуда взять IP апстрима»), а в конфиге рядом
// им всё равно не место: прибитый адрес резолва не требует вовсе.
//
// Резолвер для имён без привязки в карте задать негде — для него есть
// отдельный ключ bootstrap_dns.
type BootstrapSpec struct {
	Addr string            // скалярная форма: адрес резолвера
	Pins map[string]string // карта: имя -> IP[:порт]
}

func (b *BootstrapSpec) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		b.Addr, b.Pins = strings.TrimSpace(s), nil
	case yaml.MappingNode:
		m := map[string]string{}
		if err := n.Decode(&m); err != nil {
			return err
		}
		b.Addr, b.Pins = "", m
	case yaml.SequenceNode:
		return fmt.Errorf("bootstrap: ожидается адрес или карта «имя: адрес», а не список")
	}
	return nil
}

func defaultConfig() Config {
	return Config{
		Listen:  listenAddrs{"127.0.0.1:53"},
		IPv6:    false,
		Timeout: "4s",
		Reject: RejectConfig{
			Networks: []string{"0.0.0.0/8", "::/128"},
			EmptyA:   true,
			Rcodes:   []string{"SERVFAIL", "REFUSED", "NOTIMP"},
		},
		Cache: CacheConfig{
			Enabled:     true,
			MaxEntries:  10000,
			MinTTL:      10,
			MaxTTL:      86400,
			NegativeTTL: 60,
		},
		Servers: map[string]string{},
		Hosts:   map[string]string{},
		Routes:  []Route{},
	}
}

// GeoSource — один именованный источник гео-списков. URL с {name} —
// поштучный текстовый режим ({name} заменяется именем набора); URL без
// {name} — единый .dat источника (из него берутся упомянутые категории).
// Несколько URL в списке — зеркала: качаем по первому, при сбое следующее.
type GeoSource struct {
	Name    string   `yaml:"name"`
	Geosite []string `yaml:"geosite"`
	Geoip   []string `yaml:"geoip"`
}

// Geo — секция geo: кэш, прокси и источники.
type Geo struct {
	CacheDir string      `yaml:"cache_dir"`
	Proxy    string      `yaml:"proxy"`
	Sources  []GeoSource `yaml:"sources"`
}

// geoSourceResolved — разобранный источник: нормализованные URL и режимы.
type geoSourceResolved struct {
	name       string
	geosite    []string
	geoip      []string
	datGeosite bool // geosite-URL без {name} — единый .dat
	datGeoip   bool
}

// datMode — единый .dat или поштучные файлы для этого вида.
func (s *geoSourceResolved) datMode(kind string) bool {
	if kind == "geoip" {
		return s.datGeoip
	}
	return s.datGeosite
}

// proxySpec — разобранное значение proxy: (direct | env | yes | URL).
type proxySpec struct {
	mode int
	url  *url.URL
}

const (
	proxyNone = iota
	proxyDirect
	proxyEnv
	proxyURL
)

// parseProxySpec — разбираем значение proxy. "direct" — напрямую (полезно
// в geo.proxy перекрыть глобальный), "env"/"yes" — окружение, иначе URL
// с понятной схемой. Всё остальное — ошибка, а не молчаливое "напрямую":
// опечатка вида sock5:// должна падать в -check, а не тихо качать напрямую.
func parseProxySpec(v string) (proxySpec, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return proxySpec{}, nil
	}
	switch strings.ToLower(v) {
	case "direct":
		return proxySpec{mode: proxyDirect}, nil
	case "env", "yes", "true":
		return proxySpec{mode: proxyEnv}, nil
	}
	u, err := url.Parse(v)
	if err != nil {
		return proxySpec{}, fmt.Errorf("proxy %q: %w", v, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	case "":
		return proxySpec{}, fmt.Errorf("proxy %q: нет схемы — жду http://, https://, socks5:// или socks5h://", v)
	default:
		return proxySpec{}, fmt.Errorf("proxy %q: схема %q не поддерживается — жду http://, https://, socks5:// или socks5h://", v, u.Scheme)
	}
	if u.Host == "" {
		return proxySpec{}, fmt.Errorf("proxy %q: нет адреса хоста", v)
	}
	return proxySpec{mode: proxyURL, url: u}, nil
}

// geoKey — ключ набора в картах c.geosite/c.geoip: "источник/имя".
func geoKey(src, name string) string { return src + "/" + name }

// splitGeoKindRef — хвост ссылки в маршруте: "hagezi:pro" → (hagezi, pro).
func splitGeoKindRef(s string) (string, string, error) {
	src, name, ok := strings.Cut(s, ":")
	if !ok || strings.TrimSpace(src) == "" || strings.TrimSpace(name) == "" ||
		strings.ContainsAny(src, "@") || strings.Contains(name, "@") {
		return "", "", fmt.Errorf("жду источник:имя (например hagezi:pro)")
	}
	return strings.ToLower(strings.TrimSpace(src)), strings.ToLower(strings.TrimSpace(name)), nil
}

// parseGeoSetRef — ссылка на набор в поле set: (answer_geoip, catches).
// "rf@ru-blocked" — из источника rf; "ru-blocked" — первый источник,
// объявивший geoip.
func parseGeoSetRef(v string) (src, name string, err error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "", "", fmt.Errorf("пустая ссылка на набор")
	}
	if i := strings.IndexByte(v, '@'); i >= 0 {
		src, name = v[:i], v[i+1:]
		if src == "" || name == "" || strings.ContainsAny(name, "@:") {
			return "", "", fmt.Errorf("ссылка %q: жду источник@имя", v)
		}
		return src, name, nil
	}
	if strings.ContainsAny(v, "@:") {
		return "", "", fmt.Errorf("ссылка %q: @ и : тут не нужны", v)
	}
	return "", v, nil
}

// geoSrc — источник по имени.
func (c *Config) geoSrc(name string) *geoSourceResolved {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, s := range c.geoSrcs {
		if s.name == name {
			return s
		}
	}
	return nil
}

// firstGeoSrc — первый источник, объявивший наборы такого вида.
func (c *Config) firstGeoSrc(kind string) *geoSourceResolved {
	for _, s := range c.geoSrcs {
		if (kind == "geosite" && len(s.geosite) > 0) || (kind == "geoip" && len(s.geoip) > 0) {
			return s
		}
	}
	return nil
}

// resolveGeoSrc — кто отвечает за ссылку: URL-источники по порядку, в конце —
// локальные каталоги geosite_dir/geoip_dir как псевдо-источник "dir".
func (c *Config) resolveGeoSrc(kind, src string) *geoSourceResolved {
	if src != "" {
		return c.geoSrc(src)
	}
	if s := c.firstGeoSrc(kind); s != nil {
		return s
	}
	if (kind == "geosite" && strings.TrimSpace(c.GeositeDir) != "") ||
		(kind == "geoip" && strings.TrimSpace(c.GeoipDir) != "") {
		return &geoSourceResolved{name: "dir"}
	}
	return nil
}

func (c *Config) geoSrcList() string {
	names := make([]string, 0, len(c.geoSrcs))
	for _, s := range c.geoSrcs {
		names = append(names, s.name)
	}
	return strings.Join(names, ", ")
}

// prepareGeo — разбираем секцию geo: источники, кэш, прокси — и проверяем,
// что каждая ссылка из правил попадает в существующий источник.
func (c *Config) prepareGeo() error {
	c.geoSrcs = nil
	seen := map[string]bool{}
	for i, s := range c.Geo.Sources {
		name := strings.ToLower(strings.TrimSpace(s.Name))
		if name == "" {
			return fmt.Errorf("geo.sources[%d]: у источника нужно имя (name:)", i)
		}
		if seen[name] {
			return fmt.Errorf("geo.sources: источник %q объявлен дважды", name)
		}
		seen[name] = true
		src := &geoSourceResolved{name: name}
		var err error
		if src.geosite, src.datGeosite, err = normalizeGeoURLs(name, "geosite", s.Geosite); err != nil {
			return err
		}
		if src.geoip, src.datGeoip, err = normalizeGeoURLs(name, "geoip", s.Geoip); err != nil {
			return err
		}
		if len(src.geosite) == 0 && len(src.geoip) == 0 {
			return fmt.Errorf("geo.sources[%d] %q: не задан ни один URL (geosite:/geoip:)", i, name)
		}
		c.geoSrcs = append(c.geoSrcs, src)
	}

	// кэш: geo.cache_dir перекрывает geo_cache_dir; разные значения — ошибка
	if cd := strings.TrimSpace(c.Geo.CacheDir); cd != "" {
		if strings.TrimSpace(c.GeoCacheDir) != "" && c.GeoCacheDir != cd {
			return fmt.Errorf("заданы и geo.cache_dir (%s), и geo_cache_dir (%s) — оставь один", cd, c.GeoCacheDir)
		}
		c.GeoCacheDir = cd
	}

	spec, err := parseProxySpec(c.Geo.Proxy)
	if err != nil {
		return fmt.Errorf("geo.proxy: %w", err)
	}
	c.geoProxy = spec

	return c.validateGeoRefs()
}

// normalizeGeoURLs — проверяем схему и единообразие режима: в одном списке
// нельзя смешивать {name}-шаблоны и единый .dat.
func normalizeGeoURLs(src, kind string, urls []string) ([]string, bool, error) {
	out := make([]string, 0, len(urls))
	withName := 0
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		pu, err := url.Parse(u)
		if err != nil {
			return nil, false, fmt.Errorf("geo.sources[%s] %s: %q: %w", src, kind, u, err)
		}
		scheme := strings.ToLower(pu.Scheme)
		if scheme != "http" && scheme != "https" {
			return nil, false, fmt.Errorf("geo.sources[%s] %s: %q: схема %q — жду http:// или https://", src, kind, u, scheme)
		}
		if pu.Host == "" {
			return nil, false, fmt.Errorf("geo.sources[%s] %s: %q: нет хоста", src, kind, u)
		}
		if strings.Contains(u, "{name}") {
			withName++
		}
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, false, nil
	}
	dat := withName == 0
	if !dat && withName != len(out) {
		return nil, false, fmt.Errorf("geo.sources[%s] %s: смешаны шаблоны с {name} и без — раздели на разные источники", src, kind)
	}
	return out, dat, nil
}

// validateGeoRefs — ссылка на набор должна попадать в существующий источник,
// объявивший нужный вид. Иначе правило молчит (тот класс багов, что мы ловили
// с referencedSets) — лучше упасть в -check.
func (c *Config) validateGeoRefs() error {
	checkGeosite := func(src, name string) error {
		if src == "" {
			if c.firstGeoSrc("geosite") == nil && strings.TrimSpace(c.GeositeDir) == "" {
				return fmt.Errorf("geosite:%s — в geo.sources нет ни одного источника с geosite (плоские geosite_url/geoip_url убраны — перенеси источники в geo: sources)", name)
			}
			return nil
		}
		s := c.geoSrc(src)
		if s == nil {
			return fmt.Errorf("geosite@%s:%s — нет источника %q (есть: %s)", src, name, src, c.geoSrcList())
		}
		if len(s.geosite) == 0 {
			return fmt.Errorf("geosite@%s:%s — источник %q не объявляет geosite", src, name, src)
		}
		return nil
	}
	checkGeoip := func(src, name string) error {
		if src == "" {
			if c.firstGeoSrc("geoip") == nil && strings.TrimSpace(c.GeoipDir) == "" {
				return fmt.Errorf("set: %s — в geo.sources нет ни одного источника с geoip", name)
			}
			return nil
		}
		s := c.geoSrc(src)
		if s == nil {
			return fmt.Errorf("set: %s@%s — нет источника %q (есть: %s)", name, src, src, c.geoSrcList())
		}
		if len(s.geoip) == 0 {
			return fmt.Errorf("set: %s@%s — источник %q не объявляет geoip", name, src, src)
		}
		return nil
	}
	for _, r := range c.Routes {
		for _, m := range r.Match {
			m = strings.ToLower(strings.TrimSpace(m))
			if strings.HasPrefix(m, "geosite@") {
				src, nm, err := splitGeoKindRef(strings.TrimPrefix(m, "geosite@"))
				if err != nil {
					return fmt.Errorf("маршрут %q: %w", m, err)
				}
				if err := checkGeosite(src, nm); err != nil {
					return err
				}
				continue
			}
			if set, ok := strings.CutPrefix(m, "geosite:"); ok {
				if err := checkGeosite("", set); err != nil {
					return err
				}
			}
		}
	}
	for _, r := range c.AnswerGeoip {
		src, nm, err := parseGeoSetRef(r.Set)
		if err != nil {
			return fmt.Errorf("answer_geoip: %w", err)
		}
		if err := checkGeoip(src, nm); err != nil {
			return err
		}
	}
	for _, r := range c.Catches {
		if strings.TrimSpace(r.Set) == "" {
			continue
		}
		src, nm, err := parseGeoSetRef(r.Set)
		if err != nil {
			return fmt.Errorf("catches %q: %w", r.Name, err)
		}
		if err := checkGeoip(src, nm); err != nil {
			return err
		}
	}
	return nil
}

// knownTopKeys — ключи верхнего уровня, которые конфиг понимает.
//
// YAML разбирается нестрого (yaml.Unmarshal, без KnownFields), поэтому
// опечатка в названии ключа иначе проглатывается молча: конфиг читается,
// настройка не применяется, а почему сервер ведёт себя иначе — не видно.
// Строгим разбор делать не стали: он ломает уже работающие конфиги с
// лишними ключами. Предупреждение в лог даёт понять причину и не ломает
// ничего.
var knownTopKeys = []string{
	"listen", "ipv6", "timeout", "log", "verbose", "reject", "cache",
	"dot", "doh", "warm", "warm_name", "warm_servers", "prefetch",
	"bootstrap", "bootstrap_dns", "servers", "hosts", "hosts_files", "geosite_dir", "geoip_dir", "answer_geoip", "geo", "geo_cache_dir", "proxy", "routes", "catches", "rewrite", "bind_devices",
}

func warnUnknownKeys(data []byte) {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil || len(node.Content) == 0 {
		return
	}
	root := node.Content[0]
	if root.Kind != yaml.MappingNode {
		return
	}
	known := make(map[string]bool, len(knownTopKeys))
	for _, k := range knownTopKeys {
		known[k] = true
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k := strings.ToLower(strings.TrimSpace(root.Content[i].Value))
		if k == "" || known[k] {
			continue
		}
		log.Printf("конфиг: неизвестный ключ %q — игнорирую", root.Content[i].Value)
	}
}

// rejectRemovedGeoKeys — плоские geosite_url/geoip_url убраны в пользу
// geo.sources. Ловим их прямо в YAML и объясняем миграцию: без этого конфиг
// выглядел бы рабочим, а наборы перестали бы качаться.
func rejectRemovedGeoKeys(data []byte) error {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil || len(node.Content) == 0 {
		return nil
	}
	root := node.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		k := strings.ToLower(strings.TrimSpace(root.Content[i].Value))
		if k == "geosite_url" || k == "geoip_url" {
			return fmt.Errorf("ключ %s убран — перенеси источники в секцию geo:\n"+
				"  geo:\n"+
				"    cache_dir: /var/cache/smartdns\n"+
				"    proxy: socks5://127.0.0.1:10808   # по желанию\n"+
				"    sources:\n"+
				"      - name: rf\n"+
				"        geosite: [ https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/{name}.txt ]\n"+
				"        geoip:   [ https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/text/{name}.txt ]", k)
		}
	}
	return nil
}

// LoadConfig читает YAML поверх значений по умолчанию: чего в файле нет,
// то остаётся дефолтным.
func LoadConfig(path string) (*Config, error) {
	cfg := defaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("не могу прочитать %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("разбор %s: %w", path, err)
		}
		if err := rejectRemovedGeoKeys(data); err != nil {
			return nil, err
		}
		warnUnknownKeys(data)
	}

	if len(cfg.Listen) == 0 {
		cfg.Listen = listenAddrs{"127.0.0.1:53"}
	}
	if cfg.Timeout == "" {
		cfg.Timeout = "4s"
	}
	cfg.timeoutDur, _ = time.ParseDuration(cfg.Timeout)
	if cfg.timeoutDur <= 0 {
		return nil, fmt.Errorf("timeout: не понимаю %q — нужно вроде 4s или 500ms", cfg.Timeout)
	}
	if cfg.Warm != "" && cfg.Warm != "0" {
		d, err := time.ParseDuration(cfg.Warm)
		if err != nil {
			return nil, fmt.Errorf("warm: не понимаю %q — нужно вроде 30s или 1m", cfg.Warm)
		}
		if d < 2*time.Second {
			return nil, fmt.Errorf("warm: %q слишком часто — минимум 2s", cfg.Warm)
		}
		cfg.warmDur = d
	}
	if cfg.WarmName == "" {
		cfg.WarmName = "example.com"
	}
	cfg.warmServers = map[string]bool{}
	for _, n := range cfg.WarmServers {
		cfg.warmServers[strings.TrimSpace(n)] = true
	}
	if cfg.Cache.MinTTL <= 0 {
		cfg.Cache.MinTTL = 10
	}
	if cfg.Cache.MaxTTL <= 0 || cfg.Cache.MaxTTL < cfg.Cache.MinTTL {
		cfg.Cache.MaxTTL = 86400
	}
	if cfg.Cache.NegativeTTL <= 0 {
		cfg.Cache.NegativeTTL = 60
	}
	if cfg.Cache.MaxEntries <= 0 {
		cfg.Cache.MaxEntries = 10000
	}
	if cfg.Servers == nil {
		cfg.Servers = map[string]string{}
	}
	if cfg.Hosts == nil {
		cfg.Hosts = map[string]string{}
	}
	if len(cfg.Servers) == 0 {
		cfg.Servers = map[string]string{
			"cloudflare": "1.1.1.1:53",
			"google":     "8.8.8.8:53",
		}
	}
	if len(cfg.Routes) == 0 {
		cfg.Routes = []Route{{Match: []string{"*"}, Chain: []string{"cloudflare", "google"}}}
	}

	if err := cfg.prepare(); err != nil {
		return nil, err
	}
	// Файлы hosts подмешиваются до validate: их записи должны пройти ту же
	// проверку значения, что и явные.
	if err := cfg.loadHostsFiles(); err != nil {
		return nil, err
	}
	if err := cfg.loadGeosite(); err != nil {
		return nil, err
	}
	if err := cfg.loadGeoip(); err != nil {
		return nil, err
	}
	if cfg.GeoCacheDir == "" {
		cfg.GeoCacheDir = defaultGeoCache
	}
	cfg.fetch = newGeoFetcher(&cfg)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// prepare разбирает сети и коды ответа один раз, на загрузке.
func (c *Config) prepare() error {
	c.rejectNets = nil
	for _, s := range c.Reject.Networks {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("reject.networks: %q — %v", s, err)
		}
		c.rejectNets = append(c.rejectNets, *n)
	}
	c.rejectRcodes = map[int]bool{}
	for _, s := range c.Reject.Rcodes {
		s = strings.ToUpper(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if n, err := strconv.Atoi(s); err == nil {
			c.rejectRcodes[n] = true
			continue
		}
		n, ok := dns.StringToRcode[s]
		if !ok {
			return fmt.Errorf("reject.rcodes: неизвестный код %q", s)
		}
		c.rejectRcodes[n] = true
	}
	if err := c.prepareProxy(); err != nil {
		return err
	}
	if err := c.prepareGeo(); err != nil {
		return err
	}
	if err := c.prepareCatches(); err != nil {
		return err
	}
	return c.prepareRewrites()
}

// prepareProxy — разбираем верхний proxy: (global для скачивания гео;
// geo.proxy перекрывает). Разбор значения — в parseProxySpec.
func (c *Config) prepareProxy() error {
	spec, err := parseProxySpec(c.Proxy)
	if err != nil {
		return err
	}
	c.proxy = spec
	return nil
}

// prepareRewrites нормализует пары «имя -> имя»: нижний регистр, без точки
// на конце. Значение обязано быть доменом: IP — это hosts, а не патч имени.
func (c *Config) prepareRewrites() error {
	c.rewrites = map[string]string{}
	for from, to := range c.Rewrite {
		f := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(from), "."))
		t := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(to), "."))
		if f == "" || t == "" {
			return fmt.Errorf("rewrite: пустое имя в паре %q: %q", from, to)
		}
		if strings.ContainsAny(f+t, "*") {
			return fmt.Errorf("rewrite: %s -> %s: шаблоны не поддерживаются, только точные имена", f, t)
		}
		if net.ParseIP(t) != nil {
			return fmt.Errorf("rewrite: %s -> %s: для IP используйте hosts", f, t)
		}
		if _, ok := dns.IsDomainName(dns.Fqdn(f)); !ok {
			return fmt.Errorf("rewrite: %q — не доменное имя", from)
		}
		if _, ok := dns.IsDomainName(dns.Fqdn(t)); !ok {
			return fmt.Errorf("rewrite: %q — не доменное имя", to)
		}
		if f == t {
			return fmt.Errorf("rewrite: %s -> %s: имя ссылается на себя", f, t)
		}
		c.rewrites[f] = t
	}
	return nil
}

// rewriteFor — на какое имя подменить запрос ("" — не подменять).
func (c *Config) rewriteFor(name string) (string, bool) {
	if len(c.rewrites) == 0 {
		return "", false
	}
	to, ok := c.rewrites[name]
	return to, ok
}

func (c *Config) validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("не задан ни один сервер")
	}
	if len(c.Routes) == 0 {
		return fmt.Errorf("не задано ни одного правила маршрутизации")
	}
	seenListen := map[string]bool{}
	for _, a := range c.Listen {
		if seenListen[a] {
			return fmt.Errorf("listen: адрес %s повторяется", a)
		}
		seenListen[a] = true
	}
	known := map[string]bool{}
	names := make([]string, 0, len(c.Servers))
	for name := range c.Servers {
		if !isValidName(name) {
			return fmt.Errorf("странное имя сервера %q", name)
		}
		known[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	for _, r := range c.Routes {
		if len(r.Match) == 0 {
			return fmt.Errorf("правило без match")
		}
		if len(r.Chain) == 0 {
			return fmt.Errorf("правило без chain: %v", r.Match)
		}
		for _, s := range r.Chain {
			if !known[s] {
				return fmt.Errorf("в chain указан неизвестный сервер %q; известные: %v", s, names)
			}
		}
	}
	if err := c.validateCatches(known, names); err != nil {
		return err
	}
	for s, dev := range c.BindDevices {
		if !known[s] {
			return fmt.Errorf("bind_devices: неизвестный сервер %q; известные: %v", s, names)
		}
		if dev == "" || strings.ContainsAny(dev, " \t\"'") {
			return fmt.Errorf("bind_devices: странное имя интерфейса %q у сервера %q", dev, s)
		}
		if !bindDeviceSupported {
			return fmt.Errorf("bind_devices: SO_BINDTODEVICE есть только на Linux")
		}
	}
	if c.Bootstrap.Addr != "" && strings.TrimSpace(c.BootstrapDNS) != "" {
		return fmt.Errorf("bootstrap задан адресом и строки, и bootstrap_dns — оставьте что-то одно")
	}
	resolver := c.Bootstrap.Addr
	if resolver == "" {
		resolver = strings.TrimSpace(c.BootstrapDNS)
	}
	if resolver != "" {
		b := normalizeAddr(resolver)
		host, _, err := net.SplitHostPort(b)
		if err != nil || net.ParseIP(host) == nil {
			return fmt.Errorf("bootstrap: %q — нужен IP[:порт], имя резолвить некому", resolver)
		}
		c.boot.resolver = b
	}
	if len(c.Bootstrap.Pins) > 0 {
		// Имя в привязке должно встречаться среди апстримов: опечатка
		// здесь молча означает «настройка ни к чему не применена».
		hosts := map[string]bool{}
		for _, spec := range c.Servers {
			if h := specHost(spec); h != "" {
				hosts[h] = true
			}
		}
		c.boot.pins = make(map[string]string, len(c.Bootstrap.Pins))
		keys := make([]string, 0, len(c.Bootstrap.Pins))
		for k := range c.Bootstrap.Pins {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			host := bootKey(k)
			if host == "" {
				return fmt.Errorf("bootstrap: пустое имя в привязках")
			}
			pin, err := normalizePin(c.Bootstrap.Pins[k])
			if err != nil {
				return fmt.Errorf("bootstrap: %s — %v", k, err)
			}
			if !hosts[host] {
				log.Printf("bootstrap: имя %q не встречается среди апстримов — привязка ни к чему не применяется", k)
			}
			c.boot.pins[host] = pin
		}
	}
	for k, v := range c.Hosts {
		if err := validateHostValue(v); err != nil {
			return fmt.Errorf("hosts: %q — %v", k, err)
		}
	}
	seen := map[string]bool{}
	for _, d := range c.Dot {
		if d.Listen == "" {
			return fmt.Errorf("dot.listen не задан")
		}
		if d.Cert == "" || d.Key == "" {
			return fmt.Errorf("dot %s: нужны оба — cert и key", d.Listen)
		}
		if seen[d.Listen] {
			return fmt.Errorf("dot: адрес %s повторяется", d.Listen)
		}
		seen[d.Listen] = true
		ns := map[string]bool{}
		for _, n := range d.Named {
			if n.ServerName == "" {
				return fmt.Errorf("dot %s: у named не задан server_name", d.Listen)
			}
			if n.Cert == "" || n.Key == "" {
				return fmt.Errorf("dot %s: для %s нужны оба — cert и key", d.Listen, n.ServerName)
			}
			key := sniKey(n.ServerName)
			if ns[key] {
				return fmt.Errorf("dot %s: имя %s повторяется", d.Listen, n.ServerName)
			}
			ns[key] = true
		}
	}
	seenDoh := map[string]bool{}
	for _, d := range c.Doh {
		if d.Listen == "" {
			return fmt.Errorf("doh.listen не задан")
		}
		if d.Cert == "" || d.Key == "" {
			return fmt.Errorf("doh %s: нужны оба — cert и key", d.Listen)
		}
		if seenDoh[d.Listen] {
			return fmt.Errorf("doh: адрес %s повторяется", d.Listen)
		}
		seenDoh[d.Listen] = true
	}
	return nil
}

type listener struct {
	addr string
	net  string // udp | tcp | tcp-tls
	tls  *tls.Config
}

// listeners — все сокеты, которые нужно поднять.
// tls раздаётся по порядку следования dot-слушателей: у каждого свой
// сертификат, общего на всех уже нет.
func (c *Config) listeners(tlsConfs []*tls.Config) []listener {
	ls := make([]listener, 0, 2*len(c.Listen)+len(c.Dot))
	for _, a := range c.Listen {
		ls = append(ls, listener{addr: a, net: "udp"}, listener{addr: a, net: "tcp"})
	}
	for i, d := range c.Dot {
		if d.Listen == "" {
			continue
		}
		var tc *tls.Config
		if i < len(tlsConfs) {
			tc = tlsConfs[i]
		}
		ls = append(ls, listener{addr: d.Listen, net: "tcp-tls", tls: tc})
	}
	// TLS-конфиги DoH-слушателей идут в tlsConfs следом за DoT.
	for i, d := range c.Doh {
		if d.Listen == "" {
			continue
		}
		var tc *tls.Config
		if j := len(c.Dot) + i; j < len(tlsConfs) {
			tc = tlsConfs[j]
		}
		ls = append(ls, listener{addr: d.Listen, net: "doh", tls: tc})
	}
	return ls
}

func isValidName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r == ' ' || r == '"' || r == '\t' {
			return false
		}
	}
	return true
}

func validateHostValue(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		switch strings.ToLower(part) {
		case "", "nxdomain", "nx", "refused", "noerror":
			continue
		}
		if net.ParseIP(part) != nil {
			continue
		}
		if !strings.HasSuffix(part, ".") {
			part += "."
		}
		if _, ok := dns.IsDomainName(part); !ok {
			return fmt.Errorf("не пойму значение %q: нужен IP, домен (CNAME) или nxdomain", part)
		}
	}
	return nil
}

// routeFor возвращает цепочку для имени: первое подходящее правило.
// Точное совпадение имени и суффикс `.domain` проверяются раньше, чем "*".
func (c *Config) routeFor(name string) []string {
	for _, r := range c.Routes {
		for _, m := range r.Match {
			m = strings.ToLower(strings.TrimSpace(m))
			if strings.HasPrefix(m, "geosite@") {
				src, set, err := splitGeoKindRef(strings.TrimPrefix(m, "geosite@"))
				if err != nil {
					continue // невалидную ссылку отсеял prepareGeo
				}
				if c.geositeMatchIn(src, set, name) {
					return r.Chain
				}
				continue
			}
			if set, ok := strings.CutPrefix(m, "geosite:"); ok {
				if c.geositeMatch(set, name) {
					return r.Chain
				}
				continue
			}
			m = strings.TrimPrefix(m, "*.")
			if m == "" || m == "*" {
				continue
			}
			m = strings.TrimSuffix(m, ".")
			if name == m || strings.HasSuffix(name, "."+m) {
				return r.Chain
			}
		}
	}
	for _, r := range c.Routes {
		for _, m := range r.Match {
			if strings.TrimSpace(m) == "*" {
				return r.Chain
			}
		}
	}
	return nil
}

// hostValue ищет имя в секции hosts. Сначала точное совпадение, потом "*.domain".
func (c *Config) hostValue(name string) (string, bool) {
	if v, ok := c.Hosts[name]; ok {
		return v, true
	}
	for k, v := range c.Hosts {
		pat := strings.ToLower(strings.TrimSpace(k))
		if !strings.HasPrefix(pat, "*.") {
			continue
		}
		pat = strings.TrimSuffix(pat[2:], ".")
		if name == pat || strings.HasSuffix(name, "."+pat) {
			return v, true
		}
	}
	return "", false
}

func normalizeAddr(spec string) string {
	// та же осторожность с IPv6, что и в normalizeAddrPort: JoinHostPort
	// слепо добавляет скобки ко всему, где есть двоеточие.
	return normalizeAddrPort(spec, "53")
}

func (c *Config) String() string {
	names := make([]string, 0, len(c.Servers))
	for n := range c.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		fmt.Fprintf(&sb, "\n  %-12s %s", n, c.Servers[n])
	}
	return sb.String()
}
