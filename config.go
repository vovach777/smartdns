package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
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
	// Bootstrap — резолвер для адресов самих апстримов (IP[:порт]).
	// Нужен, когда апстрим задан именем (tls://dns.quad9.net) и наш
	// сервер стоит системным: системный резолв — это петля через нас.
	// Бутстрап ходит к своему серверу напрямую. IP-апстримам не нужен.
	Bootstrap string            `yaml:"bootstrap"`
	Servers   map[string]string `yaml:"servers"`
	Hosts     map[string]string `yaml:"hosts"`
	Routes    []Route           `yaml:"routes"`

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
	"bootstrap", "servers", "hosts", "routes", "bind_devices",
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
	return nil
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
	if c.Bootstrap != "" {
		b := normalizeAddr(strings.TrimSpace(c.Bootstrap))
		host, _, err := net.SplitHostPort(b)
		if err != nil || net.ParseIP(host) == nil {
			return fmt.Errorf("bootstrap: %q — нужен IP[:порт], имя резолвить некому", c.Bootstrap)
		}
		c.Bootstrap = b
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
