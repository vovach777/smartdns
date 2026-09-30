// smartdns — локальный DNS-форвардер с отбраковкой мусорных ответов.
//
// Идея: для каждого имени задана ЦЕПОЧКА серверов. Спрашиваем первый,
// смотрим ответ. Если он «погадил» (0.0.0.1, пустой NOERROR, SERVFAIL) —
// молча идём к следующему в цепочке. Так «умный» резолвер, который
// подменяет адреса, используется там, где он полезен, и обходится там,
// где он ломает домен.
//
// Фолбэк делается ВНУТРИ сервера, потому что stub-резолвер ОС не продолжает
// цепочку на NXDOMAIN: NXDOMAIN — окончательный ответ. На следующий сервер
// система переходит только при таймауте или SERVFAIL.
//
// Всё настраивается одним файлом smartdns.yaml. Из параметров командной
// строки осталось только три штуки: -config, -check и -service (Windows).
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	flagConfig  = flag.String("config", "", "путь к smartdns.yaml (по умолчанию ищется рядом с программой)")
	flagVerbose = flag.Bool("v", false, "подробный лог поверх настроек конфига")
	flagCheck   = flag.Bool("check", false, "проверить конфиг, показать как понят, и выйти")
	flagService = flag.String("service", "", "управление службой Windows: install | remove | start | stop")
)

var (
	app       *App
	cfgPath   string
	group     = &serverGroup{}
	stopPurge = make(chan struct{})
	quit      = make(chan struct{})
	quitOnce  sync.Once

	// dotSels — по одному выборщику сертификатов на каждый dot-слушатель,
	// dohSels — то же для doh-слушателей.
	dotSels []*certSelector
	dohSels []*certSelector
)

func isWindows() bool { return runtime.GOOS == "windows" }

// gracefulStop глушит серверы и отпускает main.
func gracefulStop() {
	quitOnce.Do(func() {
		group.stop()
		close(quit)
		close(stopPurge)
	})
}

func main() {
	flag.Parse()

	// команды управления службой: install / remove / start / stop
	if *flagService != "" {
		if err := serviceCommand(*flagService); err != nil {
			log.Fatalf("служба: %v", err)
		}
		return
	}

	path, err := findConfig(*flagConfig)
	if err != nil {
		log.Fatal(err)
	}
	cfgPath = path

	cfg, err := load()
	if err != nil {
		log.Fatal(err)
	}

	if *flagCheck {
		describe(cfg, path)
		return
	}

	// запущены диспетчером служб — работаем как служба
	if inService() {
		if err := runAsService(); err != nil {
			log.Fatalf("служба: %v", err)
		}
		return
	}

	if err := run(nil); err != nil {
		log.Fatal(err)
	}
}

// load читает конфиг и применяет -v поверх него.
func load() (*Config, error) {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return nil, err
	}
	if *flagVerbose {
		cfg.Verbose = true
	}
	if cfg.Log == "" && inService() {
		// в службе консоли нет — пишем лог рядом с программой
		if exe, err := os.Executable(); err == nil {
			cfg.Log = filepath.Join(filepath.Dir(exe), "smartdns.log")
		}
	}
	return cfg, nil
}

// reload перечитывает конфиг на ходу (SIGHUP). Кэш при этом сбрасывается.
func reload() error {
	cfg, err := load()
	if err != nil {
		log.Printf("перезагрузка конфига не удалась: %v", err)
		return err
	}
	if err := app.apply(cfg); err != nil {
		log.Printf("перезагрузка конфига не удалась: %v", err)
		return err
	}
	setupLog(cfg)
	tc, err := prepareTLS(cfg)
	if err != nil {
		log.Printf("перезагрузка конфига не удалась: %v", err)
		return err
	}
	group.setTLS(tc)
	group.start(app, cfg)
	log.Printf("конфиг перечитан из %s, кэш сброшен", cfgPath)
	return nil
}

func run(stop <-chan struct{}) error {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfg, err := load()
	if err != nil {
		return err
	}
	setupLog(cfg)

	app, err = NewApp(cfg)
	if err != nil {
		return err
	}

	tc, err := prepareTLS(cfg)
	if err != nil {
		return err
	}
	group.setTLS(tc)

	for _, l := range cfg.listeners(tc) {
		log.Printf("слушаю %s/%s", l.addr, l.net)
	}
	log.Printf("IPv6: %s", map[bool]string{true: "пропускаем", false: "вырезаем"}[cfg.IPv6])
	log.Printf("кэш: %s", cacheStatus(cfg))
	log.Printf("серверы:%s", cfg.String())
	log.Printf("правил: %d, записей в hosts: %d", len(cfg.Routes), len(cfg.Hosts))

	group.start(app, cfg)
	watchSignals()
	go purgeLoop()

	if stop == nil {
		stop = quit
	}
	<-stop
	group.stop()
	return nil
}

// purgeLoop раз в минуту выкидывает просроченные записи, чтобы кэш не рос.
func purgeLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if n := app.PurgeCache(); n > 0 {
				cfg, _, _ := app.snapshot()
				if cfg.Verbose {
					log.Printf("кэш: выброшено просроченных записей: %d", n)
				}
			}
		case <-stopPurge:
			return
		}
	}
}

// setupLog перенаправляет лог в файл, если задан.
func setupLog(cfg *Config) {
	if cfg == nil || cfg.Log == "" {
		return
	}
	f, err := os.OpenFile(cfg.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("не могу открыть лог %s: %v", cfg.Log, err)
		return
	}
	log.SetOutput(f)
}

func cacheStatus(cfg *Config) string {
	if !cfg.Cache.Enabled {
		return "выключен"
	}
	return fmt.Sprintf("включён, до %d записей, TTL %d..%d с (пустые ответы: %d с)",
		cfg.Cache.MaxEntries, cfg.Cache.MinTTL, cfg.Cache.MaxTTL, cfg.Cache.NegativeTTL)
}

// describe печатает, как конфиг понят — для -check.
func describe(cfg *Config, path string) {
	fmt.Printf("конфиг: %s — ОК\n\n", path)
	fmt.Printf("слушаем:     %s\n", cfg.Listen)
	fmt.Printf("IPv6:        %s\n", map[bool]string{true: "пропускаем", false: "вырезаем"}[cfg.IPv6])
	fmt.Printf("таймаут:     %v\n", cfg.timeoutDur)
	fmt.Printf("лог:         %s\n", orDash(cfg.Log))
	fmt.Printf("кэш:         %s\n", cacheStatus(cfg))
	if cfg.warmDur > 0 {
		who := "все апстримы"
		if len(cfg.WarmServers) > 0 {
			who = strings.Join(cfg.WarmServers, ", ")
		}
		fmt.Printf("прогрев:     каждые %v -> %s", cfg.warmDur, who)
		if cfg.Prefetch {
			fmt.Printf(", кэш актуализируется теми же запросами\n")
		} else {
			fmt.Printf(", холостым запросом %q\n", cfg.WarmName)
		}
	} else {
		fmt.Printf("прогрев:     выключен (канал поднимается на каждом запросе)\n")
	}
	if cfg.Bootstrap != "" {
		fmt.Printf("бутстрап:    %s (имена апстримов — через него, мимо системы)\n", cfg.Bootstrap)
	} else {
		fmt.Printf("бутстрап:    не задан (имена апстримов — системным резолвером)\n")
	}
	fmt.Printf("отбраковка:  сети %v, пустой A: %v, коды %v\n",
		cfg.Reject.Networks, cfg.Reject.EmptyA, cfg.Reject.Rcodes)
	for _, d := range cfg.Dot {
		fmt.Printf("DoT:         %s (сертификат %s)\n", d.Listen, d.Cert)
		for _, n := range d.Named {
			fmt.Printf("             по SNI %s -> сертификат %s\n", n.ServerName, n.Cert)
		}
	}
	for _, d := range cfg.Doh {
		fmt.Printf("DoH:         %s/dns-query (сертификат %s)\n", d.Listen, d.Cert)
	}
	fmt.Println("\nсерверы:")
	for _, n := range sortedKeys(cfg.Servers) {
		dev := ""
		if d := cfg.BindDevices[n]; d != "" {
			dev = " (dev " + d + ")"
		}
		fmt.Printf("  %-12s %s%s\n", n, cfg.Servers[n], dev)
	}
	if len(cfg.Hosts) > 0 {
		fmt.Println("\nhosts:")
		for _, k := range sortedKeys(cfg.Hosts) {
			fmt.Printf("  %-34s %s\n", k, cfg.Hosts[k])
		}
	}
	fmt.Println("\nцепочки (первое совпадение выигрывает):")
	for _, r := range cfg.Routes {
		fmt.Printf("  %-52s -> %s\n", strings.Join(r.Match, ", "), strings.Join(r.Chain, " -> "))
	}
	fmt.Println()
	for _, name := range []string{"claude.ai", "www.workbuddy.ai", "google.com"} {
		fmt.Printf("  например %-22s пойдёт по цепочке: %s\n", name, strings.Join(cfg.routeFor(name), " -> "))
	}
}

func orDash(s string) string {
	if s == "" {
		return "(в консоль)"
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// ---------- поиск конфига ----------

func findConfig(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("конфиг %s не найден", explicit)
		}
		return explicit, nil
	}
	if v := os.Getenv("SMARTDNS_CONFIG"); v != "" {
		return v, nil
	}

	exe, _ := os.Executable()
	var candidates []string
	if exe != "" {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "smartdns.yaml"),
			filepath.Join(dir, "..", "etc", "smartdns.yaml"),
		)
	}
	candidates = append(candidates, "smartdns.yaml")
	if !isWindows() {
		candidates = append(candidates,
			"/etc/smartdns.yaml",
			"/usr/local/etc/smartdns.yaml",
		)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	// ничего не нашли — вернём «правильный» путь, чтобы ошибка была понятной
	if exe != "" {
		return filepath.Join(filepath.Dir(exe), "smartdns.yaml"), nil
	}
	return "smartdns.yaml", nil
}

// ---------- прослушивание ----------

// serverGroup держит текущие слушатели и перезапускает их, если в конфиге
// поменялись адреса (SIGHUP).
type serverGroup struct {
	mu   sync.Mutex
	key  string
	tls  []*tls.Config
	done []chan struct{}
}

func (g *serverGroup) start(a *App, cfg *Config) {
	g.mu.Lock()
	defer g.mu.Unlock()

	ls := cfg.listeners(g.tls)
	key := ""
	for _, l := range ls {
		key += l.net + "|" + l.addr + ";"
	}
	// Адреса те же — слушатели не трогаем. Сертификат при этом всё равно
	// обновится: tls.Config держит GetCertificate на тот же релоадер,
	// который prepareTLS уже перечитал.
	if g.key == key && len(g.done) > 0 {
		return
	}
	g.shutdownLocked()
	g.key = key
	for _, l := range ls {
		st := make(chan struct{})
		g.done = append(g.done, st)
		go a.serve(l.addr, l.net, l.tls, st)
	}
}

func (g *serverGroup) stop() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.shutdownLocked()
}

func (g *serverGroup) shutdownLocked() {
	for _, d := range g.done {
		close(d)
	}
	g.done = nil
}

// serve поднимает один сокет. stop закрывается при остановке службы
// или при смене адреса в конфиге.
func (a *App) serve(addr, net string, tc *tls.Config, stop <-chan struct{}) {
	if net == "doh" {
		a.serveDoH(addr, tc, stop)
		return
	}
	s := &dns.Server{Addr: addr, Net: net, Handler: a.handle(upstreamNet(net))}
	if net == "tcp-tls" {
		s.TLSConfig = tc
	}
	errCh := make(chan error, 1)
	go func() { errCh <- s.ListenAndServe() }()

	select {
	case err := <-errCh:
		if err != nil {
			log.Printf("прослушивание %s/%s: %v", addr, net, err)
		}
	case <-stop:
		s.Shutdown()
	}
}

// upstreamNet: к апстриму стучимся тем же транспортом, кроме DoT — там tcp.
func upstreamNet(net string) string {
	if net == "udp" {
		return "udp"
	}
	return "tcp"
}

// prepareTLS готовит по TLS-конфигу на каждый DoT-слушатель. Внутри одного
// слушателя сертификат выбирается по SNI (см. certSelector), потому что на
// одном порту могут встретиться и клиент по IP, и клиент по имени.
//
// Релоадеры живут в dotSels и перечитывают файлы раз в час, поэтому
// продление подхватывается без перезапуска. На SIGHUP тот же релоадер
// получает новые пути через update(), и уже поднятые слушатели начинают
// отдавать новый сертификат — tls.Config ссылается на него.
// tlsForListeners готовит по TLS-конфигу на каждый слушатель списка
// (dot или doh — механика одна: default-сертификат + выбор по SNI).
// Возвращаемые конфиги идут в том же порядке, в каком listeners()
// раздаёт их слушателям.
func tlsForListeners(list dotListeners, sels *[]*certSelector) ([]*tls.Config, error) {
	if len(list) == 0 {
		return nil, nil
	}
	for len(*sels) < len(list) {
		*sels = append(*sels, &certSelector{named: map[string]*certReloader{}})
	}
	out := make([]*tls.Config, 0, len(list))
	for i, d := range list {
		s := (*sels)[i]
		if err := upsertReloader(&s.def, d.Cert, d.Key); err != nil {
			return nil, fmt.Errorf("TLS %s: %w", d.Listen, err)
		}
		live := map[string]bool{}
		for _, n := range d.Named {
			name := sniKey(n.ServerName)
			r := s.named[name]
			if err := upsertReloader(&r, n.Cert, n.Key); err != nil {
				return nil, fmt.Errorf("TLS %s (%s): %w", d.Listen, n.ServerName, err)
			}
			s.named[name] = r
			live[name] = true
		}
		for k := range s.named {
			if !live[k] {
				delete(s.named, k)
			}
		}
		out = append(out, &tls.Config{GetCertificate: s.get, MinVersion: tls.VersionTLS12})
	}
	return out, nil
}

func prepareTLS(cfg *Config) ([]*tls.Config, error) {
	dotTC, err := tlsForListeners(cfg.Dot, &dotSels)
	if err != nil {
		return nil, err
	}
	dohTC, err := tlsForListeners(cfg.Doh, &dohSels)
	if err != nil {
		return nil, err
	}
	return append(dotTC, dohTC...), nil
}

// upsertReloader заводит релоадер с часовым watch-циклом или обновляет
// пути у существующего.
func upsertReloader(p **certReloader, certFile, keyFile string) error {
	if *p == nil {
		r, err := newCertReloader(certFile, keyFile)
		if err != nil {
			return err
		}
		go r.watch()
		*p = r
		return nil
	}
	return (*p).update(certFile, keyFile)
}

func (g *serverGroup) setTLS(tc []*tls.Config) {
	if len(tc) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tls = tc
}
