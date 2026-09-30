package main

import (
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// App — живое состояние сервера: конфиг, апстримы, кэш.
// Всё под одним замком, чтобы SIGHUP мог подменить конфиг на ходу.
type App struct {
	mu    sync.RWMutex
	cfg   *Config
	ups   map[string]*upstream
	cache *Cache

	// закрывается при подмене конфига, чтобы старые горулины прогрева
	// не висели и не долбили уже несуществующие апстримы.
	warmStop chan struct{}

	// очередь записей кэша, взятых на актуализацию.
	pfMu    sync.Mutex
	pfQueue []string
}

func NewApp(cfg *Config) (*App, error) {
	a := &App{}
	if err := a.apply(cfg); err != nil {
		return nil, err
	}
	return a, nil
}

// apply подменяет конфиг. Кэш при этом сбрасывается: правила могли
// поменяться, а старые ответы уже не соответствуют новым цепочкам.
func (a *App) apply(cfg *Config) error {
	ups := make(map[string]*upstream, len(cfg.Servers))
	for name, spec := range cfg.Servers {
		u, err := newUpstream(name, spec, cfg.timeoutDur, cfg.BindDevices[name])
		if err != nil {
			return err
		}
		ups[name] = u
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// прежние горулины прогрева останавливаем сразу: они крутятся вокруг
	// старых объектов upstream, которые никто уже не спрашивает.
	if a.warmStop != nil {
		close(a.warmStop)
	}
	a.warmStop = make(chan struct{})

	if cfg.warmDur > 0 {
		for name, u := range ups {
			if len(cfg.WarmServers) > 0 && !cfg.warmServers[name] {
				continue
			}
			u.enablePool()
			uu := u
			tick := a.tickFor(uu)
			go uu.warmUp(tick)
			go uu.warmLoop(cfg.warmDur, tick, a.warmStop)
		}
	}

	old := a.cache
	a.cfg, a.ups = cfg, ups
	if old == nil ||
		old.limit != cfg.Cache.MaxEntries ||
		old.minTTL != cfg.Cache.MinTTL ||
		old.maxTTL != cfg.Cache.MaxTTL ||
		old.negTTL != cfg.Cache.NegativeTTL {
		a.cache = NewCache(cfg.Cache)
	} else {
		old.Flush()
	}
	return nil
}

// ---------- прогрев и актуализация кэша ----------

// prefetchBatch — сколько записей за раз берём на актуализацию. Ограничитель
// нужен, иначе на большом кэше с короткими TTL один тик превратится в сотни
// запросов подряд.
const prefetchBatch = 32

// prefetchActiveWindow — как давно записью должны были пользоваться, чтобы
// считать её живой. Обновлять то, что никто не спрашивает, незачем.
const prefetchActiveWindow = time.Hour

// tickFor — один запрос к данному апстриму, который заодно актуализирует
// кэш.
//
// Смысл: канал до апстрима мы обязаны греть каждые несколько секунд, иначе
// прокси его убьёт. Раз трафик всё равно идёт — пусть он переспрашивает то,
// что вот-вот протухнет, а не фиктивное имя. Тогда клиент в принципе не
// видит промахов: запись обновляется до того, как истечёт.
func (a *App) tickFor(u *upstream) func() {
	return func() {
		cfg, _, cache := a.snapshot()
		if cfg == nil {
			return
		}
		name, qtype := a.nextTarget(cfg)
		if name == "" {
			return
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		m.RecursionDesired = true

		resp, err := u.exchange(m, "udp")
		if err != nil || resp == nil {
			return
		}
		if cfg.rejectReason(resp, qtype) != "" {
			return
		}
		if !cfg.IPv6 {
			stripIPv6(resp)
		}
		if cfg.Cache.Enabled && cache != nil {
			cache.Refresh(CacheKey(name, qtype), resp)
		}
		if cfg.Verbose {
			log.Printf("ОБНОВИЛ %-5s %-34s <- %s", dns.TypeToString[qtype], name, u.name)
		}
	}
}

// nextTarget — что спросить следующим: запись кэша, которой осталось жить
// меньше двух интервалов прогрева; если таких нет — холостое имя из конфига.
func (a *App) nextTarget(cfg *Config) (string, uint16) {
	_, _, cache := a.snapshot()
	if cfg.Prefetch && cache != nil {
		a.pfMu.Lock()
		if len(a.pfQueue) == 0 {
			within := 2 * cfg.warmDur
			if within < 10*time.Second {
				within = 10 * time.Second
			}
			a.pfQueue = cache.Expiring(within, prefetchActiveWindow, prefetchBatch)
		}
		var key string
		if len(a.pfQueue) > 0 {
			key, a.pfQueue = a.pfQueue[0], a.pfQueue[1:]
		}
		a.pfMu.Unlock()
		if name, qtype, ok := SplitKey(key); ok {
			return name, qtype
		}
	}
	return cfg.WarmName, dns.TypeA
}

func (a *App) snapshot() (*Config, map[string]*upstream, *Cache) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg, a.ups, a.cache
}

// FlushCache выбрасывает весь кэш.
func (a *App) FlushCache() {
	_, _, c := a.snapshot()
	if c != nil {
		c.Flush()
	}
}

// PurgeCache выбрасывает только просроченное.
func (a *App) PurgeCache() int {
	_, _, c := a.snapshot()
	if c == nil {
		return 0
	}
	return c.Purge()
}

func (a *App) Stats() (int, int, int) {
	_, _, c := a.snapshot()
	if c == nil {
		return 0, 0, 0
	}
	return c.Stats()
}

// ---------- обработчик ----------

type step struct {
	server  string
	verdict string // ok | bad | err
	detail  string
}

func (a *App) handle(network string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if m := a.resolveQuery(r, network); m != nil {
			w.WriteMsg(m)
		}
	}
}

// resolveQuery — вся логика одного запроса: hosts, кэш, цепочка с
// отбраковкой. Возвращает готовый ответ или nil (клиенту не отвечаем).
// Вызывается и из DNS-слушателей (udp/tcp), и из DoH-обработчика —
// разница только в транспорте, резолв один и тот же.
func (a *App) resolveQuery(r *dns.Msg, network string) *dns.Msg {
	{
		if len(r.Question) == 0 || r.MsgHdr.Opcode != dns.OpcodeQuery {
			return nil
		}
		cfg, ups, cache := a.snapshot()

		q := r.Question[0]
		name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		key := name + "|" + strconv.Itoa(int(q.Qtype))

		// 1. Статические подмены из секции hosts.
		if v, ok := cfg.hostValue(name); ok {
			m := hostAnswer(r, q, v)
			if cfg.Verbose {
				log.Printf("ХОСТ    %-5s %-34s -> %s", dns.TypeToString[q.Qtype], name, v)
			}
			return m
		}

		// 2. IPv6 вырезан: на AAAA отвечаем пустым NOERROR, без записей.
		// Пустой NOERROR (а не NXDOMAIN) — чтобы клиент не решил, что имени нет.
		if !cfg.IPv6 && q.Qtype == dns.TypeAAAA {
			m := new(dns.Msg)
			m.SetReply(r)
			m.RecursionAvailable = true
			if cfg.Verbose {
				log.Printf("БЛОК    AAAA  %-34s -> пустой NOERROR (IPv6 вырезан)", name)
			}
			return m
		}

		// 3. Кэш.
		if cfg.Cache.Enabled && cache != nil {
			if hit := cache.Get(key); hit != nil {
				hit.Id = r.Id
				if cfg.Verbose {
					log.Printf("КЭШ     %-5s %-34s", dns.TypeToString[q.Qtype], name)
				}
				return hit
			}
		}

		// 4. Цепочка: первый сервер, чей ответ не отбракован, и есть ответ.
		chain := cfg.routeFor(name)
		var (
			resp    *dns.Msg
			lastBad *dns.Msg
			trace   []step
		)
		for _, srv := range chain {
			u := ups[srv]
			if u == nil {
				continue
			}
			m, err := u.exchange(r, network)
			if err != nil || m == nil {
				trace = append(trace, step{srv, "err", errText(err)})
				continue
			}
			if why := cfg.rejectReason(m, q.Qtype); why != "" {
				trace = append(trace, step{srv, "bad", why})
				lastBad = m
				continue
			}
			trace = append(trace, step{srv, "ok", ""})
			resp = m
			break
		}

		usedBad := false
		if resp == nil && lastBad != nil {
			// Вся цепочка погадила — отдаём последний ответ как есть,
			// иначе клиент получит SERVFAIL и тоже никуда не пойдёт.
			resp, usedBad = lastBad, true
		}

		if resp == nil {
			m := new(dns.Msg)
			m.SetReply(r)
			m.RecursionAvailable = true
			m.Rcode = dns.RcodeServerFailure
			log.Printf("СБОЙ    %-5s %-34s никто из цепочки не ответил: %s",
				dns.TypeToString[q.Qtype], name, traceString(trace))
			return m
		}

		if !cfg.IPv6 {
			stripIPv6(resp)
		}
		if cfg.Cache.Enabled && cache != nil && !usedBad {
			cache.Put(key, resp)
		}
		resp.Id = r.Id

		if cfg.Verbose || usedBad || len(trace) > 1 {
			ip := answerIP(resp, q.Qtype)
			verdict := "OK"
			switch {
			case usedBad:
				verdict = "ПОГАНЫЙ"
			case len(trace) > 1:
				verdict = "ФОЛБЭК"
			}
			log.Printf("%-8s %-5s %-34s %-18s %s",
				verdict, dns.TypeToString[q.Qtype], name, ip, traceString(trace))
		}
		return resp
	}
}

func errText(err error) string {
	if err == nil {
		return "пустой ответ"
	}
	return err.Error()
}

func traceString(s []step) string {
	if len(s) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(s))
	for _, x := range s {
		switch x.verdict {
		case "ok":
			parts = append(parts, x.server+" OK")
		case "bad":
			parts = append(parts, x.server+"["+x.detail+"]")
		default:
			parts = append(parts, x.server+"(ошибка)")
		}
	}
	return strings.Join(parts, " -> ")
}

func answerIP(m *dns.Msg, qtype uint16) string {
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				return v.A.String()
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				return v.AAAA.String()
			}
		case *dns.CNAME:
			return "CNAME " + v.Target
		}
	}
	if m.Rcode != dns.RcodeSuccess {
		return dns.RcodeToString[m.Rcode]
	}
	return "-"
}

// ---------- отбраковка ----------

// rejectReason возвращает причину, почему ответ считается мусором,
// или "" если ответ годится.
func (c *Config) rejectReason(m *dns.Msg, qtype uint16) string {
	if m == nil {
		return "нет ответа"
	}
	if c.rejectRcodes[m.Rcode] {
		return "rcode " + dns.RcodeToString[m.Rcode]
	}
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if which, ok := inNetworks(v.A, c.rejectNets); ok {
				return "A " + v.A.String() + " из " + which
			}
		case *dns.AAAA:
			if which, ok := inNetworks(v.AAAA, c.rejectNets); ok {
				return "AAAA " + v.AAAA.String() + " из " + which
			}
		}
	}
	if c.Reject.EmptyA && qtype == dns.TypeA && m.Rcode == dns.RcodeSuccess {
		for _, rr := range m.Answer {
			if _, ok := rr.(*dns.A); ok {
				return ""
			}
		}
		return "NOERROR без единой A-записи"
	}
	return ""
}

func inNetworks(ip net.IP, nets []net.IPNet) (string, bool) {
	for _, n := range nets {
		if n.Contains(ip) {
			return n.String(), true
		}
	}
	return "", false
}

// ---------- статические ответы из hosts ----------

func hostAnswer(r *dns.Msg, q dns.Question, value string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = true

	hdr := dns.RR_Header{
		Name:   q.Name,
		Rrtype: q.Qtype,
		Class:  dns.ClassINET,
		Ttl:    300,
	}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(strings.TrimSuffix(part, "."))
		if part == "" {
			continue
		}
		switch strings.ToLower(part) {
		case "nxdomain", "nx":
			m.Rcode = dns.RcodeNameError
			return m
		case "refused":
			m.Rcode = dns.RcodeRefused
			return m
		case "noerror":
			return m
		}
		if ip := net.ParseIP(part); ip != nil {
			if q.Qtype == dns.TypeA {
				if ip4 := ip.To4(); ip4 != nil {
					m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip4})
				}
			} else if q.Qtype == dns.TypeAAAA {
				if ip.To4() == nil {
					m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
				}
			}
			continue
		}
		// остальное считаем CNAME
		if q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			ch := hdr
			ch.Rrtype = dns.TypeCNAME
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: ch, Target: dns.Fqdn(part)})
		}
	}
	return m
}

// ---------- вырезание IPv6 ----------

// dropIPv6Hint убирает параметр ipv6hint из SVCB/HTTPS-записи (RFC 9460, ключ 6).
func dropIPv6Hint(v []dns.SVCBKeyValue) []dns.SVCBKeyValue {
	out := v[:0]
	for _, kv := range v {
		if kv.Key() == dns.SVCB_IPV6HINT {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// stripIPv6 выкидывает AAAA-записи и ipv6hint из всех секций ответа.
func stripIPv6(m *dns.Msg) {
	if m == nil {
		return
	}
	clean := func(rrs []dns.RR) []dns.RR {
		out := rrs[:0]
		for _, rr := range rrs {
			switch v := rr.(type) {
			case *dns.AAAA:
				continue // выкидываем
			case *dns.HTTPS:
				v.Value = dropIPv6Hint(v.Value)
				out = append(out, rr)
			case *dns.SVCB:
				v.Value = dropIPv6Hint(v.Value)
				out = append(out, rr)
			default:
				out = append(out, rr)
			}
		}
		return out
	}
	m.Answer = clean(m.Answer)
	m.Ns = clean(m.Ns)
	m.Extra = clean(m.Extra)
}
