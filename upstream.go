package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// upstream — один DNS-сервер из секции servers.
// Поддерживаются:
//   - "1.1.1.1:53" или "1.1.1.1"   — обычный UDP (TCP, если клиент пришёл по TCP)
//   - "tls://9.9.9.9" / "tls://host" — DoT, порт 853 по умолчанию; по IP
//     сертификат проверяется против IP SAN, по имени — против CN
//   - "https://host/dns-query"     — DoH
//
// Апстрим, заданный ИМЕНЕМ, требует резолва — а системным резолвером
// можем быть мы сами. Поэтому имена ходят через bootstrapResolver,
// если в конфиге задан bootstrap; IP-литералы резолва не требуют.
//
// warmPoolSize — сколько прогретых UDP-сокетов держим на один апстрим.
// Сокет «привязан» к постоянному 5-tuple, поэтому через прокси или NAT
// именно он, а не направление, определяет, платим ли мы за установление
// потока. Одного мало: пока он занят запросом, следующий ушёл бы холодным.
const warmPoolSize = 4

type upstream struct {
	name    string
	kind    string // udp | dot | doh
	addr    string // host:port либо URL
	timeout time.Duration

	// dialer — все исходящие соединения апстрима. Control прибивает
	// сокет к интерфейсу, если задан bind_devices (SO_BINDTODEVICE).
	dialer *net.Dialer

	// постоянное DoT-соединение. Заведено отдельно, потому что поднимать
	// TCP+TLS на каждый запрос слишком дорого: через USA-прокси handshake
	// стоит ~600 мс, а сам запрос по уже открытому соединению — ~120 мс.
	mu   sync.Mutex
	conn *dns.Conn

	// пул прогретых UDP-сокетов. nil — работаем как раньше, одноразовыми.
	pool     chan *dns.Conn
	inflight atomic.Int32 // сколько сокетов выдано в работу

	device string // имя интерфейса из bind_devices ("" — не прибит)

	// hc — постоянный HTTP-клиент для DoH. Заведён один на апстрим, чтобы
	// соединение жило между запросами: транспорт с пулом переиспользует
	// уже открытый TCP+TLS, а новый клиент на каждый запрос платил бы
	// полную цену установления потока (на USA-прокси ~600 мс против ~120).
	hc *http.Client

	// host — hostname апстрима, если он задан именем ("" — задан IP).
	// cachedIP — последний резолв host через бутстрап. Диал идёт на
	// cachedIP сразу, без DNS-запроса; warm-тик его освежает. Пустой —
	// падаем обратно на диал по имени (резолв inline через Resolver).
	host     string
	ipMu     sync.RWMutex
	cachedIP string
}

func newUpstream(name, spec string, timeout time.Duration, device, bootstrap string) (*upstream, error) {
	spec = strings.TrimSpace(spec)
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	u := &upstream{name: name, timeout: timeout, dialer: &net.Dialer{Timeout: timeout}}
	if device != "" {
		u.device = device
		u.dialer.Control = bindToDevice(device)
	}
	// Имена в адресах апстримов (tls://host, https://host) резолвим
	// через бутстрап, не через систему: системой можем оказаться мы сами.
	u.dialer.Resolver = bootstrapResolver(bootstrap, device, timeout)
	switch {
	case strings.HasPrefix(spec, "https://"), strings.HasPrefix(spec, "http://"):
		u.kind, u.addr = "doh", spec
		if pu, err := url.Parse(spec); err == nil {
			u.host = hostnameOnly(pu.Hostname())
		}
	case strings.HasPrefix(spec, "tls://"):
		u.kind = "dot"
		u.addr = normalizeAddrPort(strings.TrimSuffix(strings.TrimPrefix(spec, "tls://"), "/"), "853")
	default:
		u.kind, u.addr = "udp", normalizeAddr(spec)
	}
	if u.kind != "doh" {
		h, _, err := net.SplitHostPort(u.addr)
		if err == nil {
			u.host = hostnameOnly(h)
		}
	}
	// Имя + бутстрап — резолвим сразу, чтобы первый диал уже шёл на IP.
	u.refreshHost()
	return u, nil
}

// hostnameOnly возвращает имя, если это НЕ IP-литерал; IP → "".
func hostnameOnly(h string) string {
	if h == "" || net.ParseIP(h) != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// refreshHost переспрашивает у бутстрапа адрес апстрима и обновляет кэш.
// Ошибку глотаем: диал тогда пойдёт по имени через Resolver — тот же
// бутстрап, просто без кэша.
func (u *upstream) refreshHost() {
	if u.host == "" || u.dialer.Resolver == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), u.timeout)
	// ip4: AAAA не спрашиваем — smartdns всё равно вырезает IPv6,
	// второй запрос к бутстрапу каждый тик был бы впустую.
	ips, err := u.dialer.Resolver.LookupIP(ctx, "ip4", u.host)
	cancel()
	if err != nil || len(ips) == 0 {
		log.Printf("бутстрап: %s не резолвится (%v)", u.host, err)
		return
	}
	u.ipMu.Lock()
	u.cachedIP = ips[0].String()
	u.ipMu.Unlock()
}

// ipOf — последний известный IP host ("" — ещё не резолвили).
func (u *upstream) ipOf() string {
	u.ipMu.RLock()
	defer u.ipMu.RUnlock()
	return u.cachedIP
}

// dialAddr — куда реально диалить: cachedIP:port, если host резолвили,
// иначе исходный addr (резолв случится внутри диалера через бутстрап).
func (u *upstream) dialAddr(addr string) string {
	ip := u.ipOf()
	if u.host == "" || ip == "" {
		return addr
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return net.JoinHostPort(ip, port)
}

// normalizeAddrPort добавляет порт по умолчанию, если его не указали.
// Отличается от normalizeAddr тем, что порт зависит от протокола:
// у DoT это 853, а не 53.
func normalizeAddrPort(spec, defPort string) string {
	spec = strings.TrimSpace(spec)
	if _, _, err := net.SplitHostPort(spec); err == nil {
		return spec
	}
	// Голый IPv6 (со скобками или без) — JoinHostPort его не осилит:
	// для "[2606::1111]" он добавит скобки второй раз.
	if strings.HasPrefix(spec, "[") && strings.HasSuffix(spec, "]") {
		return spec + ":" + defPort
	}
	if strings.Count(spec, ":") >= 2 {
		return "[" + spec + "]:" + defPort
	}
	return net.JoinHostPort(spec, defPort)
}

func (u *upstream) String() string {
	var s string
	if u.kind == "doh" {
		s = u.name + " (" + u.addr + ")"
	} else {
		s = u.name + " (" + u.addr + "/" + u.kind + ")"
	}
	if u.device != "" {
		s += " dev " + u.device
	}
	return s
}

func (u *upstream) exchange(m *dns.Msg, network string) (*dns.Msg, error) {
	switch u.kind {
	case "doh":
		return u.doh(m)
	case "dot":
		return u.dot(m)
	}
	return u.plain(m, network)
}

// plain — обычный DNS тем же транспортом, каким пришёл клиент
// (с TCP-клиента стучимся по TCP).
func (u *upstream) plain(m *dns.Msg, network string) (*dns.Msg, error) {
	c := &dns.Client{Net: network, Timeout: u.timeout, Dialer: u.dialer}
	if network != "udp" || u.pool == nil {
		resp, _, err := c.Exchange(m.Copy(), u.dialAddr(u.addr))
		return resp, err
	}

	conn := u.take()
	if conn == nil {
		// пул пуст или занят — не блокируем, работаем одноразовым сокетом
		resp, _, err := c.Exchange(m.Copy(), u.dialAddr(u.addr))
		go u.refill()
		return resp, err
	}
	conn.SetDeadline(time.Now().Add(u.timeout))
	resp, _, err := c.ExchangeWithConn(m.Copy(), conn)
	if err != nil {
		conn.Close()
		go u.refill()
		return nil, err
	}
	u.give(conn)
	return resp, nil
}

// put — положить сокет в пул. Места нет — закрываем: держать пятый
// сокет сверх лимита незачем.
func (u *upstream) put(c *dns.Conn) {
	if c == nil {
		return
	}
	select {
	case u.pool <- c:
	default:
		c.Close()
	}
}

// take — взять сокет из пула. nil, если пул пуст или всё занято: тогда
// запрос обслуживается одноразовым сокетом, медленнее, но без блокировки.
func (u *upstream) take() *dns.Conn {
	select {
	case c := <-u.pool:
		u.inflight.Add(1)
		return c
	default:
		return nil
	}
}

// give — вернуть взятый сокет.
func (u *upstream) give(c *dns.Conn) {
	u.inflight.Add(-1)
	u.put(c)
}

// refill — долить пул после потерянного сокета.
//
// Считаем не только лежащее в канале, но и выданное в работу: иначе в момент,
// когда один сокет занят запросом, мы решим, что пул неполон, заведём новый
// и при возврате занятого выбросим как раз тёплый — а новый останется
// холодным. Проверено на практике: канал полон, give закрывает сокет.
func (u *upstream) refill() {
	if u.pool == nil {
		return
	}
	if len(u.pool)+int(u.inflight.Load()) >= warmPoolSize {
		return
	}
	c, err := u.dialUDP()
	if err != nil {
		return
	}
	u.put(c)
}

func (u *upstream) dialUDP() (*dns.Conn, error) {
	c := &dns.Client{
		Net:     "udp",
		Timeout: u.timeout,
		Dialer:  u.dialer,
	}
	// Dial по udp создаёт присоединённый сокет: локальный порт фиксирован,
	// значит 5-tuple не меняется и поток через прокси не пересоздаётся.
	return c.Dial(u.dialAddr(u.addr))
}

// enablePool заводит пул прогретых сокетов для обычного UDP-апстрима.
func (u *upstream) enablePool() {
	if u.kind == "udp" && u.pool == nil {
		u.pool = make(chan *dns.Conn, warmPoolSize)
	}
}

// ping — один запрос к ЭТОМУ апстриму. Что именно спросить и что сделать
// с ответом, решает tick: обычно это актуализация кэша, а не фиктивное имя.
func (u *upstream) ping(tick func()) {
	if tick == nil {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
		_, _ = u.exchange(m, "udp")
		return
	}
	tick()
}

// keepalive — холостые запросы, по одному на каждый слот пула.
//
// Тонкость именно для UDP: присоединённый сокет сам по себе НИКАКОГО потока
// не создаёт — пакетов с него ещё не уходило. Прогреть «один раз на апстрим»
// значит прогреть один слот из четырёх; остальные три останутся холодными и
// заплатят полную цену установления на первом же настоящем запросе.
//
// Смысл не в ответе, а в том, что по каналу пошёл трафик: пока он идёт,
// прокси и NAT держат поток, и переподнимать его не приходится.
func (u *upstream) keepalive(tick func()) {
	n := 1
	if u.pool != nil {
		n = warmPoolSize
	}
	for i := 0; i < n; i++ {
		u.ping(tick)
	}
}

// warmUp поднимает каналы заранее, чтобы первый же настоящий запрос не
// платил за установление. Для DoT это один холостой обмен (он сам положит
// соединение в u.conn), для UDP — параллельный набор пула и параллельный же
// прогрев каждого слота: последовательно это были бы четыре цены
// установления подряд.
func (u *upstream) warmUp(tick func()) {
	u.refreshHost() // освежить IP до того, как пойдут диалы
	if u.kind != "udp" || u.pool == nil {
		u.keepalive(tick)
		return
	}
	var wg sync.WaitGroup
	for i := 0; i < warmPoolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, err := u.dialUDP(); err == nil {
				u.put(c)
			}
		}()
	}
	wg.Wait()

	var wg2 sync.WaitGroup
	for i := 0; i < warmPoolSize; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			u.ping(tick)
		}()
	}
	wg2.Wait()
}

// warmLoop поддерживает каналы тёплыми: доливает пул и шлёт холостые запросы.
func (u *upstream) warmLoop(interval time.Duration, tick func(), stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		u.refreshHost() // греем и бутстрап: запрос держит путь живым + свежий IP
		if u.kind == "udp" && u.pool != nil {
			for len(u.pool)+int(u.inflight.Load()) < warmPoolSize {
				c, err := u.dialUDP()
				if err != nil {
					break
				}
				u.put(c)
			}
		}
		u.keepalive(tick)
	}
}

// dot — DNS-over-TLS.
//
// Две вещи, которые тут важны.
//
//  1. ServerName задаём явно: без него проверка сертификата упадёт, когда
//     адрес задан IP (а у нас как раз IP-сертификат).
//  2. Соединение переиспользуем. На каждый запрос открывать новое нельзя:
//     если апстрим сидит за прокси с медленным установлением потока
//     (у нас это USA-прокси: ~600 мс на TCP+TLS), то холодный резолв
//     уезжает в секунду. По уже открытому соединению — те же ~120 мс,
//     что и по WARP. Умершее соединение прозрачно переоткрывается.
func (u *upstream) dot(m *dns.Msg) (*dns.Msg, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	host, _, err := net.SplitHostPort(u.addr)
	if err != nil {
		host = u.addr
	}
	c := &dns.Client{
		Net:       "tcp-tls",
		Timeout:   u.timeout,
		TLSConfig: &tls.Config{ServerName: host},
		Dialer:    u.dialer,
	}

	if u.conn != nil {
		u.conn.SetDeadline(time.Now().Add(u.timeout))
		if resp, _, err := c.ExchangeWithConn(m.Copy(), u.conn); err == nil {
			return resp, nil
		}
		u.conn.Close()
		u.conn = nil
	}

	conn, err := c.Dial(u.dialAddr(u.addr))
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(u.timeout))
	resp, _, err := c.ExchangeWithConn(m.Copy(), conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	u.conn = conn
	return resp, nil
}

// httpClient — постоянный клиент для DoH, один на апстрим.
//
// Клиент, а не только транспорт: переиспользование соединения держится
// на пуле внутри Transport, поэтому создавать его на каждый запрос —
// значит каждый раз платить за TCP+TLS и терять смысл HTTP/2.
func (u *upstream) httpClient() *http.Client {
	if u.hc != nil {
		return u.hc
	}
	u.hc = &http.Client{
		Timeout: u.timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Диалим cachedIP вместо hostname: сертификат при этом
				// всё равно проверяется по имени из URL (ServerName),
				// а DNS-запрос на каждый новый коннект не нужен.
				// IP подставляется на каждом диал, а не один раз при
				// создании клиента — так смена адреса апстрима
				// подхватывается без пересоздания клиента.
				if host, port, err := net.SplitHostPort(addr); err == nil && u.host != "" && strings.EqualFold(host, u.host) {
					if ip := u.ipOf(); ip != "" {
						addr = net.JoinHostPort(ip, port)
					}
				}
				return u.dialer.DialContext(ctx, network, addr)
			},
			// Прогретые соединения держат канал открытым: через прокси
			// установление потока дороже самого запроса.
			MaxIdleConns:        8,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: u.timeout,
			ForceAttemptHTTP2:   true,
		},
	}
	return u.hc
}

func (u *upstream) doh(m *dns.Msg) (*dns.Msg, error) {
	packed, err := m.Copy().Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", u.addr, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	out.Id = m.Id
	return out, nil
}
