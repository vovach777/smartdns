package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// upstream — один DNS-сервер из секции servers.
// Поддерживаются:
//   - "1.1.1.1:53" или "1.1.1.1"  — обычный UDP (TCP, если клиент пришёл по TCP)
//   - "tls://1.1.1.1"             — DoT, порт 853 по умолчанию
//   - "https://host/dns-query"     — DoH
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

	// постоянное DoT-соединение. Заведено отдельно, потому что поднимать
	// TCP+TLS на каждый запрос слишком дорого: через USA-прокси handshake
	// стоит ~600 мс, а сам запрос по уже открытому соединению — ~120 мс.
	mu   sync.Mutex
	conn *dns.Conn

	// пул прогретых UDP-сокетов. nil — работаем как раньше, одноразовыми.
	pool     chan *dns.Conn
	inflight atomic.Int32 // сколько сокетов выдано в работу
}

func newUpstream(name, spec string, timeout time.Duration) (*upstream, error) {
	spec = strings.TrimSpace(spec)
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	switch {
	case strings.HasPrefix(spec, "https://"), strings.HasPrefix(spec, "http://"):
		return &upstream{name: name, kind: "doh", addr: spec, timeout: timeout}, nil
	case strings.HasPrefix(spec, "tls://"):
		hostport := strings.TrimSuffix(strings.TrimPrefix(spec, "tls://"), "/")
		return &upstream{name: name, kind: "dot", addr: normalizeAddrPort(hostport, "853"), timeout: timeout}, nil
	default:
		return &upstream{name: name, kind: "udp", addr: normalizeAddr(spec), timeout: timeout}, nil
	}
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
	if u.kind == "doh" {
		return u.name + " (" + u.addr + ")"
	}
	return u.name + " (" + u.addr + "/" + u.kind + ")"
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
	c := &dns.Client{Net: network, Timeout: u.timeout}
	if network != "udp" || u.pool == nil {
		resp, _, err := c.Exchange(m.Copy(), u.addr)
		return resp, err
	}

	conn := u.take()
	if conn == nil {
		// пул пуст или занят — не блокируем, работаем одноразовым сокетом
		resp, _, err := c.Exchange(m.Copy(), u.addr)
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
		Dialer:  &net.Dialer{Timeout: u.timeout},
	}
	// Dial по udp создаёт присоединённый сокет: локальный порт фиксирован,
	// значит 5-tuple не меняется и поток через прокси не пересоздаётся.
	return c.Dial(u.addr)
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
	}

	if u.conn != nil {
		u.conn.SetDeadline(time.Now().Add(u.timeout))
		if resp, _, err := c.ExchangeWithConn(m.Copy(), u.conn); err == nil {
			return resp, nil
		}
		u.conn.Close()
		u.conn = nil
	}

	conn, err := c.Dial(u.addr)
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
	client := &http.Client{Timeout: u.timeout}
	resp, err := client.Do(req)
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
