package main

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheEntry struct {
	msg *dns.Msg
	// ttls — исходные TTL в порядке обхода Answer/Ns/Extra (OPT пропущен).
	// Нужны, чтобы на отдаче уменьшить TTL на время хранения: копию ответа
	// мы мутируем, а оригиналы должны остаться неизменными.
	ttls     []uint32
	stored   time.Time
	expiry   time.Time
	lastSeen time.Time
}

// foreachTTL обходит все записи ответа, у которых TTL что-то значит.
//
// OPT (EDNS0) пропускается: это псевдо-запись, её поле TTL — на самом деле
// расширенный RCODE, версия и флаги, и почти всегда равно 0. Учитывать его
// нельзя, иначе минимальный TTL любого ответа станет нулевым.
func foreachTTL(m *dns.Msg, fn func(h *dns.RR_Header)) {
	for _, sect := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sect {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			fn(h)
		}
	}
}

// Cache — кэш DNS-ответов в памяти.
//
// Когда запись выбрасывается:
//   - истёк TTL (минимальный среди записей ответа, в пределах [min_ttl, max_ttl]);
//   - ответ пришёл с TTL=0 — он вообще не кэшируется;
//   - вытеснение при переполнении (сначала просроченные, потом самые давние);
//   - явный сброс: сигнал SIGUSR1 или перезагрузка конфига по SIGHUP;
//   - остановка процесса — кэш в памяти, на диск не пишется.
//
// Мусорные ответы (отбракованные) в кэш не попадают.
type Cache struct {
	mu                     sync.Mutex
	m                      map[string]*cacheEntry
	limit                  int
	minTTL, maxTTL, negTTL int

	hits, misses, evictions int
}

func NewCache(c CacheConfig) *Cache {
	return &Cache{m: map[string]*cacheEntry{}, limit: c.MaxEntries, minTTL: c.MinTTL, maxTTL: c.MaxTTL, negTTL: c.NegativeTTL}
}

func (c *Cache) Get(key string) *dns.Msg {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		c.misses++
		return nil
	}
	if time.Now().After(e.expiry) {
		delete(c.m, key)
		c.misses++
		return nil
	}
	e.lastSeen = time.Now()
	c.hits++
	return c.aged(e)
}

// aged отдаёт копию ответа с TTL, уменьшенным на время хранения.
// Без этого клиент получит «свежий» TTL 300 от записи, которой осталось жить
// 5 секунд, и будет считать ответ валидным дольше, чем он есть на самом деле.
func (c *Cache) aged(e *cacheEntry) *dns.Msg {
	out := e.msg.Copy()
	elapsed := uint32(time.Since(e.stored).Seconds())
	if elapsed == 0 {
		return out
	}
	i := 0
	foreachTTL(out, func(h *dns.RR_Header) {
		if i >= len(e.ttls) {
			return
		}
		if orig := e.ttls[i]; orig > elapsed {
			h.Ttl = orig - elapsed
		} else {
			h.Ttl = 0
		}
		i++
	})
	return out
}

func (c *Cache) Put(key string, m *dns.Msg) {
	if m == nil {
		return
	}
	ttl := c.effectiveTTL(m)
	if ttl <= 0 {
		return // TTL=0 — «не кэшировать»
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	stored := c.clamped(m)
	ttls := make([]uint32, 0, 8)
	foreachTTL(stored, func(h *dns.RR_Header) { ttls = append(ttls, h.Ttl) })
	now := time.Now()
	c.m[key] = &cacheEntry{
		msg:      stored,
		ttls:     ttls,
		stored:   now,
		expiry:   now.Add(time.Duration(ttl) * time.Second),
		lastSeen: now,
	}
	if len(c.m) > c.limit {
		c.evictLocked()
	}
}

// Refresh — перезаписать существующую запись новым ответом, сохранив
// lastSeen. Отличается от Put ровно этим: актуализация не должна сама себя
// поддерживать.
//
// Если бы prefetch обновлял lastSeen, запись, которой перестали пользоваться,
// считалась бы «живой» до бесконечности и продолжала бы тянуть трафик через
// канал — ровно то, чего мы хотели избежать. Пусть отпускает её через
// activeWindow после последнего настоящего обращения клиента.
func (c *Cache) Refresh(key string, m *dns.Msg) {
	if m == nil {
		return
	}
	ttl := c.effectiveTTL(m)
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	stored := c.clamped(m)
	ttls := make([]uint32, 0, 8)
	foreachTTL(stored, func(h *dns.RR_Header) { ttls = append(ttls, h.Ttl) })
	now := time.Now()
	last := now
	if e, ok := c.m[key]; ok {
		last = e.lastSeen
	}
	c.m[key] = &cacheEntry{
		msg:      stored,
		ttls:     ttls,
		stored:   now,
		expiry:   now.Add(time.Duration(ttl) * time.Second),
		lastSeen: last,
	}
	if len(c.m) > c.limit {
		c.evictLocked()
	}
}

// clamped — копия ответа, в которой TTL каждой записи зажат в [min_ttl,
// max_ttl]. Кэш хранит именно её: иначе ответ клиенту обещает больше, чем
// запись реально проживёт в кэше.
//
// Пример с прода: max_ttl 20, апстрим отдал netflix.com с TTL 45. Без зажима
// клиент видел «41» и считал ответ валидным ещё 41 с, хотя мы его выбросили
// через 20. С зажимом — честные 20, и ровно столько запись и живёт.
//
// Нулевые TTL не трогаем: 0 означает «не кэшировать» и поднимать его до
// min_ttl значит врать ещё сильнее.
func (c *Cache) clamped(m *dns.Msg) *dns.Msg {
	out := m.Copy()
	foreachTTL(out, func(h *dns.RR_Header) {
		if h.Ttl == 0 {
			return
		}
		if t := int(h.Ttl); t < c.minTTL {
			h.Ttl = uint32(c.minTTL)
		} else if t > c.maxTTL && c.maxTTL > 0 {
			h.Ttl = uint32(c.maxTTL)
		}
	})
	return out
}

// effectiveTTL: минимальный TTL среди записей ответа; для пустых/негативных
// ответов — negative_ttl. Результат зажимается в [min_ttl, max_ttl].
func (c *Cache) effectiveTTL(m *dns.Msg) int {
	min := 0
	count := 0
	foreachTTL(m, func(h *dns.RR_Header) {
		if t := int(h.Ttl); count == 0 || t < min {
			min = t
		}
		count++
	})
	if count == 0 {
		min = c.negTTL // NXDOMAIN или пустой ответ
	}
	if min == 0 {
		return 0
	}
	if min < c.minTTL {
		min = c.minTTL
	}
	if min > c.maxTTL {
		min = c.maxTTL
	}
	return min
}

func (c *Cache) evictLocked() {
	now := time.Now()
	for k, e := range c.m {
		if now.After(e.expiry) {
			delete(c.m, k)
			c.evictions++
		}
	}
	if len(c.m) <= c.limit {
		return
	}
	// добираем по давности обращения
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(c.m))
	for k, e := range c.m {
		all = append(all, kv{k, e.lastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	over := len(c.m) - c.limit
	for i := 0; i < over && i < len(all); i++ {
		delete(c.m, all[i].k)
		c.evictions++
	}
}

// Expiring — ключи записей, которые истекут в ближайшие within и которыми
// ещё пользуются (lastSeen свежее activeWithin). Первыми идут те, кому жить
// осталось меньше всего.
//
// Зачем: чтобы прогрев канала не тратился на фиктивное имя, а переспрашивал
// то, что вот-вот протухнет и что клиенты реально запрашивают.
func (c *Cache) Expiring(within, activeWithin time.Duration, limit int) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	deadline := now.Add(within)

	type kv struct {
		k   string
		exp time.Time
	}
	out := make([]kv, 0, 16)
	for k, e := range c.m {
		if now.After(e.expiry) || e.expiry.After(deadline) {
			continue
		}
		if activeWithin > 0 && now.Sub(e.lastSeen) > activeWithin {
			continue // записью давно не пользовались — нечего и обновлять
		}
		out = append(out, kv{k, e.expiry})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].exp.Before(out[j].exp) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	keys := make([]string, 0, len(out))
	for _, x := range out {
		keys = append(keys, x.k)
	}
	return keys
}

// SplitKey разбирает ключ кэша обратно на имя и тип записи.
func SplitKey(key string) (string, uint16, bool) {
	i := strings.LastIndex(key, "|")
	if i <= 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(key[i+1:])
	if err != nil {
		return "", 0, false
	}
	return key[:i], uint16(n), true
}

// CacheKey — имя и тип в один ключ.
func CacheKey(name string, qtype uint16) string {
	return name + "|" + strconv.Itoa(int(qtype))
}

// Purge выбрасывает только просроченные.
func (c *Cache) Purge() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	n := 0
	for k, e := range c.m {
		if now.After(e.expiry) {
			delete(c.m, k)
			n++
		}
	}
	return n
}

// Flush выбрасывает всё.
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = map[string]*cacheEntry{}
}

func (c *Cache) Stats() (size, hits, misses int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m), c.hits, c.misses
}
