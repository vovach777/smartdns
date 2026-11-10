package main

// catch.go — правила отлова по адресу в ГОТОВОМ ответе.
//
// Зачем отдельная сущность, а не routes: routes выбираются по имени ДО
// запроса, а адрес появляется только ПОСЛЕ ответа. Catch — это второй
// проход: получили ответ, посмотрели на конечные A/AAAA, и если адрес
// попал под правило — переспросили другой цепочкой.
//
// Правило срабатывает не больше одного раза на запрос (общий набор used
// в exchangeChain), поэтому зациклиться нельзя: каждое звено выгорает
// ровно один раз, и цепочка правил конечна.
//
// Приоритет: catch проверяется РАНЬШЕ reject. Правило знает, чем именно
// плох адрес и куда за ним идти; reject — общая страховка для всего
// остального. Если переспрос не помог, поведение откатывается к обычному,
// как будто правила не было.
//
// Матч по адресу, а не по имени, поэтому CNAME-цепочка не мешает: в
// ответе уже лежат конечные A/AAAA, и смотрим ровно на них.

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// CatchRule — «если в ответе есть такой адрес — переспросить этой цепочкой».
// Match и Set складываются по ИЛИ: можно перечислить и конкретные адреса,
// и целый набор из geoip. Match понимает IP и CIDR, включая IPv6; Set —
// только IPv4 (наборы geoip хранят 32-битные диапазоны).
type CatchRule struct {
	Name  string   `yaml:"name"`
	Match []string `yaml:"match"`
	Set   string   `yaml:"set"`
	Chain []string `yaml:"chain"`

	nets []net.IPNet
}

// what — человекочитаемый матч для -check и логов.
func (r *CatchRule) what() string {
	parts := make([]string, 0, len(r.Match)+1)
	for _, s := range r.Match {
		if s = strings.TrimSpace(s); s != "" {
			parts = append(parts, s)
		}
	}
	if s := strings.TrimSpace(r.Set); s != "" {
		parts = append(parts, "geoip:"+s)
	}
	return strings.Join(parts, ", ")
}

// prepareCatches разбирает адреса один раз, на загрузке. Имя по умолчанию
// не пустое: по нему ищут в логе, и «catch#2» лучше, чем ничего.
func (c *Config) prepareCatches() error {
	for i := range c.Catches {
		r := &c.Catches[i]
		if strings.TrimSpace(r.Name) == "" {
			r.Name = fmt.Sprintf("catch#%d", i+1)
		}
		r.nets = r.nets[:0]
		for _, s := range r.Match {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if ip := net.ParseIP(s); ip != nil {
				bits := 128
				if v4 := ip.To4(); v4 != nil {
					ip, bits = v4, 32
				}
				r.nets = append(r.nets, net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
				continue
			}
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return fmt.Errorf("catches: %s: %q — не адрес и не CIDR", r.Name, s)
			}
			r.nets = append(r.nets, *n)
		}
	}
	return nil
}

// validateCatches проверяет правила после того, как известны имена серверов.
func (c *Config) validateCatches(known map[string]bool, names []string) error {
	seen := map[string]bool{}
	for i := range c.Catches {
		r := &c.Catches[i]
		if len(r.nets) == 0 && strings.TrimSpace(r.Set) == "" {
			return fmt.Errorf("catches: %s: нужен match или set — иначе правило ничего не ловит", r.Name)
		}
		if len(r.Chain) == 0 {
			return fmt.Errorf("catches: %s: пустой chain", r.Name)
		}
		for _, s := range r.Chain {
			if !known[s] {
				return fmt.Errorf("catches: %s: в chain неизвестный сервер %q; известные: %v", r.Name, s, names)
			}
		}
		if seen[r.Name] {
			return fmt.Errorf("catches: имя %q повторяется — по нему ищут в логе", r.Name)
		}
		seen[r.Name] = true
	}
	return nil
}

// catchMatch ищет первое неприменённое правило, чей адрес есть в ответе.
// Смотрит только конечные A/AAAA — CNAME разворачивается сам собой.
func (c *Config) catchMatch(m *dns.Msg, used map[string]bool) (*CatchRule, net.IP) {
	if m == nil || len(c.Catches) == 0 {
		return nil, nil
	}
	for i := range c.Catches {
		r := &c.Catches[i]
		if used != nil && used[r.Name] {
			continue
		}
		for _, rr := range m.Answer {
			var ip net.IP
			switch v := rr.(type) {
			case *dns.A:
				ip = v.A
			case *dns.AAAA:
				ip = v.AAAA
			default:
				continue
			}
			if c.catchHit(r, ip) {
				return r, ip
			}
		}
	}
	return nil, nil
}

// catchHit — попал ли адрес под правило: либо в перечисленные сети, либо
// в набор geoip. Наборы сейчас IPv4-only, поэтому IPv6 мимо них — это
// осознанно, а не молчаливая ошибка: для IPv6 есть match.
func (c *Config) catchHit(r *CatchRule, ip net.IP) bool {
	for i := range r.nets {
		if r.nets[i].Contains(ip) {
			return true
		}
	}
	if name := strings.TrimSpace(r.Set); name != "" {
		if set := c.geoipSetRef(name); set != nil && set.match(ip) {
			return true
		}
	}
	return false
}
