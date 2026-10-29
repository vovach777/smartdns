package main

// geoip.go — наборы адресов (CIDR) и фильтр ОТВЕТА по ним.
//
// Зачем именно фильтр ответа, а не маршрут: маршрут выбирается по имени ДО
// запроса, а адрес появляется только ПОСЛЕ ответа. Если бы решение по адресу
// меняло цепочку, пришлось бы резолвить заново — это цикл и повторные запросы.
// Поэтому здесь фильтр чистый: он смотрит на готовый ответ и может только
// переписать его (nxdomain / refused / пустой noerror). Отфильтрованный ответ
// кладётся в кэш как есть, повторной фильтрации и повторного запроса нет.
//
// Набор — текстовый файл, по строке на префикс:
//
//	1.0.1.0/24
//	203.0.113.7            # одиночный адрес тоже можно
//	# комментарий
//
// IPv6 в наборах пока не поддерживается: такие строки пропускаются и
// считаются отдельно (видно в -check), но не ломают загрузку.

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type ipRange struct{ lo, hi uint32 }

// ipSet — отсортированные и слитые диапазоны IPv4.
type ipSet struct {
	Name      string
	Source    string
	Ranges    []ipRange
	Entries   int
	SkippedV6 int
}

// match — есть ли адрес в наборе. Только IPv4.
func (s *ipSet) match(ip net.IP) bool {
	if s == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	x := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	i := sort.Search(len(s.Ranges), func(i int) bool { return s.Ranges[i].lo > x })
	if i == 0 {
		return false
	}
	r := s.Ranges[i-1]
	return x >= r.lo && x <= r.hi
}

func ip4ToU32(ip net.IP) uint32 {
	v4 := ip.To4()
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

// parseIPSet читает текстовый список CIDR/адресов.
func parseIPSet(path string) (*ipSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: %s: %w", path, err)
	}
	set := &ipSet{Source: path}
	for i, line := range strings.Split(string(data), "\n") {
		if h := strings.IndexByte(line, '#'); h >= 0 {
			line = line[:h]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ip := net.ParseIP(line)
		var lo, hi uint32
		switch {
		case ip != nil && ip.To4() != nil:
			lo, hi = ip4ToU32(ip), ip4ToU32(ip)
		case strings.Contains(line, "/"):
			_, n, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: не CIDR: %q", path, i+1, line)
			}
			if n.IP.To4() == nil {
				set.SkippedV6++
				continue
			}
			base := ip4ToU32(n.IP)
			ones, _ := n.Mask.Size()
			hi = base | (^uint32(0) >> uint(ones))
			lo = base & ^(^uint32(0) >> uint(ones))
		case ip != nil:
			set.SkippedV6++ // IPv6-литерал
			continue
		default:
			return nil, fmt.Errorf("%s:%d: не адрес и не CIDR: %q", path, i+1, line)
		}
		set.Ranges = append(set.Ranges, ipRange{lo, hi})
		set.Entries++
	}
	// сортировка и слияние: пересекающиеся и смежные диапазоны — один
	sort.Slice(set.Ranges, func(a, b int) bool { return set.Ranges[a].lo < set.Ranges[b].lo })
	merged := set.Ranges[:0]
	for _, r := range set.Ranges {
		if len(merged) > 0 && (r.lo <= merged[len(merged)-1].hi || r.lo == merged[len(merged)-1].hi+1) {
			if r.hi > merged[len(merged)-1].hi {
				merged[len(merged)-1].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	set.Ranges = merged
	return set, nil
}

// loadGeoip читает каталог geoip_dir: по файлу <name>.txt на набор.
func (c *Config) loadGeoip() error {
	c.geoip = map[string]*ipSet{}
	if strings.TrimSpace(c.GeoipDir) == "" {
		return nil
	}
	ents, err := os.ReadDir(c.GeoipDir)
	if err != nil {
		return fmt.Errorf("geoip_dir %s: %w", c.GeoipDir, err)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, fn := range names {
		set, err := parseIPSet(filepath.Join(c.GeoipDir, fn))
		if err != nil {
			return err
		}
		set.Name = strings.TrimSuffix(fn, ".txt")
		c.geoip[set.Name] = set
	}
	return nil
}

// applyAnswerGeoip переписывает готовый ответ, если его адрес попал в набор.
// Никаких запросов не делает — по построению не может зациклиться.
func (c *Config) applyAnswerGeoip(m *dns.Msg) bool {
	if m == nil || len(c.AnswerGeoip) == 0 || len(c.geoip) == 0 {
		return false
	}
	var addrs []net.IP
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			addrs = append(addrs, a.A)
		}
	}
	for _, rule := range c.AnswerGeoip {
		set := c.getGeoip(strings.ToLower(strings.TrimSpace(rule.Set)))
		if set == nil {
			continue
		}
		hit := false
		for _, a := range addrs {
			if set.match(a) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(rule.Action)) {
		case "nxdomain":
			m.Answer = nil
			m.Rcode = 3 // NXDOMAIN
		case "refused":
			m.Answer = nil
			m.Rcode = 5 // REFUSED
		case "noerror", "":
			m.Answer = nil
			m.Rcode = dns.RcodeSuccess
		default:
			m.Answer = nil
			m.Rcode = dns.RcodeRefused
		}
		return true
	}
	return false
}

// geoipFilesSignature / watchGeoip — обновление наборов без рестарта.
func geoipFilesSignature(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "err"
	}
	var b strings.Builder
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			fmt.Fprintf(&b, "%s:err;", e.Name())
			continue
		}
		fmt.Fprintf(&b, "%s:%d:%d;", e.Name(), fi.ModTime().UnixNano(), fi.Size())
	}
	return b.String()
}

func watchGeoip(dirGetter func() string) {
	const every = 5 * time.Second
	t := time.NewTicker(every)
	defer t.Stop()
	last := geoipFilesSignature(dirGetter())
	for {
		select {
		case <-t.C:
			dir := dirGetter()
			got := geoipFilesSignature(dir)
			if got == "" || got == "err" || got == last {
				continue
			}
			log.Printf("geoip: наборы изменились — перечитываю конфиг")
			if err := reload(); err != nil {
				log.Printf("geoip: перечитывание не удалось: %v", err)
				last = got
				continue
			}
			last = geoipFilesSignature(dirGetter())
		case <-stopPurge:
			return
		}
	}
}

// geoipNames — имена наборов по алфавиту.
func geoipNames(m map[string]*ipSet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
