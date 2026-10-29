package main

// geo_dat.go — чтение баз geosite/geoip в формате v2ray (.dat, protobuf).
//
// Зачем свой декодер: .dat — это protobuf, но схема крошечная и стабильная
// (GeoSiteList/GeoIPList), а тянуть protobuf-рантайм с кодогенерацией в
// резолвер, который держится на стандартной библиотеке, не хочется.
//
// Парсим ОДНИМ проходом и держим в памяти только запрошенные категории:
// geosite.dat — 70 МБ и 1543 категории, из которых в routes упомянуты единицы.
//
// Схема (v2ray/v2fly):
//
//	GeoSiteList { repeated GeoSite entry = 1; }
//	GeoSite     { string country_code = 1; repeated Domain domain = 2; }
//	Domain      { Type type = 1; string value = 2; repeated Attribute attr = 3; }
//	Type        { Plain = 0; Regex = 1; Domain = 2; Full = 3; }
//
//	GeoIPList   { repeated GeoIP entry = 1; }
//	GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool inverse = 3; }
//	CIDR        { bytes ip = 1; uint32 prefix = 2; }

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
)

var errMalformed = errors.New("битый protobuf")

func readVarint(b []byte, i int) (uint64, int, error) {
	var v uint64
	var s uint
	for {
		if i >= len(b) {
			return 0, i, errMalformed
		}
		c := b[i]
		i++
		v |= uint64(c&0x7f) << s
		if c&0x80 == 0 {
			return v, i, nil
		}
		s += 7
		if s > 63 {
			return 0, i, errMalformed
		}
	}
}

// walkFields перебирает поля protobuf-сообщения.
func walkFields(b []byte, fn func(field int, wire int, bytes []byte, u64 uint64) error) error {
	for i := 0; i < len(b); {
		key, ni, err := readVarint(b, i)
		if err != nil {
			return err
		}
		i = ni
		field, wire := int(key>>3), int(key&7)
		switch wire {
		case 0:
			v, ni, err := readVarint(b, i)
			if err != nil {
				return err
			}
			i = ni
			if err := fn(field, wire, nil, v); err != nil {
				return err
			}
		case 1:
			if i+8 > len(b) {
				return errMalformed
			}
			i += 8
		case 2:
			l, ni, err := readVarint(b, i)
			if err != nil {
				return err
			}
			i = ni
			if i+int(l) > len(b) {
				return errMalformed
			}
			if err := fn(field, wire, b[i:i+int(l)], 0); err != nil {
				return err
			}
			i += int(l)
		case 5:
			if i+4 > len(b) {
				return errMalformed
			}
			i += 4
		default:
			return errMalformed
		}
	}
	return nil
}

// extractGeosite проходит geosite.dat и собирает только категории из want
// (имена сравниваются без регистра).
func extractGeosite(data []byte, want map[string]bool) (map[string]*domainSet, error) {
	out := map[string]*domainSet{}
	err := walkFields(data, func(field, wire int, entry []byte, _ uint64) error {
		if field != 1 || wire != 2 {
			return nil
		}
		code := ""
		type dom struct {
			typ   int
			value string
		}
		var doms []dom
		if err := walkFields(entry, func(f2, w2 int, v2 []byte, _ uint64) error {
			switch {
			case f2 == 1 && w2 == 2:
				code = string(v2)
			case f2 == 2 && w2 == 2:
				typ := 0
				val := ""
				if err := walkFields(v2, func(f3, w3 int, v3 []byte, u3 uint64) error {
					if f3 == 1 && w3 == 0 {
						typ = int(u3)
					}
					if f3 == 2 && w3 == 2 {
						val = string(v3)
					}
					return nil
				}); err != nil {
					return err
				}
				doms = append(doms, dom{typ, val})
			}
			return nil
		}); err != nil {
			return err
		}
		key := strings.ToLower(code)
		if !want[key] || len(doms) == 0 {
			return nil
		}
		set := &domainSet{Name: key, Full: map[string]bool{}}
		suf := map[string]struct{}{}
		for _, d := range doms {
			v := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d.value), "."))
			if v == "" {
				continue
			}
			switch d.typ {
			case 2: // Domain: имя и поддомены
				suf[v] = struct{}{}
				set.Entries++
			case 0, 3: // Plain/Full: только точное
				if !set.Full[v] {
					set.Full[v] = true
					set.Entries++
				}
			default: // Regex и прочее не поддержаны
				set.SkippedUnsupported++
			}
		}
		set.suffixes = make([]string, 0, len(suf))
		for s := range suf {
			set.suffixes = append(set.suffixes, s)
		}
		sort.Strings(set.suffixes)
		out[key] = set
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("geosite.dat: %w", err)
	}
	return out, nil
}

// extractGeoip проходит geoip.dat и собирает только нужные страны.
func extractGeoip(data []byte, want map[string]bool) (map[string]*ipSet, error) {
	out := map[string]*ipSet{}
	err := walkFields(data, func(field, wire int, entry []byte, _ uint64) error {
		if field != 1 || wire != 2 {
			return nil
		}
		code := ""
		var ranges []ipRange
		skipped := 0
		if err := walkFields(entry, func(f2, w2 int, v2 []byte, _ uint64) error {
			switch {
			case f2 == 1 && w2 == 2:
				code = string(v2)
			case f2 == 2 && w2 == 2:
				var ipb []byte
				var prefix uint64
				if err := walkFields(v2, func(f3, w3 int, v3 []byte, u3 uint64) error {
					if f3 == 1 && w3 == 2 {
						ipb = v3
					}
					if f3 == 2 && w3 == 0 {
						prefix = u3
					}
					return nil
				}); err != nil {
					return err
				}
				if len(ipb) != 4 {
					skipped++ // IPv6
					return nil
				}
				base := uint32(ipb[0])<<24 | uint32(ipb[1])<<16 | uint32(ipb[2])<<8 | uint32(ipb[3])
				var mask uint32
				if prefix > 0 && prefix <= 32 {
					mask = ^uint32(0) << (32 - prefix)
				}
				ranges = append(ranges, ipRange{lo: base & mask, hi: base | ^mask})
			}
			return nil
		}); err != nil {
			return err
		}
		key := strings.ToLower(code)
		if !want[key] || len(ranges) == 0 {
			return nil
		}
		sort.Slice(ranges, func(a, b int) bool { return ranges[a].lo < ranges[b].lo })
		merged := ranges[:0]
		for _, r := range ranges {
			if len(merged) > 0 && (r.lo <= merged[len(merged)-1].hi || r.lo == merged[len(merged)-1].hi+1) {
				if r.hi > merged[len(merged)-1].hi {
					merged[len(merged)-1].hi = r.hi
				}
				continue
			}
			merged = append(merged, r)
		}
		out[key] = &ipSet{Name: key, Ranges: merged, Entries: len(merged), SkippedV6: skipped}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("geoip.dat: %w", err)
	}
	return out, nil
}

// cidr4 — хелпер на будущее: единичный адрес в диапазон.
func cidr4(ip net.IP) ipRange {
	return ipRange{lo: ip4ToU32(ip), hi: ip4ToU32(ip)}
}
