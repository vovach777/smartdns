package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// boot — настройки бутстрапа в том виде, в каком их видят апстримы.
//
// Два способа задать адрес апстрима, который в конфиге написан именем:
//
//	resolver — один резолвер на все имена: спрашиваем его, запоминаем ответ
//	pins     — имя -> IP, прибито гвоздём: ничего не спрашиваем вообще
//
// Они не исключают друг друга: прибитое имя резолвить незачем, остальные
// имена идут к resolver. Нет ни того, ни другого — работает система.
type boot struct {
	resolver string            // IP[:порт]; "" — резолвить системой
	pins     map[string]string // имя (нижний регистр, без точки) -> IP[:порт]
}

// pinFor даёт прибитый адрес имени. "" — привязки нет.
func (b boot) pinFor(host string) string {
	if len(b.pins) == 0 || host == "" {
		return ""
	}
	return b.pins[bootKey(host)]
}

// bootKey приводит имя к виду, в котором оно лежит в pins.
func bootKey(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// pinAddr собирает адрес из привязки: если в ней уже есть порт, он важнее
// порта из адреса апстрима (прибитый IP часто живёт на нестандартном порту).
func pinAddr(pin, defPort string) string {
	if _, p, err := net.SplitHostPort(pin); err == nil && p != "" {
		return pin
	}
	if defPort == "" {
		return pin
	}
	return net.JoinHostPort(pin, defPort)
}

// normalizePin проверяет значение привязки: это должен быть IP или IP:порт.
// Домен тут бессмыслен — он сам потребовал бы резолва, то есть ровно того,
// от чего этот ключ и должен избавить.
func normalizePin(v string) (string, error) {
	v = strings.TrimSpace(v)
	if ip := net.ParseIP(v); ip != nil {
		return ip.String(), nil
	}
	if h, p, err := net.SplitHostPort(v); err == nil && p != "" {
		if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
			return net.JoinHostPort(ip.String(), p), nil
		}
	}
	return "", fmt.Errorf("нужен IP или IP:порт, а не %q", v)
}

// bootstrap — резолвер только для адресов самих апстримов.
//
// Зачем отдельный: когда smartdns сам является системным резолвером
// (клиенты ходят на 127.0.0.1:53), имя в "tls://dns.quad9.net" или
// "https://dns.quad9.net/dns-query" нельзя резолвить через систему —
// это петля: система спросит нас, а мы ещё не знаем, куда идти.
// Бутстрап спрашивает заданный DNS-сервер напрямую, минуя и системный
// резолвер, и нас самих.
//
// Апстримы, заданные IP-литералом ("9.9.9.9", "tls://9.9.9.9"), резолва
// не требуют вовсе — им бутстрап не нужен.
//
// Бутстрап обязан быть IP[:порт]: адрес самого резолвера нельзя
// резолвить, иначе курица с яйцом вернётся.
//
// Go-штука: net.Dialer.Resolver. Если его подменить, все hostname'ы,
// которые dial'ит этот диалер, уйдут в нашу функцию — включая DoH
// (http.Transport) и DoT (miekg c.Dial). Возвращаемый net.Conn —
// это DNS-транспорт: по нему резолвер сам спросит A/AAAA.
func bootstrapResolver(server, device string, timeout time.Duration) *net.Resolver {
	if server == "" {
		return nil // системный резолвер, как раньше
	}
	d := &net.Dialer{Timeout: timeout}
	if device != "" {
		// Резолв идёт тем же интерфейсом, что и сам апстрим: иначе
		// имени, прибитому к туннелю, бутстрап ответит мимо него.
		d.Control = bindToDevice(device)
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// В address резолвер передаёт системный DNS из resolv.conf —
			// игнорируем: ходим только к своему бутстрапу.
			n := "udp"
			if strings.Contains(network, "tcp") {
				n = "tcp"
			}
			return d.DialContext(ctx, n, server)
		},
	}
}
