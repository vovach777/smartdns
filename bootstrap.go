package main

import (
	"context"
	"net"
	"strings"
	"time"
)

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
