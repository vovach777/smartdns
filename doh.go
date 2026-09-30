// doh.go — слушатель DNS-over-HTTPS (RFC 8484).
//
// Зачем: через прокси Cloudflare (оранжевое облако) проходит только
// HTTP(S) — обычный UDP/53 и DoT/853 до origin не доходят. DoH живёт
// внутри обычного HTTPS-запроса, поэтому это единственный способ
// дать клиенту ссылку вида https://us.vovach777.win/dns-query,
// которая через облако попадёт в наш умный резолвер.
//
// Обработчик один: /dns-query (POST с телом wire-format или GET
// ?dns=<base64url>). Сам запрос дальше идёт в тот же resolveQuery,
// что обслуживает UDP/TCP-слушателей — вся гео-логика, отбраковка
// и фолбэк по цепочке общие.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

const dohPath = "/dns-query"

// serveDoH поднимает HTTPS-сервер на addr. Сертификат приходит в tc
// (GetCertificate умеет подхватывать продлённые файлы сам).
// ServeTLS сам включает HTTP/2 — h2 по RFC 8484 обязателен, и ряд
// клиентов (Firefox, Android DoH) без него не работает.
func (a *App) serveDoH(addr string, tc *tls.Config, stop <-chan struct{}) {
	mux := http.NewServeMux()
	mux.HandleFunc(dohPath, a.dohQuery)
	// всё, что не /dns-query, — 404: этот порт для DNS, а не для сайта
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := &http.Server{
		Addr:            addr,
		Handler:         mux,
		TLSConfig:       tc,
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    15 * time.Second,
		IdleTimeout:     60 * time.Second,
		MaxHeaderBytes:  8192,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("DoH %s: %v", addr, err)
		return
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ServeTLS(ln, "", "") }()

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Printf("прослушивание DoH %s: %v", addr, err)
		}
	case <-stop:
		srv.Shutdown(context.Background())
	}
	ln.Close()
}

// dohQuery принимает запрос, прогоняет через resolveQuery и отдаёт
// wire-format ответ. К апстримам при этом ходим по TCP: ответ может
// быть крупнее UDP-фрейма, и резать его флагом TC незачем.
func (a *App) dohQuery(w http.ResponseWriter, r *http.Request) {
	var wire []byte
	var err error

	switch r.Method {
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "" && ct != "application/dns-message" {
			http.Error(w, "Content-Type должен быть application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		wire, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 65535))
	case http.MethodGet:
		s := r.URL.Query().Get("dns")
		if s == "" {
			http.Error(w, "нет параметра dns", http.StatusBadRequest)
			return
		}
		wire, err = base64.RawURLEncoding.DecodeString(s)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err != nil || len(wire) == 0 {
		http.Error(w, "битый DNS-пейлоад", http.StatusBadRequest)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		http.Error(w, "не DNS-сообщение", http.StatusBadRequest)
		return
	}
	// DoH запрещает клиенту задавать свой ID — по RFC отвечаем с ID=0
	req.Id = 0

	resp := a.resolveQuery(req, "tcp")
	if resp == nil {
		http.Error(w, "не DNS-запрос", http.StatusBadRequest)
		return
	}
	resp.Id = 0

	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "не удалось упаковать ответ", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	w.Write(packed)
}
