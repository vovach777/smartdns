package main

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// certReloader держит TLS-сертификат в памяти и подхватывает новый файл,
// когда acme.sh его обновит. Иначе после продления сертификата DoT-клиенты
// начнут ругаться на просрочку до перезапуска процесса.
type certReloader struct {
	mu             sync.RWMutex
	cert           *tls.Certificate
	certFile       string
	keyFile        string
	loadedCertName string
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{}
	if err := r.update(certFile, keyFile); err != nil {
		return nil, err
	}
	return r, nil
}

// update перечитывает файлы, если путь изменился.
func (r *certReloader) update(certFile, keyFile string) error {
	if r.certFile == certFile && r.keyFile == keyFile && r.cert != nil {
		return nil
	}
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cert = &c
	r.certFile, r.keyFile = certFile, keyFile
	r.mu.Unlock()
	log.Printf("DoT: сертификат загружен (%s)", certFile)
	return nil
}

// reload принудительно перечитывает файлы (после продления).
func (r *certReloader) reload() error {
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.cert = &c
	r.mu.Unlock()
	return nil
}

// certSelector выбирает сертификат по SNI на одном порту.
//
// Зачем: клиент, которому можно указать только адрес без порта (Трон с
// tls://164.215.97.95), шлёт запрос вообще без SNI — Go не отправляет SNI
// для IP-литерала. Ему нужен сертификат с IP в SAN, а у того, по правилам
// Let's Encrypt, subject пустой. Клиент, который назвал имя, должен получить
// сертификат с CN — иначе клиенты на GnuTLS не завершат рукопожатие вовсе.
// Один порт, два сертификата.
type certSelector struct {
	def   *certReloader
	named map[string]*certReloader
}

func (s *certSelector) get(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if chi != nil && chi.ServerName != "" {
		// SNI регистронезависим (RFC 6066), и некоторые клиенты шлют
		// имя с точкой на конце — приводим к тому же виду, что и ключи.
		if name := sniKey(chi.ServerName); name != "" {
			// IP в SNI — это всё тот же «стучится по адресу», имени он не назвал
			if net.ParseIP(name) == nil {
				if r, ok := s.named[name]; ok {
					return r.get(chi)
				}
			}
		}
	}
	if s.def != nil {
		return s.def.get(chi)
	}
	return nil, errors.New("для этого имени сертификата нет")
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.cert == nil {
		return nil, errors.New("сертификат не загружен")
	}
	return r.cert, nil
}

// sniKey — нормализует имя из SNI для сравнения: нижний регистр, без точки
// на конце. Ключи в named-карте прогоняются через ту же функцию.
func sniKey(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// watch раз в час проверяет, не продлился ли сертификат.
func (r *certReloader) watch() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		if err := r.reload(); err != nil {
			log.Printf("DoT: не смог перечитать сертификат: %v", err)
		}
	}
}
