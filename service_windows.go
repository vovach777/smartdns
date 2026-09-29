//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcName    = "smartdns"
	svcDisplay = "SmartDNS — локальный форвардер с отбраковкой мусора"
)

// inService сообщает, что процесс запущен диспетчером служб, а не из консоли.
func inService() bool {
	v, err := svc.IsWindowsService()
	return err == nil && v
}

type svcHandler struct{ stop chan struct{} }

func (h *svcHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}
	go func() {
		if err := run(h.stop); err != nil {
			log.Printf("сервер остановлен: %v", err)
		}
	}()
	changes <- svc.Status{State: svc.Running, Accepts: accepts}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			close(h.stop)
			time.Sleep(500 * time.Millisecond)
			return false, 0
		}
	}
	return false, 0
}

func runAsService() error {
	// Лог по умолчанию подставляется в load(): рядом с exe, так как в службе
	// консоли нет и рабочий каталог — System32.
	return svc.Run(svcName, &svcHandler{stop: make(chan struct{})})
}

func serviceCommand(cmd string) error {
	switch strings.ToLower(cmd) {
	case "install":
		return installService()
	case "remove", "uninstall":
		return removeService()
	case "start":
		return withService(func(s *mgr.Service) error { return s.Start() })
	case "stop":
		return withService(func(s *mgr.Service) error { _, err := s.Control(svc.Stop); return err })
	default:
		return fmt.Errorf("неизвестная команда %q — нужно install | remove | start | stop", cmd)
	}
}

func withService(do func(*mgr.Service) error) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("служба %s не найдена: %w", svcName, err)
	}
	defer s.Close()
	return do(s)
}

func installService() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)

	// Копируем текущие аргументы, выкидывая сам "-service install".
	var args []string
	a := os.Args[1:]
	for i := 0; i < len(a); i++ {
		if a[i] == "-service" || a[i] == "--service" {
			i++
			continue
		}
		args = append(args, a[i])
	}

	// Служба стартует с рабочим каталогом System32, поэтому путь к конфигу
	// нужен абсолютный: относительный она просто не найдёт.
	if !hasFlag(args, "-config") {
		args = append(args, "-config", filepath.Join(dir, "smartdns.yaml"))
	}

	cmd := `"` + exe + `"`
	for _, v := range args {
		cmd += " " + quote(v)
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return fmt.Errorf("служба %s уже установлена — сначала: smartdns -service remove", svcName)
	}

	s, err := m.CreateService(svcName, exe, mgr.Config{
		ServiceType:    windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:      windows.SERVICE_AUTO_START,
		ErrorControl:   windows.SERVICE_ERROR_NORMAL,
		DisplayName:    svcDisplay,
		BinaryPathName: cmd,
	})
	if err != nil {
		return err
	}
	defer s.Close()
	fmt.Printf("служба %s установлена (автозапуск)\n  %s\n", svcName, cmd)
	fmt.Println("запуск: smartdns -service start")
	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("служба %s не найдена: %w", svcName, err)
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop) // если запущена — глушим, ошибку игнорируем
	time.Sleep(700 * time.Millisecond)
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Printf("служба %s удалена\n", svcName)
	return nil
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || a == "-"+name {
			return true
		}
	}
	return false
}

func quote(s string) string {
	if strings.ContainsAny(s, " \t\"") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
