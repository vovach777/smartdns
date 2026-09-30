//go:build linux

package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

const bindDeviceSupported = true

// bindToDevice возвращает Dialer.Control, прибивающий сокет к интерфейсу:
// пакеты апстрима уходят через него независимо от ip rule. Если интерфейс
// исчезнет, диал валится мгновенно (ENODEV) — цепочка уходит дальше без
// ожидания, это и есть желаемое поведение при аварии туннеля.
func bindToDevice(dev string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)
		})
		if err != nil {
			return err
		}
		if serr != nil {
			return fmt.Errorf("SO_BINDTODEVICE %q: %w", dev, serr)
		}
		return nil
	}
}
