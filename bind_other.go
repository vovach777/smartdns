//go:build !linux

package main

import "syscall"

const bindDeviceSupported = false

// До сюда не доходим: bind_devices отбраковывается при валидации конфига.
func bindToDevice(dev string) func(network, address string, c syscall.RawConn) error {
	return nil
}
