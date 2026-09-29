//go:build !windows

package main

import "errors"

// Вне Windows управление службами недоступно — exe просто работает в консоли.
func inService() bool { return false }

func runAsService() error {
	return errors.New("службы Windows доступны только в Windows-сборке")
}

func serviceCommand(cmd string) error {
	return errors.New("управление службой доступно только в Windows-сборке")
}
