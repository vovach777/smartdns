//go:build windows

package main

// В Windows сигналов нет: перезагрузку делает диспетчер служб
// (остановка + запуск). Оставляем заглушку, чтобы main был одинаковым.
func watchSignals() {}
