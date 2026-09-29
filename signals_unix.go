//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

// watchSignals:
//
//	SIGHUP  — перечитать конфиг (кэш при этом сбрасывается)
//	SIGUSR1 — сбросить кэш целиком
//	SIGUSR2 — показать статистику кэша в логе
func watchSignals() {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2,
		syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range ch {
			switch s {
			case syscall.SIGHUP:
				log.Printf("SIGHUP: перечитываю %s", cfgPath)
				reload()
			case syscall.SIGUSR1:
				app.FlushCache()
				log.Printf("SIGUSR1: кэш сброшен")
			case syscall.SIGUSR2:
				size, hits, misses := app.Stats()
				log.Printf("кэш: записей %d, попаданий %d, промахов %d", size, hits, misses)
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("%s: останавливаюсь", s)
				gracefulStop()
				return
			}
		}
	}()
}
