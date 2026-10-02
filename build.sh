#!/bin/sh
# Сборка бинарников под все платформы одной командой.
#
# CGO выключен: зависимостей от системных библиотек нет, зато бинарник
# получается статическим и одинаково запускается на любом дистрибутиве.
# -trimpath убирает из отладочной информации путь до исходников на машине
# сборки — чтобы в бинарнике не светился чужой домашний каталог.
set -e
cd "$(dirname "$0")"

export CGO_ENABLED=0

GOOS=linux   GOARCH=amd64 go build -trimpath -o smartdns-linux-amd64       .
GOOS=darwin  GOARCH=arm64 go build -trimpath -o smartdns-darwin-arm64      .
GOOS=darwin  GOARCH=amd64 go build -trimpath -o smartdns-darwin-amd64      .
GOOS=windows GOARCH=amd64 go build -trimpath -o smartdns-windows-amd64.exe .
GOOS=windows GOARCH=amd64 go build -trimpath -o smartdns.exe               .

ls -l smartdns-linux-amd64 smartdns-darwin-arm64 smartdns-darwin-amd64 \
      smartdns-windows-amd64.exe smartdns.exe
