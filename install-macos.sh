#!/bin/bash
# Установка smartdns на macOS как демона launchd (порт 53, автозапуск).
#
#   sudo ./install-macos.sh            установить
#   sudo ./install-macos.sh --set-dns  установить и прописать 127.0.0.1 в DNS системы
#   sudo ./install-macos.sh --remove   удалить
#
# Что делает:
#   /usr/local/bin/smartdns              бинарник под вашу архитектуру
#   /usr/local/etc/smartdns.yaml         конфиг (существующий не трогает)
#   /Library/LaunchDaemons/com.smartdns.plist
set -e

PREFIX=/usr/local
BIN=$PREFIX/bin/smartdns
CONF=$PREFIX/etc/smartdns.yaml
PLIST=/Library/LaunchDaemons/com.smartdns.plist
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" != "0" ]; then
    echo "нужен sudo:  sudo ./install-macos.sh"
    exit 1
fi

remove() {
    launchctl unload -w "$PLIST" 2>/dev/null || true
    rm -f "$PLIST" "$BIN"
    echo "удалено. Конфиг оставлен: $CONF"
    exit 0
}
[ "$1" = "--remove" ] && remove

case "$(uname -m)" in
    arm64) SRC="$HERE/smartdns-darwin-arm64" ;;
    x86_64) SRC="$HERE/smartdns-darwin-amd64" ;;
    *) echo "не знаю такую архитектуру: $(uname -m)"; exit 1 ;;
esac

[ -f "$SRC" ] || { echo "нет файла $SRC"; exit 1; }

install -m 755 "$SRC" "$BIN"
# Gatekeeper: скачанный с интернета бинарник запускаться не даст
xattr -dr com.apple.quarantine "$BIN" 2>/dev/null || true

mkdir -p "$(dirname "$CONF")"
if [ ! -f "$CONF" ]; then
    install -m 644 "$HERE/smartdns.yaml" "$CONF"
    echo "конфиг положен в $CONF — поправьте под себя"
else
    echo "конфиг уже есть, не трогаю: $CONF"
fi

install -m 644 "$HERE/com.smartdns.plist" "$PLIST"
launchctl unload -w "$PLIST" 2>/dev/null || true
launchctl load -w "$PLIST"
sleep 1

echo
echo "готово. Проверка:"
echo "  dig @127.0.0.1 claude.ai A +short"
echo "  tail -f /var/log/smartdns.log"
echo

if [ "$1" = "--set-dns" ]; then
    echo "Сетевые сервисы:"
    networksetup -listallnetworkservices | grep -v '^\*'
    echo
    echo "Чтобы система сама ходила в smartdns, пропишите 127.0.0.1 первым DNS"
    echo "у нужного сервиса, например:"
    echo "  sudo networksetup -setdnsservers Wi-Fi 127.0.0.1 1.1.1.1"
    echo "  sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder"
    echo
    echo "Вернуть как было:"
    echo "  sudo networksetup -setdnsservers Wi-Fi empty"
fi
