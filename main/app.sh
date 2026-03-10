#!/bin/bash
# app.sh — Основное приложение (Shell)
# HWID проверка через AUTH_HWID env переменную.

# ─── HWID сбор ───────────────────────────────────────────────────────────────
get_hwid() {
    local raw=""

    # MAC адрес
    local iface
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
    if [ -n "$iface" ] && [ -f "/sys/class/net/$iface/address" ]; then
        local mac
        mac=$(cat "/sys/class/net/$iface/address" | tr -d ':')
        raw="${raw}${mac}"
    fi

    # hostname + uname
    raw="${raw}$(hostname 2>/dev/null)"
    raw="${raw}$(uname -srm 2>/dev/null)"

    [ -z "$raw" ] && raw="unknown"

    # SHA-256
    echo -n "$raw" | sha256sum 2>/dev/null | awk '{print $1}' \
        || echo -n "$raw" | openssl dgst -sha256 2>/dev/null | awk '{print $2}' \
        || echo "$raw"
}

# ─── HWID проверка ────────────────────────────────────────────────────────────
if [ -z "$AUTH_HWID" ]; then
    echo "[!] Запусти через авторизатор."
    exit 1
fi

CURRENT_HWID=$(get_hwid)
if [ "$CURRENT_HWID" != "$AUTH_HWID" ]; then
    exit 1  # тихо
fi

# ─── Твоя логика ─────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════╗"
echo "║   МОЁ ПРИЛОЖЕНИЕ  v1.0  [Shell]    ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "  Пользователь : ${AUTH_USER}"
echo "  HWID         : совпадает ✓"
echo "  Сервер       : ${AUTH_SERVER}"
echo ""

# === ПИШИ СВОЮ ЛОГИКУ ЗДЕСЬ ===
for i in 1 2 3 4 5; do
    echo "    [$i/5] работаю..."
    sleep 0.4
done
# ================================

echo ""
echo "  Готово! Нажми Enter."
read