--[[
    app.lua — Основное приложение (Lua)
    HWID проверка через AUTH_HWID env переменную.
    Если не совпадает — os.exit(1) без вывода.
--]]

local sha2 = require("sha2") -- если нет sha2, используем io/popen

-- ─── HWID сбор ───────────────────────────────────────────────────────────────
local function get_hwid()
    local raw = ""
    local ok, result

    -- Linux: MAC адрес
    local f = io.popen("ip route show default 2>/dev/null | awk '/default/ {print $5}'")
    if f then
        local iface = f:read("*l") or ""
        f:close()
        if iface ~= "" then
            local fm = io.open("/sys/class/net/" .. iface .. "/address", "r")
            if fm then
                local mac = fm:read("*l") or ""
                fm:close()
                raw = raw .. mac:gsub(":", "")
            end
        end
    end

    -- hostname
    local fh = io.popen("hostname 2>/dev/null")
    if fh then
        raw = raw .. (fh:read("*l") or "")
        fh:close()
    end

    -- uname
    local fu = io.popen("uname -srm 2>/dev/null")
    if fu then
        raw = raw .. (fu:read("*l") or "")
        fu:close()
    end

    if raw == "" then raw = "unknown" end

    -- SHA-256 через openssl (не требует дополнительных модулей)
    local cmd = string.format("echo -n '%s' | openssl dgst -sha256 | awk '{print $2}'",
                              raw:gsub("'", ""))
    local fsha = io.popen(cmd)
    if fsha then
        local h = fsha:read("*l") or ""
        fsha:close()
        if #h == 64 then return h end
    end

    -- Запасной вариант — просто возвращаем raw (менее безопасно)
    return raw
end

-- ─── HWID проверка ────────────────────────────────────────────────────────────
local expected = os.getenv("AUTH_HWID") or ""
if expected == "" then
    print("[!] Запусти через авторизатор.")
    os.exit(1)
end

local current = get_hwid()
if current ~= expected then
    os.exit(1)  -- тихо
end

-- ─── Переменные из auth_client ────────────────────────────────────────────────
local AUTH_USER   = os.getenv("AUTH_USER")   or ""
local AUTH_SERVER = os.getenv("AUTH_SERVER") or ""

-- ─── Твоя логика ─────────────────────────────────────────────────────────────
print()
print("╔══════════════════════════════════════╗")
print("║     МОЁ ПРИЛОЖЕНИЕ  v1.0  [Lua]    ║")
print("╚══════════════════════════════════════╝")
print()
print("  Пользователь : " .. AUTH_USER)
print("  HWID         : совпадает ✓")
print("  Сервер       : " .. AUTH_SERVER)
print()

-- === ПИШИ СВОЮ ЛОГИКУ ЗДЕСЬ ===
for i = 1, 5 do
    print(string.format("    [%d/5] работаю...", i))
    local t = os.clock() + 0.4
    while os.clock() < t do end
end
-- ================================

print("\n  Готово!")
io.read()