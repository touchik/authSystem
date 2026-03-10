"""
Auth Server v3.0 — FastAPI + SQLite + keys.json
v3:
  - SECRET_KEY и ADMIN_KEY хранятся в keys.json (автогенерация при первом запуске)
  - .env больше не нужен для ключей (опционально для переопределения)
  - SQLite для пользователей/сессий/логов (надёжно)
  - keys.json для секретных ключей (читаемо, версионируемо)
"""

import sqlite3
import hashlib
import secrets
import os
import json
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional
from pathlib import Path

# Загружаем .env ДО всего остального
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env", override=True)
except ImportError:
    pass  # python-dotenv не установлен — переменные берутся из окружения

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, field_validator
import jwt
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ─── Директория для данных ────────────────────────────────────────────────────
# Все файлы (БД, логи) хранятся в data/ рядом с main.py
# Переопределить: DATA_DIR=/другой/путь uvicorn main:app ...
DATA_DIR = Path(os.getenv("DATA_DIR") or (Path(__file__).parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(DATA_DIR / "auth.log", encoding="utf-8"),
    ]
)
log = logging.getLogger("auth")

# ─── keys.json — хранилище секретных ключей ──────────────────────────────────
KEYS_FILE = DATA_DIR / "keys.json"

def load_keys() -> dict:
    """
    Загружает резервные ключи из keys.json.
    Используются ТОЛЬКО если .env не задаёт SECRET_KEY / ADMIN_KEY.
    При отсутствии файла — генерирует и сохраняет новые.
    """
    if KEYS_FILE.exists():
        try:
            with open(KEYS_FILE, "r") as f:
                keys = json.load(f)
            log.info(f"keys.json загружен ({KEYS_FILE})")
            return keys
        except Exception as e:
            log.error(f"Ошибка чтения keys.json: {e} — генерируем новые")

    # Генерируем новые ключи (первый запуск)
    keys = {
        "SECRET_KEY": secrets.token_hex(32),
        "ADMIN_KEY":  secrets.token_urlsafe(32),
        "_note": "Запасные ключи. .env имеет приоритет. Не добавляй в git!"
    }
    try:
        with open(KEYS_FILE, "w") as f:
            json.dump(keys, f, indent=2, ensure_ascii=False)
        try: os.chmod(KEYS_FILE, 0o600)
        except Exception: pass
        log.info(f"Новые ключи сгенерированы → {KEYS_FILE}")
        log.info(f"  ADMIN_KEY (из keys.json): {keys['ADMIN_KEY']}")
    except Exception as e:
        log.error(f"Не удалось сохранить keys.json: {e}")
    return keys

# ─── Config ───────────────────────────────────────────────────────────────────
# Приоритет: .env → keys.json → авто-генерация (только для SECRET_KEY)
_env_secret = os.getenv("SECRET_KEY")
_env_admin  = os.getenv("ADMIN_KEY")

if _env_secret and _env_admin:
    # Оба ключа заданы в .env — keys.json не нужен
    SECRET_KEY = _env_secret
    ADMIN_KEY  = _env_admin
    log.info("Ключи загружены из .env")
else:
    # Хотя бы один не задан — читаем keys.json как запасной источник
    _keys = load_keys()
    SECRET_KEY = _env_secret or _keys.get("SECRET_KEY")
    ADMIN_KEY  = _env_admin  or _keys.get("ADMIN_KEY", "change-me")
    if _env_secret:
        log.info("SECRET_KEY из .env, ADMIN_KEY из keys.json")
    elif _env_admin:
        log.info("ADMIN_KEY из .env, SECRET_KEY из keys.json")
    else:
        log.info("Оба ключа из keys.json (.env не задан)")

if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    log.warning("SECRET_KEY не удалось загрузить! Токены сбросятся при рестарте.")

if ADMIN_KEY == "change-me":
    log.warning("ADMIN_KEY не задан! Задай в .env или keys.json.")

DB_PATH   = str(DATA_DIR / os.getenv("DB_FILE", "auth.db"))
JWT_ALG   = "HS256"
JWT_EXP_H = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

# ─── Rate limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ─── DB (thread-local + WAL) ──────────────────────────────────────────────────
_local = threading.local()

def get_db() -> sqlite3.Connection:
    if not hasattr(_local, "conn") or _local.conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")    # нет "database is locked"
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")  # баланс скорости и надёжности
        _local.conn = conn
    return _local.conn

def migrate_db(conn):
    """Добавляет новые колонки в существующую БД (миграция)."""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "ip_address" not in existing:
        conn.execute("ALTER TABLE users ADD COLUMN ip_address TEXT")
        log.info("Миграция: добавлена колонка ip_address")
    if "hwid" not in existing:
        conn.execute("ALTER TABLE users ADD COLUMN hwid TEXT")
        log.info("Миграция: добавлена колонка hwid")
    if "banned" not in existing:
        conn.execute("ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0")
        log.info("Миграция: добавлена колонка banned")
    conn.commit()

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS invites (
            code        TEXT PRIMARY KEY,
            used        INTEGER DEFAULT 0,
            created_at  TEXT NOT NULL,
            used_by     TEXT
        );
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            invite_code TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            last_login  TEXT,
            ip_address  TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       TEXT NOT NULL,
            event    TEXT NOT NULL,
            username TEXT,
            ip       TEXT,
            detail   TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            username    TEXT NOT NULL,
            hwid        TEXT,
            ip          TEXT,
            created_at  TEXT NOT NULL,
            last_ping   TEXT NOT NULL,
            expires_at  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_username  ON users(username);
        CREATE INDEX IF NOT EXISTS idx_invites_code    ON invites(code);
        CREATE INDEX IF NOT EXISTS idx_sessions_token  ON sessions(token);
        CREATE INDEX IF NOT EXISTS idx_sessions_user   ON sessions(username);
    """)
    conn.commit()
    migrate_db(conn)
    log.info("БД инициализирована (WAL включён)")

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

def audit(event: str, username: str = None, ip: str = None, detail: str = None):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
            (utcnow(), event, username, ip, detail)
        )
        conn.commit()
    except Exception as e:
        log.error(f"audit error: {e}")

# ─── Helpers ──────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode(), 260_000)
    return f"{salt}:{h.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        new_h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode(), 260_000)
        return secrets.compare_digest(h, new_h.hex())
    except Exception:
        return False

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXP_H),
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALG)

def require_admin(x_admin_key: Optional[str] = Header(None)):
    if not x_admin_key or not secrets.compare_digest(x_admin_key, ADMIN_KEY):
        raise HTTPException(403, "Неверный admin ключ")

def get_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.client.host or "unknown")

# ─── Schemas ──────────────────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    invite_code: str
    username:    str
    password:    str

    @field_validator("username")
    @classmethod
    def username_valid(cls, v):
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError("Имя пользователя: 3–32 символа")
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        if not all(c in allowed for c in v):
            raise ValueError("Только латиница, цифры, _ и -")
        return v

    @field_validator("password")
    @classmethod
    def password_valid(cls, v):
        if len(v) < 8:   raise ValueError("Пароль: минимум 8 символов")
        if len(v) > 128: raise ValueError("Пароль: максимум 128 символов")
        return v

    @field_validator("invite_code")
    @classmethod
    def invite_valid(cls, v):
        v = v.strip()
        if len(v) < 4 or len(v) > 64: raise ValueError("Неверный инвайт-код")
        return v

class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def u_len(cls, v):
        if len(v) > 64: raise ValueError("Слишком длинное имя")
        return v.strip()

    @field_validator("password")
    @classmethod
    def p_len(cls, v):
        if len(v) > 128: raise ValueError("Слишком длинный пароль")
        return v

# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="Auth Server", version="2.0.0", docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup():
    init_db()
    tg.start()
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    tg.notify_server_start(host, port)
    # Автозапуск FunPay бота если включён
    if os.getenv("FUNPAY_ENABLED", "0") == "1":
        _start_funpay_bot()
    log.info(f"Сервер запущен. JWT TTL={JWT_EXP_H}h")

@app.on_event("shutdown")
def shutdown():
    tg.notify_server_stop()
    tg.stop()

def _start_funpay_bot():
    """Запускает FunPay бота в отдельном потоке."""
    import importlib, threading
    try:
        bot = importlib.import_module("funpay_bot")
        t = threading.Thread(target=bot.run_bot, daemon=True, name="funpay-bot")
        t.start()
        log.info("FunPay бот запущен в фоне")
    except ImportError:
        log.warning("funpay_bot.py не найден — бот не запущен")
    except Exception as e:
        log.error(f"Ошибка запуска FunPay бота: {e}")
        tg.notify_error("FunPay bot startup", str(e))

# ── Register ──────────────────────────────────────────────────────────────────
@app.post("/register")
@limiter.limit("5/minute")
def register(request: Request, req: RegisterRequest):
    ip   = get_ip(request)
    conn = get_db()

    invite = conn.execute(
        "SELECT * FROM invites WHERE code=? AND used=0", (req.invite_code,)
    ).fetchone()
    if not invite:
        audit("REGISTER_FAIL", ip=ip, detail=f"bad invite")
        raise HTTPException(400, "Неверный или уже использованный инвайт-код")

    if conn.execute("SELECT 1 FROM users WHERE username=?", (req.username,)).fetchone():
        audit("REGISTER_FAIL", username=req.username, ip=ip, detail="username taken")
        raise HTTPException(409, "Имя пользователя занято")

    ts = utcnow()
    conn.execute(
        "INSERT INTO users (username, password, invite_code, created_at, ip_address) VALUES (?,?,?,?,?)",
        (req.username, hash_password(req.password), req.invite_code, ts, ip)
    )
    conn.execute("UPDATE invites SET used=1, used_by=? WHERE code=?", (req.username, req.invite_code))
    conn.commit()

    audit("REGISTER_OK", username=req.username, ip=ip)
    log.info(f"Новый пользователь: {req.username} ({ip})")
    tg.notify_register(req.username, ip)
    return {"status": "ok", "token": create_token(req.username), "username": req.username}

# ── Login ─────────────────────────────────────────────────────────────────────
@app.post("/login")
@limiter.limit("10/minute")
def login(request: Request, req: LoginRequest):
    ip   = get_ip(request)
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (req.username,)).fetchone()

    if not user or not verify_password(req.password, user["password"]):
        audit("LOGIN_FAIL", username=req.username, ip=ip)
        tg.notify_login_fail(req.username, ip)
        raise HTTPException(401, "Неверные учётные данные")

    conn.execute("UPDATE users SET last_login=? WHERE username=?", (utcnow(), req.username))
    conn.commit()

    audit("LOGIN_OK", username=req.username, ip=ip)
    log.info(f"Вход: {req.username} ({ip})")
    return {"status": "ok", "token": create_token(req.username), "username": req.username}

# ── Admin endpoints ───────────────────────────────────────────────────────────
@app.post("/admin/invite", dependencies=[Depends(require_admin)])
@limiter.limit("30/minute")
def create_invite(request: Request, count: int = 1):
    if count < 1 or count > 100: raise HTTPException(400, "count: 1–100")
    conn, codes, ts = get_db(), [], utcnow()
    for _ in range(count):
        code = secrets.token_urlsafe(12)
        conn.execute("INSERT INTO invites (code, created_at) VALUES (?,?)", (code, ts))
        codes.append(code)
    conn.commit()
    audit("INVITE_CREATED", detail=f"count={count}", ip=get_ip(request))
    return {"status": "ok", "codes": codes}

@app.get("/admin/users", dependencies=[Depends(require_admin)])
def list_users():
    rows = get_db().execute(
        "SELECT id, username, invite_code, created_at, last_login, ip_address FROM users ORDER BY id DESC"
    ).fetchall()
    return {"users": [dict(r) for r in rows]}

@app.delete("/admin/users/{username}", dependencies=[Depends(require_admin)])
def delete_user(username: str):
    conn = get_db()
    if not conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        raise HTTPException(404, "Пользователь не найден")
    conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    audit("USER_DELETED", username=username)
    return {"status": "ok"}

@app.get("/admin/invites", dependencies=[Depends(require_admin)])
def list_invites():
    rows = get_db().execute("SELECT * FROM invites ORDER BY created_at DESC").fetchall()
    return {"invites": [dict(r) for r in rows]}

@app.get("/admin/audit", dependencies=[Depends(require_admin)])
def get_audit(limit: int = 200):
    rows = get_db().execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (min(limit, 1000),)
    ).fetchall()
    return {"log": [dict(r) for r in rows]}

@app.get("/admin/stats", dependencies=[Depends(require_admin)])
def get_stats():
    conn = get_db()
    return {
        "total_users":   conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_invites": conn.execute("SELECT COUNT(*) FROM invites").fetchone()[0],
        "used_invites":  conn.execute("SELECT COUNT(*) FROM invites WHERE used=1").fetchone()[0],
        "free_invites":  conn.execute("SELECT COUNT(*) FROM invites WHERE used=0").fetchone()[0],
        "logins_24h":    conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE event='LOGIN_OK' AND ts > datetime('now','-24 hours')"
        ).fetchone()[0],
    }

# ── Admin Console ─────────────────────────────────────────────────────────────
# Тема задаётся в .env через ADMIN_THEME=<name>
# Сервер ищет файл admin_<name>.html рядом с main.py
# Если файл не найден — фолбэк на admin.html
# Доступные значения: dark (по умолчанию), light, cyberpunk — или любое своё

def _resolve_console_html() -> Path:
    theme = os.getenv("ADMIN_THEME", "").strip().lower()
    if theme:
        themed = Path(__file__).parent / f"themes/admin_{theme}.html"
        if themed.exists():
            log.info(f"Admin консоль: тема '{theme}' → {themed.name}")
            return themed
        log.warning(f"ADMIN_THEME='{theme}' задан, но файл '{themed.name}' не найден — используется admin.html")
    return Path(__file__).parent / "admin.html"

@app.get("/admin/console", response_class=HTMLResponse)
def admin_console():
    html_file = _resolve_console_html()
    if not html_file.exists():
        raise HTTPException(404, f"Файл {html_file} не найден")
    return HTMLResponse(html_file.read_text(encoding="utf-8"))

# ══════════════════════════════════════════════════════════════════════════════
# ЗАШИФРОВАННЫЕ ЭНДПОИНТЫ (/secure/*)
# Все запросы и ответы шифруются AES-256-GCM после ECDH handshake
# ══════════════════════════════════════════════════════════════════════════════
from crypto import create_session, get_session, decrypt_request, encrypt_response
import telegram as tg

# ── Шаг 1: клиент запрашивает публичный ключ сервера ──────────────────────────
@app.get("/secure/handshake")
def handshake_init():
    """
    Возвращает публичный ключ сервера (X25519) и session_id.
    Клиент должен ответить своим pub_key через POST /secure/handshake.
    """
    session = create_session()
    return {
        "session_id":     session.session_id,
        "server_pub_key": session.server_pub_b64(),
        "ttl_seconds":    300,
    }

# ── Шаг 2: клиент отправляет свой публичный ключ ──────────────────────────────
class HandshakeComplete(BaseModel):
    session_id:     str
    client_pub_key: str  # X25519 public key, base64

@app.post("/secure/handshake")
def handshake_complete(req: HandshakeComplete):
    """
    Принимает публичный ключ клиента, завершает ECDH.
    После этого сессия готова к шифрованию.
    """
    session = get_session(req.session_id)
    if not session:
        raise HTTPException(400, "Сессия не найдена или истекла")
    if not session.complete_handshake(req.client_pub_key):
        raise HTTPException(400, "Неверный публичный ключ клиента")
    return {"status": "ok", "session_id": req.session_id}

# ── Зашифрованное тело запроса ────────────────────────────────────────────────
class EncryptedRequest(BaseModel):
    session_id:  str
    nonce:       str   # base64, 12 байт
    ciphertext:  str   # base64, AES-GCM зашифрованный JSON

# ── /secure/register ──────────────────────────────────────────────────────────
@app.post("/secure/register")
@limiter.limit("5/minute")
def secure_register(request: Request, enc: EncryptedRequest):
    ip = get_ip(request)
    try:
        data = decrypt_request(enc.session_id, enc.nonce, enc.ciphertext)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Валидация расшифрованных полей
    invite   = str(data.get("invite_code", "")).strip()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not invite or len(invite) < 4 or len(invite) > 64:
        raise HTTPException(400, "Неверный инвайт-код")
    if len(username) < 3 or len(username) > 32:
        raise HTTPException(400, "Имя пользователя: 3–32 символа")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    if not all(c in allowed for c in username):
        raise HTTPException(400, "Только латиница, цифры, _ и -")
    if len(password) < 8 or len(password) > 128:
        raise HTTPException(400, "Пароль: 8–128 символов")

    conn = get_db()
    inv_row = conn.execute(
        "SELECT * FROM invites WHERE code=? AND used=0", (invite,)
    ).fetchone()
    if not inv_row:
        audit("REGISTER_FAIL", ip=ip, detail="bad invite (secure)")
        raise HTTPException(400, "Неверный или уже использованный инвайт-код")

    if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        audit("REGISTER_FAIL", username=username, ip=ip, detail="username taken (secure)")
        raise HTTPException(409, "Имя пользователя занято")

    ts = utcnow()
    conn.execute(
        "INSERT INTO users (username, password, invite_code, created_at, ip_address) VALUES (?,?,?,?,?)",
        (username, hash_password(password), invite, ts, ip)
    )
    conn.execute("UPDATE invites SET used=1, used_by=? WHERE code=?", (username, invite))
    conn.commit()

    audit("REGISTER_OK", username=username, ip=ip, detail="encrypted")
    log.info(f"[secure] Новый пользователь: {username} ({ip})")

    result = {"status": "ok", "token": create_token(username), "username": username}
    return encrypt_response(enc.session_id, result)

# ── /secure/ping (онлайн-проверка сессии каждые N минут) ─────────────────────
@app.post("/secure/ping")
@limiter.limit("60/minute")
def secure_ping(request: Request, enc: EncryptedRequest):
    """
    Клиент вызывает каждые 5 минут чтобы подтвердить сессию.
    Сервер проверяет: токен валиден, не истёк, пользователь не забанен, HWID совпадает.
    Если что-то не так — клиент должен завершить работу.
    """
    ip = get_ip(request)
    try:
        data = decrypt_request(enc.session_id, enc.nonce, enc.ciphertext)
    except ValueError as e:
        raise HTTPException(400, str(e))

    token    = str(data.get("token", ""))
    hwid     = str(data.get("hwid", ""))

    # Проверяем JWT
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        username = payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "TOKEN_EXPIRED")
    except Exception:
        raise HTTPException(401, "TOKEN_INVALID")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        raise HTTPException(401, "USER_NOT_FOUND")
    if user["banned"]:
        audit("PING_BANNED", username=username, ip=ip)
        raise HTTPException(403, "USER_BANNED")

    # Проверяем HWID если он уже привязан
    stored_hwid = user["hwid"]
    if stored_hwid and hwid and stored_hwid != hwid:
        audit("PING_HWID_MISMATCH", username=username, ip=ip,
              detail=f"expected={stored_hwid[:16]} got={hwid[:16]}")
        raise HTTPException(403, "HWID_MISMATCH")

    # Если HWID ещё не привязан — привязываем
    if not stored_hwid and hwid:
        conn.execute("UPDATE users SET hwid=? WHERE username=?", (hwid, username))
        conn.commit()
        log.info(f"HWID привязан: {username}")

    # Обновляем last_ping в сессии
    conn.execute(
        "UPDATE sessions SET last_ping=?, ip=? WHERE token=?",
        (utcnow(), ip, token)
    )
    conn.commit()

    audit("PING_OK", username=username, ip=ip)
    result = {"status": "ok", "username": username}
    return encrypt_response(enc.session_id, result)


# ── Admin: забанить/разбанить пользователя ────────────────────────────────────
@app.post("/admin/users/{username}/ban", dependencies=[Depends(require_admin)])
def ban_user(username: str):
    conn = get_db()
    if not conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        raise HTTPException(404, "Пользователь не найден")
    conn.execute("UPDATE users SET banned=1 WHERE username=?", (username,))
    conn.commit()
    audit("USER_BANNED", username=username)
    tg.notify_ban(username)
    return {"status": "ok"}

@app.post("/admin/users/{username}/unban", dependencies=[Depends(require_admin)])
def unban_user(username: str):
    conn = get_db()
    conn.execute("UPDATE users SET banned=0 WHERE username=?", (username,))
    conn.commit()
    audit("USER_UNBANNED", username=username)
    tg.notify_unban(username)
    return {"status": "ok"}

# ── Admin: сбросить HWID пользователя ────────────────────────────────────────
@app.delete("/admin/users/{username}/hwid", dependencies=[Depends(require_admin)])
def reset_hwid(username: str):
    conn = get_db()
    conn.execute("UPDATE users SET hwid=NULL WHERE username=?", (username,))
    conn.commit()
    audit("HWID_RESET", username=username)
    return {"status": "ok"}

# ── Admin: активные сессии ────────────────────────────────────────────────────
@app.get("/admin/sessions", dependencies=[Depends(require_admin)])
def list_sessions():
    rows = get_db().execute(
        "SELECT username, hwid, ip, created_at, last_ping, expires_at FROM sessions ORDER BY last_ping DESC"
    ).fetchall()
    return {"sessions": [dict(r) for r in rows]}

# ── /secure/login ─────────────────────────────────────────────────────────────
@app.post("/secure/login")
@limiter.limit("10/minute")
def secure_login(request: Request, enc: EncryptedRequest):
    ip = get_ip(request)
    try:
        data = decrypt_request(enc.session_id, enc.nonce, enc.ciphertext)
    except ValueError as e:
        raise HTTPException(400, str(e))

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        raise HTTPException(400, "Пустые поля")
    if len(username) > 64 or len(password) > 128:
        raise HTTPException(400, "Поля слишком длинные")

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user or not verify_password(password, user["password"]):
        audit("LOGIN_FAIL", username=username, ip=ip, detail="encrypted")
        raise HTTPException(401, "Неверные учётные данные")

    conn.execute("UPDATE users SET last_login=? WHERE username=?", (utcnow(), username))
    conn.commit()

    hwid  = str(data.get("hwid", ""))
    token = create_token(username)

    # Проверяем HWID
    stored_hwid = user["hwid"]
    if stored_hwid and hwid and stored_hwid != hwid:
        audit("LOGIN_HWID_MISMATCH", username=username, ip=ip)
        tg.notify_hwid_mismatch(username, ip)
        raise HTTPException(403, "HWID_MISMATCH: эта программа привязана к другому компьютеру")

    # Привязываем HWID при первом входе
    if not stored_hwid and hwid:
        conn.execute("UPDATE users SET hwid=? WHERE username=?", (hwid, username))
        log.info(f"[secure] HWID привязан: {username}")

    # Проверяем не забанен ли
    if user["banned"]:
        audit("LOGIN_BANNED", username=username, ip=ip)
        raise HTTPException(403, "USER_BANNED")

    # Сохраняем сессию в БД
    expires = (datetime.now(timezone.utc) + timedelta(hours=JWT_EXP_H)).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO sessions (token, username, hwid, ip, created_at, last_ping, expires_at) VALUES (?,?,?,?,?,?,?)",
        (token, username, hwid, ip, utcnow(), utcnow(), expires)
    )
    conn.commit()

    audit("LOGIN_OK", username=username, ip=ip, detail="encrypted")
    log.info(f"[secure] Вход: {username} ({ip})")

    result = {"status": "ok", "token": token, "username": username}
    return encrypt_response(enc.session_id, result)

# ══════════════════════════════════════════════════════════════════════════════
# ЗАПУСК PAYLOAD (/secure/launch)
# Сервер шифрует и отдаёт файл приложения после проверки JWT + HWID
# ══════════════════════════════════════════════════════════════════════════════

# Папка с файлами приложений (рядом с main.py)
# Структура:
#   payload/
#     app.exe        ← C++ бинарник
#     app.py         ← Python скрипт
#     app.lua        ← Lua скрипт
#     app.sh         ← Shell скрипт
#     app.bat        ← Batch скрипт
# Приоритет выбора файла настраивается в .env через PAYLOAD_FILE
# Если не задан — берётся первый найденный файл в папке payload/

PAYLOAD_DIR  = Path(__file__).parent / "payload"

# Поддерживаемые типы и их идентификатор для клиента
PAYLOAD_TYPES = {
    ".exe": "exe",
    ".py":  "python",
    ".pyc": "python",
    ".lua": "lua",
    ".sh":  "shell",
    ".bat": "batch",
    ".cmd": "batch",
}

def find_payload() -> Optional[Path]:
    """
    Находит файл приложения.
    Порядок поиска:
      1. PAYLOAD_FILE из .env — абсолютный путь
      2. PAYLOAD_FILE из .env — относительно папки сервера (рядом с main.py)
      3. PAYLOAD_FILE из .env — относительно PAYLOAD_DIR (server/payload/)
      4. Автовыбор: первый подходящий файл в PAYLOAD_DIR
    """
    payload_file = os.getenv("PAYLOAD_FILE", "").strip()

    if payload_file:
        # 1. Абсолютный путь
        p = Path(payload_file)
        if p.is_absolute() and p.exists():
            log.info(f"Payload: абсолютный путь → {p}")
            return p

        # 2. Относительно папки сервера (рядом с main.py)
        p = Path(__file__).parent / payload_file
        if p.exists():
            log.info(f"Payload: относительно сервера → {p}")
            return p

        # 3. Относительно PAYLOAD_DIR (server/payload/)
        p = PAYLOAD_DIR / payload_file
        if p.exists():
            log.info(f"Payload: относительно payload/ → {p}")
            return p

        log.error(f"PAYLOAD_FILE='{payload_file}' не найден ни по одному пути")
        return None

    # 4. Автовыбор — первый подходящий файл в PAYLOAD_DIR
    if not PAYLOAD_DIR.exists():
        return None
    for ext in PAYLOAD_TYPES:
        for f in sorted(PAYLOAD_DIR.glob(f"**/*{ext}")):  # рекурсивно
            return f
    return None

def encrypt_payload(data: bytes, session_id: str) -> Optional[dict]:
    """Шифрует байты файла тем же AES ключом сессии."""
    from crypto import get_session
    import base64, os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    session = get_session(session_id)
    if not session or not session.is_ready():
        return None

    nonce = os.urandom(12)
    ct    = AESGCM(session.aes_key).encrypt(nonce, data, None)
    return {
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }

@app.post("/secure/launch")
@limiter.limit("10/minute")
def secure_launch(request: Request, enc: EncryptedRequest):
    """
    Возвращает зашифрованный файл приложения.
    Клиент должен быть авторизован (валидный JWT + HWID совпадает).
    """
    ip = get_ip(request)
    try:
        data = decrypt_request(enc.session_id, enc.nonce, enc.ciphertext)
    except ValueError as e:
        raise HTTPException(400, str(e))

    token = str(data.get("token", ""))
    hwid  = str(data.get("hwid", ""))

    # Проверяем JWT
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALG])
        username = payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "TOKEN_EXPIRED")
    except Exception:
        raise HTTPException(401, "TOKEN_INVALID")

    # Проверяем пользователя
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        raise HTTPException(401, "USER_NOT_FOUND")
    if user["banned"]:
        audit("LAUNCH_BANNED", username=username, ip=ip)
        raise HTTPException(403, "USER_BANNED")

    # Проверяем HWID
    stored_hwid = user["hwid"]
    if stored_hwid and hwid and stored_hwid != hwid:
        audit("LAUNCH_HWID_MISMATCH", username=username, ip=ip)
        tg.notify_hwid_mismatch(username, ip)
        raise HTTPException(403, "HWID_MISMATCH")

    # Находим файл приложения
    payload_path = find_payload()
    if not payload_path:
        log.error("Файл приложения не найден в папке payload/")
        raise HTTPException(503, "PAYLOAD_NOT_FOUND: файл приложения не найден на сервере")

    # Читаем и шифруем
    try:
        file_data = payload_path.read_bytes()
    except Exception as e:
        log.error(f"Ошибка чтения payload: {e}")
        raise HTTPException(500, "PAYLOAD_READ_ERROR")

    file_type = PAYLOAD_TYPES.get(payload_path.suffix.lower(), "unknown")
    file_size = len(file_data)
    encrypted = encrypt_payload(file_data, enc.session_id)
    if not encrypted:
        raise HTTPException(400, "Crypto сессия недоступна")

    audit("LAUNCH_OK", username=username, ip=ip,
          detail=f"{payload_path.name} ({file_size} bytes)")
    log.info(f"[launch] {username} ({ip}) → {payload_path.name} ({file_size} b)")

    return {
        "status":    "ok",
        "file_type": file_type,
        "file_name": payload_path.name,
        "file_size": str(file_size),   # строка — клиент парсит через jget
        "nonce":     encrypted["nonce"],
        "ciphertext":encrypted["ciphertext"],
    }


# ── Admin: загрузить payload файл ────────────────────────────────────────────
@app.post("/admin/payload/upload", dependencies=[Depends(require_admin)])
async def upload_payload(request: Request):
    """
    Загружает файл приложения на сервер.
    Используй multipart/form-data или передай base64 в JSON.
    """
    from fastapi import UploadFile, File
    import shutil
    PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)
    body = await request.body()
    data = json.loads(body)
    filename  = data.get("filename", "app.py")
    b64_data  = data.get("data", "")
    import base64
    file_bytes = base64.b64decode(b64_data)
    dest = PAYLOAD_DIR / Path(filename).name  # только имя, без path traversal
    dest.write_bytes(file_bytes)
    audit("PAYLOAD_UPLOADED", detail=f"{filename} ({len(file_bytes)} bytes)")
    log.info(f"Payload загружен: {dest.name} ({len(file_bytes)} bytes)")
    return {"status": "ok", "file": dest.name, "size": len(file_bytes)}

@app.get("/admin/payload/list", dependencies=[Depends(require_admin)])
def list_payloads():
    """Список доступных файлов в папке payload/."""
    if not PAYLOAD_DIR.exists():
        return {"files": []}
    files = []
    for f in PAYLOAD_DIR.iterdir():
        if f.is_file():
            files.append({
                "name": f.name,
                "size": f.stat().st_size,
                "type": PAYLOAD_TYPES.get(f.suffix.lower(), "unknown"),
                "active": f == find_payload(),
            })
    return {"files": files}

@app.delete("/admin/payload/{filename}", dependencies=[Depends(require_admin)])
def delete_payload(filename: str):
    """Удаляет файл из папки payload/."""
    p = PAYLOAD_DIR / Path(filename).name
    if not p.exists():
        raise HTTPException(404, "Файл не найден")
    p.unlink()
    audit("PAYLOAD_DELETED", detail=filename)
    return {"status": "ok"}

# ══════════════════════════════════════════════════════════════════════════════
# УПРАВЛЕНИЕ КЛЮЧАМИ (/admin/keys)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/admin/keys/info", dependencies=[Depends(require_admin)])
def keys_info():
    """Информация о текущих ключах (без самих значений)."""
    keys_exist = KEYS_FILE.exists()
    return {
        "keys_file":    str(KEYS_FILE),
        "keys_exist":   keys_exist,
        "secret_key_len": len(SECRET_KEY) if SECRET_KEY else 0,
        "admin_key_len":  len(ADMIN_KEY)  if ADMIN_KEY  else 0,
        "source": "env override" if os.getenv("SECRET_KEY") else "keys.json",
    }

@app.post("/admin/keys/rotate", dependencies=[Depends(require_admin)])
def rotate_keys(rotate_secret: bool = False, rotate_admin: bool = False):
    """
    Ротация ключей.
    rotate_secret=true — новый SECRET_KEY (все токены станут недействительны!)
    rotate_admin=true  — новый ADMIN_KEY
    """
    global SECRET_KEY, ADMIN_KEY
    if not rotate_secret and not rotate_admin:
        raise HTTPException(400, "Укажи rotate_secret=true или rotate_admin=true")

    try:
        with open(KEYS_FILE, "r") as f:
            keys = json.load(f)
    except Exception:
        keys = {}

    changed = []
    if rotate_secret:
        keys["SECRET_KEY"] = secrets.token_hex(32)
        SECRET_KEY = keys["SECRET_KEY"]
        changed.append("SECRET_KEY")
        log.warning("SECRET_KEY ротирован — все активные токены недействительны!")

    if rotate_admin:
        keys["ADMIN_KEY"] = secrets.token_urlsafe(32)
        ADMIN_KEY = keys["ADMIN_KEY"]
        changed.append("ADMIN_KEY")
        log.info(f"ADMIN_KEY ротирован. Новый: {ADMIN_KEY}")

    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2, ensure_ascii=False)

    audit("KEYS_ROTATED", detail=", ".join(changed))
    tg.send(f"🔑 Ключи ротированы: {', '.join(changed)}", tg.TgLevel.WARNING)
    return {"status": "ok", "rotated": changed,
            "warning": "Все токены недействительны!" if rotate_secret else None}