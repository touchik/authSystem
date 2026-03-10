"""
crypto.py — ECDH + AES-256-GCM шифрование для Auth Server

Схема:
  1. GET /handshake  → сервер генерирует ECDH пару, отдаёт pub_key + session_id
  2. Клиент шлёт свой pub_key, обе стороны вычисляют shared_secret
  3. AES ключ = HKDF-SHA256(shared_secret)
  4. Все запросы /secure/* — тело зашифровано AES-256-GCM

Сессии хранятся в памяти с TTL 5 минут (очищаются автоматически).
"""

import os
import json
import time
import base64
import threading
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ─── Константы ────────────────────────────────────────────────────────────────
SESSION_TTL   = 300   # секунд до истечения handshake-сессии
NONCE_SIZE    = 12    # байт (96 бит) — стандарт для AES-GCM
AES_KEY_SIZE  = 32    # байт (256 бит)
HKDF_INFO     = b"auth-server-v2"

# ─── Хранилище сессий (in-memory, thread-safe) ────────────────────────────────
_sessions: dict = {}
_lock = threading.Lock()

class CryptoSession:
    def __init__(self, session_id: str):
        self.session_id   = session_id
        self.server_priv  = X25519PrivateKey.generate()
        self.server_pub   = self.server_priv.public_key()
        self.aes_key: Optional[bytes] = None   # None до завершения handshake
        self.created_at   = time.time()

    def server_pub_b64(self) -> str:
        # public_bytes_raw() — современный API, не требует Raw из serialization
        raw = self.server_pub.public_bytes_raw()
        return base64.b64encode(raw).decode()

    def complete_handshake(self, client_pub_b64: str) -> bool:
        """Принимает публичный ключ клиента, вычисляет AES ключ."""
        try:
            client_pub_raw = base64.b64decode(client_pub_b64)
            client_pub     = X25519PublicKey.from_public_bytes(client_pub_raw)
            shared_secret  = self.server_priv.exchange(client_pub)
            self.aes_key   = HKDF(
                algorithm=SHA256(),
                length=AES_KEY_SIZE,
                salt=None,
                info=HKDF_INFO,
            ).derive(shared_secret)
            return True
        except Exception:
            return False

    def is_ready(self) -> bool:
        return self.aes_key is not None

    def encrypt(self, plaintext: bytes) -> dict:
        """Шифрует байты, возвращает {"nonce": b64, "ciphertext": b64}."""
        if not self.aes_key:
            raise RuntimeError("Handshake не завершён")
        nonce = os.urandom(NONCE_SIZE)
        ct    = AESGCM(self.aes_key).encrypt(nonce, plaintext, None)
        return {
            "nonce":      base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ct).decode(),
        }

    def decrypt(self, nonce_b64: str, ciphertext_b64: str) -> bytes:
        """Расшифровывает тело запроса. Бросает ValueError если неверно."""
        if not self.aes_key:
            raise RuntimeError("Handshake не завершён")
        try:
            nonce = base64.b64decode(nonce_b64)
            ct    = base64.b64decode(ciphertext_b64)
            return AESGCM(self.aes_key).decrypt(nonce, ct, None)
        except Exception:
            raise ValueError("Расшифровка не удалась: неверный ключ или данные повреждены")

# ─── Управление сессиями ──────────────────────────────────────────────────────

def create_session() -> CryptoSession:
    """Создаёт новую handshake-сессию и сохраняет её."""
    _cleanup_expired()
    session_id = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")
    session    = CryptoSession(session_id)
    with _lock:
        _sessions[session_id] = session
    return session

def get_session(session_id: str) -> Optional[CryptoSession]:
    """Возвращает сессию если она существует и не истекла."""
    _cleanup_expired()
    with _lock:
        session = _sessions.get(session_id)
    if session and (time.time() - session.created_at) < SESSION_TTL:
        return session
    return None

def _cleanup_expired():
    """Удаляет истёкшие сессии (вызывается при каждом обращении)."""
    now = time.time()
    with _lock:
        expired = [sid for sid, s in _sessions.items()
                   if (now - s.created_at) >= SESSION_TTL]
        for sid in expired:
            del _sessions[sid]

# ─── Вспомогательная функция для эндпоинтов ──────────────────────────────────

def decrypt_request(session_id: str, nonce: str, ciphertext: str) -> dict:
    """
    Расшифровывает тело запроса и парсит JSON.
    Бросает ValueError / KeyError при ошибках.
    """
    session = get_session(session_id)
    if not session:
        raise ValueError("Сессия не найдена или истекла. Повторите handshake.")
    if not session.is_ready():
        raise ValueError("Handshake не завершён.")
    raw  = session.decrypt(nonce, ciphertext)
    return json.loads(raw.decode("utf-8"))

def encrypt_response(session_id: str, data: dict) -> dict:
    """
    Шифрует dict ответа. Если сессия не найдена — возвращает данные открыто
    (fallback для handshake-эндпоинтов где ключа ещё нет).
    """
    session = get_session(session_id)
    if not session or not session.is_ready():
        return data  # handshake ответ — ещё нечем шифровать
    return session.encrypt(json.dumps(data).encode("utf-8"))