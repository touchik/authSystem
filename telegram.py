"""
telegram.py — Telegram уведомления для Auth Server

Отправляет сообщения в Telegram чат при важных событиях:
  - Новая регистрация
  - Вход пользователя
  - Неудачная попытка входа (>3 подряд с одного IP)
  - Бан/разбан пользователя
  - Новая покупка на FunPay
  - Ошибки сервера
  - Запуск/остановка сервера

Настройка:
  1. Создай бота через @BotFather в Telegram
  2. Получи токен бота
  3. Напиши боту любое сообщение
  4. Открой https://api.telegram.org/bot<TOKEN>/getUpdates
  5. Найди "chat":{"id": ...} — это твой CHAT_ID
  6. Добавь в .env: TG_TOKEN и TG_CHAT_ID
"""

import os
import logging
import threading
import queue
import time
import requests
from typing import Optional
from enum import Enum

log = logging.getLogger("telegram")

TG_TOKEN   = os.getenv("TG_TOKEN")
TG_CHAT_ID = os.getenv("TG_CHAT_ID")
TG_ENABLED = bool(TG_TOKEN and TG_CHAT_ID)

if not TG_ENABLED:
    log.info("Telegram уведомления отключены (TG_TOKEN/TG_CHAT_ID не заданы в .env)")


class TgLevel(Enum):
    INFO    = "ℹ️"
    SUCCESS = "✅"
    WARNING = "⚠️"
    ERROR   = "❌"
    BAN     = "🔨"
    SHOP    = "🛒"
    SERVER  = "🖥️"


# ─── Очередь отправки (не блокирует основной поток) ───────────────────────────
_queue: queue.Queue = queue.Queue()
_worker_thread: Optional[threading.Thread] = None


def _worker():
    """Фоновый поток — отправляет сообщения из очереди с retry."""
    while True:
        item = _queue.get()
        if item is None:
            break
        text, attempt = item
        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                json={
                    "chat_id":    TG_CHAT_ID,
                    "text":       text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
                timeout=10,
            )
            if not resp.ok:
                raise Exception(f"HTTP {resp.status_code}: {resp.text[:100]}")
        except Exception as e:
            if attempt < 3:
                log.warning(f"Telegram retry {attempt+1}/3: {e}")
                time.sleep(2 ** attempt)  # экспоненциальная задержка
                _queue.put((text, attempt + 1))
            else:
                log.error(f"Telegram: не удалось отправить после 3 попыток: {e}")
        finally:
            _queue.task_done()


def start():
    """Запускает фоновый поток отправки."""
    global _worker_thread
    if not TG_ENABLED:
        return
    _worker_thread = threading.Thread(target=_worker, daemon=True, name="tg-worker")
    _worker_thread.start()
    log.info("Telegram уведомления активны")


def stop():
    """Останавливает фоновый поток."""
    if _worker_thread and _worker_thread.is_alive():
        _queue.put(None)


def send(text: str, level: TgLevel = TgLevel.INFO):
    """Ставит сообщение в очередь на отправку."""
    if not TG_ENABLED:
        return
    icon  = level.value
    _queue.put((f"{icon} {text}", 0))


# ─── Готовые уведомления ──────────────────────────────────────────────────────

def notify_server_start(host: str, port: int):
    send(
        f"<b>Сервер запущен</b>\n"
        f"Адрес: <code>{host}:{port}</code>\n"
        f"Время: {_now()}",
        TgLevel.SERVER
    )

def notify_server_stop():
    send("<b>Сервер остановлен</b>", TgLevel.SERVER)

def notify_register(username: str, ip: str, hwid_short: str = ""):
    send(
        f"<b>Новая регистрация</b>\n"
        f"Пользователь: <code>{username}</code>\n"
        f"IP: <code>{ip}</code>\n"
        f"HWID: <code>{hwid_short or '—'}</code>\n"
        f"Время: {_now()}",
        TgLevel.SUCCESS
    )

def notify_login(username: str, ip: str):
    send(
        f"<b>Вход</b>\n"
        f"Пользователь: <code>{username}</code>\n"
        f"IP: <code>{ip}</code>\n"
        f"Время: {_now()}",
        TgLevel.INFO
    )

def notify_login_fail(username: str, ip: str, reason: str = ""):
    send(
        f"<b>Неудачный вход</b>\n"
        f"Пользователь: <code>{username}</code>\n"
        f"IP: <code>{ip}</code>\n"
        f"Причина: {reason or 'неверный пароль'}\n"
        f"Время: {_now()}",
        TgLevel.WARNING
    )

def notify_hwid_mismatch(username: str, ip: str):
    send(
        f"<b>⚠️ HWID несовпадение</b>\n"
        f"Пользователь: <code>{username}</code>\n"
        f"IP: <code>{ip}</code>\n"
        f"Возможна попытка использования с чужого ПК\n"
        f"Время: {_now()}",
        TgLevel.WARNING
    )

def notify_ban(username: str, by: str = "admin"):
    send(
        f"<b>Пользователь заблокирован</b>\n"
        f"Аккаунт: <code>{username}</code>\n"
        f"Кем: {by}\n"
        f"Время: {_now()}",
        TgLevel.BAN
    )

def notify_unban(username: str):
    send(
        f"<b>Пользователь разблокирован</b>\n"
        f"Аккаунт: <code>{username}</code>\n"
        f"Время: {_now()}",
        TgLevel.SUCCESS
    )

def notify_funpay_purchase(buyer: str, order_id: str, invite_code: str):
    send(
        f"<b>Новая покупка FunPay</b>\n"
        f"Покупатель: <code>{buyer}</code>\n"
        f"Заказ: <code>#{order_id}</code>\n"
        f"Инвайт: <code>{invite_code}</code>\n"
        f"Время: {_now()}",
        TgLevel.SHOP
    )

def notify_funpay_error(order_id: str, error: str):
    send(
        f"<b>Ошибка FunPay бота</b>\n"
        f"Заказ: <code>#{order_id}</code>\n"
        f"Ошибка: {error}\n"
        f"Время: {_now()}",
        TgLevel.ERROR
    )

def notify_error(context: str, error: str):
    send(
        f"<b>Ошибка сервера</b>\n"
        f"Контекст: {context}\n"
        f"Ошибка: <code>{error[:200]}</code>\n"
        f"Время: {_now()}",
        TgLevel.ERROR
    )

def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
