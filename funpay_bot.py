"""
funpay_bot.py — Бот FunPay для автоматической выдачи инвайт-кодов

Что делает:
  1. Подключается к FunPay через golden_key
  2. Слушает события: новый заказ (OrderStatusChanged → PAID)
  3. При покупке создаёт инвайт-код через Auth Server API
  4. Отправляет код покупателю в личные сообщения FunPay

Запуск:
  pip install FunPayAPI requests python-dotenv
  python funpay_bot.py

Получение golden_key:
  1. Войди на funpay.com в браузере
  2. Установи расширение "Cookie Editor"
  3. Найди cookie "golden_key" и скопируй значение
"""

import os
import logging
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / "server/.env")
load_dotenv(Path(__file__).parent / ".env")

# ─── Telegram (опционально) ──────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent / "server"))
try:
    import telegram as tg
    _tg_available = True
except ImportError:
    _tg_available = False
    class _FakeTg:
        def __getattr__(self, name): return lambda *a, **k: None
    tg = _FakeTg()

# ─── FunPayAPI ────────────────────────────────────────────────────────────────
try:
    from FunPayAPI import Account, Runner
    from FunPayAPI.types import OrderShortcut
    from FunPayAPI import enums
except ImportError:
    print("[!] FunPayAPI не установлен. Запусти: pip install FunPayAPI")
    raise

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("data/funpay_bot.log", encoding="utf-8"),
    ]
)
log = logging.getLogger("funpay_bot")

# ─── Config из .env ───────────────────────────────────────────────────────────
GOLDEN_KEY  = os.getenv("FUNPAY_GOLDEN_KEY")
USER_AGENT  = os.getenv("FUNPAY_USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
AUTH_SERVER = os.getenv("AUTH_SERVER_URL", "http://127.0.0.1:8000")
ADMIN_KEY   = os.getenv("ADMIN_KEY")

if not GOLDEN_KEY:
    raise ValueError("FUNPAY_GOLDEN_KEY не задан в .env!")
if not ADMIN_KEY:
    raise ValueError("ADMIN_KEY не задан в .env!")

# ─── Сообщение покупателю (можно изменить) ────────────────────────────────────
MESSAGE_TEMPLATE = """✅ Спасибо за покупку!

Ваш инвайт-код для регистрации:
┌─────────────────────────┐
│  {invite_code}
└─────────────────────────┘

📌 Как использовать:
1. Запустите программу
2. Выберите "Регистрация"
3. Введите этот код

⚠️ Код одноразовый — не передавайте его другим.
Если возникнут проблемы — напишите мне."""

# ─── Auth Server API ──────────────────────────────────────────────────────────
def create_invite_code() -> str | None:
    """Создаёт один инвайт-код через Auth Server и возвращает его."""
    try:
        resp = requests.post(
            f"{AUTH_SERVER}/admin/invite",
            params={"count": 1},
            headers={"X-Admin-Key": ADMIN_KEY},
            timeout=10,
        )
        if resp.status_code == 200:
            codes = resp.json().get("codes", [])
            if codes:
                return codes[0]
        log.error(f"Ошибка создания инвайта: {resp.status_code} {resp.text}")
    except requests.RequestException as e:
        log.error(f"Не удалось подключиться к Auth Server: {e}")
    return None

# ─── Обработчики событий ──────────────────────────────────────────────────────
def on_order_status_changed(runner: Runner, event) -> None:
    """
    Вызывается когда статус заказа меняется.
    Нас интересует только переход в PAID (оплачен).
    """
    order: OrderShortcut = event.order

    # Проверяем что заказ именно оплачен
    if order.status != enums.OrderStatuses.PAID:
        return

    log.info(f"Новый оплаченный заказ: #{order.id} от {order.buyer_username}")

    # Создаём инвайт-код
    invite_code = create_invite_code()
    if not invite_code:
        log.error(f"Не удалось создать инвайт для заказа #{order.id}")
        tg.notify_funpay_error(str(order.id), "Не удалось создать инвайт-код")
        # Уведомляем покупателя об ошибке
        try:
            runner.account.send_message(
                order.buyer_id,
                "❌ Произошла ошибка при создании кода. Напишите продавцу — он выдаст вручную."
            )
        except Exception as e:
            log.error(f"Ошибка отправки сообщения об ошибке: {e}")
        return

    # Отправляем код покупателю
    message = MESSAGE_TEMPLATE.format(invite_code=invite_code)
    try:
        runner.account.send_message(order.buyer_id, message)
        log.info(f"[✓] Код {invite_code} отправлен покупателю {order.buyer_username} (заказ #{order.id})")
        tg.notify_funpay_purchase(order.buyer_username, str(order.id), invite_code)
    except Exception as e:
        log.error(f"Ошибка отправки сообщения покупателю {order.buyer_username}: {e}")
        # Код уже создан — логируем чтобы выдать вручную
        log.warning(f"ВЫДАТЬ ВРУЧНУЮ: {order.buyer_username} → {invite_code}")


def on_new_message(runner: Runner, event) -> None:
    """
    Опционально: отвечаем на входящие сообщения.
    Например если покупатель написал первым до покупки.
    """
    msg = event.message
    # Пропускаем свои сообщения
    if msg.author_id == runner.account.id:
        return

    text = msg.text.lower().strip()

    # Автоответ на частые вопросы
    auto_replies = {
        "привет":    "Привет! 👋 Чем могу помочь?",
        "цена":      "Цена указана в объявлении. Покупайте через FunPay — код придёт автоматически.",
        "как купить": "Нажмите кнопку 'Купить' в объявлении. После оплаты код придёт автоматически в этот чат.",
        "не пришёл": "Попробуйте подождать 1-2 минуты. Если код не пришёл — напишите и я выдам вручную.",
    }

    for keyword, reply in auto_replies.items():
        if keyword in text:
            try:
                runner.account.send_message(msg.author_id, reply)
                log.info(f"Авто-ответ '{keyword}' → {msg.author_id}")
            except Exception as e:
                log.error(f"Ошибка авто-ответа: {e}")
            break


# ─── Запуск ───────────────────────────────────────────────────────────────────
def main():
    log.info("Запуск FunPay бота...")
    log.info(f"Auth Server: {AUTH_SERVER}")

    # Проверяем доступность Auth Server
    try:
        resp = requests.get(f"{AUTH_SERVER}/admin/stats",
                            headers={"X-Admin-Key": ADMIN_KEY}, timeout=5)
        if resp.status_code == 200:
            stats = resp.json()
            log.info(f"Auth Server онлайн. Свободных инвайтов: {stats.get('free_invites', '?')}")
        else:
            log.warning(f"Auth Server ответил {resp.status_code} — проверь ADMIN_KEY")
    except Exception as e:
        log.warning(f"Auth Server недоступен: {e}")

    # Подключаемся к FunPay
    log.info("Подключение к FunPay...")
    account = Account(GOLDEN_KEY, USER_AGENT).get()
    log.info(f"Авторизован как: {account.username} (ID: {account.id})")
    log.info(f"Баланс: {account.balance} ₽")

    # Создаём Runner — он держит соединение и раздаёт события
    runner = Runner(account)

    # Подписываемся на события
    runner.add_event_handler(
        enums.EventTypes.ORDER_STATUS_CHANGED,
        on_order_status_changed
    )
    runner.add_event_handler(
        enums.EventTypes.NEW_MESSAGE,
        on_new_message
    )

    log.info("Бот запущен. Ожидание заказов...")
    log.info("Для остановки нажми Ctrl+C")

    try:
        runner.run()
    except KeyboardInterrupt:
        log.info("Бот остановлен.")


def run_bot():
    """Точка входа для запуска из main.py (автозапуск при старте сервера)."""
    main()

if __name__ == "__main__":
    main()
