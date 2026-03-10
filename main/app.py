import os, sys, time

AUTH_TOKEN  = os.environ.get("AUTH_TOKEN",  "")
AUTH_USER   = os.environ.get("AUTH_USER",   "")
AUTH_SERVER = os.environ.get("AUTH_SERVER", "")
AUTH_HWID   = os.environ.get("AUTH_HWID",   "")

if not AUTH_TOKEN or not AUTH_HWID:
    sys.exit(1)

def wait_enter():
    """input() не работает через popen stdin — читаем из терминала напрямую."""
    try:
        with open("/dev/tty", "r") as tty:
            tty.readline()
    except Exception:
        time.sleep(3)

def main():
    print()
    print("╔══════════════════════════════════════╗")
    print("║       МОЁ ПРИЛОЖЕНИЕ  v1.0           ║")
    print("╚══════════════════════════════════════╝")
    print()
    print(f"  Пользователь : {AUTH_USER}")
    print(f"  Сервер       : {AUTH_SERVER}")
    print()

    # === ПИШИ СВОЮ ЛОГИКУ ЗДЕСЬ ===
    for i in range(1, 6):
        print(f"    [{i}/5] работаю...")
        time.sleep(0.4)
    # ================================

    print("\n  Готово! Нажми Enter.")
    wait_enter()

if __name__ == "__main__":
    main()