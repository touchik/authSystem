# 🔐 Auth System v4.0

A software licensing and copy-protection system built on **FastAPI + SQLite + C++ client**.

The user **never receives the application file directly** — it is downloaded from the server in encrypted form and executed entirely in memory, only after successful authentication and hardware verification.

---

## 📐 Architecture

```
┌──────────────────────────────────────────────────────────┐
│                      auth_client.cpp                     │
│                                                          │
│  1. ECDH X25519 handshake → shared secret               │
│  2. AES-256-GCM encryption for all requests             │
│  3. Login / registration (encrypted)                    │
│  4. Ping every 5 minutes (server can revoke access)     │
│  5. Request payload → decrypt in memory → execute       │
└────────────────────┬─────────────────────────────────────┘
                     │  HTTPS / HTTP
┌────────────────────▼─────────────────────────────────────┐
│                    server/main.py (FastAPI)               │
│                                                          │
│  /handshake        — ECDH key exchange                  │
│  /secure/register  — registration (encrypted)           │
│  /secure/login     — login (encrypted)                  │
│  /secure/ping      — session keep-alive check           │
│  /secure/launch    — deliver encrypted payload          │
│  /admin/*          — user management                    │
└──────────┬────────────────────────┬──────────────────────┘
           │                        │
    ┌──────▼──────┐        ┌────────▼──────┐
    │  auth.db    │        │  Telegram Bot │
    │  (SQLite)   │        │  (alerts)     │
    └─────────────┘        └───────────────┘
```

---

## ✨ Key Features

### 🔒 Security
- **ECDH X25519** — every session uses a unique ephemeral key. Intercepting traffic yields nothing.
- **HKDF-SHA256** — AES key derivation from the shared secret. The standard used in Signal Protocol.
- **AES-256-GCM** — authenticated encryption. Protects against data tampering.
- **PBKDF2-SHA256** with 260,000 iterations — secure password storage.
- **JWT tokens** (HS256) with configurable TTL.
- **HWID binding** — the program binds to the user's hardware on first login. Sharing credentials with another person is impossible without an admin HWID reset.

### 🛡️ Payload Protection
- The application file is **never written to disk** on the client.
- The payload is downloaded encrypted, decrypted in RAM, and executed immediately.
- Supports: **Python**, **Lua**, **Shell/Bash**, **Batch**, **EXE**.
- The payload itself also verifies HWID via environment variables (double protection).

### 👁️ Monitoring
- **Telegram alerts** in real time: registrations, logins, bans, errors, purchases.
- **Audit log** of all events stored in SQLite.
- **Ping system** — the server can revoke access at any time (client will notice on the next ping, within 5 minutes at most).

### 🛒 FunPay Integration (optional)
- Bot automatically issues invite codes when a purchase is made on FunPay.
- Notifies Telegram on every purchase.

---

## 📁 Project Structure

```
project/
├── server/
│   ├── main.py              # Main FastAPI server
│   ├── crypto.py            # ECDH + AES encryption (server side)
│   ├── telegram.py          # Telegram notifications
│   ├── funpay_bot.py        # FunPay bot (optional)
│   ├── .env                 # Configuration (do NOT commit to git!)
│   ├── data/
│   │   ├── auth.db          # SQLite database
│   │   ├── auth.log         # Server log file
│   │   └── keys.json        # Auto-generated SECRET/ADMIN keys
│   └── payload/
│       ├── app.py           # Your application (Python)
│       ├── app.lua          # Your application (Lua)
│       ├── app.sh           # Your application (Shell)
│       └── app.exe          # Your application (compiled binary)
├── client/
│   └── auth_client.cpp      # C++ client
└── README.md
```

---

## 🚀 Server Installation

### Requirements
- Python 3.10+
- pip

### 1. Clone the repository and navigate to the server folder

```bash
cd server/
```

### 2. Install dependencies

```bash
pip install fastapi uvicorn[standard] pyjwt cryptography python-dotenv slowapi requests
```

Or via `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 3. Create the `.env` file

Copy `.env.example` and fill it in:

```bash
cp .env.example .env
```

```ini
# Secret keys (can be left empty — auto-generated in keys.json on first run)
SECRET_KEY=         # JWT signing key. If empty, loaded from keys.json
ADMIN_KEY=          # Key for /admin/* endpoints. CHANGE THIS!

# Server
HOST=0.0.0.0
PORT=8000
JWT_EXPIRE_HOURS=24

# Telegram notifications (optional)
TG_TOKEN=           # Bot token from @BotFather
TG_CHAT_ID=         # Chat ID to send alerts to

# Payload (which file to deliver to clients)
PAYLOAD_FILE=main/app.py   # Path to your application file

# FunPay (optional)
FUNPAY_ENABLED=0
FUNPAY_GOLDEN_KEY=
```

### 4. Place your application in the `payload/` folder

```bash
cp my_app.py server/payload/app.py
```

### 5. Start the server

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

On first run, automatically:
- `data/auth.db` (SQLite) is created
- Keys are generated in `data/keys.json`
- The `ADMIN_KEY` is printed to the console — **save it**

### 6. Create the first invite code

```bash
curl -X POST "http://localhost:8000/admin/invite" \
     -H "x-admin-key: YOUR_ADMIN_KEY"
```

---

## 🔨 Building the Client

### Requirements
- GCC / Clang with C++17 support
- libcurl
- OpenSSL 3.x

### Linux / macOS

```bash
g++ -O2 -std=c++17 auth_client.cpp -lcurl -lssl -lcrypto -o auth_client
```

### Windows (MinGW)

```bash
g++ -O2 -std=c++17 auth_client.cpp -lcurl -lssl -lcrypto -lws2_32 -o auth_client.exe
```

### Running the Client

```bash
./auth_client http://YOUR_SERVER:8000
```

Defaults to `http://127.0.0.1:8000` if no argument is given.

---

## 🎯 How It Works — Step by Step

```
Client                                    Server
  │                                          │
  │  GET /handshake                          │
  │─────────────────────────────────────────►│  Generates ECDH key pair
  │◄─────────────────────────────────────────│  { session_id, server_pub_key }
  │                                          │
  │  Client generates its own ECDH pair      │
  │  Computes shared_secret                  │
  │  AES_key = HKDF(shared_secret)           │
  │                                          │
  │  POST /handshake  { client_pub_key }     │
  │─────────────────────────────────────────►│  Derives the same AES_key
  │◄─────────────────────────────────────────│  { ok }
  │                                          │
  │  All further requests are AES-encrypted  │
  │                                          │
  │  POST /secure/login [encrypted]          │
  │─────────────────────────────────────────►│  Verifies password + HWID
  │◄─────────────────────────────────────────│  { JWT_token } [encrypted]
  │                                          │
  │  POST /secure/launch [encrypted]         │
  │─────────────────────────────────────────►│  Checks JWT + HWID + ban status
  │◄─────────────────────────────────────────│  { encrypted_payload }
  │                                          │
  │  Decrypts payload in RAM                 │
  │  Executes (python/lua/sh/exe)            │
  │                                          │
  │  POST /secure/ping  every 5 min         │
  │─────────────────────────────────────────►│  Checks: banned? HWID ok?
  │◄─────────────────────────────────────────│  { ok } or 401/403 → client exits
```

---

## 🛠️ Admin API

All `/admin/*` endpoints require the header `x-admin-key: YOUR_ADMIN_KEY`.

### Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/users` | List all users |
| DELETE | `/admin/users/{username}` | Delete a user |
| POST | `/admin/users/{username}/ban` | Ban a user |
| POST | `/admin/users/{username}/unban` | Unban a user |
| DELETE | `/admin/users/{username}/hwid` | Reset HWID binding |

### Invites

| Method | Path | Description |
|--------|------|-------------|
| POST | `/admin/invite?count=5` | Generate N invite codes |
| GET | `/admin/invites` | List all invites |

### Sessions & Audit

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/sessions` | Active sessions |
| GET | `/admin/audit?limit=200` | Audit log |
| GET | `/admin/stats` | Server statistics |

### Payload

| Method | Path | Description |
|--------|------|-------------|
| POST | `/admin/payload/upload` | Upload a new file |
| GET | `/admin/payload/list` | List available files |
| DELETE | `/admin/payload/{filename}` | Delete a file |

### Keys

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/keys/info` | Key info (lengths, source) |
| POST | `/admin/keys/rotate?rotate_admin=true` | Rotate ADMIN_KEY |
| POST | `/admin/keys/rotate?rotate_secret=true` | Rotate SECRET_KEY ⚠️ invalidates all tokens |

---

## 📦 Writing Your Own Payload

### Python (recommended)

Template `payload/app.py`:

```python
import os, sys, time

AUTH_TOKEN  = os.environ.get("AUTH_TOKEN",  "")
AUTH_USER   = os.environ.get("AUTH_USER",   "")
AUTH_SERVER = os.environ.get("AUTH_SERVER", "")
AUTH_HWID   = os.environ.get("AUTH_HWID",   "")

# Required guard — won't run without the auth client
if not AUTH_TOKEN or not AUTH_HWID:
    sys.exit(1)

def main():
    print(f"Hello, {AUTH_USER}!")
    # === YOUR LOGIC HERE ===

if __name__ == "__main__":
    main()
```

### Available Environment Variables in Payload

| Variable | Description |
|----------|-------------|
| `AUTH_TOKEN` | JWT token for the current session |
| `AUTH_USER` | Authenticated username |
| `AUTH_SERVER` | Server address (for additional requests) |
| `AUTH_HWID` | SHA-256 hardware fingerprint of the client machine |

### Shell

```bash
#!/bin/bash
[ -z "$AUTH_HWID" ] && exit 1
echo "Hello, $AUTH_USER!"
# your logic here
```

### Lua

```lua
local AUTH_HWID = os.getenv("AUTH_HWID") or ""
if AUTH_HWID == "" then os.exit(1) end
print("Hello, " .. (os.getenv("AUTH_USER") or "") .. "!")
-- your logic here
```

---

## 📲 Setting Up Telegram Notifications

1. Create a bot via [@BotFather](https://t.me/BotFather) — get the **TOKEN**
2. Send your bot any message
3. Open `https://api.telegram.org/bot<TOKEN>/getUpdates`
4. Find `"chat":{"id": ...}` — that is your **CHAT_ID**
5. Add to `.env`:

```ini
TG_TOKEN=123456789:AABBccddEEff...
TG_CHAT_ID=987654321
```

### Events Sent to Telegram

- ✅ New registration (username, IP, HWID)
- ℹ️ Successful login
- ⚠️ Failed login / HWID mismatch
- 🔨 User banned / unbanned
- 🛒 New FunPay purchase
- ❌ Server errors
- 🖥️ Server start / stop

---

## 🔄 Production Deployment

### systemd (Linux)

Create `/etc/systemd/system/auth-server.service`:

```ini
[Unit]
Description=Auth Server
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/auth-server/server
ExecStart=uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> ⚠️ Use `--workers 1`. With multiple workers, ECDH sessions (stored in-memory) won't be shared between processes.

```bash
systemctl enable auth-server
systemctl start auth-server
```

### HTTPS (recommended for production)

Using Nginx as a reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

Or directly via uvicorn with SSL:

```bash
uvicorn main:app --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt
```

---

## 🖥️ Web Admin Console

`admin.html` is a standalone browser-based management panel. No installation required — just open the file in any browser.

### Opening

```bash
open server/admin.html          # macOS
xdg-open server/admin.html      # Linux
start server/admin.html         # Windows
```

Or use `File → Open` in any browser. The file runs entirely client-side and connects to the server via the Admin API.

### Login Screen

| Field | Description |
|-------|-------------|
| **Server URL** | Address of the FastAPI server, e.g. `http://127.0.0.1:8000` |
| **Admin Key** | Your `ADMIN_KEY` from `.env` or `keys.json` |

Press **Enter** in either field to log in quickly.

---

### 📊 Dashboard

The home screen with overall server statistics.

**Metric cards** — refresh on every page load and show a trend indicator (▲/▼) compared to the previous visit:

| Card | What it shows |
|------|---------------|
| Users | Total number of registered accounts |
| Free invites | Unused invite codes |
| Used invites | Already-redeemed codes |
| Logins 24h | Successful logins in the last 24 hours |

**Mini charts** — two bar charts for the last 7 days:
- Logins per day
- Registrations per day

**Recent events feed** — the latest 8 audit log entries displayed directly on the dashboard.

---

### 👤 Users

A table of all registered accounts.

**Table columns:**

| Column | Description |
|--------|-------------|
| # | Database ID |
| Name | Username |
| Status | `active` (green) / `banned` (red) |
| HWID | First 10 characters of the SHA-256 fingerprint (full value in tooltip) |
| Invite | The code used to register |
| IP | IP address at registration time |
| Registered | Account creation date and time |
| Last login | Date and time of the most recent login |

**Search** — filters by username or IP address in real time.

**Per-user actions:**

| Button | Action |
|--------|--------|
| `ban` | Block the account (user gets 403 on the next ping) |
| `unban` | Remove the block |
| `delete` | Permanently delete the account (with confirmation dialog) |
| `hwid↺` | Reset HWID binding — allows the user to log in from a different machine |

---

### 🔗 Active Sessions

Shows all users who have an active session record in the database.

Each session card displays:
- Username
- Connection IP address
- HWID (first 10 characters)
- Session creation time
- Last ping time

> A session is "active" as long as the JWT token has not expired. The user may already be offline — the ping updates every 5 minutes.

---

### 🔑 Invite Codes

Managing invite codes for registration.

**Creating codes:**
- Enter a quantity (1–100) and click `+ Create codes`
- New codes appear immediately above the table
- Click any code to copy it to clipboard (briefly shows ✓)

**Invite table:**

| Column | Description |
|--------|-------------|
| Code | The invite code itself (click to copy) |
| Status | `free` / `used` |
| Created | Generation date and time |
| Used by | Username of the account that redeemed the code |

**Filters:**
- Search by code or username
- **"Free only"** checkbox — hides already-used codes

---

### 📋 Event Log

A complete history of all system actions (up to the latest 500 records).

**Event types and their colors:**

| Event | Color | Description |
|-------|-------|-------------|
| `LOGIN_OK` | 🟢 green | Successful login |
| `LOGIN_FAIL` | 🔴 red | Wrong password |
| `REGISTER_OK` | 🔵 blue | Successful registration |
| `REGISTER_FAIL` | 🟡 yellow | Registration error |
| `INVITE_CREATED` | 🔵 blue | Invites generated |
| `USER_BANNED` | 🔴 red | Account banned |
| `USER_UNBANNED` | 🟢 green | Account unbanned |
| `HWID_MISMATCH` | 🔴 red | HWID did not match |
| `HWID_RESET` | 🟡 yellow | HWID cleared |
| `PING_OK` | 🟢 green | Ping accepted |
| `PING_BANNED` | 🔴 red | Ping from a banned user |
| `LAUNCH_OK` | 🟢 green | Payload delivered |

**Filters:**
- Free-text search across all fields (event, username, IP, details)
- Dropdown for quick filtering by event type: Logins / Failed logins / Registrations / Bans / HWID events

---

### ⚙️ Settings

| Setting | Description |
|---------|-------------|
| **Server URL** | Displays the current connection address (read-only) |
| **Status** | `Online ✓` if the server is responding |
| **Auto-refresh** | Toggle — automatically reload the active page every 30 seconds |
| **Sound notifications** | Toggle — play a sound when new events appear |
| **Logout** | Clear the session and return to the login screen |

---

### 🎨 Themes

4 themes are available, selected via the `ADMIN_THEME` variable in `.env`:

| Theme | Description |
|-------|-------------|
| *(default)* | Dark theme with green accent, terminal aesthetic |
| `dark` | Dark with green — classic hacker style |
| `light` | Light minimalist theme |
| `cyberpunk` | Neon colors, purple-pink accent |
| `aurora` | Dark with gradient northern lights |

Each theme is a separate HTML file in the `themes/` folder.

---

### Technical Notes

- The console is a **static HTML file** — no separate server needed
- All data is fetched directly from FastAPI via `fetch()`
- **Server ping** every 15 seconds — online/offline indicator in the header
- **Auto-refresh** of the active page every 30 seconds (can be disabled in Settings)
- Dashboard metric cards compare against the previous visit using `localStorage`
- The console does not persist the Admin Key between sessions — must be entered each time

---

## ⚠️ Known Limitations

| Issue | Description | Workaround |
|-------|-------------|------------|
| **Single worker** | ECDH sessions are in-memory, not shared across processes | Run with `--workers 1` |
| **Ban not instant** | JWT token remains valid until expiry (up to 24h) after ban | Lower `JWT_EXPIRE_HOURS` or implement a token blacklist |
| **CORS open** | `allow_origins=["*"]` | Restrict to your client's specific domain |
| **IP rate limiting** | Unreliable if `X-Forwarded-For` is spoofed | Deploy behind a trusted reverse proxy |

---

## 🔑 Key Management

Keys are stored in `data/keys.json` (auto-created on first run) with `600` permissions.

**Loading priority:**
```
.env → keys.json → auto-generation
```

Rotate ADMIN_KEY (without invalidating user tokens):

```bash
curl -X POST "http://localhost:8000/admin/keys/rotate?rotate_admin=true" \
     -H "x-admin-key: CURRENT_ADMIN_KEY"
```

Rotate SECRET_KEY (⚠️ all users will be logged out):

```bash
curl -X POST "http://localhost:8000/admin/keys/rotate?rotate_secret=true" \
     -H "x-admin-key: YOUR_ADMIN_KEY"
```

---

## 📋 Dependencies

### Server (Python)

```
fastapi
uvicorn[standard]
pyjwt
cryptography
python-dotenv
slowapi
requests
```

### Client (C++)

```
libcurl
openssl >= 3.0
```

---

## 📜 License

For personal and commercial use. Do not distribute server source code together with the client binary.
