"""SQLite storage. Google refresh tokens are encrypted; our own tokens are stored only as hashes."""
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time

from cryptography.fernet import Fernet

from . import config

_lock = threading.Lock()
_fernet = Fernet(config.ENCRYPTION_KEY.encode())


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(config.DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


_db = _connect()


def init() -> None:
    with _lock:
        _db.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                email TEXT PRIMARY KEY,
                label TEXT NOT NULL DEFAULT '',
                display_name TEXT NOT NULL DEFAULT '',
                refresh_token_enc BLOB NOT NULL,
                status TEXT NOT NULL DEFAULT 'ok',
                added_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_secret_hash TEXT,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_codes (
                code_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                scope TEXT,
                resource TEXT,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tokens (
                token_hash TEXT PRIMARY KEY,
                kind TEXT NOT NULL,              -- 'access' or 'refresh'
                client_id TEXT NOT NULL,
                scope TEXT,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value_enc BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS google_states (
                state TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );
            """
        )
        _db.commit()


def h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def _purge_expired() -> None:
    now = int(time.time())
    for table in ("auth_codes", "tokens", "google_states"):
        _db.execute(f"DELETE FROM {table} WHERE expires_at < ?", (now,))


# ---------- Google accounts ----------

def save_account(email: str, refresh_token: str, display_name: str) -> None:
    enc = _fernet.encrypt(refresh_token.encode())
    with _lock:
        _db.execute(
            """INSERT INTO accounts (email, refresh_token_enc, display_name, status, added_at)
               VALUES (?, ?, ?, 'ok', ?)
               ON CONFLICT(email) DO UPDATE SET refresh_token_enc=excluded.refresh_token_enc,
                    status='ok'""",
            (email.lower(), enc, display_name, int(time.time())),
        )
        _db.commit()


def list_accounts() -> list[dict]:
    with _lock:
        rows = _db.execute(
            "SELECT email, label, display_name, status FROM accounts ORDER BY email"
        ).fetchall()
    return [dict(r) for r in rows]


def get_refresh_token(email: str) -> str | None:
    with _lock:
        row = _db.execute(
            "SELECT refresh_token_enc FROM accounts WHERE email=?", (email.lower(),)
        ).fetchone()
    return _fernet.decrypt(row["refresh_token_enc"]).decode() if row else None


def update_account(email: str, label: str, display_name: str) -> None:
    with _lock:
        _db.execute(
            "UPDATE accounts SET label=?, display_name=? WHERE email=?",
            (label.strip(), display_name.strip(), email.lower()),
        )
        _db.commit()


def set_account_status(email: str, status: str) -> None:
    with _lock:
        _db.execute("UPDATE accounts SET status=? WHERE email=?", (status, email.lower()))
        _db.commit()


def delete_account(email: str) -> None:
    with _lock:
        _db.execute("DELETE FROM accounts WHERE email=?", (email.lower(),))
        _db.commit()


# ---------- OAuth clients (dynamic registration) ----------

def register_client(data: dict, with_secret: bool) -> tuple[str, str | None]:
    client_id = new_secret(16)
    secret = new_secret(32) if with_secret else None
    with _lock:
        _db.execute(
            "INSERT INTO oauth_clients VALUES (?, ?, ?, ?)",
            (client_id, h(secret) if secret else None, json.dumps(data), int(time.time())),
        )
        _db.commit()
    return client_id, secret


def get_client(client_id: str) -> dict | None:
    with _lock:
        row = _db.execute(
            "SELECT client_secret_hash, data FROM oauth_clients WHERE client_id=?", (client_id,)
        ).fetchone()
    if not row:
        return None
    d = json.loads(row["data"])
    d["_secret_hash"] = row["client_secret_hash"]
    return d


# ---------- Authorization codes ----------

def save_code(client_id, redirect_uri, code_challenge, scope, resource) -> str:
    code = new_secret(32)
    with _lock:
        _purge_expired()
        _db.execute(
            "INSERT INTO auth_codes VALUES (?, ?, ?, ?, ?, ?, ?)",
            (h(code), client_id, redirect_uri, code_challenge, scope, resource,
             int(time.time()) + config.AUTH_CODE_TTL),
        )
        _db.commit()
    return code


def pop_code(code: str) -> dict | None:
    """Fetch and delete a code in one step, so it can only be used once."""
    with _lock:
        row = _db.execute(
            "SELECT * FROM auth_codes WHERE code_hash=? AND expires_at>=?",
            (h(code), int(time.time())),
        ).fetchone()
        _db.execute("DELETE FROM auth_codes WHERE code_hash=?", (h(code),))
        _db.commit()
    return dict(row) if row else None


# ---------- Access / refresh tokens ----------

def issue_tokens(client_id: str, scope: str | None) -> dict:
    access, refresh = new_secret(32), new_secret(32)
    now = int(time.time())
    with _lock:
        _purge_expired()
        _db.execute("INSERT INTO tokens VALUES (?, 'access', ?, ?, ?)",
                    (h(access), client_id, scope, now + config.ACCESS_TOKEN_TTL))
        _db.execute("INSERT INTO tokens VALUES (?, 'refresh', ?, ?, ?)",
                    (h(refresh), client_id, scope, now + config.REFRESH_TOKEN_TTL))
        _db.commit()
    out = {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": config.ACCESS_TOKEN_TTL,
        "refresh_token": refresh,
    }
    if scope:
        out["scope"] = scope
    return out


def check_access_token(token: str) -> bool:
    with _lock:
        row = _db.execute(
            "SELECT 1 FROM tokens WHERE token_hash=? AND kind='access' AND expires_at>=?",
            (h(token), int(time.time())),
        ).fetchone()
    return row is not None


def pop_refresh_token(token: str, client_id: str) -> dict | None:
    with _lock:
        row = _db.execute(
            "SELECT * FROM tokens WHERE token_hash=? AND kind='refresh' AND client_id=? AND expires_at>=?",
            (h(token), client_id, int(time.time())),
        ).fetchone()
        _db.execute("DELETE FROM tokens WHERE token_hash=?", (h(token),))
        _db.commit()
    return dict(row) if row else None


def revoke_all_tokens() -> None:
    with _lock:
        _db.execute("DELETE FROM tokens")
        _db.commit()


# ---------- Google OAuth state ----------

def new_google_state() -> str:
    state = new_secret(24)
    with _lock:
        _purge_expired()
        _db.execute("INSERT INTO google_states VALUES (?, ?)", (state, int(time.time()) + 600))
        _db.commit()
    return state


def pop_google_state(state: str) -> bool:
    with _lock:
        row = _db.execute(
            "SELECT 1 FROM google_states WHERE state=? AND expires_at>=?",
            (state, int(time.time())),
        ).fetchone()
        _db.execute("DELETE FROM google_states WHERE state=?", (state,))
        _db.commit()
    return row is not None


# ---------- settings (encrypted) ----------

def set_setting(key: str, value: str) -> None:
    with _lock:
        _db.execute("INSERT INTO settings VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value_enc=excluded.value_enc",
                    (key, _fernet.encrypt(value.encode())))
        _db.commit()


def get_setting(key: str) -> str | None:
    with _lock:
        row = _db.execute("SELECT value_enc FROM settings WHERE key=?", (key,)).fetchone()
    return _fernet.decrypt(row["value_enc"]).decode() if row else None


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + ":" + dk.hex()


def verify_password(pw: str) -> bool:
    stored = get_setting("admin_password_hash")
    if not stored:
        return False
    salt_hex, dk_hex = stored.split(":")
    dk = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
    import hmac
    return hmac.compare_digest(dk.hex(), dk_hex)


def is_configured() -> bool:
    return bool(get_setting("admin_password_hash") and get_setting("google_client_secret")
                and get_setting("google_client_id"))
