"""Server settings, all read from environment variables."""
import os
import sys


def _req(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        sys.exit(f"Missing required environment variable: {name}")
    return val


PUBLIC_URL = _req("PUBLIC_URL").rstrip("/")          # e.g. https://mail-mcp.example.com
ENCRYPTION_KEY = _req("ENCRYPTION_KEY")              # Fernet key, generated on the server
SESSION_SECRET = _req("SESSION_SECRET")              # random string for signing cookies
# One-time code required by the /setup page. The owner password and the Google client
# secret are entered by the owner on that page and stored (hashed / encrypted) in the DB.
SETUP_CODE = os.environ.get("SETUP_CODE", "").strip()
GOOGLE_CLIENT_ID_DEFAULT = os.environ.get("GOOGLE_CLIENT_ID", "").strip()

DB_PATH = os.environ.get("DB_PATH", "/data/gmail_mcp.sqlite3")
PORT = int(os.environ.get("PORT", "8000"))


# Only these redirect URIs may be registered by MCP clients (Claude's callbacks).
ALLOWED_REDIRECT_URIS = [
    u.strip()
    for u in os.environ.get(
        "ALLOWED_REDIRECT_URIS",
        "https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback",
    ).split(",")
    if u.strip()
]
# Set to 1 to also allow loopback redirects (http://localhost:*/ , http://127.0.0.1:*/),
# which Claude Code / desktop proxies may use.
ALLOW_LOOPBACK_REDIRECTS = os.environ.get("ALLOW_LOOPBACK_REDIRECTS", "0") == "1"

ACCESS_TOKEN_TTL = 3600                 # 1 hour
REFRESH_TOKEN_TTL = 60 * 60 * 24 * 90   # 90 days, rotated on every use
AUTH_CODE_TTL = 300                     # 5 minutes

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
]
GOOGLE_REDIRECT_URI = f"{PUBLIC_URL}/admin/google/callback"
