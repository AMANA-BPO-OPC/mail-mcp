"""End-to-end test: OAuth flow for Claude, MCP endpoint, and Gmail tools against a fake Gmail API."""
import asyncio
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from urllib.parse import parse_qs, urlparse

from cryptography.fernet import Fernet

tmp = tempfile.mkdtemp()
os.environ.update({
    "PUBLIC_URL": "http://localhost:8765",
    "SETUP_CODE": "setup-code-123456",
    "GOOGLE_CLIENT_ID": "gid.apps.googleusercontent.com",
    "ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "SESSION_SECRET": "s" * 40,
    "DB_PATH": os.path.join(tmp, "t.sqlite3"),
})
ADMIN_PW = "correct-horse-battery-staple"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402

from app import gmail, store  # noqa: E402
from app.main import app, asgi, _failures  # noqa: E402


def _failures_reset():
    _failures.clear()

# ------------------------------------------------------------ fake Gmail API
SENT = []


def _b64(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


MAILBOX = {
    "a@wolfpack.test": {"m1": ("t1", "Supplier <sup@kr.test>", "a@wolfpack.test", "New order", "Two new orders please")},
    "b@mikshati.test": {"m2": ("t2", "Client <c@x.test>", "b@mikshati.test", "Invoice", "<p>Invoice <b>attached</b></p>")},
}


def fake_gmail(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url.startswith(gmail.TOKEN_URL):
        form = parse_qs(request.content.decode())
        if form["refresh_token"][0] == "revoked":
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(200, json={"access_token": "AT-" + form["refresh_token"][0], "expires_in": 3600})
    email = request.headers["authorization"].split("AT-RT-")[1]
    box = MAILBOX[email]
    path = request.url.path.split("/users/me")[1]
    if path == "/messages" and request.method == "GET":
        return httpx.Response(200, json={"messages": [{"id": k} for k in box]})
    if path.startswith("/messages/") and request.method == "GET":
        mid = path.split("/")[-1]
        tid, frm, to, subj, body = box[mid]
        return httpx.Response(200, json={
            "id": mid, "threadId": tid, "snippet": body[:20], "labelIds": ["INBOX"],
            "payload": {"headers": [{"name": "From", "value": frm}, {"name": "To", "value": to},
                                    {"name": "Subject", "value": subj}, {"name": "Message-ID", "value": f"<{mid}@x>"}]}})
    if path.startswith("/threads/"):
        mid = next(iter(box))
        tid, frm, to, subj, body = box[mid]
        mime = "text/html" if body.startswith("<") else "text/plain"
        return httpx.Response(200, json={"id": tid, "messages": [{
            "id": mid, "threadId": tid, "snippet": "",
            "payload": {"mimeType": "multipart/mixed", "headers": [{"name": "From", "value": frm}, {"name": "Subject", "value": subj}],
                        "parts": [{"mimeType": mime, "body": {"data": _b64(body)}},
                                  {"mimeType": "application/pdf", "filename": "inv.pdf", "body": {"size": 1234}}]}}]})
    if path in ("/messages/send", "/drafts"):
        payload = json.loads(request.content)
        raw = (payload.get("message") or payload)["raw"]
        SENT.append((email, path, base64.urlsafe_b64decode(raw + "==").decode()))
        return httpx.Response(200, json={"id": "new1", "threadId": payload.get("threadId", "tnew"),
                                          "message": {"id": "new1"}})
    return httpx.Response(404)


gmail._http = httpx.AsyncClient(transport=httpx.MockTransport(fake_gmail))
store.save_account("a@wolfpack.test", "RT-a@wolfpack.test", "")
store.save_account("b@mikshati.test", "RT-b@mikshati.test", "")
store.save_account("c@old.test", "revoked", "")
store.update_account("b@mikshati.test", "مكشاتي", "Mikshati Store")

CB = "https://claude.ai/api/mcp/auth_callback"
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


async def main():
    async with app.router.lifespan_context(app):
        c = httpx.AsyncClient(transport=httpx.ASGITransport(app=asgi), base_url="http://localhost:8765")

        r = await c.get("/admin")
        check("unconfigured -> redirect to setup", r.status_code == 303 and r.headers["location"] == "/setup")
        r = await c.post("/mcp", json={})
        check("unconfigured mcp blocked", r.status_code == 303)
        base = {"pw1": ADMIN_PW, "pw2": ADMIN_PW, "client_id": "gid.apps.googleusercontent.com",
                "client_secret": "GOCSPX-secret-value"}
        r = await c.post("/setup", data={**base, "setup_code": "wrong"})
        check("setup rejects wrong code", r.status_code == 400 and not store.is_configured())
        r = await c.post("/setup", data={**base, "setup_code": "setup-code-123456", "pw2": "different-password-xx"})
        check("setup rejects mismatched pw", r.status_code == 400)
        _failures_reset()
        r = await c.post("/setup", data={**base, "setup_code": "setup-code-123456"})
        check("setup ok", r.status_code == 200 and store.is_configured()
              and store.get_setting("google_client_secret") == "GOCSPX-secret-value")
        r = await c.post("/setup", data={**base, "setup_code": "setup-code-123456", "pw1": "x" * 20, "pw2": "x" * 20})
        check("setup locked after first use", r.status_code == 303 and store.verify_password(ADMIN_PW))

        r = await c.get("/.well-known/oauth-authorization-server")
        check("AS metadata", r.json()["registration_endpoint"].endswith("/register"))
        r = await c.get("/.well-known/oauth-protected-resource/mcp")
        check("PR metadata", r.json()["resource"] == "http://localhost:8765/mcp")

        r = await c.post("/mcp", json={})
        check("mcp without token -> 401", r.status_code == 401 and "resource_metadata" in r.headers["www-authenticate"])
        r = await c.post("/mcp", json={}, headers={"Authorization": "Bearer nope"})
        check("mcp bad token -> 401", r.status_code == 401)

        r = await c.post("/register", json={"redirect_uris": ["https://evil.test/cb"]})
        check("DCR rejects foreign redirect", r.status_code == 400)
        r = await c.post("/register", json={"redirect_uris": [CB], "client_name": "Claude",
                                            "token_endpoint_auth_method": "client_secret_post"})
        reg = r.json()
        check("DCR ok with secret", r.status_code == 201 and reg.get("client_secret"))
        cid, csec = reg["client_id"], reg["client_secret"]

        verifier = "v" * 50
        chal = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        q = {"response_type": "code", "client_id": cid, "redirect_uri": CB, "code_challenge": chal,
             "code_challenge_method": "S256", "state": "xyz", "scope": "mail"}
        r = await c.get("/authorize", params={**q, "redirect_uri": "https://evil.test/cb"})
        check("authorize refuses unregistered redirect (no redirect)", r.status_code == 400)
        r = await c.get("/authorize", params=q)
        check("authorize page shown", r.status_code == 200 and "كلمة مرور" in r.text and r.headers["x-frame-options"] == "DENY")
        r = await c.post("/authorize", data={**q, "password": "wrong", "decision": "allow"})
        check("wrong password -> no code", r.status_code == 200 and "غير صحيحة" in r.text)
        r = await c.post("/authorize", data={**q, "password": ADMIN_PW, "decision": "allow"})
        loc = urlparse(r.headers["location"])
        qs = parse_qs(loc.query)
        check("correct password -> code + state", r.status_code == 302 and loc.netloc == "claude.ai" and qs["state"] == ["xyz"])
        code = qs["code"][0]

        r = await c.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                         "client_id": cid, "client_secret": csec, "code_verifier": "bad" * 20})
        check("bad PKCE verifier rejected", r.status_code == 400)
        # code was consumed by the failed attempt -> must get a new one
        r = await c.post("/authorize", data={**q, "password": ADMIN_PW, "decision": "allow"})
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
        r = await c.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                         "client_id": cid, "client_secret": "wrong", "code_verifier": verifier})
        check("wrong client secret rejected", r.status_code == 401)
        r = await c.post("/authorize", data={**q, "password": ADMIN_PW, "decision": "allow"})
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
        basic = base64.b64encode(f"{cid}:{csec}".encode()).decode()
        r = await c.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                         "code_verifier": verifier}, headers={"Authorization": f"Basic {basic}"})
        tok = r.json()
        check("token issued (basic auth)", r.status_code == 200 and tok.get("access_token"))
        r = await c.post("/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                         "client_id": cid, "client_secret": csec, "code_verifier": verifier})
        check("code reuse rejected", r.status_code == 400)

        r = await c.post("/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                         "client_id": cid, "client_secret": csec})
        tok2 = r.json()
        check("refresh works", r.status_code == 200 and tok2["access_token"] != tok["access_token"])
        r = await c.post("/token", data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"],
                                         "client_id": cid, "client_secret": csec})
        check("old refresh token rotated out", r.status_code == 400)

        H = {"Authorization": f"Bearer {tok2['access_token']}", "Accept": "application/json, text/event-stream",
             "Content-Type": "application/json", "MCP-Protocol-Version": "2025-06-18"}

        async def rpc(method, params=None, i=1):
            r = await c.post("/mcp", headers=H, json={"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}})
            return r

        r = await rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "clientInfo": {"name": "test", "version": "1"}})
        check("MCP initialize", r.status_code == 200 and r.json()["result"]["serverInfo"]["name"])
        r = await rpc("tools/list")
        names = sorted(t["name"] for t in r.json()["result"]["tools"])
        print("   tools:", names)
        check("tools listed", len(names) == 6)

        async def call(name, args):
            r = await rpc("tools/call", {"name": name, "arguments": args})
            res = r.json()["result"]
            txt = res["content"][0]["text"] if res.get("content") else ""
            return res, txt

        res, txt = await call("search_emails", {"query": "order", "account": "all"})
        data = json.loads(txt)
        check("search all accounts", data["a@wolfpack.test"]["messages"][0]["subject"] == "New order"
              and data["b@mikshati.test"]["messages"][0]["id"] == "m2"
              and "expired or was revoked" in data["c@old.test"]["error"])
        check("revoked account flagged", any(a["status"] == "reconnect_needed" for a in store.list_accounts()))

        res, txt = await call("search_emails", {"query": "x", "account": "مكشاتي"})
        check("search by Arabic label", "b@mikshati.test" in json.loads(txt))

        res, txt = await call("read_email_thread", {"account": "b@mikshati.test", "thread_id": "t2"})
        d = json.loads(txt)
        check("read thread html->text + attachments", "Invoice attached" in d["messages"][0]["body"]
              and d["messages"][0]["attachments"][0]["filename"] == "inv.pdf")

        res, txt = await call("send_email", {"account": "مكشاتي", "to": ["c@x.test"], "subject": "مرحبا",
                                             "body": "نص الرسالة"})
        em, path, raw = SENT[-1]
        check("send from chosen account", em == "b@mikshati.test" and path == "/messages/send"
              and "From: Mikshati Store <b@mikshati.test>" in raw)

        res, txt = await call("reply_to_email", {"account": "a@wolfpack.test", "message_id": "m1", "body": "Confirmed"})
        em, path, raw = SENT[-1]
        check("reply threaded", em == "a@wolfpack.test" and "In-Reply-To: <m1@x>" in raw
              and "Subject: Re: New order" in raw and "To: sup@kr.test" in raw)

        res, txt = await call("create_email_draft", {"account": "a@wolfpack.test", "body": "draft",
                                                     "reply_to_message_id": "m1"})
        check("draft created, not sent", SENT[-1][1] == "/drafts")

        res, txt = await call("send_email", {"account": "nobody@x", "to": ["a@b.c"], "subject": "s", "body": "b"})
        check("unknown account error", res.get("isError"))

        # admin pages
        r = await c.get("/admin")
        check("admin needs login", "دخول" in r.text and "a@wolfpack" not in r.text)
        r = await c.post("/admin/accounts/delete", data={"email": "a@wolfpack.test"})
        check("admin POST without session refused", r.status_code == 403)
        r = await c.post("/admin/login", data={"password": ADMIN_PW})
        check("admin login sets cookie", r.status_code == 303 and "admin_session" in r.cookies)
        check("admin cookie is SameSite=Lax (survives Google redirect)", "samesite=lax" in r.headers["set-cookie"].lower())
        r = await c.get("/admin")
        check("admin lists accounts", "a@wolfpack.test" in r.text)
        r = await c.post("/admin/accounts/update", data={"email": "a@wolfpack.test", "label": "ولف باك", "display_name": "Wolfpack"},
                         headers={"Origin": "https://evil.test"})
        check("cross-origin admin POST refused", r.status_code == 403)
        r = await c.get("/admin/google/start")
        check("google consent redirect", r.status_code == 302 and "access_type=offline" in r.headers["location"]
              and "gmail.compose" in r.headers["location"])
        r = await c.post("/admin/revoke-sessions")
        r = await rpc("tools/list")
        check("revoke sessions kills tokens", r.status_code == 401)

    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    sys.exit(1 if failed else 0)


asyncio.run(main())
