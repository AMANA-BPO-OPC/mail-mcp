"""Entry point: OAuth server for Claude + admin pages for Google accounts + the MCP endpoint."""
import base64
import hashlib
import hmac
import html
import time
from urllib.parse import urlencode, urlparse

import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Route

from . import config, gmail, store
from .tools import mcp

store.init()
P = config.PUBLIC_URL

# ---------------------------------------------------------------- helpers

_failures: list[float] = []   # timestamps of failed password attempts (single-owner server)


def _locked() -> bool:
    now = time.time()
    _failures[:] = [t for t in _failures if now - t < 900]
    return len(_failures) >= 10


def _check_password(pw: str) -> bool:
    if _locked():
        return False
    ok = store.verify_password(pw)
    if not ok:
        _failures.append(time.time())
    return ok


def _sign(value: str) -> str:
    return hmac.new(config.SESSION_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()


def _is_admin(request: Request) -> bool:
    c = request.cookies.get("admin_session", "")
    try:
        exp, sig = c.split(".", 1)
        return hmac.compare_digest(sig, _sign(exp)) and int(exp) > time.time()
    except ValueError:
        return False


def _same_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    return origin is None or origin == P


SEC_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https:; frame-ancestors 'none'",
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    doc = f"""<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Tahoma,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#1d1d1f;background:#fafafa}}
h1{{font-size:22px}} .card{{background:#fff;border:1px solid #e5e5e5;border-radius:12px;padding:16px;margin:12px 0}}
input[type=text],input[type=password]{{width:100%;padding:10px;border:1px solid #ccc;border-radius:8px;box-sizing:border-box;margin:4px 0 10px}}
button,.btn{{background:#1d1d1f;color:#fff;border:0;border-radius:8px;padding:10px 16px;cursor:pointer;text-decoration:none;display:inline-block;font-size:14px}}
.danger{{background:#b42318}} .muted{{color:#666;font-size:13px}} .bad{{color:#b42318;font-weight:600}}
code{{direction:ltr;unicode-bidi:embed;background:#f0f0f0;padding:2px 6px;border-radius:4px}}
</style></head><body>{body}</body></html>"""
    return HTMLResponse(doc, status_code=status, headers=SEC_HEADERS)


def oauth_error(error: str, desc: str = "", status: int = 400) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": desc}, status_code=status,
                        headers={"Cache-Control": "no-store"})


def _redirect_allowed(uri: str) -> bool:
    if uri in config.ALLOWED_REDIRECT_URIS:
        return True
    if config.ALLOW_LOOPBACK_REDIRECTS:
        u = urlparse(uri)
        return u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1")
    return False


# ---------------------------------------------------------------- discovery metadata

AS_METADATA = {
    "issuer": P,
    "authorization_endpoint": f"{P}/authorize",
    "token_endpoint": f"{P}/token",
    "registration_endpoint": f"{P}/register",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code", "refresh_token"],
    "code_challenge_methods_supported": ["S256"],
    "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
    "scopes_supported": ["mail"],
}
PR_METADATA = {
    "resource": f"{P}/mcp",
    "authorization_servers": [P],
    "scopes_supported": ["mail"],
    "bearer_methods_supported": ["header"],
}


async def as_metadata(request):
    return JSONResponse(AS_METADATA)


async def pr_metadata(request):
    return JSONResponse(PR_METADATA)


# ---------------------------------------------------------------- dynamic client registration

async def register(request: Request):
    try:
        data = await request.json()
    except Exception:
        return oauth_error("invalid_client_metadata", "JSON body required")
    uris = data.get("redirect_uris") or []
    if not uris or not all(isinstance(u, str) and _redirect_allowed(u) for u in uris):
        return oauth_error("invalid_redirect_uri", "redirect_uri not allowed on this server")
    method = data.get("token_endpoint_auth_method", "client_secret_basic")
    if method not in AS_METADATA["token_endpoint_auth_methods_supported"]:
        return oauth_error("invalid_client_metadata", "unsupported token_endpoint_auth_method")
    meta = {
        "redirect_uris": uris,
        "client_name": str(data.get("client_name", ""))[:100],
        "token_endpoint_auth_method": method,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }
    client_id, secret = store.register_client(meta, with_secret=(method != "none"))
    out = {**meta, "client_id": client_id, "client_id_issued_at": int(time.time())}
    if secret:
        out["client_secret"] = secret
        out["client_secret_expires_at"] = 0
    return JSONResponse(out, status_code=201, headers={"Cache-Control": "no-store"})


# ---------------------------------------------------------------- authorization endpoint

AUTH_PARAMS = ("response_type", "client_id", "redirect_uri", "code_challenge",
               "code_challenge_method", "state", "scope", "resource")


async def authorize(request: Request):
    params = dict(request.query_params) if request.method == "GET" else dict(await request.form())
    client = store.get_client(params.get("client_id", ""))
    redirect_uri = params.get("redirect_uri", "")
    # Never redirect to an unverified URI: show the error on our own page instead.
    if not client or redirect_uri not in client["redirect_uris"]:
        return page("خطأ", "<h1>طلب ربط غير صالح</h1><p>العميل أو عنوان الرجوع غير مسجّل.</p>", 400)

    def back(**q):
        if params.get("state"):
            q["state"] = params["state"]
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(f"{redirect_uri}{sep}{urlencode(q)}", status_code=302)

    if params.get("response_type") != "code":
        return back(error="unsupported_response_type")
    if not params.get("code_challenge") or params.get("code_challenge_method") != "S256":
        return back(error="invalid_request", error_description="PKCE S256 required")

    error_html = ""
    if request.method == "POST":
        if params.get("decision") == "deny":
            return back(error="access_denied")
        if _check_password(params.get("password", "")):
            code = store.save_code(params["client_id"], redirect_uri, params["code_challenge"],
                                   params.get("scope"), params.get("resource"))
            return back(code=code)
        error_html = ('<p class="bad">كلمة المرور غير صحيحة.</p>' if not _locked()
                      else '<p class="bad">محاولات كثيرة خاطئة. حاول بعد ١٥ دقيقة.</p>')

    hidden = "".join(
        f'<input type="hidden" name="{k}" value="{html.escape(params.get(k, ""))}">'
        for k in AUTH_PARAMS if params.get(k)
    )
    name = html.escape(client.get("client_name") or "عميل غير مسمّى")
    return page("ربط كلود بالبريد", f"""
<h1>طلب صلاحية الوصول إلى بريدك</h1>
<div class="card">
<p>التطبيق <b>{name}</b> يطلب الوصول إلى كل صناديق البريد المربوطة بهذا الخادم: البحث والقراءة والإرسال.</p>
<p class="muted">سيعود بعد الموافقة إلى: <code>{html.escape(redirect_uri)}</code></p>
{error_html}
<form method="post">{hidden}
<label>كلمة مرور المالك</label><input type="password" name="password" autocomplete="current-password" autofocus>
<button name="decision" value="allow">موافقة</button>
<button name="decision" value="deny" class="danger">رفض</button>
</form></div>""")


# ---------------------------------------------------------------- token endpoint

def _client_auth(request: Request, form) -> tuple[dict | None, str]:
    client_id, secret = form.get("client_id", ""), form.get("client_secret")
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            from urllib.parse import unquote
            cid, _, sec = base64.b64decode(auth[6:]).decode().partition(":")
            client_id, secret = unquote(cid), unquote(sec)
        except Exception:
            return None, "invalid_client"
    client = store.get_client(client_id)
    if not client:
        return None, "invalid_client"
    client["client_id"] = client_id
    if client["_secret_hash"]:
        if not secret or not hmac.compare_digest(store.h(secret), client["_secret_hash"]):
            return None, "invalid_client"
    return client, ""


async def token(request: Request):
    form = await request.form()
    client, err = _client_auth(request, form)
    if not client:
        return oauth_error(err, "client authentication failed", 401)
    grant = form.get("grant_type")

    if grant == "authorization_code":
        row = store.pop_code(form.get("code", ""))
        if not row or row["client_id"] != client["client_id"]:
            return oauth_error("invalid_grant", "code invalid or expired")
        if form.get("redirect_uri") and form["redirect_uri"] != row["redirect_uri"]:
            return oauth_error("invalid_grant", "redirect_uri mismatch")
        verifier = form.get("code_verifier", "")
        digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if not verifier or not hmac.compare_digest(digest, row["code_challenge"]):
            return oauth_error("invalid_grant", "PKCE verification failed")
        return JSONResponse(store.issue_tokens(client["client_id"], row["scope"]),
                            headers={"Cache-Control": "no-store"})

    if grant == "refresh_token":
        row = store.pop_refresh_token(form.get("refresh_token", ""), client["client_id"])
        if not row:
            return oauth_error("invalid_grant", "refresh token invalid or expired")
        return JSONResponse(store.issue_tokens(client["client_id"], row["scope"]),
                            headers={"Cache-Control": "no-store"})

    return oauth_error("unsupported_grant_type")


# ---------------------------------------------------------------- admin pages

LOGIN_FORM = """<h1>لوحة إدارة حسابات البريد</h1><div class="card">{err}
<form method="post" action="/admin/login"><label>كلمة مرور المالك</label>
<input type="password" name="password" autofocus><button>دخول</button></form></div>"""


async def admin_home(request: Request):
    if not _is_admin(request):
        return page("دخول", LOGIN_FORM.format(err=""))
    rows = []
    for a in store.list_accounts():
        e = html.escape(a["email"])
        status = ('<span class="bad">يحتاج إعادة ربط</span>' if a["status"] != "ok" else "يعمل")
        rows.append(f"""<div class="card"><b><code>{e}</code></b> — {status}
<form method="post" action="/admin/accounts/update"><input type="hidden" name="email" value="{e}">
<label>اسم مختصر (تستخدمه مع كلود، مثل: مكشاتي)</label><input type="text" name="label" value="{html.escape(a['label'])}">
<label>الاسم الظاهر للمستلم</label><input type="text" name="display_name" value="{html.escape(a['display_name'])}">
<button>حفظ</button></form>
<p><a class="btn" href="/admin/google/start?hint={e}">إعادة الربط</a></p>
<form method="post" action="/admin/accounts/delete"><input type="hidden" name="email" value="{e}">
<button class="danger">حذف الحساب وإلغاء صلاحيته</button></form></div>""")
    return page("حسابات البريد", f"""<h1>حسابات البريد المربوطة</h1>
<p><a class="btn" href="/admin/google/start">+ ربط حساب جوجل جديد</a></p>
{''.join(rows) or '<p class="muted">لا توجد حسابات بعد.</p>'}
<div class="card"><p>رابط الموصل الذي تضيفه في كلود:</p><p><code>{P}/mcp</code></p></div>
<div class="card"><form method="post" action="/admin/revoke-sessions">
<p class="muted">إن شككت أن جهازاً غير مصرّح به ربط الموصل، ألغِ كل جلسات كلود ثم أعد الربط.</p>
<button class="danger">إلغاء كل جلسات كلود</button></form>
<form method="post" action="/admin/logout"><button>خروج</button></form></div>""")


async def admin_login(request: Request):
    form = await request.form()
    if not _same_origin(request) or not _check_password(form.get("password", "")):
        err = ('<p class="bad">محاولات كثيرة خاطئة. حاول بعد ١٥ دقيقة.</p>' if _locked()
               else '<p class="bad">كلمة المرور غير صحيحة.</p>')
        return page("دخول", LOGIN_FORM.format(err=err), 401)
    exp = str(int(time.time()) + 3600)
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie("admin_session", f"{exp}.{_sign(exp)}", max_age=3600, httponly=True,
                    secure=P.startswith("https"), samesite="strict")
    return resp


async def admin_logout(request: Request):
    resp = RedirectResponse("/admin", status_code=303)
    resp.delete_cookie("admin_session")
    return resp


def _admin_post_guard(request: Request):
    if not _is_admin(request) or not _same_origin(request):
        return page("ممنوع", "<h1>غير مصرّح</h1>", 403)
    return None


async def google_start(request: Request):
    if not _is_admin(request):
        return RedirectResponse("/admin", status_code=303)
    q = {
        "client_id": store.get_setting("google_client_id"),
        "redirect_uri": config.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(config.GOOGLE_SCOPES),
        "access_type": "offline",
        "prompt": "consent select_account",
        "state": store.new_google_state(),
    }
    if request.query_params.get("hint"):
        q["login_hint"] = request.query_params["hint"]
    return RedirectResponse("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(q), 302)


async def google_callback(request: Request):
    if not _is_admin(request):
        return RedirectResponse("/admin", status_code=303)
    if not store.pop_google_state(request.query_params.get("state", "")):
        return page("خطأ", "<h1>انتهت صلاحية الطلب، أعد المحاولة.</h1>", 400)
    if request.query_params.get("error"):
        return page("ملغى", f"<h1>لم يتم الربط</h1><p>{html.escape(request.query_params['error'])}</p>"
                    '<p><a class="btn" href="/admin">رجوع</a></p>', 400)
    tok = await gmail.exchange_code(request.query_params.get("code", ""))
    granted = set(tok.get("scope", "").split())
    missing = [s for s in config.GOOGLE_SCOPES if s not in granted]
    if missing or not tok.get("refresh_token"):
        return page("ناقص", "<h1>لم تُمنح كل الصلاحيات</h1><p>أعد الربط ووافق على كل الخانات.</p>"
                    '<p><a class="btn" href="/admin">رجوع</a></p>', 400)
    prof = await gmail.profile_with_token(tok["access_token"])
    store.save_account(prof["emailAddress"], tok["refresh_token"], display_name="")
    return RedirectResponse("/admin", status_code=303)


async def account_update(request: Request):
    if (bad := _admin_post_guard(request)):
        return bad
    f = await request.form()
    store.update_account(f.get("email", ""), f.get("label", ""), f.get("display_name", ""))
    return RedirectResponse("/admin", status_code=303)


async def account_delete(request: Request):
    if (bad := _admin_post_guard(request)):
        return bad
    email = (await request.form()).get("email", "")
    rt = store.get_refresh_token(email)
    if rt:
        try:  # best effort: also revoke at Google
            async with httpx.AsyncClient(timeout=15) as c:
                await c.post("https://oauth2.googleapis.com/revoke", data={"token": rt})
        except Exception:
            pass
    store.delete_account(email)
    return RedirectResponse("/admin", status_code=303)


async def revoke_sessions(request: Request):
    if (bad := _admin_post_guard(request)):
        return bad
    store.revoke_all_tokens()
    return RedirectResponse("/admin", status_code=303)


SETUP_FORM = """<h1>الإعداد الأول للخادم</h1><div class="card">{err}
<p>هذه الصفحة تعمل مرة واحدة فقط. بعد الحفظ تُقفل نهائياً.</p>
<form method="post" action="/setup">
<label>رمز الإعداد (يظهر في نافذة الخادم)</label><input type="password" name="setup_code" autocomplete="off">
<label>كلمة مرور المالك الجديدة (١٦ حرفاً على الأقل)</label><input type="password" name="pw1" autocomplete="new-password">
<label>أعد كتابة كلمة المرور</label><input type="password" name="pw2" autocomplete="new-password">
<label>معرّف عميل جوجل (Client ID)</label><input type="text" name="client_id" value="{cid}">
<label>سر عميل جوجل (Client secret)</label><input type="password" name="client_secret" autocomplete="off">
<button>حفظ وإقفال الإعداد</button></form></div>"""


async def setup(request: Request):
    if store.is_configured():
        return RedirectResponse("/admin", status_code=303)
    cid = html.escape(config.GOOGLE_CLIENT_ID_DEFAULT)
    if request.method == "GET":
        return page("الإعداد", SETUP_FORM.format(err="", cid=cid))
    f = await request.form()
    err = ""
    if not config.SETUP_CODE or _locked():
        err = "الإعداد مقفل مؤقتاً."
    elif not hmac.compare_digest(f.get("setup_code", "").strip().encode(), config.SETUP_CODE.encode()):
        _failures.append(time.time())
        err = "رمز الإعداد غير صحيح."
    elif len(f.get("pw1", "")) < 16:
        err = "كلمة المرور قصيرة، ١٦ حرفاً على الأقل."
    elif f.get("pw1") != f.get("pw2"):
        err = "كلمتا المرور غير متطابقتين."
    elif not f.get("client_id", "").strip().endswith(".apps.googleusercontent.com") or len(f.get("client_secret", "").strip()) < 10:
        err = "تحقق من معرّف العميل والسر."
    if err:
        return page("الإعداد", SETUP_FORM.format(err=f'<p class="bad">{err}</p>', cid=cid), 400)
    store.set_setting("google_client_id", f["client_id"].strip())
    store.set_setting("google_client_secret", f["client_secret"].strip())
    store.set_setting("admin_password_hash", store.hash_password(f["pw1"]))
    return page("تم", '<h1>تم الإعداد</h1><p><a class="btn" href="/admin">الانتقال إلى لوحة الإدارة</a></p>')


async def root(request):
    return PlainTextResponse("Multi-account Gmail MCP server. Admin: /admin  MCP: /mcp")


async def privacy(request):
    return page("Privacy policy", """<div dir="ltr" lang="en"><h1>Privacy policy</h1><div class="card">
<p>This is a private, single-owner server operated by S4L for its owner's own mailboxes.
No other users are served.</p>
<p><b>Data accessed:</b> Gmail messages and settings (read), and the ability to create drafts and
send email, only for Google accounts the owner connects.</p>
<p><b>Use:</b> data is used solely to let the owner's AI assistant (Claude) search, read and send the
owner's own email at the owner's request. It is not sold, shared, used for advertising, or used to
train AI models.</p>
<p><b>Storage:</b> email content is not stored on the server. Google refresh tokens are stored encrypted
and can be revoked at any time from the admin page or from the Google account's security settings.</p>
<p><b>Google API Services User Data Policy:</b> use of information received from Google APIs adheres to
the Google API Services User Data Policy, including the Limited Use requirements.</p>
<p>Contact: ab@s4l.us</p></div></div>""")


# ---------------------------------------------------------------- assemble the app

app = mcp.streamable_http_app()
app.router.routes[0:0] = [
    Route("/", root),
    Route("/privacy", privacy),
    Route("/setup", setup, methods=["GET", "POST"]),
    Route("/.well-known/oauth-authorization-server", as_metadata),
    Route("/.well-known/openid-configuration", as_metadata),
    Route("/.well-known/oauth-protected-resource", pr_metadata),
    Route("/.well-known/oauth-protected-resource/mcp", pr_metadata),
    Route("/register", register, methods=["POST"]),
    Route("/authorize", authorize, methods=["GET", "POST"]),
    Route("/token", token, methods=["POST"]),
    Route("/admin", admin_home),
    Route("/admin/login", admin_login, methods=["POST"]),
    Route("/admin/logout", admin_logout, methods=["POST"]),
    Route("/admin/google/start", google_start),
    Route("/admin/google/callback", google_callback),
    Route("/admin/accounts/update", account_update, methods=["POST"]),
    Route("/admin/accounts/delete", account_delete, methods=["POST"]),
    Route("/admin/revoke-sessions", revoke_sessions, methods=["POST"]),
]


class BearerGuard:
    """Rejects any /mcp request without a valid access token issued by this server."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if (scope["type"] == "http" and not store.is_configured()
                and scope["path"] not in ("/setup", "/privacy", "/")):
            await RedirectResponse("/setup", status_code=303)(scope, receive, send)
            return
        if scope["type"] == "http" and scope["path"].rstrip("/") == "/mcp":
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"").decode()
            if not (auth.lower().startswith("bearer ") and store.check_access_token(auth[7:].strip())):
                resp = JSONResponse(
                    {"error": "invalid_token"}, status_code=401,
                    headers={"WWW-Authenticate":
                             f'Bearer resource_metadata="{P}/.well-known/oauth-protected-resource"'},
                )
                await resp(scope, receive, send)
                return
        await self.inner(scope, receive, send)


asgi = BearerGuard(app)


def run():
    import uvicorn
    import os
    uvicorn.run(asgi, host=os.environ.get("HOST", "0.0.0.0"), port=config.PORT, proxy_headers=True,
                forwarded_allow_ips="*")


if __name__ == "__main__":
    run()
