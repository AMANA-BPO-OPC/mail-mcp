"""Thin async Gmail API client, one Google account at a time."""
import asyncio
import base64
import html
import re
import time
from email.message import EmailMessage
from email.utils import formataddr, getaddresses, make_msgid

import httpx

from . import config, store

API = "https://gmail.googleapis.com/gmail/v1/users/me"
TOKEN_URL = "https://oauth2.googleapis.com/token"
MAX_BODY_CHARS = 15000

_access_cache: dict[str, tuple[str, float]] = {}
_http = httpx.AsyncClient(timeout=30)


class AccountError(Exception):
    pass


async def exchange_code(code: str) -> dict:
    r = await _http.post(TOKEN_URL, data={
        "code": code,
        "client_id": store.get_setting("google_client_id"),
        "client_secret": store.get_setting("google_client_secret"),
        "redirect_uri": config.GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    })
    r.raise_for_status()
    return r.json()


async def profile_with_token(access_token: str) -> dict:
    r = await _http.get(f"{API}/profile", headers={"Authorization": f"Bearer {access_token}"})
    r.raise_for_status()
    return r.json()


async def _access_token(email: str) -> str:
    cached = _access_cache.get(email)
    if cached and cached[1] > time.time() + 60:
        return cached[0]
    refresh = store.get_refresh_token(email)
    if not refresh:
        raise AccountError(f"Account {email} is not connected.")
    r = await _http.post(TOKEN_URL, data={
        "client_id": store.get_setting("google_client_id"),
        "client_secret": store.get_setting("google_client_secret"),
        "refresh_token": refresh,
        "grant_type": "refresh_token",
    })
    if r.status_code == 400 and "invalid_grant" in r.text:
        store.set_account_status(email, "reconnect_needed")
        raise AccountError(
            f"Google access for {email} expired or was revoked. "
            "The owner must reconnect it from the server's admin page."
        )
    r.raise_for_status()
    data = r.json()
    _access_cache[email] = (data["access_token"], time.time() + data.get("expires_in", 3600))
    return data["access_token"]


async def _call(email: str, method: str, path: str, **kw) -> dict:
    token = await _access_token(email)
    r = await _http.request(method, f"{API}{path}",
                            headers={"Authorization": f"Bearer {token}"}, **kw)
    if r.status_code == 401:
        _access_cache.pop(email, None)
        token = await _access_token(email)
        r = await _http.request(method, f"{API}{path}",
                                headers={"Authorization": f"Bearer {token}"}, **kw)
    if r.status_code >= 400:
        raise AccountError(f"Gmail API error for {email} ({r.status_code}): {r.text[:300]}")
    return r.json() if r.content else {}


# ---------- parsing helpers ----------

def _headers(payload: dict) -> dict:
    return {h["name"].lower(): h["value"] for h in payload.get("headers", [])}


def _b64(data: str) -> str:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")


def _html_to_text(s: str) -> str:
    s = re.sub(r"(?is)<(script|style).*?</\1>", "", s)
    s = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>", "\n", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = html.unescape(s)
    return re.sub(r"\n\s*\n+", "\n\n", s).strip()


def _walk(part: dict, texts: list, htmls: list, attachments: list) -> None:
    mime = part.get("mimeType", "")
    body = part.get("body", {})
    if part.get("filename"):
        attachments.append({
            "filename": part["filename"], "mimeType": mime, "size": body.get("size", 0),
            "attachmentId": body.get("attachmentId"), "_data": body.get("data"),
        })
    elif mime == "text/plain" and body.get("data"):
        texts.append(_b64(body["data"]))
    elif mime == "text/html" and body.get("data"):
        htmls.append(_b64(body["data"]))
    for p in part.get("parts", []) or []:
        _walk(p, texts, htmls, attachments)


def _summarize(msg: dict, full: bool) -> dict:
    hd = _headers(msg.get("payload", {}))
    out = {
        "id": msg["id"],
        "threadId": msg.get("threadId"),
        "from": hd.get("from", ""),
        "to": hd.get("to", ""),
        "cc": hd.get("cc", ""),
        "subject": hd.get("subject", ""),
        "date": hd.get("date", ""),
        "labels": msg.get("labelIds", []),
        "snippet": html.unescape(msg.get("snippet", "")),
    }
    if full:
        texts, htmls, atts = [], [], []
        _walk(msg.get("payload", {}), texts, htmls, atts)
        body = "\n".join(texts).strip() or _html_to_text("\n".join(htmls))
        if len(body) > MAX_BODY_CHARS:
            body = body[:MAX_BODY_CHARS] + "\n...[truncated]"
        out["body"] = body
        out["attachments"] = [{k: v for k, v in a.items() if not k.startswith("_") and k != "attachmentId"}
                              for a in atts]
    return out


# ---------- operations ----------

async def search(email: str, query: str, max_results: int) -> list[dict]:
    listing = await _call(email, "GET", "/messages",
                          params={"q": query, "maxResults": max_results})
    ids = [m["id"] for m in listing.get("messages", [])]
    sem = asyncio.Semaphore(8)

    async def one(mid):
        async with sem:
            m = await _call(email, "GET", f"/messages/{mid}", params=[
                ("format", "metadata"),
                ("metadataHeaders", "From"), ("metadataHeaders", "To"),
                ("metadataHeaders", "Cc"), ("metadataHeaders", "Subject"),
                ("metadataHeaders", "Date"),
            ])
            return _summarize(m, full=False)

    return await asyncio.gather(*(one(i) for i in ids))


async def read_thread(email: str, thread_id: str) -> dict:
    t = await _call(email, "GET", f"/threads/{thread_id}", params={"format": "full"})
    return {"threadId": t["id"], "messages": [_summarize(m, full=True) for m in t.get("messages", [])]}


ATTACH_HOST_SUFFIXES = (".dropboxusercontent.com", ".dropbox.com")
MAX_ATTACH_TOTAL = 24 * 1024 * 1024


async def fetch_attachments(items) -> list[tuple[str, str, bytes]]:
    """Download attachments from allow-listed HTTPS hosts (Dropbox temporary links).
    items: [{"url": ..., "filename": ...}]. Returns [(filename, mime, bytes)]."""
    import mimetypes
    from urllib.parse import urlparse
    out, total = [], 0
    for it in items or []:
        url = (it or {}).get("url", "")
        name = ((it or {}).get("filename") or "").strip().replace("/", "_").replace("\\", "_")
        u = urlparse(url)
        host = (u.hostname or "").lower()
        if u.scheme != "https" or not any(host.endswith(sfx) for sfx in ATTACH_HOST_SUFFIXES):
            raise AccountError("Attachment URL must be an https Dropbox download link: %s" % host)
        r = await _http.get(url, follow_redirects=True, timeout=60)
        if r.status_code != 200:
            raise AccountError("Could not download attachment '%s' (HTTP %s)" % (name or url, r.status_code))
        final = (r.url.host or "").lower()
        if not any(final.endswith(sfx) for sfx in ATTACH_HOST_SUFFIXES):
            raise AccountError("Attachment redirected off Dropbox: %s" % final)
        data = r.content
        total += len(data)
        if total > MAX_ATTACH_TOTAL:
            raise AccountError("Attachments exceed 24 MB in total (Gmail limit is 25 MB).")
        if not name:
            name = u.path.rsplit("/", 1)[-1] or "attachment"
        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        out.append((name, mime, data))
    return out


def _build(email: str, display_name: str, to, cc, bcc, subject, body, html_body,
           in_reply_to=None, references=None, attachments=None) -> str:
    msg = EmailMessage()
    msg["From"] = formataddr((display_name, email)) if display_name else email
    if to:
        msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if bcc:
        msg["Bcc"] = ", ".join(bcc)
    msg["Subject"] = subject or ""
    msg["Message-ID"] = make_msgid(domain=email.split("@")[-1])
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = (references + " " if references else "") + in_reply_to
    msg.set_content(body or _html_to_text(html_body or ""))
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    for name, mime, data in attachments or []:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype or "octet-stream", filename=name)
    return base64.urlsafe_b64encode(msg.as_bytes()).decode()


async def send(email, display_name, to, cc, bcc, subject, body, html_body, draft_only,
               attachments=None) -> dict:
    raw = _build(email, display_name, to, cc, bcc, subject, body, html_body,
                 attachments=attachments)
    if draft_only:
        d = await _call(email, "POST", "/drafts", json={"message": {"raw": raw}})
        return {"draftId": d.get("id"), "messageId": d.get("message", {}).get("id"),
                "attached": [a[0] for a in attachments or []]}
    m = await _call(email, "POST", "/messages/send", json={"raw": raw})
    return {"messageId": m.get("id"), "threadId": m.get("threadId")}


async def reply(email, display_name, message_id, body, html_body, reply_all,
                extra_cc, draft_only, attachments=None) -> dict:
    orig = await _call(email, "GET", f"/messages/{message_id}", params=[
        ("format", "metadata"),
        *[("metadataHeaders", n) for n in
          ("From", "To", "Cc", "Reply-To", "Subject", "Message-ID", "References")],
    ])
    hd = _headers(orig.get("payload", {}))
    me = email.lower()
    sent_by_me = me in hd.get("from", "").lower()
    if sent_by_me:
        to = [a for _, a in getaddresses([hd.get("to", "")]) if a]
    else:
        to = [a for _, a in getaddresses([hd.get("reply-to") or hd.get("from", "")]) if a]
    cc = []
    if reply_all:
        everyone = getaddresses([hd.get("to", ""), hd.get("cc", "")])
        cc = [a for _, a in everyone if a and a.lower() != me and a not in to]
    cc += [a for a in (extra_cc or []) if a not in cc]
    subject = hd.get("subject", "")
    if not subject.lower().startswith("re:"):
        subject = f"Re: {subject}"
    raw = _build(email, display_name, to, cc, None, subject, body, html_body,
                 in_reply_to=hd.get("message-id"), references=hd.get("references"),
                 attachments=attachments)
    payload = {"raw": raw, "threadId": orig["threadId"]}
    if draft_only:
        d = await _call(email, "POST", "/drafts", json={"message": payload})
        return {"draftId": d.get("id"), "to": to, "cc": cc, "subject": subject,
                "attached": [a[0] for a in attachments or []]}
    m = await _call(email, "POST", "/messages/send", json=payload)
    return {"messageId": m.get("id"), "threadId": m.get("threadId"), "to": to, "cc": cc,
            "subject": subject}


async def get_attachment(email: str, message_id: str, filename: str | None) -> tuple[dict, bytes]:
    """Find an attachment on a message by filename (or the only one) and return (meta, bytes)."""
    msg = await _call(email, "GET", f"/messages/{message_id}", params={"format": "full"})
    texts, htmls, atts = [], [], []
    _walk(msg.get("payload", {}), texts, htmls, atts)
    if not atts:
        raise AccountError("This message has no attachments.")
    if filename:
        match = [a for a in atts if a["filename"] == filename] or \
                [a for a in atts if filename.lower() in a["filename"].lower()]
        if not match:
            raise AccountError("No attachment named '%s'. Available: %s"
                               % (filename, ", ".join(a["filename"] for a in atts)))
        att = match[0]
    elif len(atts) == 1:
        att = atts[0]
    else:
        raise AccountError("Several attachments; pass filename. Available: "
                           + ", ".join(a["filename"] for a in atts))
    data = att.get("_data")
    if not data:
        r = await _call(email, "GET", f"/messages/{message_id}/attachments/{att['attachmentId']}")
        data = r.get("data", "")
    raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    return {"filename": att["filename"], "mimeType": att["mimeType"], "size": len(raw)}, raw


async def list_drafts(email: str, query: str | None, max_results: int) -> list[dict]:
    params = {"maxResults": max(1, min(max_results, 50))}
    if query:
        params["q"] = query
    r = await _call(email, "GET", "/drafts", params=params)
    out = []
    for d in r.get("drafts", []) or []:
        m = await _call(email, "GET", f"/drafts/{d['id']}", params={"format": "metadata"})
        msg = m.get("message", {})
        hd = _headers(msg.get("payload", {}))
        out.append({"draftId": d["id"], "threadId": msg.get("threadId"), "to": hd.get("to", ""),
                    "cc": hd.get("cc", ""), "subject": hd.get("subject", ""),
                    "snippet": msg.get("snippet", "")})
    return out


async def send_draft(email: str, draft_id: str) -> dict:
    m = await _call(email, "POST", "/drafts/send", json={"id": draft_id})
    return {"messageId": m.get("id"), "threadId": m.get("threadId")}


async def delete_draft(email: str, draft_id: str) -> dict:
    await _call(email, "DELETE", f"/drafts/{draft_id}")
    return {"deleted": draft_id}
