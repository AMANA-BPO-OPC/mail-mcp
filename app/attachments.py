"""Turn an email attachment (bytes) into text and/or images Claude can read."""
import csv
import io
import json
import zipfile

MAX_TEXT = 40000          # characters returned per attachment
MAX_PAGES_AS_IMAGES = 5   # scanned PDF pages rendered for Claude to look at
MAX_IMAGE_SIDE = 1568     # px, longest side sent to Claude
MAX_ZIP_MEMBERS = 10

TEXT_EXT = {"txt", "md", "log", "json", "xml", "html", "htm", "csv", "tsv", "ics", "vcf", "eml"}


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _clip(text: str) -> str:
    text = text.strip()
    return text if len(text) <= MAX_TEXT else text[:MAX_TEXT] + "\n...[truncated]"


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "cp1256", "latin-1"):   # cp1256 = Arabic Windows
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def image_to_jpeg(data: bytes) -> bytes:
    from PIL import Image
    try:
        import pillow_heif
        pillow_heif.register_heif_opener()
    except Exception:
        pass
    im = Image.open(io.BytesIO(data))
    im.load()
    if im.mode not in ("RGB", "L"):
        im = im.convert("RGB")
    im.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
    out = io.BytesIO()
    im.save(out, "JPEG", quality=85)
    return out.getvalue()


def _pdf(data: bytes) -> tuple[str, list[bytes]]:
    import pymupdf
    doc = pymupdf.open(stream=data, filetype="pdf")
    parts, images = [], []
    for i, page in enumerate(doc):
        t = page.get_text().strip()
        if t:
            parts.append(f"--- page {i + 1} ---\n{t}")
    text = "\n\n".join(parts)
    # Little or no text layer -> probably scanned: render pages for Claude to read visually.
    if len(text) < 50 * max(1, min(doc.page_count, 3)):
        for page in list(doc)[:MAX_PAGES_AS_IMAGES]:
            pix = page.get_pixmap(dpi=110)
            images.append(image_to_jpeg(pix.tobytes("png")))
        text = (text + "\n" if text else "") + (
            f"[Scanned PDF: {doc.page_count} page(s); first {len(images)} attached as images]")
    return f"PDF, {doc.page_count} page(s)\n{text}", images


def _docx(data: bytes) -> str:
    import docx
    d = docx.Document(io.BytesIO(data))
    lines = [p.text for p in d.paragraphs if p.text.strip()]
    for ti, table in enumerate(d.tables, 1):
        lines.append(f"--- table {ti} ---")
        for row in table.rows:
            lines.append(" | ".join(c.text.strip() for c in row.cells))
    return "\n".join(lines)


def _xlsx(data: bytes) -> str:
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    out = []
    for ws in wb.worksheets:
        out.append(f"--- sheet: {ws.title} ---")
        for row in ws.iter_rows(values_only=True):
            if any(v is not None and str(v).strip() for v in row):
                out.append(" | ".join("" if v is None else str(v) for v in row))
            if sum(len(x) for x in out) > MAX_TEXT:
                break
    return "\n".join(out)


def _xls(data: bytes) -> str:
    import xlrd
    wb = xlrd.open_workbook(file_contents=data)
    out = []
    for sh in wb.sheets():
        out.append(f"--- sheet: {sh.name} ---")
        for r in range(sh.nrows):
            vals = [str(v) for v in sh.row_values(r)]
            if any(v.strip() for v in vals):
                out.append(" | ".join(vals))
    return "\n".join(out)


def _pptx(data: bytes) -> str:
    from pptx import Presentation
    prs = Presentation(io.BytesIO(data))
    out = []
    for i, slide in enumerate(prs.slides, 1):
        out.append(f"--- slide {i} ---")
        for shape in slide.shapes:
            if shape.has_text_frame and shape.text_frame.text.strip():
                out.append(shape.text_frame.text)
            if getattr(shape, "has_table", False) and shape.has_table:
                for row in shape.table.rows:
                    out.append(" | ".join(c.text for c in row.cells))
    return "\n".join(out)


def _text(data: bytes, ext: str) -> str:
    s = _decode(data)
    if ext in ("html", "htm"):
        from .gmail import _html_to_text
        return _html_to_text(s)
    if ext == "json":
        try:
            return json.dumps(json.loads(s), ensure_ascii=False, indent=1)
        except ValueError:
            return s
    if ext in ("csv", "tsv"):
        rows = csv.reader(io.StringIO(s), delimiter="\t" if ext == "tsv" else ",")
        return "\n".join(" | ".join(r) for r in rows)
    return s


def extract(name: str, mime: str, data: bytes, _depth: int = 0) -> tuple[str, list[bytes]]:
    """Return (text, [jpeg images]) for one file."""
    ext = _ext(name)
    mime = (mime or "").lower()
    try:
        if ext == "pdf" or mime == "application/pdf":
            return _pdf(data)
        if ext in ("docx", "docm") or "wordprocessingml" in mime:
            return _docx(data), []
        if ext in ("xlsx", "xlsm") or "spreadsheetml" in mime:
            return _xlsx(data), []
        if ext == "xls" or mime == "application/vnd.ms-excel":
            return _xls(data), []
        if ext == "pptx" or "presentationml" in mime:
            return _pptx(data), []
        if mime.startswith("image/") or ext in ("jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff", "heic", "heif"):
            return f"Image {name}", [image_to_jpeg(data)]
        if ext == "zip" or mime in ("application/zip", "application/x-zip-compressed"):
            if _depth:
                return "[nested zip not opened]", []
            zf = zipfile.ZipFile(io.BytesIO(data))
            members = [m for m in zf.infolist() if not m.is_dir()]
            lines = [f"ZIP with {len(members)} file(s):"] + [f"- {m.filename} ({m.file_size} bytes)" for m in members]
            images = []
            for m in members[:MAX_ZIP_MEMBERS]:
                if m.file_size > 15_000_000:
                    continue
                t, imgs = extract(m.filename, "", zf.read(m), _depth=1)
                lines.append(f"\n===== {m.filename} =====\n{t}")
                images += imgs[:2]
            return "\n".join(lines), images[:MAX_PAGES_AS_IMAGES]
        if ext in ("doc", "ppt", "rtf"):
            return (f"[{ext.upper()} is a legacy format this server cannot parse. "
                    "Ask the sender for DOCX/PPTX/PDF.]"), []
        if ext in TEXT_EXT or mime.startswith("text/") or mime in ("application/json", "application/xml"):
            return _text(data, ext or mime.split("/")[-1]), []
        return f"[Unsupported file type: {name} ({mime or 'unknown'})]", []
    except Exception as e:  # corrupt or password-protected file
        return f"[Could not read {name}: {type(e).__name__}: {e}]", []


def to_result(name: str, mime: str, size: int, data: bytes):
    text, images = extract(name, mime, data)
    return f"Attachment: {name} ({mime}, {size} bytes)\n\n{_clip(text)}", images
