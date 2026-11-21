"""Attachment extraction on generated samples of every supported format (Arabic included)."""
import io
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("PUBLIC_URL", "http://localhost")
os.environ.setdefault("ENCRYPTION_KEY", "x" * 43 + "=")
os.environ.setdefault("SESSION_SECRET", "s" * 40)

from app.attachments import extract  # noqa: E402

results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -> {detail[:200]}"))


AR = "فاتورة رقم 1234 لشركة شب فور لس"

# PDF with a text layer
import pymupdf  # noqa: E402
doc = pymupdf.open()
page = doc.new_page()
page.insert_text((72, 72), "Invoice INV-2026-77 total 4,250 USD")
pdf_text = doc.tobytes()
t, imgs = extract("invoice.pdf", "application/pdf", pdf_text)
check("pdf text layer", "INV-2026-77" in t and not imgs, t)

# Scanned PDF (image only, no text layer) -> pages come back as images
from PIL import Image, ImageDraw  # noqa: E402
im = Image.new("RGB", (800, 400), "white")
ImageDraw.Draw(im).text((40, 180), "SCANNED RECEIPT 998", fill="black")
buf = io.BytesIO()
im.save(buf, "PNG")
doc2 = pymupdf.open()
p2 = doc2.new_page()
p2.insert_image(p2.rect, stream=buf.getvalue())
t, imgs = extract("scan.pdf", "application/pdf", doc2.tobytes())
check("scanned pdf -> page images", len(imgs) == 1 and "Scanned PDF" in t, t)

# DOCX with Arabic paragraph and a table
import docx  # noqa: E402
d = docx.Document()
d.add_paragraph(AR)
tbl = d.add_table(rows=2, cols=2)
tbl.cell(0, 0).text, tbl.cell(0, 1).text = "الصنف", "الكمية"
tbl.cell(1, 0).text, tbl.cell(1, 1).text = "ولاعة", "40"
b = io.BytesIO(); d.save(b)
t, _ = extract("عرض.docx", "", b.getvalue())
check("docx arabic + table", AR in t and "ولاعة | 40" in t, t)

# XLSX
import openpyxl  # noqa: E402
wb = openpyxl.Workbook(); ws = wb.active; ws.title = "Orders"
ws.append(["SKU", "Qty", "Price"]); ws.append(["WP-01", 12, 35.5])
b = io.BytesIO(); wb.save(b)
t, _ = extract("orders.xlsx", "", b.getvalue())
check("xlsx", "sheet: Orders" in t and "WP-01 | 12 | 35.5" in t, t)

# CSV in Arabic Windows encoding
t, _ = extract("list.csv", "text/csv", "اسم,سعر\nقهوة,20\n".encode("cp1256"))
check("csv cp1256 arabic", "قهوة | 20" in t, t)

# PPTX
from pptx import Presentation  # noqa: E402
from pptx.util import Inches  # noqa: E402
prs = Presentation()
s = prs.slides.add_slide(prs.slide_layouts[5])
s.shapes.title.text = "Kickstarter Plan Q1"
b = io.BytesIO(); prs.save(b)
t, _ = extract("plan.pptx", "", b.getvalue())
check("pptx", "Kickstarter Plan Q1" in t, t)

# Images incl. HEIC
b = io.BytesIO(); im.save(b, "PNG")
t, imgs = extract("photo.png", "image/png", b.getvalue())
check("png -> image", len(imgs) == 1 and imgs[0][:2] == b"\xff\xd8", t)
import pillow_heif  # noqa: E402
pillow_heif.register_heif_opener()
b = io.BytesIO(); im.save(b, "HEIF")
t, imgs = extract("IMG_0001.HEIC", "image/heic", b.getvalue())
check("heic -> image", len(imgs) == 1, t)

# HTML / JSON / TXT
t, _ = extract("note.html", "text/html", "<p>Hello <b>world</b></p><script>x()</script>".encode())
check("html -> text", "Hello world" in t and "x()" not in t, t)
t, _ = extract("data.json", "application/json", b'{"a": "\\u0642\\u0647\\u0648\\u0629"}')
check("json pretty", "قهوة" in t, t)

# ZIP containing a PDF and a docx
z = io.BytesIO()
with zipfile.ZipFile(z, "w") as zf:
    zf.writestr("docs/invoice.pdf", pdf_text)
    b = io.BytesIO(); d.save(b); zf.writestr("docs/offer.docx", b.getvalue())
t, _ = extract("bundle.zip", "application/zip", z.getvalue())
check("zip lists and reads members", "2 file(s)" in t and "INV-2026-77" in t and AR in t, t)

# Legacy / unsupported / corrupt
t, _ = extract("old.doc", "application/msword", b"\xd0\xcf\x11\xe0junk")
check("legacy doc explained", "legacy format" in t, t)
t, _ = extract("broken.pdf", "application/pdf", b"not a pdf")
check("corrupt file handled", "Could not read" in t, t)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
