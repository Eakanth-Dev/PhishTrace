"""QR decoding. The image is only decoded into text - the destination is never visited."""
import io
from urllib.parse import parse_qs, urlparse

from config import MAX_UPLOAD_BYTES
from core.findings import make_finding
from core.message_analyzer import analyze_message
from core.url_analyzer import analyze_url
from utils.helpers import extract_urls

SRC = "QR payload analysis"
try:  # optional
    from pyzbar import pyzbar as _pyzbar
except Exception:
    _pyzbar = None
try:
    import cv2
    import numpy as np
    from PIL import Image, ImageOps
except Exception:  # pragma: no cover
    cv2 = np = Image = ImageOps = None


def decoders_available() -> dict:
    return {"pyzbar": _pyzbar is not None, "opencv": cv2 is not None}


def decode_qr(image_bytes: bytes):
    """Return (payloads, error). Validates size/format; never executes anything."""
    if not image_bytes:
        return [], "Empty file."
    if len(image_bytes) > MAX_UPLOAD_BYTES:
        return [], f"File larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit."
    if Image is None:
        return [], "Pillow/OpenCV are not installed, so QR decoding is unavailable."
    try:
        Image.MAX_IMAGE_PIXELS = 40_000_000
        img = Image.open(io.BytesIO(image_bytes))
        img.verify()
        img = Image.open(io.BytesIO(image_bytes))
        img = ImageOps.exif_transpose(img).convert("RGB")
    except Exception:
        return [], "The file is not a valid image."
    payloads = []
    if _pyzbar is not None:
        try:
            payloads = [d.data.decode("utf-8", "replace") for d in _pyzbar.decode(img) if d.type == "QRCODE"]
        except Exception:
            payloads = []
    if not payloads and cv2 is not None:
        arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
        det = cv2.QRCodeDetector()
        for candidate in (arr, cv2.resize(arr, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC),
                          cv2.cvtColor(arr, cv2.COLOR_BGR2GRAY)):
            try:
                data, _, _ = det.detectAndDecode(candidate)
            except Exception:
                data = ""
            if data:
                payloads = [data]
                break
    if not payloads:
        return [], "No QR code could be decoded (blurry, cropped or not a QR code)."
    return list(dict.fromkeys(payloads)), None


def analyze_qr_payload(payload: str, resolve_dns: bool = False) -> dict:
    """Analyse the decoded text of a QR code."""
    payload = (payload or "").strip()
    findings = []
    entities = {"urls": [], "domains": [], "ips": [], "emails": [], "phones": []}
    scam_type, url_results = "", []
    if payload.lower().startswith("upi://"):
        p = urlparse(payload)
        q = {k.lower(): v[0] for k, v in parse_qs(p.query).items()}
        findings.append(make_finding("UPI payment QR", f"Pays to {q.get('pa', '?')} (name: {q.get('pn', '?')}) "
                                     f"amount: {q.get('am', 'not preset')}. Scanning a UPI QR SENDS money; QR codes "
                                     "are never needed to receive money.", "medium", SRC, category="upi_qr"))
        if q.get("am"):
            findings.append(make_finding("Preset payment amount", "The QR pre-fills an amount. Combined with a "
                                         "'refund' or 'prize' story this is a payment trap.", "medium", SRC))
        text_fields = " ".join([q.get("tn", ""), q.get("pn", "")])
        if text_fields.strip():
            sub = analyze_message(text_fields)
            findings += sub["findings"]
            scam_type = sub["scam_type"]
        if q.get("pa"):
            entities["emails"].append(q["pa"].lower())
        scam_type = scam_type or "UPI payment QR"
    else:
        urls = extract_urls(payload, limit=3)
        if urls:
            for u in urls:
                r = analyze_url(u, resolve_dns=resolve_dns)
                url_results.append(r)
                findings += [dict(x, context=r["url"]) for x in r["findings"]]
                for k in ("urls", "domains", "ips"):
                    entities[k] += [x for x in r["entities"][k] if x not in entities[k]]
            if len(payload) > 3 and not payload.lower().startswith(("http://", "https://")):
                findings.append(make_finding("QR contains more than a plain link", "The payload mixes text and a link.",
                                             "low", SRC))
        else:
            findings.append(make_finding("QR contains plain text (no link)", "Non-URL payload; analysed as message text.",
                                         "info", SRC))
            sub = analyze_message(payload)
            findings += sub["findings"]
            entities = sub["entities"]
            scam_type = sub["scam_type"]
    return {"findings": findings, "entities": entities, "scam_type": scam_type, "categories": [],
            "url_results": url_results, "meta": {"qr_payload": payload[:500]}, "events": []}


def analyze_qr_image(image_bytes: bytes, resolve_dns: bool = False) -> dict:
    payloads, err = decode_qr(image_bytes)
    if err:
        return {"error": err, "findings": [], "entities": {"urls": [], "domains": [], "ips": [], "emails": [], "phones": []},
                "scam_type": "", "categories": [], "url_results": [], "meta": {}, "events": []}
    res = analyze_qr_payload(payloads[0], resolve_dns=resolve_dns)
    res["meta"]["all_payloads"] = payloads[:5]
    return res
