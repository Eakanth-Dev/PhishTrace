"""Shared parsing helpers: entity extraction, domain splitting, string tools."""
import ipaddress
import math
import re
from collections import Counter
from datetime import datetime, timezone

from config import MAX_URLS_PER_INPUT

try:  # optional dependency
    import tldextract
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline snapshot only: no network calls
except Exception:  # pragma: no cover
    _EXTRACT = None

MULTI_SUFFIX = {"co.in", "org.in", "net.in", "gov.in", "ac.in", "nic.in", "res.in", "co.uk", "org.uk",
                "gov.uk", "ac.uk", "com.au", "co.nz", "co.jp", "com.br", "co.za", "com.sg", "com.cn"}

BARE_TLDS = ["com", "in", "net", "org", "co", "io", "info", "xyz", "top", "club", "online", "site", "link",
             "click", "shop", "app", "me", "ly", "gl", "cc", "biz", "live", "store", "tk", "ml", "ga", "cf",
             "gq", "us", "uk", "ru", "cn", "icu", "vip", "work", "support", "help", "bank", "example", "sbi"]
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
EXPLICIT_URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
BARE_URL_RE = re.compile(
    r"(?i)(?<![@\w.\-])((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:%s))(?![\w\-])(?:[/?#][^\s<>\"'`]*)?"
    % "|".join(sorted(BARE_TLDS, key=len, reverse=True)))
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_TRAIL = ".,;:!?)]}'\""


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def defang_to_url(text: str) -> str:
    """Convert common 'defanged' notation (hxxp, [.]) back to normal form for analysis only."""
    t = re.sub(r"(?i)\bhxxp(s?)", r"http\1", text)
    return t.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def split_host(host: str):
    """Return (subdomain, domain, suffix) using tldextract if available, else a heuristic."""
    host = host.lower().strip(".")
    if _EXTRACT:
        try:
            e = _EXTRACT(host)
            if e.suffix and e.domain:
                return e.subdomain, e.domain, e.suffix
        except Exception:
            pass
    parts = host.split(".")
    if len(parts) < 2:
        return "", host, ""
    if ".".join(parts[-2:]) in MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[:-3]), parts[-3], ".".join(parts[-2:])
    return ".".join(parts[:-2]), parts[-2], parts[-1]


def registered_domain(host: str) -> str:
    _, dom, suf = split_host(host)
    return f"{dom}.{suf}" if suf else dom


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def extract_emails(text: str):
    return list(dict.fromkeys(m.lower() for m in EMAIL_RE.findall(text or "")))


def extract_phones(text: str):
    return list(dict.fromkeys(re.sub(r"[\s-]", "", m) for m in PHONE_RE.findall(text or "")))


def extract_ips(text: str):
    out = []
    for m in IP_RE.findall(text or ""):
        if is_ip(m):
            out.append(m)
    return list(dict.fromkeys(out))


def extract_urls(text: str, limit: int = MAX_URLS_PER_INPUT):
    """Extract URLs (explicit and bare-domain) from free text. Never fetches them."""
    text = defang_to_url(text or "")
    found, spans = [], []
    for m in EXPLICIT_URL_RE.finditer(text):
        found.append((m.start(), m.group(0).rstrip(_TRAIL)))
        spans.append((m.start(), m.end()))
    remainder = list(text)
    for s, e in spans:
        for i in range(s, e):
            remainder[i] = " "
    remainder = EMAIL_RE.sub(lambda m: " " * len(m.group(0)), "".join(remainder))
    for m in BARE_URL_RE.finditer(remainder):
        found.append((m.start(), m.group(0).rstrip(_TRAIL)))
    found.sort()
    return list(dict.fromkeys(u for _, u in found))[:limit]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def normalize_lookalike(label: str) -> str:
    return label.lower().translate(_LEET).replace("rn", "m").replace("vv", "w")


_SENSITIVE_PATTERNS = [
    (re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), "[MASKED-NUMBER]"),
    (re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"), "[MASKED-ID]"),
    (re.compile(r"(?i)\b(otp|pin|cvv|passcode)(\W{0,15})(\d{3,8})\b"), r"\1\2[MASKED]"),
]


def mask_sensitive(text: str) -> str:
    """Mask card-like numbers, Aadhaar-like IDs and OTP/PIN values before storing evidence."""
    for pattern, repl in _SENSITIVE_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def defang_display(url: str) -> str:
    """Render a URL so it cannot be clicked accidentally."""
    return re.sub(r"(?i)^http", "hxxp", url).replace(".", "[.]")
