"""URL threat analysis. Purely static + optional DNS resolution.

SAFETY: this module NEVER opens a connection to the submitted URL, never follows redirects
and never fetches content. The only network activity is an optional DNS lookup of the
hostname, and resolved private/loopback addresses are flagged rather than contacted.
"""
import concurrent.futures
import ipaddress
import re
import socket
from urllib.parse import parse_qs, unquote, urlparse

from config import MAX_URL_CHARS
from core.findings import make_finding
from utils.helpers import (defang_to_url, is_ip, levenshtein, normalize_lookalike, registered_domain,
                           shannon_entropy, split_host)

SRC = "URL structure analysis"

# Curated, NON-exhaustive map of brand token -> legitimate registered domains.
OFFICIAL_DOMAINS = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfcbank.net"},
    "icici": {"icicibank.com", "icicibank.co.in"},
    "axis": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "paytm": {"paytm.com", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "npci": {"npci.org.in"},
    "irctc": {"irctc.co.in"},
    "uidai": {"uidai.gov.in"},
    "incometax": {"incometax.gov.in"},
    "indiapost": {"indiapost.gov.in"},
    "dtdc": {"dtdc.in", "dtdc.com"},
    "bluedart": {"bluedart.com"},
    "google": {"google.com", "google.co.in", "gstatic.com", "googleapis.com", "googleusercontent.com", "withgoogle.com"},
    "amazon": {"amazon.in", "amazon.com", "amazonaws.com"},
    "flipkart": {"flipkart.com"},
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "netflix": {"netflix.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at",
              "tiny.cc", "rebrand.ly", "bl.ink", "lnkd.in", "buff.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "loan", "work", "rest",
                   "country", "kim", "icu", "cyou", "buzz", "monster"}
KEYWORDS = ["login", "signin", "verify", "update", "secure", "account", "kyc", "bank", "confirm", "password",
            "wallet", "bonus", "gift", "claim", "suspend", "unlock", "refund", "otp", "billing", "invoice",
            "support", "reward", "prize", "recharge", "aadhaar", "pan"]
REDIRECT_PARAMS = {"url", "redirect", "redirect_uri", "next", "return", "returnurl", "goto", "dest", "destination",
                   "link", "target", "redir", "continue"}


def normalize_url(raw: str):
    """Return (normalized_url, problems). Does not touch the network."""
    raw = (raw or "").strip().strip("<>\"'")
    if not raw:
        return "", ["empty input"]
    if len(raw) > MAX_URL_CHARS:
        return raw[:MAX_URL_CHARS], [f"URL longer than {MAX_URL_CHARS} characters (truncated for analysis)"]
    raw = defang_to_url(raw)
    if re.match(r"(?i)^(javascript|data|vbscript|file|blob|about):", raw):
        return raw, ["non-web scheme"]
    if "://" not in raw:
        raw = "http://" + raw.lstrip("/")
        return raw, ["no scheme given; http assumed"]
    return raw, []


def url_features(url: str) -> dict:
    """Deterministic numeric features (also used by the ML engine). No network access."""
    norm, _ = normalize_url(url)
    try:
        p = urlparse(norm)
        host = (p.hostname or "").lower()
    except ValueError:
        p, host = urlparse(""), ""
    sub, dom, suf = split_host(host) if host else ("", "", "")
    low = unquote(norm).lower()
    return {
        "url_length": len(norm),
        "host_length": len(host),
        "num_dots": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits_host": sum(c.isdigit() for c in host),
        "num_subdomains": len([s for s in sub.split(".") if s and s != "www"]),
        "has_ip_host": int(is_ip(host)),
        "is_https": int(p.scheme == "https"),
        "has_at": int("@" in (p.netloc or "")),
        "num_percent": norm.count("%"),
        "num_keywords": sum(k in low for k in KEYWORDS),
        "label_entropy": round(shannon_entropy(dom), 3),
        "path_depth": len([x for x in (p.path or "").split("/") if x]),
        "query_length": len(p.query or ""),
        "is_shortener": int(registered_domain(host) in SHORTENERS) if host else 0,
        "suspicious_tld": int(suf.split(".")[-1] in SUSPICIOUS_TLDS) if suf else 0,
        "has_punycode": int("xn--" in host),
        "num_params": len(parse_qs(p.query or "")),
    }


def _brand_checks(host, reg_dom, path_q, findings):
    sub, dom, suf = split_host(host)
    host_tokens = set(re.split(r"[.\-_]", host))
    for brand, officials in OFFICIAL_DOMAINS.items():
        if reg_dom in officials:
            continue
        in_host = brand in host_tokens or (len(brand) >= 6 and brand in host)
        if in_host:
            findings.append(make_finding(
                f"Brand impersonation pattern ({brand})",
                f"The hostname contains '{brand}' but the registered domain is '{reg_dom}', which is not on the "
                f"curated list of official {brand} domains. Attackers embed brand names to look legitimate.",
                "high", SRC + " + curated brand list", category="impersonation"))
            return
        norm_dom = normalize_lookalike(dom)
        if len(brand) >= 5 and dom != brand:
            dist = levenshtein(norm_dom, brand)
            if dist == 0 or (dist == 1 and len(brand) >= 5) or (dist == 2 and len(brand) >= 8):
                findings.append(make_finding(
                    f"Possible typosquatting of '{brand}'",
                    f"'{dom}' is visually very close to '{brand}' (character substitutions or small edits).",
                    "high", SRC + " + curated brand list", category="impersonation"))
                return
        if brand in path_q.lower() and len(brand) >= 4:
            findings.append(make_finding(
                f"Brand name in URL path ({brand})",
                f"'{brand}' appears in the path/query of a non-official domain ('{reg_dom}'). "
                "Legitimate brands serve pages from their own domains.",
                "medium", SRC + " + curated brand list", category="impersonation"))
            return


def resolve_host(host: str, timeout: float = 3.0):
    """DNS lookup only (no connection). Returns (addresses, error)."""
    def _lookup():
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_lookup)
        try:
            return fut.result(timeout=timeout), None
        except concurrent.futures.TimeoutError:
            return [], "DNS lookup timed out"
        except socket.gaierror:
            return [], "NXDOMAIN"
        except Exception as exc:  # pragma: no cover
            return [], f"DNS error: {type(exc).__name__}"


def analyze_url(raw: str, resolve_dns: bool = False) -> dict:
    url, problems = normalize_url(raw)
    result = {"url": url, "valid": False, "findings": [], "features": {},
              "entities": {"urls": [], "domains": [], "ips": []}, "dns": None}
    f = result["findings"]
    if not url:
        return result
    if "non-web scheme" in problems:
        f.append(make_finding("Non-web URL scheme", "javascript:, data:, file: and similar schemes can execute code or "
                              "hide content and are a common attack vector.", "critical", SRC))
        result["valid"] = True
        result["entities"]["urls"].append(url[:200])
        return result
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        f.append(make_finding("Malformed URL", "The URL could not be parsed (invalid port, brackets or characters).",
                              "medium", SRC))
        return result
    if not host:
        f.append(make_finding("No hostname", "The input does not contain a recognisable hostname.", "low", SRC))
        return result
    result["valid"] = True
    result["url"] = url
    result["features"] = url_features(url)
    ent = result["entities"]
    ent["urls"].append(url)
    for pr in problems:
        if pr.startswith("URL longer"):
            f.append(make_finding("Extremely long input", pr, "low", SRC))

    # Scheme
    if p.scheme == "https":
        f.append(make_finding("Uses HTTPS", "Encryption is present, but HTTPS says nothing about whether the site is "
                              "trustworthy - phishing sites commonly use it.", "info", SRC))
    else:
        f.append(make_finding("No HTTPS", "The link uses unencrypted HTTP. Legitimate login and payment pages use HTTPS.",
                              "medium", SRC, points=10, category="transport"))

    # Host type
    host_is_ip = is_ip(host)
    reg = registered_domain(host) if not host_is_ip else host
    ent["domains"].append(host if host_is_ip is False else host)
    if reg and reg != host and not host_is_ip:
        ent["domains"].append(reg)
    if host_is_ip:
        ent["ips"].append(host.strip("[]"))
        f.append(make_finding("IP address used as host", "Legitimate services use domain names; raw IP addresses are "
                              "typical of throw-away phishing servers.", "high", SRC, category="structure"))
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                f.append(make_finding("Non-public IP address", "The host is a private/reserved address. The URL may "
                                      "target internal services (SSRF-style) - PhishTrace never connects to it.",
                                      "medium", SRC))
        except ValueError:
            pass
    elif re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host):
        f.append(make_finding("Obfuscated IP address", "Numeric/hex host formats are used to hide the real IP address.",
                              "high", SRC, category="structure"))

    if "@" in (p.netloc or ""):
        f.append(make_finding("Credentials-style '@' in URL", "Text before '@' is ignored by browsers and is used to "
                              "display a trusted-looking name while loading a different host.", "high", SRC))
    if port and port not in (80, 443):
        f.append(make_finding("Non-standard port", f"Port {port} is unusual for a public website.", "low", SRC))

    # Length & structure
    n = len(url)
    if n > 150:
        f.append(make_finding("Very long URL", f"{n} characters; long URLs can hide the real destination.", "medium", SRC))
    elif n > 75:
        f.append(make_finding("Long URL", f"{n} characters.", "low", SRC))
    if not host_is_ip:
        sub, dom, suf = split_host(host)
        n_sub = len([s for s in sub.split(".") if s and s != "www"])
        if n_sub >= 3:
            f.append(make_finding("Excessive subdomains", f"{n_sub} subdomain levels ('{sub}'). Attackers stack "
                                  "subdomains so the trusted-looking part appears first.", "medium", SRC))
        elif n_sub == 2:
            f.append(make_finding("Multiple subdomains", f"Two subdomain levels ('{sub}').", "low", SRC))
        if host.count("-") >= 3:
            f.append(make_finding("Many hyphens in hostname", "Hyphen-stuffed names (e.g. secure-bank-login-update) are "
                                  "a common phishing pattern.", "medium", SRC))
        if sum(c.isdigit() for c in dom) >= 4 and sum(c.isdigit() for c in dom) / max(len(dom), 1) > 0.3:
            f.append(make_finding("Digit-heavy domain", "Many digits in the domain name are unusual for established brands.",
                                  "low", SRC))
        if len(dom) >= 12 and shannon_entropy(dom) > 3.6:
            f.append(make_finding("Random-looking domain", "High character entropy suggests an auto-generated name "
                                  "(weak signal).", "low", SRC))
        if suf and suf.split(".")[-1] in SUSPICIOUS_TLDS:
            f.append(make_finding("Frequently abused TLD", f".{suf.split('.')[-1]} is over-represented in abuse reports. "
                                  "Weak signal - many legitimate sites use these too.", "low", SRC))
        if reg in SHORTENERS:
            f.append(make_finding("URL shortener", "The real destination is hidden. PhishTrace does not follow the "
                                  "redirect; expand it with a safe previewer.", "medium", SRC))
        if host.startswith("xn--") or ".xn--" in host or "xn--" in host:
            f.append(make_finding("Punycode / IDN host", "Internationalised names can hide look-alike characters "
                                  "(homograph attacks).", "medium", SRC, category="obfuscation"))
        if re.search(r"[^a-z0-9.\-\[\]:]", host):
            f.append(make_finding("Unusual characters in hostname", "Hostname contains characters outside "
                                  "letters, digits, hyphen and dot.", "medium", SRC, category="obfuscation"))
        _brand_checks(host, reg, unquote(p.path + "?" + (p.query or "")), f)

    # Obfuscation & keywords
    pct = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    if "%25" in url:
        f.append(make_finding("Double URL-encoding", "Encoded '%' characters (%25) are used to evade filters.", "medium",
                              SRC, category="obfuscation"))
    elif pct > 3:
        f.append(make_finding("Heavy URL-encoding", f"{pct} percent-encoded characters may hide the real content.",
                              "low", SRC, category="obfuscation"))
    low = unquote(url).lower()
    hits = [k for k in KEYWORDS if k in low]
    if len(hits) >= 3:
        f.append(make_finding("Multiple sensitive keywords", "Contains: " + ", ".join(hits[:6]) +
                              ". Combined, these mimic account-security pages.", "medium", SRC, category="keywords"))
    elif len(hits) == 2:
        f.append(make_finding("Sensitive keywords", "Contains: " + ", ".join(hits) + ".", "low", SRC, category="keywords"))
    qs = parse_qs(p.query or "")
    for k, vals in qs.items():
        if k.lower() in REDIRECT_PARAMS and any(re.match(r"(?i)https?(://|%3a)", unquote(v)) for v in vals):
            f.append(make_finding("Embedded redirect target", f"Parameter '{k}' carries another URL - possible open "
                                  "redirect abuse.", "medium", SRC))
            break

    if resolve_dns and not host_is_ip:
        addrs, err = resolve_host(host)
        result["dns"] = {"addresses": addrs, "error": err}
        if addrs:
            ent["ips"].extend(addrs)
            bad = [a for a in addrs if _non_public(a)]
            if bad:
                f.append(make_finding("Resolves to non-public address", f"{host} resolves to {', '.join(bad)}. "
                                      "Never fetched by PhishTrace.", "high", "DNS resolution"))
            else:
                f.append(make_finding("DNS resolves", f"Resolved to {', '.join(addrs[:3])}. Resolving proves existence only.",
                                      "info", "DNS resolution"))
        elif err == "NXDOMAIN":
            f.append(make_finding("Domain does not resolve", "No DNS record found - the domain may be fake, mistyped or "
                                  "already taken down.", "low", "DNS resolution"))
        elif err:
            f.append(make_finding("DNS check inconclusive", err, "info", "DNS resolution"))
    ent["domains"] = list(dict.fromkeys(ent["domains"]))
    ent["ips"] = list(dict.fromkeys(ent["ips"]))
    return result


def _non_public(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False
