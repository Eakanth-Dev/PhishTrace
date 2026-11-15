"""Email analysis: parses headers/body with the standard library only. Nothing is executed or fetched.

Attachments are never opened or saved - only their file names are inspected.
"""
import re
from email import message_from_bytes, policy
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

from core.findings import make_finding
from core.message_analyzer import scan_patterns, scam_type_from
from core.url_analyzer import OFFICIAL_DOMAINS, analyze_url
from utils.helpers import (extract_emails, extract_ips, extract_phones, extract_urls, registered_domain)

SRC_H = "Email header analysis"
RISKY_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".bat", ".cmd", ".com", ".msi", ".jar", ".ps1", ".iso", ".img",
             ".lnk", ".hta", ".html", ".htm", ".docm", ".xlsm", ".pptm", ".apk", ".dll"}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com", "proton.me", "protonmail.com",
             "mail.com", "aol.com", "icloud.com"}


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.text, self._href, self._buf = [], [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._buf = []
        elif tag in ("br", "p", "div", "tr"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._buf).strip()))
            self._href = None

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)


def _iso(dt):
    try:
        return dt.astimezone().isoformat() if dt.tzinfo is None else dt.isoformat()
    except Exception:
        return None


def _parse_date(value):
    try:
        return _iso(parsedate_to_datetime(value))
    except Exception:
        return None


def parse_email(raw: bytes):
    msg = message_from_bytes(raw, policy=policy.default)
    plain, html = [], []
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        fname = part.get_filename()
        if fname:
            attachments.append(fname)
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except Exception:
            continue
        if not isinstance(content, str):
            continue
        if ctype == "text/plain":
            plain.append(content)
        elif ctype == "text/html":
            html.append(content)
    return msg, "\n".join(plain), "\n".join(html), attachments


def analyze_email(raw, resolve_dns: bool = False) -> dict:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    msg, plain, html, attachments = parse_email(raw)
    has_headers = bool(msg["From"] or msg["Subject"] or msg["Received"])
    link_parser = _LinkParser()
    if html:
        try:
            link_parser.feed(html)
        except Exception:
            pass
    body = plain if plain.strip() else "".join(link_parser.text)
    if not has_headers and not body.strip():
        body = raw.decode("utf-8", errors="replace")  # headerless paste

    subject = str(msg["Subject"] or "")
    from_raw, reply_raw = str(msg["From"] or ""), str(msg["Reply-To"] or "")
    f_name, f_addr = parseaddr(from_raw)
    r_name, r_addr = parseaddr(reply_raw)
    f_dom = f_addr.split("@")[-1].lower() if "@" in f_addr else ""
    r_dom = r_addr.split("@")[-1].lower() if "@" in r_addr else ""
    findings = []
    meta = {"from": from_raw, "reply_to": reply_raw, "subject": subject, "date": str(msg["Date"] or ""),
            "return_path": str(msg["Return-Path"] or ""), "to": ", ".join(a for _, a in getaddresses(msg.get_all("To", []))),
            "auth": {}, "attachments": attachments, "has_headers": has_headers}

    # --- authentication results (only what the message itself reports) ---
    auth_text = " ".join(str(h) for h in (msg.get_all("Authentication-Results", []) + msg.get_all("Received-SPF", [])))
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}\s*=\s*(\w+)", auth_text, re.I) or (re.match(r"\s*(\w+)", str(msg["Received-SPF"] or ""))
                                                                  if mech == "spf" and msg["Received-SPF"] else None)
        if m:
            meta["auth"][mech] = m.group(1).lower()
    for mech, val in meta["auth"].items():
        if val in ("fail", "permerror", "temperror"):
            findings.append(make_finding(f"{mech.upper()} authentication failed", f"The receiving server reported "
                                         f"{mech}={val}: the sender may not be authorised to use this domain.",
                                         "high", SRC_H, category="auth"))
        elif val in ("softfail", "neutral", "none"):
            findings.append(make_finding(f"{mech.upper()} not passing ({val})", f"Reported {mech}={val}: weak or no "
                                         "proof the sender is authorised.", "medium", SRC_H, category="auth"))
        elif val == "pass":
            findings.append(make_finding(f"{mech.upper()} passed", f"{mech}=pass confirms domain-level authorisation, "
                                         "not that the content is honest (attackers can authenticate their own domains).",
                                         "info", SRC_H))
    if not meta["auth"]:
        findings.append(make_finding("No authentication results available", "SPF/DKIM/DMARC results are missing "
                                     "(pasted text often drops headers). Neither a good nor a bad sign.", "info", SRC_H))

    # --- sender consistency ---
    if f_dom and r_dom and registered_domain(f_dom) != registered_domain(r_dom):
        findings.append(make_finding("Reply-To differs from From", f"Replies go to {r_dom}, not {f_dom}. Attackers "
                                     "use this to receive victim replies.", "medium", SRC_H, category="sender"))
    if f_name:
        spoof = extract_emails(f_name)
        if spoof and f_dom and spoof[0].split("@")[-1] != f_dom:
            findings.append(make_finding("Display name shows a different address", f"Display name '{f_name}' contains an "
                                         f"address that differs from the real sender ({f_addr}).", "high", SRC_H, category="sender"))
        low_name = f_name.lower()
        for brand, officials in OFFICIAL_DOMAINS.items():
            if re.search(rf"\b{re.escape(brand)}\b", low_name) and f_dom and registered_domain(f_dom) not in officials:
                kind = "a free webmail address" if registered_domain(f_dom) in FREE_MAIL else f"the domain {f_dom}"
                findings.append(make_finding(f"Sender name claims '{brand}' but address is not official",
                                             f"Display name '{f_name}' but mail comes from {kind}.", "high", SRC_H,
                                             category="impersonation"))
                break
    if not f_addr and has_headers:
        findings.append(make_finding("Missing or unparsable From address", "Legitimate mail has a valid sender.", "low", SRC_H))

    # --- content ---
    text_for_rules = (subject + "\n" + body)
    pat_findings, cats = scan_patterns(text_for_rules)
    findings += pat_findings

    # --- links ---
    urls = extract_urls(text_for_rules + "\n" + "\n".join(h for h, _ in link_parser.links if h))
    entities = {"urls": [], "domains": [], "ips": extract_ips(raw.decode("utf-8", "replace")), "emails": [],
                "phones": extract_phones(body)}
    for e in extract_emails(from_raw + " " + reply_raw + " " + str(msg["Return-Path"] or "") + " " + body):
        entities["emails"].append(e)
    url_results = []
    for u in urls:
        r = analyze_url(u, resolve_dns=resolve_dns)
        url_results.append(r)
        findings += [dict(x, context=r["url"]) for x in r["findings"]]
        for k in ("urls", "domains", "ips"):
            entities[k] += [x for x in r["entities"][k] if x not in entities[k]]
    for href, label in link_parser.links:
        label_urls = extract_urls(label or "")
        if label_urls and href:
            try:
                shown, real = registered_domain(re.sub(r"^https?://", "", label_urls[0]).split("/")[0].lower()), \
                              registered_domain(re.sub(r"^https?://", "", href).split("/")[0].split("@")[-1].lower())
            except Exception:
                continue
            if shown and real and shown != real:
                findings.append(make_finding("Link text does not match link target",
                                             f"The visible text shows {shown} but the link goes to {real}.", "high",
                                             "HTML link analysis", context=href[:200], category="deception"))
    if f_dom and url_results:
        mismatched = [r for r in url_results if r["entities"]["domains"] and
                      registered_domain(f_dom) not in [registered_domain(d) for d in r["entities"]["domains"]]]
        if mismatched and len(mismatched) == len(url_results) and f_dom not in FREE_MAIL:
            findings.append(make_finding("Links point away from the sender's domain", f"Sender domain {f_dom} does not "
                                         "match any linked domain (weak signal; common for newsletters).", "low", SRC_H))

    # --- attachments (names only) ---
    for name in attachments:
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in RISKY_EXT:
            findings.append(make_finding("Risky attachment type", f"'{name}' has an executable/script/macro-capable "
                                         "extension. PhishTrace did not open it.", "high", "Attachment metadata"))
        if name.lower().count(".") >= 2 and ext in RISKY_EXT | {".pdf", ".zip"}:
            findings.append(make_finding("Double file extension", f"'{name}' may disguise its real type.", "medium",
                                         "Attachment metadata"))

    # --- timeline events (only real timestamps found in the message) ---
    events = []
    d = _parse_date(meta["date"])
    if d:
        events.append({"time": d, "event": "Email Date header", "source": "Date header"})
    for rec in (msg.get_all("Received", []) or [])[:10]:
        rec = str(rec)
        if ";" in rec:
            t = _parse_date(rec.rsplit(";", 1)[-1].strip())
            if t:
                host = re.search(r"by\s+([\w.\-]+)", rec)
                events.append({"time": t, "event": f"Received by {host.group(1) if host else 'server'}",
                               "source": "Received header"})
    entities["emails"] = list(dict.fromkeys(entities["emails"]))
    return {"findings": findings, "entities": entities, "scam_type": scam_type_from(cats), "categories": cats,
            "url_results": url_results, "meta": meta, "events": events}
