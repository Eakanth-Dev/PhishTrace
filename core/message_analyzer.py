"""SMS / chat / email-body scam analysis using transparent, documented regex rules.

Includes Indian banking, UPI, KYC, delivery and job-fee scam patterns. Each rule reports the
matched text as evidence. No network access.
"""
import re

from core.findings import make_finding
from core.url_analyzer import analyze_url
from utils.helpers import extract_emails, extract_ips, extract_phones, extract_urls

SRC = "Message pattern rules"

# (category, regex, indicator, explanation, severity)
RULES = [
    ("otp_share", r"\b(share|send|tell|give|forward|read out|provide|reply with)\b.{0,40}\b(otp|pin|cvv|password|one[- ]time|passcode)\b",
     "Asks you to share an OTP / PIN / CVV / password",
     "No bank, UPI app or government body will ever ask you to hand over an OTP, PIN, CVV or password.", "critical"),
    ("upi_collect", r"(collect request|approve (the |this )?(request|collect)|enter (your )?upi pin|scan (this |the )?qr.{0,40}(receive|refund|get (your )?money|credit)|accept (the )?(payment )?request.{0,30}(receive|refund))",
     "UPI 'receive money' trick",
     "You never need to enter a UPI PIN or approve a collect request to RECEIVE money - doing so sends money out.", "critical"),
    ("remote_access", r"\b(anydesk|teamviewer|quick ?support|rustdesk|ammyy|alpemix)\b",
     "Remote-access app mentioned",
     "Scammers ask victims to install screen-sharing apps to read OTPs and operate banking apps.", "critical"),
    ("apk", r"(\.apk\b|install (this |the |our )?(app|apk)|download (this |the )?(apk|app) from)",
     "Asks you to install an app / APK",
     "Side-loaded apps are a common way to steal SMS OTPs and banking data.", "high"),
    ("cred_ask", r"\b(enter|submit|confirm|update|verify|provide)\b.{0,35}\b(card number|debit card|credit card|net ?banking|login details|password|aadhaar|pan (card|number)|account number|date of birth|atm pin)\b",
     "Requests sensitive credentials or identity data",
     "Legitimate organisations do not collect credentials or identity numbers through links or messages.", "high"),
    ("threat", r"\b(account|card|sim|number|service|upi|wallet|connection|a/c)\b.{0,45}\b(block(ed)?|suspend(ed)?|deactivat\w*|freez\w*|clos(ed|ure)|expire[sd]?|disconnect\w*|restrict\w*)\b",
     "Threat of account blocking / suspension",
     "Fear of losing access is the most common pressure tactic in banking scams.", "high"),
    ("kyc", r"(\bre-?kyc\b|\bkyc\b|\b(pan|aadhaar)\b.{0,20}\b(update|verif\w*|link\w*|expire\w*)\b)",
     "KYC / identity update request",
     "Fake KYC messages are among the most reported banking scams in India; banks do not complete KYC through SMS links.", "medium"),
    ("job_fee", r"\b(registration|processing|security|refundable|joining|training|kit|verification|onboarding)\s*(fee|deposit|charges?|amount)\b",
     "Fee requested for a job / internship / service",
     "Genuine employers and programmes do not charge candidates to be hired or onboarded.", "high"),
    ("payment", r"((pay|send|transfer|deposit|remit)\b.{0,30}(\u20b9|rs\.?|inr)\s*\d|(\u20b9|rs\.?|inr)\s*\d[\d,]*.{0,30}\b(fee|charges?|deposit|payment|pay now)\b)",
     "Requests a payment",
     "Unexpected requests to pay small 'fees' are a classic way to harvest card/UPI details.", "high"),
    ("prize", r"\b(you (have )?won|lottery|lucky (draw|winner)|prize|congratulations|cashback of|reward points? (will )?expire|free (gift|iphone|recharge))\b",
     "Prize / reward lure",
     "Unsolicited prizes are used to collect personal data or advance fees.", "medium"),
    ("delivery", r"\b(parcel|package|courier|shipment|delivery|consignment)\b.{0,70}\b(held|pending|failed|undelivered|incomplete address|customs|redeliver\w*|reschedule|fee|on hold)\b",
     "Delivery problem notice",
     "Fake courier/postal notices push you to a lookalike site to pay a small 'redelivery fee'.", "medium"),
    ("urgency", r"\b(immediately|urgent(ly)?|within \d+\s*(min(ute)?s?|hours?|hrs?)|today only|last (chance|warning|reminder)|expires? (today|tonight|soon)|act now|final notice|without delay|asap)\b",
     "Artificial urgency",
     "Manufactured deadlines stop you from verifying. Real institutions give time and use official channels.", "medium"),
    ("contact_ask", r"\b(call|whatsapp|contact|message|text)\b.{0,30}(\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}",
     "Pushes you to call / WhatsApp a personal number",
     "Moving the conversation to a private number removes bank-side protections.", "medium"),
    ("impersonation", r"\b(rbi|reserve bank|income tax( department)?|trai|uidai|cbi|customs|police|cyber ?cell|customer care|bank (manager|official|executive)|sbi|hdfc|icici|axis bank|kotak|paytm|phonepe|amazon|flipkart|india post|dtdc|bluedart|hr (manager|team))\b",
     "Claims to be a known organisation",
     "Scammers impersonate banks, regulators and couriers. A claim in a message is not proof - verify independently.", "low"),
]
_COMPILED = [(c, re.compile(p, re.I | re.S), i, e, s) for c, p, i, e, s in RULES]

SCAM_TYPE_PRIORITY = [
    ("otp_share", "OTP / credential theft"),
    ("upi_collect", "UPI payment scam"),
    ("remote_access", "Remote-access scam"),
    ("job_fee", "Job / internship fee scam"),
    ("kyc", "Fake KYC / account-block scam"),
    ("threat", "Fake KYC / account-block scam"),
    ("delivery", "Fake delivery notice"),
    ("prize", "Prize / lottery scam"),
    ("payment", "Payment-request scam"),
    ("cred_ask", "Credential phishing"),
    ("apk", "Malicious app lure"),
]


def scan_patterns(text: str):
    """Return (findings, categories_hit) for free text."""
    findings, cats = [], []
    for cat, rx, indicator, expl, sev in _COMPILED:
        m = rx.search(text)
        if m:
            snippet = re.sub(r"\s+", " ", m.group(0))[:110]
            findings.append(make_finding(indicator, f"{expl} Matched text: \u201c{snippet}\u201d", sev, SRC, category=cat))
            cats.append(cat)
    strong = [c for c in cats if c not in ("impersonation", "urgency")]
    if len(set(cats)) >= 4 and strong:
        findings.append(make_finding("Multiple scam tactics combined",
                                     f"{len(set(cats))} separate manipulation techniques appear together "
                                     "(e.g. impersonation + urgency + payment/credential request).", "medium", SRC,
                                     category="combo"))
    return findings, cats


def scam_type_from(cats) -> str:
    for cat, label in SCAM_TYPE_PRIORITY:
        if cat in cats:
            return label
    return ""


def analyze_message(text: str, resolve_dns: bool = False) -> dict:
    text = (text or "").strip()
    findings, cats = scan_patterns(text)
    urls = extract_urls(text)
    url_results, entities = [], {"urls": [], "domains": [], "ips": [], "emails": extract_emails(text),
                                 "phones": extract_phones(text)}
    entities["ips"] += [i for i in extract_ips(text) if i not in entities["ips"]]
    for u in urls:
        r = analyze_url(u, resolve_dns=resolve_dns)
        url_results.append(r)
        for fd in r["findings"]:
            fd = dict(fd, context=r["url"])
            findings.append(fd)
        for k in ("urls", "domains", "ips"):
            entities[k] += [x for x in r["entities"][k] if x not in entities[k]]
    if urls and cats and any(c in cats for c in ("threat", "kyc", "payment", "delivery", "prize", "job_fee")):
        findings.append(make_finding("Pressure message paired with a link",
                                     "The message creates pressure AND directs you to a link - the core phishing pattern.",
                                     "medium", SRC, category="combo"))
    return {"findings": findings, "entities": entities, "scam_type": scam_type_from(cats),
            "categories": cats, "url_results": url_results, "meta": {}, "events": []}
