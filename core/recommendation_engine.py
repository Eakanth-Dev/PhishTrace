"""Recommendations and the local (offline) explanation assistant.

All answers are generated from the stored investigation result - nothing is invented. An optional
LLM can rephrase answers when ANTHROPIC_API_KEY is set; it is given only the investigation findings.
"""
import json
import re
import urllib.request

from config import get_secret

INDIA_REPORTING = ("In India, report cyber-fraud at cybercrime.gov.in or call 1930 (National Cyber Crime Helpline); "
                   "suspicious calls/SMS can also be reported via the Sanchar Saathi portal (Chakshu).")

SCAM_DESCRIPTIONS = {
    "OTP / credential theft": "The sender wants you to reveal a one-time password, PIN or password. With it they can approve payments or take over your account.",
    "UPI payment scam": "You are told you will 'receive' money but must approve a request, scan a QR or enter your UPI PIN - which actually sends money out.",
    "Remote-access scam": "Victims are guided to install screen-sharing software so the attacker can watch OTPs and operate banking apps.",
    "Job / internship fee scam": "A job or internship offer asks for a 'registration' or 'security' fee. Real employers do not charge candidates.",
    "Fake KYC / account-block scam": "A fake bank/wallet alert claims your account will be blocked unless you 'update KYC' via a link, which harvests credentials.",
    "Fake delivery notice": "A fake courier message asks for a small redelivery fee on a lookalike page to capture card/UPI details.",
    "Prize / lottery scam": "An unexpected prize is used to collect personal data or advance fees.",
    "Payment-request scam": "Pressure to make an unexpected payment to a person or account you cannot verify.",
    "Credential phishing": "A page or message tries to collect logins, card or identity details.",
    "Malicious app lure": "You are asked to install an app outside official stores, a common route to malware.",
    "UPI payment QR": "A QR that initiates a payment. Scanning it sends money from you.",
}
GENERIC_TIPS = [
    "Never share OTPs, PINs, CVV or passwords - nobody legitimate will ask.",
    "Type the organisation's address yourself or use its official app; do not use links from messages.",
    "Call the number printed on your card or the official website, not one from the message.",
    "Pause when you feel rushed - urgency is the scammer's main tool.",
    "Enable two-factor authentication and transaction alerts; keep apps/OS updated.",
    "You never need to enter a UPI PIN or scan a QR to receive money.",
]


def recommend(result: dict) -> list:
    level, itype, st = result["risk_level"], result["input_type"], result.get("scam_type", "")
    cats = set(result.get("categories", []))
    recs = []
    if level in ("High Risk", "Critical Risk"):
        recs += ["Do not click links, open attachments, scan the QR or reply.",
                 "Do not share any OTP, PIN, CVV, password or card/Aadhaar details.",
                 "Block the sender and delete the message after reporting it."]
    elif level == "Medium Risk":
        recs += ["Treat this as suspicious until you verify it independently - do not act on the message itself."]
    else:
        recs += ["No strong indicators were found, but this is not a guarantee of safety. Verify unexpected requests independently."]
    recs.append("Verify through the organisation's official app or website, or a phone number you obtained independently.")
    if "job_fee" in cats or st == "Job / internship fee scam":
        recs.append("Check the company's official careers page or your college placement cell; genuine employers do not charge fees.")
    if "delivery" in cats:
        recs.append("Track the parcel using the tracking number on the courier's official website or app.")
    if "upi_collect" in cats or itype == "qr" or st.startswith("UPI"):
        recs.append("Remember: entering a UPI PIN or approving a collect request only ever sends money out.")
    if itype == "email":
        recs.append("Inspect the real sender address and headers; do not rely on the display name. Do not open attachments.")
    if itype in ("url", "qr") and level != "Low Risk":
        recs.append("If you must inspect the site, use a separate isolated environment - never enter credentials.")
    if level in ("High Risk", "Critical Risk"):
        recs.append("If you already clicked, paid or shared details: call your bank immediately to block cards/accounts, "
                    "change passwords, and report quickly. " + INDIA_REPORTING)
    return recs


def _top(findings, n=5):
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    real = [f for f in findings if f["severity"] != "info"]
    return sorted(real, key=lambda f: -order[f["severity"]])[:n]


def answer_question(question: str, result: dict) -> str:
    q = question.lower()
    fs, score, level = result["findings"], result["risk_score"], result["risk_level"]
    top = _top(fs)
    if re.search(r"\b(why|classif|suspicious|reason|flag)", q):
        if not top:
            return (f"I rated this **{level}** ({score}/100) because no notable indicators were found. That is not proof of safety - "
                    "new scams often have no reputation history yet.")
        lines = [f"This was rated **{level}** (score {score}/100) mainly because of:"]
        lines += [f"- **{f['indicator']}** ({f['severity']}): {f['explanation']}" for f in top]
        lines.append("\nScore = saturating sum of weighted indicators; it is an assessment, not a guarantee.")
        return "\n".join(lines)
    if re.search(r"\b(indicator|signal|evidence|found|identified)", q):
        if not fs:
            return "No indicators were recorded for this investigation."
        return "\n".join(f"- [{f['severity'].upper()}] **{f['indicator']}** - source: {f['source']}" for f in fs)
    if re.search(r"\b(mean|threat|what is|type|kind of)", q):
        st = result.get("scam_type") or ""
        base = SCAM_DESCRIPTIONS.get(st, "No specific scam pattern was identified; the rating comes from the individual indicators listed.")
        return f"**Classification:** {result['classification']}\n\n{base}"
    if re.search(r"\b(do|should|next|action|respond|step)", q):
        return "Recommended actions:\n" + "\n".join(f"- {r}" for r in result["recommendations"])
    if re.search(r"\b(protect|prevent|avoid|safe|tips|future)", q):
        return "How to protect yourself:\n" + "\n".join(f"- {t}" for t in GENERIC_TIPS) + "\n\n" + INDIA_REPORTING
    if re.search(r"\b(score|level|percent|how (risky|dangerous))", q):
        return (f"Risk score **{score}/100 = {level}**. Each finding adds weighted points (low 5, medium 12, high 22, critical 35); "
                "the total saturates towards 100. Bands: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical.")
    if re.search(r"\b(limit|sure|accura|false|certain|unknown|trust)", q):
        return "Limitations of this analysis:\n" + "\n".join(f"- {u}" for u in result.get("unknowns", []))
    return (f"Investigation **{result.get('investigation_id', '')}**: {result['classification']} - {level} ({score}/100). "
            "Ask me: *Why was this suspicious? What indicators were found? What does this threat mean? What should I do? "
            "How can I protect myself?*")


def llm_answer(question: str, result: dict):
    """Optional: rephrase using an LLM, grounded ONLY in the investigation JSON. Returns None on any failure."""
    key = get_secret("ANTHROPIC_API_KEY")
    if not key:
        return None
    context = {k: result.get(k) for k in ("input_type", "classification", "risk_score", "risk_level", "findings",
                                          "recommendations", "unknowns")}
    body = json.dumps({"model": get_secret("ANTHROPIC_MODEL") or "claude-sonnet-5-5", "max_tokens": 700,
                       "system": "You are a cybersecurity assistant. Answer ONLY from the investigation JSON. If something is "
                                 "not in it, say it was not determined. Never claim a URL or sender is safe. Be concise.",
                       "messages": [{"role": "user", "content": f"Investigation: {json.dumps(context)[:12000]}\n\nQuestion: {question}"}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.loads(r.read().decode())
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text") or None
    except Exception:
        return None
