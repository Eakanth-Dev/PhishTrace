"""Hybrid detection engine: orchestrates analyzers and computes the 0-100 risk score.

SCORING LOGIC (documented, deterministic):
  1. Every finding carries points from its severity: info 0, low 5, medium 12, high 22, critical 35
     (a few findings override this, e.g. 'No HTTPS' = 10, URLhaus listing = 40).
  2. Findings with the same indicator (e.g. the same flaw on several URLs) are merged: counted once.
  3. total = sum(points);  score = round(100 * (1 - exp(-total / 55)))  -> saturates smoothly towards 100.
       total 12 -> 20 | 22 -> 33 | 40 -> 52 | 80 -> 77
  4. Bands: 0-24 Low Risk | 25-49 Medium Risk | 50-74 High Risk | 75-100 Critical Risk.
Layers: (a) deterministic rules, (b) explainable feature scoring, (c) optional user-trained scikit-learn model,
(d) optional external threat intelligence. The score is an assessment, never a guarantee.
"""
import math

from config import MAX_INTEL_LOOKUPS, MAX_TEXT_CHARS, RISK_LEVELS
from core import ml_engine, threat_intelligence
from core.email_analyzer import analyze_email
from core.message_analyzer import analyze_message
from core.qr_analyzer import analyze_qr_image, analyze_qr_payload
from core.recommendation_engine import recommend
from core.url_analyzer import analyze_url
from utils.helpers import now_iso

INPUT_TYPES = ("url", "email", "message", "qr", "qr_payload")
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def level_for(score: int) -> str:
    for limit, name in RISK_LEVELS:
        if score < limit:
            return name
    return RISK_LEVELS[-1][1]


def merge_findings(findings: list) -> list:
    merged = {}
    for f in findings:
        key = f["indicator"]
        if key not in merged:
            merged[key] = dict(f, contexts=[f["context"]] if f.get("context") else [])
        else:
            m = merged[key]
            if f.get("context") and f["context"] not in m["contexts"]:
                m["contexts"].append(f["context"])
            if f["points"] > m["points"]:
                m.update({k: f[k] for k in ("points", "severity", "explanation", "source")})
    out = list(merged.values())
    for m in out:
        m["context"] = "; ".join(c[:120] for c in m.pop("contexts")[:3]) or None
    return sorted(out, key=lambda f: (-SEV_RANK[f["severity"]], f["indicator"]))


def compute_score(findings: list):
    total = sum(f["points"] for f in findings)
    score = min(100, round(100 * (1 - math.exp(-total / 55))))
    return score, level_for(score)


def _classification(input_type, scam_type, score, level):
    if scam_type and score >= 25:
        return scam_type
    labels = {"url": ("Likely phishing URL", "Suspicious URL", "No strong indicators"),
              "email": ("Likely phishing email", "Suspicious email", "No strong indicators"),
              "message": ("Likely scam message", "Suspicious message", "No strong indicators"),
              "qr": ("Likely malicious QR", "Suspicious QR", "No strong indicators")}
    hi, mid, lo = labels["qr" if input_type.startswith("qr") else input_type]
    return hi if score >= 50 else mid if score >= 25 else lo


def analyze(input_type: str, content, *, resolve_dns: bool = False, use_intel: bool = False) -> dict:
    """Run a full analysis and return a JSON-serialisable result dict (not yet persisted)."""
    if input_type not in INPUT_TYPES:
        raise ValueError(f"Unsupported input type: {input_type}")
    if input_type in ("email", "message", "qr_payload") and isinstance(content, str) and len(content) > MAX_TEXT_CHARS:
        raise ValueError(f"Input too long (limit {MAX_TEXT_CHARS} characters).")
    qr_error = None
    if input_type == "url":
        r = analyze_url(content, resolve_dns=resolve_dns)
        raw = {"findings": r["findings"], "entities": dict(r["entities"], emails=[], phones=[]), "scam_type": "",
               "categories": [], "url_results": [r], "meta": {"dns": r["dns"]}, "events": []}
    elif input_type == "email":
        raw = analyze_email(content, resolve_dns=resolve_dns)
    elif input_type == "message":
        raw = analyze_message(content, resolve_dns=resolve_dns)
    elif input_type == "qr":
        raw = analyze_qr_image(content, resolve_dns=resolve_dns)
        qr_error = raw.get("error")
    else:
        raw = analyze_qr_payload(content, resolve_dns=resolve_dns)

    findings = list(raw["findings"])
    unknowns, intel = [], []
    urls = [r["url"] for r in raw["url_results"] if r.get("valid")]
    # (c) optional ML layer
    if urls:
        if ml_engine.is_available():
            for u in urls[:MAX_INTEL_LOOKUPS]:
                mf = ml_engine.ml_finding(u)
                if mf:
                    findings.append(dict(mf, context=u))
        else:
            unknowns.append("No trained ML model is installed: the score is rule-based only (see Settings to train one).")
    # (d) optional threat intelligence
    if use_intel and urls:
        if not any(threat_intelligence.available_sources().values()):
            unknowns.append("Threat-intelligence lookup requested but no API keys are configured.")
        for u in urls[:MAX_INTEL_LOOKUPS]:
            for res in threat_intelligence.check_url(u):
                res = dict(res, url=u)
                intel.append(res)
                findings += [dict(f, context=u) for f in res["findings"]]
        if intel and not any(i["status"] in ("match", "no_match") for i in intel):
            unknowns.append("Threat-intelligence services could not be queried (not configured or errors).")
    elif urls:
        unknowns.append("No external threat-intelligence lookup was performed.")
    if urls and not resolve_dns:
        unknowns.append("DNS/domain checks were not performed.")
    unknowns.append("Page content was never fetched or rendered; analysis is based on the text/URL structure only.")
    if qr_error:
        unknowns.append(qr_error)
    if input_type == "email" and not raw["meta"].get("auth"):
        unknowns.append("No SPF/DKIM/DMARC results were available in the submitted email.")
    if not findings or all(f["severity"] == "info" for f in findings):
        unknowns.append("Absence of indicators does not prove safety; new scams may have no known signals yet.")

    merged = merge_findings(findings)
    score, level = compute_score(merged)
    classification = qr_error and "Could not decode QR" or _classification(input_type, raw.get("scam_type", ""), score, level)
    result = {
        "input_type": "qr" if input_type == "qr_payload" else input_type,
        "analysis_time": now_iso(),
        "classification": classification,
        "scam_type": raw.get("scam_type", ""),
        "categories": raw.get("categories", []),
        "risk_score": score,
        "risk_level": level,
        "findings": merged,
        "entities": {k: list(dict.fromkeys(v)) for k, v in raw["entities"].items()},
        "meta": raw.get("meta", {}),
        "events": raw.get("events", []),
        "intel": intel,
        "unknowns": unknowns,
        "ml_model": "available" if ml_engine.is_available() else "not available (rule-based baseline)",
        "disclaimer": "This score is an automated assessment, not a guarantee. A low score does not prove content is safe.",
    }
    result["recommendations"] = recommend(result)
    return result
