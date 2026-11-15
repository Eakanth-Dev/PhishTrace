"""Finding data model shared by every analyzer.

Every finding has: indicator, explanation, severity, evidence source (+ points, context).
Severity -> default points (used by risk_engine, see SCORING in risk_engine.py).
"""
SEVERITY_POINTS = {"info": 0, "low": 5, "medium": 12, "high": 22, "critical": 35}
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def make_finding(indicator, explanation, severity, source, points=None, context=None, category=None):
    if severity not in SEVERITY_POINTS:
        raise ValueError(f"unknown severity: {severity}")
    return {
        "indicator": indicator,
        "explanation": explanation,
        "severity": severity,
        "source": source,
        "points": SEVERITY_POINTS[severity] if points is None else points,
        "context": context,
        "category": category,
    }
