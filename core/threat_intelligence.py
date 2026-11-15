"""Optional external threat intelligence (VirusTotal, URLhaus).

* Only runs when the relevant key is configured AND the user enables it for the scan.
* Only two fixed API hosts are contacted; the submitted URL is sent purely as a query value.
  PhishTrace never contacts the submitted URL itself.
* Failures are reported honestly as 'error' - results are never fabricated or defaulted.
* A 'no match' is NOT evidence of safety.
"""
import base64
import json
import urllib.error
import urllib.parse
import urllib.request

from config import get_secret
from core.findings import make_finding

TIMEOUT = 8


def available_sources() -> dict:
    return {"VirusTotal": bool(get_secret("VIRUSTOTAL_API_KEY")), "URLhaus": bool(get_secret("URLHAUS_AUTH_KEY"))}


def _http(req):
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # fixed https hosts only
        return json.loads(resp.read().decode("utf-8", "replace"))


def query_virustotal(url: str) -> dict:
    key = get_secret("VIRUSTOTAL_API_KEY")
    if not key:
        return {"source": "VirusTotal", "status": "not_configured", "detail": "API key not set", "findings": []}
    vid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/urls/{vid}", headers={"x-apikey": key})
    try:
        data = _http(req)
        stats = data["data"]["attributes"]["last_analysis_stats"]
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())
        detail = f"{mal} malicious / {sus} suspicious of {total} engines (existing report; URL not submitted)"
        findings = []
        if mal >= 3:
            findings.append(make_finding("VirusTotal: multiple engines flag this URL", detail, "high", "VirusTotal API", points=28))
        elif mal + sus >= 1:
            findings.append(make_finding("VirusTotal: some engines flag this URL", detail, "medium", "VirusTotal API"))
        return {"source": "VirusTotal", "status": "match" if mal + sus else "no_match", "detail": detail, "findings": findings}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"source": "VirusTotal", "status": "no_match", "detail": "No existing report for this URL "
                    "(not evidence of safety).", "findings": []}
        return {"source": "VirusTotal", "status": "error", "detail": f"HTTP {e.code}", "findings": []}
    except Exception as e:
        return {"source": "VirusTotal", "status": "error", "detail": type(e).__name__, "findings": []}


def query_urlhaus(url: str) -> dict:
    key = get_secret("URLHAUS_AUTH_KEY")
    if not key:
        return {"source": "URLhaus", "status": "not_configured", "detail": "Auth key not set", "findings": []}
    body = urllib.parse.urlencode({"url": url}).encode()
    req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/url/", data=body, headers={"Auth-Key": key})
    try:
        data = _http(req)
        if data.get("query_status") == "ok":
            detail = f"Listed in URLhaus (status: {data.get('url_status', 'unknown')}, threat: {data.get('threat', 'unknown')})"
            return {"source": "URLhaus", "status": "match", "detail": detail,
                    "findings": [make_finding("URLhaus: URL is listed as malicious", detail, "critical", "URLhaus (abuse.ch)",
                                              points=40)]}
        if data.get("query_status") in ("no_results", "invalid_url"):
            return {"source": "URLhaus", "status": "no_match", "detail": "Not listed (not evidence of safety).", "findings": []}
        return {"source": "URLhaus", "status": "error", "detail": str(data.get("query_status")), "findings": []}
    except Exception as e:
        return {"source": "URLhaus", "status": "error", "detail": type(e).__name__, "findings": []}


def check_url(url: str) -> list:
    return [query_virustotal(url), query_urlhaus(url)]
