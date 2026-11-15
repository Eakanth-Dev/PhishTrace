# 🛡️ PhishTrace
**AI-Powered Cyber Threat Detection & Digital Investigation Platform** · INNOVEX 2026 · PS05 – AI-Powered Cybersecurity

PhishTrace helps people judge suspicious URLs, emails, SMS/chat messages and QR codes **before** they click, reply or pay — and keeps
every analysis as a persistent, explainable investigation with evidence graph, timeline and PDF report.

## Problem
Phishing and payment scams (fake KYC, UPI "refund" traps, fake delivery fees, internship-fee offers) reach people through many
channels. Existing tools mostly return a bare "unsafe" label for *known* bad links. Users need to understand **why**, what is **unknown**,
and what to **do next** — in one place, without handing data to a paid service.

## Solution
One hybrid engine behind four scanners → one investigation record → dashboard, graph, timeline, assistant and PDF.
**Detect → Explain → Guide.** Static analysis only: PhishTrace never visits a link.

## Features
| Area | What is implemented |
|---|---|
| Overview | KPIs, risk/type distribution, activity, score histogram, recent scans — all computed from SQLite records |
| URL scanner | HTTPS, IP/obfuscated hosts, length, subdomains, keywords, encoding, punycode, TLD, shorteners, `@` tricks, open-redirect params, brand impersonation & typosquatting, optional DNS lookup |
| Email scanner | Paste or `.eml`; From / Reply-To / Subject / Date / Received, SPF-DKIM-DMARC as reported, display-name spoofing, HTML link-text mismatch, risky attachment *names* (never opened), URLs, social-engineering text |
| Message scanner | OTP/PIN theft, fake KYC, UPI collect/QR traps, remote-access apps, APK lures, fee requests (job/internship), delivery scams, urgency, impersonation, links, phone numbers |
| QR scanner | Local decode (pyzbar if present, else OpenCV), UPI-QR parsing, URL → URL engine; destination never visited |
| Detection engine | Rules + explainable feature scoring + optional user-trained scikit-learn model + optional threat intel. Every finding has **indicator, explanation, severity, evidence source** |
| Threat intel | VirusTotal (existing-report lookup) and URLhaus, only with keys; errors/“no match” reported honestly |
| Investigation centre | Persistent records, filters, re-open, delete |
| Evidence explorer | NetworkX + Plotly graph; edges labelled *extracted* / *observed (DNS)* / *inferred* |
| Timeline | Only real timestamps (analysis time + email Date/Received headers) |
| Assistant | Answers from stored findings (why, indicators, meaning, actions, protection, score, limits); optional LLM grounded on findings |
| PDF reports | Branded report with evidence, indicators, findings, actions, limitations, scoring method |

### Risk scoring (documented, deterministic)
Findings add points by severity (low 5 · medium 12 · high 22 · critical 35; a few override, e.g. *No HTTPS* 10, URLhaus listing 40).
Identical indicators count once. `score = round(100 × (1 − e^(−total/55)))`.
Bands: **0–24 Low · 25–49 Medium · 50–74 High · 75–100 Critical**. The score is an *assessment, not a guarantee*; PhishTrace never labels anything "safe".

## Real scans, demonstration data and where records live

**Real scans.** Every scan you run in *Threat Scanner* (URL, email, message, QR image) is analysed statically and saved as a **real**
investigation (`is_demo = 0`) in a local SQLite file. Each record has a unique ID (`PT-YYYYMMDD-XXXXXX`) and keeps the evidence
(card-like numbers, Aadhaar-like IDs and OTP/PIN values are masked before storage), classification, score, findings, recommendations and timestamps.
Records survive restarts and can be reopened from *Investigations*. If an input is rejected (e.g. too long, unreadable QR image) or the analysis
or database write fails, the reason is shown on screen (and logged); nothing is dropped silently. Inputs that could not be analysed are **not**
stored, because a record would have no analysis to show.

**Demonstration data.** `core/demo_data.py` holds fictional examples (reserved `.example` domains, documentation IPs). They are stored only
when you explicitly press **Save as DEMO record** (Threat Scanner), **Load demonstration records** (Overview / Settings). Rules:
* Loading an example into an input box only fills the box. Pressing *Scan* afterwards stores a normal **real** record - PhishTrace never guesses
  "demo" by comparing your text with the examples.
* Demo loading is idempotent (fixed IDs `PT-DEMO-…`, and older demo records are recognised): pressing it repeatedly never duplicates, and it never
  reads or modifies real records.
* Demo records are labelled **DEMO** everywhere (badge, tables, PDF).

**Excluding demo records.** The Overview dashboard hides demo records by default; every KPI, chart and the recent-scans table is computed from the
same selection. Switch on *Include demonstration records* to include them (a warning banner then shows that figures mix real and fictional data).
*Investigations* has a *Records* filter (Real only / All / Demo only). *Settings → Delete demonstration records only* removes demos and keeps real data.

**Where data is stored.** `data/phishtrace.db` (SQLite; override with `PHISHTRACE_DB`). It is git-ignored. Settings shows the exact path.

**Resetting the local database safely.**
1. Stop the app. 2. Back up: copy `data/phishtrace.db` somewhere safe. 3. Either use *Settings → Delete all investigations* (needs the confirm
checkbox) or delete `data/phishtrace.db`; a fresh empty database is created on next start. To remove only fictional data use *Delete demonstration records only*.

## What is implemented vs optional
| Implemented (works with no keys) | Optional / needs setup |
|---|---|
| URL, email (.eml/paste), message and QR scanning; rule-based detection and explainable 0-100 scoring | VirusTotal / URLhaus lookups - need your API keys, off otherwise |
| SQLite investigations, dashboard, evidence graph, timeline, local assistant, PDF reports | LLM phrasing for the assistant - needs `ANTHROPIC_API_KEY` |
| Optional DNS lookup (checkbox; never connects to the site) | `pyzbar` QR decoder (OpenCV is used otherwise) |
| | **ML model: NOT included.** Detection is rule-based. A scikit-learn model is used only if *you* train one (`python -m core.ml_engine train urls.csv`) and it is loaded; Settings states whether one is present |

## Architecture
```
phishtrace/
├── app.py                  # Streamlit entry, sidebar navigation
├── config.py               # paths, limits, secrets loader (env / .env / st.secrets)
├── views/                  # UI pages (named views/ so Streamlit doesn't auto-add a second nav)
│   overview · scanner · investigations · evidence_explorer · timeline · assistant · reports · settings
├── core/
│   url_analyzer · email_analyzer · message_analyzer · qr_analyzer
│   risk_engine (orchestrator + scoring) · ml_engine · threat_intelligence
│   evidence_engine (graph + timeline) · recommendation_engine · findings · demo_data
├── database/ (db.py, schema.sql)   ├── utils/ (helpers, pdf_generator, ui)
├── tests/   ├── assets/   ├── models/   └── data/
```
Flow: input → analyzer (findings + entities) → `risk_engine.analyze` (merge, ML/intel layers, score, recommendations) → `db.save_investigation` → pages.

## Installation & run
```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                      # optional keys
streamlit run app.py
```
Open http://localhost:8501 → *Threat Scanner* to scan real evidence. The Overview is empty until you do; to explore with fictional data use **Load demonstration records** and then switch on *Include demonstration records*.
Run tests: `python -m unittest discover -s tests -v`   (or `pytest`)

Optional QR decoder: `pip install pyzbar` (needs the system `zbar` library: `apt install libzbar0` / `brew install zbar`). Without it OpenCV is used.

## Environment variables (all optional)
| Variable | Purpose |
|---|---|
| `VIRUSTOTAL_API_KEY` | Looks up *existing* VT reports (URL is not submitted) |
| `URLHAUS_AUTH_KEY` | URLhaus lookup (free abuse.ch Auth-Key) |
| `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` | Optional LLM phrasing for the assistant; grounded on findings only |
| `PHISHTRACE_DB` | Alternative SQLite path |

Keys can also live in `.streamlit/secrets.toml`. They are never displayed or logged.

## Training the optional ML model
No dataset or model is bundled and none is fabricated. Without one, scoring is the rule-based baseline and the UI says so.
```bash
python -m core.ml_engine train urls.csv     # columns: url,label  (1 = malicious, 0 = benign; ≥50 rows, ≥10 per class)
```
This trains a RandomForest on deterministic URL features, reports metrics measured on a held-out split **of your data**, and saves
`models/url_model.joblib`. Public sources you may download yourself (check licences): PhishTank, URLhaus, OpenPhish, Tranco (benign).

## Deployment
* **Streamlit Community Cloud**: push to GitHub → New app → `app.py`; add keys under *Secrets*. SQLite is ephemeral there—fine for a demo.
* **Docker/VM**: `pip install -r requirements.txt && streamlit run app.py --server.port 8501 --server.address 0.0.0.0` behind HTTPS; mount `data/` as a volume.
* No authentication is built in — put it behind an authenticated proxy before exposing publicly.

## Security design
Never visits submitted URLs, follows redirects, or executes/saves attachments · 5 MB upload cap & image validation · text/URL length limits ·
parameterised SQL · all dynamic text HTML-escaped · URLs displayed defanged · card/Aadhaar-like numbers and OTP/PIN values masked before storage ·
external lookups only to two fixed API hosts · threat intel treated as supporting evidence; "no match" ≠ safe.

## Screenshots
Add after running locally: `assets/overview.png`, `assets/scanner.png`, `assets/evidence_graph.png`, `assets/report.png`.

## Limitations
* Rule-based baseline; heuristics can produce false positives/negatives. No ML model ships by default.
* Brand/official-domain list is small and curated, not exhaustive. TLD and keyword signals are weak.
* No page rendering/WHOIS/domain-age checks (would require visiting or extra services). DNS check is opt-in.
* Email authentication is only what the pasted headers report. English-centric patterns (Hindi/Kannada/code-mixed untested).
* Evidence graph shows only relationships present in the evidence; *inferred* edges are comparisons, not proof.
* Automated tests (`python -m unittest discover -s tests -v`) cover core logic, database, workflow and scanner button logic (with a stubbed Streamlit). `tests/test_app_smoke.py` boots the real app but is skipped when Streamlit is not installed - run it after `pip install -r requirements.txt`.

## Future scope
Trained model with a documented benchmark · Kannada/Hindi/code-mixed support · browser extension · Google Safe Browsing / PhishTank connectors ·
screenshot OCR · user authentication and multi-user storage · community-reviewed indicator feed.

*Demonstration data is fictional (reserved `.example` domains, documentation IPs) and is always labelled DEMO.*
