"""Shared Streamlit UI helpers: theme CSS, badges, gauge and the result renderer.
All dynamic text is HTML-escaped before it is placed into markup."""
from html import escape as esc

import pandas as pd
import streamlit as st

from core.url_analyzer import url_features  # noqa: F401  (kept for type parity)
from utils.helpers import defang_display
from utils.pdf_generator import generate_report

LEVEL_COLORS = {"Low Risk": "#22c55e", "Medium Risk": "#f59e0b", "High Risk": "#f97316", "Critical Risk": "#ef4444"}
SEV_COLORS = {"critical": "#ef4444", "high": "#f97316", "medium": "#f59e0b", "low": "#38bdf8", "info": "#64748b"}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
html, body, [class*="css"], .stApp { font-family: 'Inter', sans-serif; }
.stApp { background: radial-gradient(1200px 600px at 80% -10%, #12234a55, transparent), #0b1220; }
section[data-testid="stSidebar"] { background: #0a1020; border-right: 1px solid #1f2a44; }
.block-container { padding-top: 2rem; max-width: 1280px; }
h1, h2, h3 { letter-spacing: -0.02em; }
.pt-brand { font-size: 1.5rem; font-weight: 700; color: #e2e8f0; }
.pt-brand span { color: #38bdf8; }
.pt-sub { color: #94a3b8; font-size: .78rem; margin-bottom: 1rem; }
.pt-card { background: linear-gradient(180deg,#111a2e,#0f172a); border: 1px solid #1f2a44; border-radius: 14px; padding: 16px 18px; }
.pt-metric-label { color: #94a3b8; font-size: .75rem; text-transform: uppercase; letter-spacing: .08em; }
.pt-metric-value { font-size: 2rem; font-weight: 700; color: #f1f5f9; line-height: 1.2; }
.pt-metric-sub { color: #64748b; font-size: .72rem; }
.pt-badge { display:inline-block; padding: 4px 12px; border-radius: 999px; font-weight: 600; font-size: .8rem; border: 1px solid; }
.pt-finding { background:#0f172a; border:1px solid #1f2a44; border-left:4px solid var(--c); border-radius:10px; padding:10px 14px; margin-bottom:8px; }
.pt-finding b { color:#f1f5f9; }
.pt-finding .meta { color:#64748b; font-size:.72rem; font-family:'JetBrains Mono',monospace; }
.pt-sev { color: var(--c); font-weight: 700; font-size:.7rem; letter-spacing:.08em; }
.pt-note { color:#94a3b8; font-size:.8rem; border:1px dashed #334155; border-radius:10px; padding:8px 12px; }
.pt-demo { background:#f59e0b22; color:#fbbf24; border:1px solid #f59e0b55; border-radius:6px; padding:1px 8px; font-size:.7rem; font-weight:600; }
code, pre { font-family: 'JetBrains Mono', monospace !important; }
div[data-testid="stTabs"] button { font-weight: 600; }
.stButton>button, .stDownloadButton>button { border-radius: 10px; border: 1px solid #1f2a44; font-weight: 600; }
.stButton>button[kind="primary"] { background: linear-gradient(90deg,#0284c7,#38bdf8); border: none; color: #04111f; }
@media (max-width: 768px) { .pt-metric-value { font-size: 1.5rem; } .block-container { padding: 1rem; } }
</style>
"""


def inject_css():
    st.markdown(CSS, unsafe_allow_html=True)


def badge(level: str) -> str:
    c = LEVEL_COLORS.get(level, "#64748b")
    return f'<span class="pt-badge" style="color:{c};border-color:{c};background:{c}22">{esc(level)}</span>'


def metric_card(label: str, value, sub: str = ""):
    st.markdown(f'<div class="pt-card"><div class="pt-metric-label">{esc(label)}</div>'
                f'<div class="pt-metric-value">{esc(str(value))}</div><div class="pt-metric-sub">{esc(sub)}</div></div>',
                unsafe_allow_html=True)


def gauge(score: int, level: str):
    import plotly.graph_objects as go
    c = LEVEL_COLORS.get(level, "#64748b")
    fig = go.Figure(go.Indicator(mode="gauge+number", value=score, number=dict(font=dict(color="#f1f5f9", size=44)),
                                 gauge=dict(axis=dict(range=[0, 100], tickcolor="#64748b"), bar=dict(color=c, thickness=0.3),
                                            bgcolor="#0f172a", borderwidth=0,
                                            steps=[dict(range=[0, 25], color="#14532d55"), dict(range=[25, 50], color="#78350f55"),
                                                   dict(range=[50, 75], color="#7c2d1255"), dict(range=[75, 100], color="#7f1d1d55")])))
    fig.update_layout(height=210, margin=dict(l=20, r=20, t=20, b=0), paper_bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0"))
    return fig


def finding_card(f: dict) -> str:
    c = SEV_COLORS[f["severity"]]
    ctx = f'<div class="meta">context: {esc(f["context"])}</div>' if f.get("context") else ""
    return (f'<div class="pt-finding" style="--c:{c}"><span class="pt-sev">{esc(f["severity"].upper())}</span> '
            f'&nbsp;<b>{esc(f["indicator"])}</b><div style="color:#cbd5e1;font-size:.85rem;margin-top:2px">{esc(f["explanation"])}</div>'
            f'<div class="meta">evidence source: {esc(f["source"])} &middot; +{f["points"]} pts</div>{ctx}</div>')


def render_result(result: dict, key: str = "res"):
    inv = result.get("investigation_id", "unsaved")
    left, right = st.columns([1, 2])
    with left:
        st.plotly_chart(gauge(result["risk_score"], result["risk_level"]), key=f"g_{key}")
    with right:
        demo = ' <span class="pt-demo">DEMO DATA</span>' if result.get("is_demo") else ""
        st.markdown(f'{badge(result["risk_level"])}{demo}', unsafe_allow_html=True)
        st.markdown(f"### {esc(result['classification'])}")
        st.caption(f"Investigation {inv} · {result['analysis_time']} · input: {result['input_type'].upper()}")
        st.markdown(f'<div class="pt-note">{esc(result.get("disclaimer", ""))} '
                    f'Engine: rule-based indicators + feature scoring · ML model: {esc(result.get("ml_model", "n/a"))}.</div>',
                    unsafe_allow_html=True)
    t1, t2, t3, t4, t5 = st.tabs(["Findings", "Indicators", "Recommendations", "Threat intel & limits", "Report"])
    with t1:
        if result["findings"]:
            st.markdown("".join(finding_card(f) for f in result["findings"]), unsafe_allow_html=True)
        else:
            st.info("No findings were produced.")
    with t2:
        ent, rows = result.get("entities", {}), []
        for k, vals in ent.items():
            for v in vals:
                rows.append({"type": k[:-1] if k.endswith("s") else k, "value": defang_display(v) if k == "urls" else v})
        meta = result.get("meta", {})
        if meta.get("from"):
            st.markdown("**Email metadata**")
            st.dataframe(pd.DataFrame([{"field": k, "value": str(v)} for k, v in meta.items()
                                       if k in ("from", "reply_to", "subject", "date", "return_path", "to", "auth", "attachments") and v]),
                         hide_index=True)
        st.markdown("**Extracted indicators** (URLs shown defanged, not clickable)")
        st.dataframe(pd.DataFrame(rows) if rows else pd.DataFrame({"info": ["Nothing extracted"]}), hide_index=True)
    with t3:
        for r in result["recommendations"]:
            st.markdown(f"- {r}")
    with t4:
        intel = result.get("intel", [])
        if intel:
            st.dataframe(pd.DataFrame([{"source": i["source"], "url": defang_display(i["url"]), "status": i["status"],
                                        "detail": i["detail"]} for i in intel]), hide_index=True)
        else:
            st.caption("No threat-intelligence lookups were run for this investigation.")
        st.markdown("**What this analysis could not determine**")
        for u in result.get("unknowns", []):
            st.markdown(f"- {u}")
    with t5:
        st.download_button("Download PDF report", data=generate_report(result), file_name=f"PhishTrace_{inv}.pdf",
                           mime="application/pdf", key=f"pdf_{key}", type="primary")
        if result.get("evidence"):
            with st.expander("Stored evidence (sensitive values masked)"):
                st.code(result["evidence"], language=None)
