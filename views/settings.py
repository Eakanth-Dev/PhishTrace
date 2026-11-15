import importlib.util

import pandas as pd
import streamlit as st

import config
from core import ml_engine, qr_analyzer, threat_intelligence
from core.workflow import load_demo_records
from database import db


def render():
    st.title("Settings & System Status")
    st.subheader("Dependencies")
    dec = qr_analyzer.decoders_available()
    deps = {"tldextract": importlib.util.find_spec("tldextract") is not None, "OpenCV (QR)": dec["opencv"],
            "pyzbar (QR, optional)": dec["pyzbar"], "scikit-learn": importlib.util.find_spec("sklearn") is not None}
    st.dataframe(pd.DataFrame({"component": list(deps), "available": ["yes" if v else "no" for v in deps.values()]}),
                 hide_index=True)
    st.subheader("Threat intelligence (optional)")
    st.caption("Keys are read from environment variables / .env / Streamlit secrets and are never displayed.")
    st.dataframe(pd.DataFrame([{"service": k, "configured": "yes" if v else "no"} for k, v in threat_intelligence.available_sources().items()]),
                 hide_index=True)
    st.subheader("Machine-learning model")
    if ml_engine.is_available():
        st.success("A locally trained model is installed.")
        st.json(ml_engine.load_metrics() or {})
    else:
        st.warning("No trained model is installed. PhishTrace ships no model or dataset (none may be fabricated), so scoring is a "
                   "rule-based baseline. Train on your own labelled CSV (columns `url,label`, 1 = malicious):")
        st.code("python -m core.ml_engine train path/to/urls.csv", language="bash")
    st.subheader("Scoring methodology")
    st.markdown("Each finding adds weighted points (**low 5, medium 12, high 22, critical 35**; a few override). Duplicate indicators "
                "count once. `score = 100 × (1 − e^(−total/55))`. Bands: **0-24 Low · 25-49 Medium · 50-74 High · 75-100 Critical**. "
                "The score is an assessment, not a guarantee; a low score never means a link is safe.")
    st.subheader("Data")
    st.caption(f"Database: `{config.DB_PATH}` · stored evidence has card-like numbers, Aadhaar-like IDs and OTP/PIN values masked.")
    counts = db.count_records()
    st.caption(f"Stored: {counts['real']} real, {counts['demo']} demonstration record(s).")
    if st.button("Load demonstration records"):
        added, existing = load_demo_records()
        st.success(f"Added {len(added)}; {len(existing)} already loaded (skipped). Real investigations were not modified.")
    if st.button("Delete demonstration records only", help="Real investigations are kept."):
        st.success(f"Deleted {db.delete_demo_records()} demonstration record(s). Real investigations were not touched.")
    st.markdown("**Danger zone**")
    confirm = st.checkbox("I understand this permanently deletes ALL investigations, including real ones")
    if st.button("Delete all investigations", disabled=not confirm):
        db.delete_all()
        st.session_state.pop("current_id", None)
        st.session_state.pop("last_result", None)
        st.success("All investigations deleted.")
