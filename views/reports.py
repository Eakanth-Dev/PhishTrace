import json

import streamlit as st

from database import db
from utils.pdf_generator import generate_report
from utils.ui import badge


def render():
    st.title("Reports")
    rows = db.list_investigations()
    if not rows:
        st.info("No investigations to report on yet.")
        return
    ids = [r["id"] for r in rows]
    cur = st.session_state.get("current_id")
    inv_id = st.selectbox("Investigation", ids, index=ids.index(cur) if cur in ids else 0)
    res = db.get_investigation(inv_id)
    st.markdown(f"{badge(res['risk_level'])} &nbsp; **{res['classification']}** &nbsp; score {res['risk_score']}/100", unsafe_allow_html=True)
    st.caption(f"{len(res['findings'])} findings · analysed {res['analysis_time']}")
    c1, c2 = st.columns(2)
    c1.download_button("Download PDF report", generate_report(res), f"PhishTrace_{inv_id}.pdf", "application/pdf", type="primary")
    c2.download_button("Download JSON (full record)", json.dumps(res, indent=2), f"PhishTrace_{inv_id}.json", "application/json")
