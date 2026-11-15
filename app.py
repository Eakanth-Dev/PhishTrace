"""PhishTrace - AI-Powered Cyber Threat Detection & Digital Investigation Platform (Streamlit entry point)."""
import streamlit as st

import config
from database import db

st.set_page_config(page_title="PhishTrace", page_icon="\U0001F6E1\uFE0F", layout="wide", initial_sidebar_state="expanded")

from utils.ui import inject_css  # noqa: E402
from views import (assistant, evidence_explorer, investigations, overview, reports, scanner, settings,  # noqa: E402
                   timeline)

PAGES = {
    "\U0001F4CA Overview": overview.render,
    "\U0001F50E Threat Scanner": scanner.render,
    "\U0001F5C2\uFE0F Investigations": investigations.render,
    "\U0001F578\uFE0F Evidence Explorer": evidence_explorer.render,
    "\u23F1\uFE0F Timeline": timeline.render,
    "\U0001F916 AI Assistant": assistant.render,
    "\U0001F4C4 Reports": reports.render,
    "\u2699\uFE0F Settings": settings.render,
}


def main():
    db.init_db()
    inject_css()
    with st.sidebar:
        st.markdown('<div class="pt-brand">\U0001F6E1\uFE0F Phish<span>Trace</span></div>'
                    '<div class="pt-sub">Threat detection &amp; digital investigation</div>', unsafe_allow_html=True)
        page = st.radio("Navigation", list(PAGES), label_visibility="collapsed", key="nav")
        st.divider()
        cur = st.session_state.get("current_id")
        st.caption(f"Current investigation: `{cur}`" if cur else "No investigation selected")
        st.caption("Static analysis only: links are never opened. Scores are assessments, not guarantees.")
    PAGES[page]()


main()
