import streamlit as st

from config import get_secret
from core import recommendation_engine as rec
from database import db

QUICK = ["Why was this classified as suspicious?", "What indicators were identified?", "What does this threat mean?",
         "What should I do?", "How can I protect myself?"]


def render():
    st.title("Cybersecurity Assistant")
    rows = db.list_investigations()
    if not rows:
        st.info("Run a scan first - the assistant explains real investigation findings.")
        return
    ids = [r["id"] for r in rows]
    cur = st.session_state.get("current_id")
    inv_id = st.selectbox("Investigation", ids, index=ids.index(cur) if cur in ids else 0)
    result = db.get_investigation(inv_id)
    use_llm = bool(get_secret("ANTHROPIC_API_KEY"))
    st.caption("Mode: " + ("LLM-assisted (grounded in this investigation's findings only)" if use_llm
                           else "local explainer (no API key needed) - answers come directly from stored findings"))
    hist = st.session_state.setdefault("chat", {}).setdefault(inv_id, [])
    cols = st.columns(len(QUICK))
    pending = None
    for c, q in zip(cols, QUICK):
        if c.button(q, key=f"q_{inv_id}_{q}"):
            pending = q
    typed = st.chat_input("Ask about this investigation...")
    question = pending or typed
    if question:
        ans = (rec.llm_answer(question, result) if use_llm else None) or rec.answer_question(question, result)
        hist += [("user", question), ("assistant", ans)]
    if not hist:
        st.markdown(f"**{result['classification']}** - {result['risk_level']} ({result['risk_score']}/100). Pick a question above or type your own.")
    for role, text in hist:
        with st.chat_message(role):
            st.markdown(text)
