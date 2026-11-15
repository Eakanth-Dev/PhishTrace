import pandas as pd
import streamlit as st

from database import db
from utils.ui import render_result


def render():
    st.title("Investigation Centre")
    rows = db.list_investigations()
    if not rows:
        st.info("No investigations stored yet. Run a scan first.")
        return
    df = pd.DataFrame(rows)
    df["record"] = df["is_demo"].map({1: "DEMO", 0: "real"})
    c0, c1, c2, c3 = st.columns([1, 1, 1, 2])
    kind = c0.selectbox("Records", ["Real only", "All", "Demo only"], key="inv_kind")
    if kind == "Real only":
        df = df[df["is_demo"] == 0]
    elif kind == "Demo only":
        df = df[df["is_demo"] == 1]
    types = c1.multiselect("Input type", sorted(df["input_type"].unique()))
    levels = c2.multiselect("Risk level", ["Low Risk", "Medium Risk", "High Risk", "Critical Risk"])
    q = c3.text_input("Search ID / classification")
    if types:
        df = df[df["input_type"].isin(types)]
    if levels:
        df = df[df["risk_level"].isin(levels)]
    if q:
        df = df[df["id"].str.contains(q, case=False, regex=False) | df["classification"].str.contains(q, case=False, regex=False)]
    st.dataframe(df.drop(columns=["is_demo"]).rename(columns={"id": "Investigation ID"}), hide_index=True)
    ids = list(df["id"])
    if not ids:
        st.warning("No records match the filters.")
        return
    default = ids.index(st.session_state["current_id"]) if st.session_state.get("current_id") in ids else 0
    sel = st.selectbox("Open investigation", ids, index=default)
    res = db.get_investigation(sel)
    if res:
        st.session_state["current_id"] = sel
        st.divider()
        render_result(res, key=f"inv_{sel}")
        if st.button("Delete this investigation", key=f"del_{sel}"):
            db.delete_investigation(sel)
            st.session_state.pop("current_id", None)
            st.session_state.pop("last_result", None)
            st.rerun()
