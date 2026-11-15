import pandas as pd
import plotly.express as px
import streamlit as st

from core import evidence_engine
from database import db
from utils.ui import LEVEL_COLORS


def render():
    st.title("Investigation Timeline")
    st.caption("Only real timestamps are plotted: the time each analysis was performed and any dates found inside submitted emails "
               "(Date / Received headers). No event times are invented.")
    rows = db.list_investigations()
    if not rows:
        st.info("No investigations yet.")
        return
    scope = st.radio("Scope", ["Current investigation", "All investigations"], horizontal=True)
    ids = [r["id"] for r in rows]
    chosen = [st.session_state.get("current_id") or ids[0]] if scope == "Current investigation" else ids[:200]
    events = evidence_engine.timeline_events(db.get_many(chosen))
    df = pd.DataFrame(events)
    df["time"] = pd.to_datetime(df["time"], utc=True, errors="coerce")
    df = df.dropna(subset=["time"])
    if df.empty:
        st.info("No timestamps available.")
        return
    fig = px.scatter(df, x="time", y="source", color="level", color_discrete_map=LEVEL_COLORS, hover_data=["investigation", "event"])
    fig.update_traces(marker=dict(size=13, line=dict(width=1, color="#0b1220")))
    fig.update_layout(height=380, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0"),
                      margin=dict(l=10, r=10, t=10, b=10), yaxis_title=None)
    fig.update_xaxes(gridcolor="#1f2a44")
    fig.update_yaxes(gridcolor="#1f2a44")
    st.plotly_chart(fig)
    st.dataframe(df.sort_values("time", ascending=False).assign(time=lambda d: d["time"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")),
                 hide_index=True)
