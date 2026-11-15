import pandas as pd
import plotly.express as px
import streamlit as st

import config
from core.workflow import load_demo_records
from database import db
from utils.ui import LEVEL_COLORS, metric_card

LEVELS = ["Low Risk", "Medium Risk", "High Risk", "Critical Risk"]


def _style(fig, h=300):
    fig.update_layout(height=h, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#e2e8f0"),
                      margin=dict(l=10, r=10, t=30, b=10), legend=dict(orientation="h", y=-0.2))
    fig.update_xaxes(gridcolor="#1f2a44")
    fig.update_yaxes(gridcolor="#1f2a44")
    return fig


def render():
    st.title("Overview")
    counts = db.count_records()
    inc_demo = st.toggle("Include demonstration records", value=False, key="ov_demo",
                         help="Demo records are fictional examples. They are excluded from every figure unless this is on.")
    s = db.stats(include_demo=inc_demo)
    if inc_demo:
        st.warning(f"Demonstration records are INCLUDED: figures below mix {counts['real']} real and {counts['demo']} fictional "
                   "records. Turn the toggle off to see real data only.")
    else:
        st.caption(f"Showing {counts['real']} real investigation(s). {counts['demo']} demonstration record(s) are hidden.")
    if s["total"] == 0:
        if counts["demo"] and not inc_demo:
            st.info("No real investigations yet. Run a scan in **Threat Scanner** and it will appear here. "
                    f"{counts['demo']} demonstration record(s) exist but are hidden - switch the toggle on to view them.")
        else:
            st.info("No investigations yet. Run a scan in **Threat Scanner**, or load the labelled demonstration records to explore the dashboard.")
        if st.button("Load demonstration records", key="ov_load_demo"):
            added, existing = load_demo_records()
            st.success(f"Added {len(added)} demonstration record(s); {len(existing)} already loaded (skipped). "
                       "Your real investigations were not touched. Switch on 'Include demonstration records' to view them.")
        return
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Total investigations", s["total"], "all stored records")
    with c2:
        metric_card("Threats detected", s["threats"], f"score \u2265 {config.THREAT_THRESHOLD} (Medium or above)")
    with c3:
        metric_card("High-risk", s["high_risk"], "High + Critical")
    with c4:
        metric_card("Average risk score", "-" if s["avg_score"] is None else s["avg_score"], "across the records shown")
    st.write("")
    a, b = st.columns(2)
    with a:
        df = pd.DataFrame({"level": LEVELS, "count": [s["by_level"].get(l, 0) for l in LEVELS]})
        fig = px.bar(df, x="level", y="count", color="level", color_discrete_map=LEVEL_COLORS, title="Risk distribution")
        st.plotly_chart(_style(fig).update_layout(showlegend=False))
    with b:
        df = pd.DataFrame({"type": list(s["by_type"]), "count": list(s["by_type"].values())})
        fig = px.pie(df, names="type", values="count", hole=0.55, title="Threat distribution by input type",
                     color_discrete_sequence=["#38bdf8", "#a78bfa", "#22c55e", "#f59e0b"])
        st.plotly_chart(_style(fig))
    a, b = st.columns(2)
    with a:
        df = pd.DataFrame(s["per_day"], columns=["day", "investigations"])
        fig = px.area(df, x="day", y="investigations", title="Investigation activity", markers=True)
        fig.update_traces(line_color="#38bdf8", fillcolor="rgba(56,189,248,.18)")
        st.plotly_chart(_style(fig))
    with b:
        fig = px.histogram(pd.DataFrame({"score": s["scores"]}), x="score", nbins=10, title="Risk score statistics")
        fig.update_traces(marker_color="#a78bfa")
        st.plotly_chart(_style(fig))
    if s["by_class"]:
        df = pd.DataFrame({"classification": list(s["by_class"]), "count": list(s["by_class"].values())})
        st.plotly_chart(_style(px.bar(df, x="count", y="classification", orientation="h", title="Top classifications"), 280)
                        .update_traces(marker_color="#38bdf8"))
    st.subheader("Recent scans")
    rec = pd.DataFrame(db.list_investigations(limit=10, include_demo=inc_demo))
    rec["record"] = rec["is_demo"].map({1: "DEMO", 0: "real"})
    st.dataframe(rec.drop(columns=["is_demo"]), hide_index=True)
