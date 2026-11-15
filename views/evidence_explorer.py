import pandas as pd
import streamlit as st

from core import evidence_engine
from database import db


def render():
    st.title("Evidence Explorer")
    st.caption("Relationship graph built from extracted evidence. Solid lines are directly extracted; dashed = DNS-observed; "
               "dotted amber = PhishTrace inference (a comparison, not proof of a connection).")
    rows = db.list_investigations()
    if not rows:
        st.info("No investigations yet.")
        return
    scope = st.radio("Scope", ["Current investigation", "Selected investigations", "All investigations (shared indicators link cases)"],
                     horizontal=True)
    ids = [r["id"] for r in rows]
    if scope == "Current investigation":
        cur = st.session_state.get("current_id") or ids[0]
        chosen = [cur]
        st.caption(f"Showing {cur}")
    elif scope == "Selected investigations":
        chosen = st.multiselect("Investigations", ids, default=ids[:2])
    else:
        chosen = ids[:100]
    results = db.get_many(chosen)
    if not results:
        st.warning("Select at least one investigation.")
        return
    g = evidence_engine.build_graph(results)
    if g.number_of_edges() == 0:
        st.info("These investigations contain no extractable relationships (no URLs, e-mails, IPs or phone numbers).")
        return
    st.plotly_chart(evidence_engine.graph_to_figure(g))
    st.subheader("Relationships")
    table = pd.DataFrame(evidence_engine.graph_table(g))
    basis = st.multiselect("Basis", ["extracted", "observed", "inferred"], default=["extracted", "observed", "inferred"])
    st.dataframe(table[table["basis"].isin(basis)], hide_index=True)
    shared = [(g.nodes[n]["label"], g.nodes[n]["ntype"], sum(1 for x in g.neighbors(n) if g.nodes[x]["ntype"] == "investigation"))
              for n in g.nodes if g.nodes[n]["ntype"] != "investigation"]
    shared = [s for s in shared if s[2] > 1]
    if shared:
        st.subheader("Indicators shared by multiple investigations")
        st.dataframe(pd.DataFrame(shared, columns=["indicator", "type", "investigations"]), hide_index=True)
