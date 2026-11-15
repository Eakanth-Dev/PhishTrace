"""Evidence graph (NetworkX) and timeline construction.

Edge 'basis':
  extracted - the relationship is directly present in the submitted evidence
              (e.g. a URL text contains hostname X; the email header says From: a@b).
  observed  - returned by a lookup (DNS resolution) at analysis time.
  inferred  - PhishTrace's own comparison (e.g. sender domain differs from link domain). NOT proof of a link.
"""
import networkx as nx

from utils.helpers import registered_domain

TYPE_COLORS = {"investigation": "#38bdf8", "url": "#f97316", "domain": "#a78bfa", "email": "#22c55e",
               "ip": "#ef4444", "phone": "#eab308"}


def _add(g, node_id, ntype, label=None):
    if node_id not in g:
        g.add_node(node_id, ntype=ntype, label=label or node_id)


def _edge(g, a, b, label, basis):
    if a != b and not g.has_edge(a, b):
        g.add_edge(a, b, label=label, basis=basis)


def build_graph(results: list) -> nx.Graph:
    """results: list of result dicts, each with 'investigation_id'."""
    g = nx.Graph()
    for res in results:
        inv = res.get("investigation_id", "?")
        _add(g, inv, "investigation", inv)
        ent = res.get("entities", {})
        url_domains = {}
        for u in ent.get("urls", []):
            _add(g, u, "url", u[:48] + ("..." if len(u) > 48 else ""))
            _edge(g, inv, u, "submitted/extracted from evidence", "extracted")
            host = u.split("://", 1)[-1].split("/")[0].split("@")[-1].split(":")[0].lower()
            if host:
                reg = registered_domain(host) if not host.replace(".", "").isdigit() else host
                _add(g, reg, "domain")
                _edge(g, u, reg, "hostname of URL", "extracted")
                url_domains[u] = reg
        for e in ent.get("emails", []):
            _add(g, e, "email")
            _edge(g, inv, e, "found in evidence", "extracted")
            dom = registered_domain(e.split("@")[-1])
            _add(g, dom, "domain")
            _edge(g, e, dom, "address domain", "extracted")
            if e in (res.get("meta", {}).get("from", "").lower()):
                for ud in set(url_domains.values()):
                    if ud != dom:
                        _edge(g, dom, ud, "sender domain differs from linked domain", "inferred")
        for ip in ent.get("ips", []):
            _add(g, ip, "ip")
            _edge(g, inv, ip, "found/resolved in evidence", "extracted")
        for ph in ent.get("phones", []):
            _add(g, ph, "phone")
            _edge(g, inv, ph, "found in evidence", "extracted")
        dns = (res.get("meta") or {}).get("dns")
        if dns and dns.get("addresses"):
            for u, dom in url_domains.items():
                for ip in dns["addresses"]:
                    _add(g, ip, "ip")
                    _edge(g, dom, ip, "DNS resolution", "observed")
    return g


def graph_table(g: nx.Graph):
    return [{"from": g.nodes[a]["label"], "to": g.nodes[b]["label"], "relationship": d["label"], "basis": d["basis"]}
            for a, b, d in g.edges(data=True)]


def graph_to_figure(g: nx.Graph):
    """Plotly figure: solid lines = extracted, dotted = observed/inferred."""
    import plotly.graph_objects as go
    pos = nx.spring_layout(g, seed=7, k=0.9) if len(g) else {}
    fig = go.Figure()
    styles = {"extracted": ("#64748b", "solid"), "observed": ("#38bdf8", "dash"), "inferred": ("#f59e0b", "dot")}
    for basis, (color, dash) in styles.items():
        xs, ys = [], []
        for a, b, d in g.edges(data=True):
            if d["basis"] == basis:
                xs += [pos[a][0], pos[b][0], None]
                ys += [pos[a][1], pos[b][1], None]
        if xs:
            fig.add_trace(go.Scatter(x=xs, y=ys, mode="lines", line=dict(width=1.6, color=color, dash=dash),
                                     hoverinfo="skip", name=f"{basis} relationship"))
    for ntype, color in TYPE_COLORS.items():
        nodes = [n for n, d in g.nodes(data=True) if d["ntype"] == ntype]
        if nodes:
            fig.add_trace(go.Scatter(
                x=[pos[n][0] for n in nodes], y=[pos[n][1] for n in nodes], mode="markers+text",
                text=[g.nodes[n]["label"][:24] for n in nodes], textposition="top center",
                textfont=dict(size=10, color="#cbd5e1"),
                marker=dict(size=[16 + 5 * g.degree(n) for n in nodes], color=color, line=dict(width=1, color="#0b1220")),
                hovertext=[f"{ntype}: {n}<br>connections: {g.degree(n)}" for n in nodes], hoverinfo="text", name=ntype))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=560, margin=dict(l=10, r=10, t=10, b=10),
                      xaxis=dict(visible=False), yaxis=dict(visible=False), font=dict(color="#e2e8f0"),
                      legend=dict(orientation="h", y=-0.05))
    return fig


def timeline_events(records: list) -> list:
    """Events from real timestamps only: investigation analysis time + timestamps found inside emails."""
    events = []
    for rec in records:
        inv = rec.get("investigation_id", "?")
        events.append({"time": rec["analysis_time"], "investigation": inv, "event": f"Analysis performed ({rec['input_type']})",
                       "source": "PhishTrace investigation record", "level": rec["risk_level"]})
        for ev in rec.get("events", []):
            events.append({"time": ev["time"], "investigation": inv, "event": ev["event"], "source": ev["source"],
                           "level": rec["risk_level"]})
    return sorted(events, key=lambda e: e["time"])
