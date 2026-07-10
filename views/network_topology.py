"""views/network_topology.py — Interactive network graph"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import math
from collections import defaultdict
from db import database as db
from utils.helpers import is_internal, bytes_to_human
from utils.ui import (
    chart_layout, section_title, empty_state, SEV_COLORS,
    TEAL, BORDER, BG_SURFACE, BG_RAISED, TEXT_MUTED, TEXT_PRI,
    TEXT_SEC, EMERALD, page_header,
)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="6" height="6" rx="1"/><rect x="16" y="2" width="6" height="6" rx="1"/><rect x="9" y="16" width="6" height="6" rx="1"/><path d="M5 8v3a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8"/><line x1="12" y1="13" x2="12" y2="16"/></svg>'


def _layout_nodes(nodes, internal):
    pos = {}
    inner = [n for n in nodes if n in set(internal)]
    outer = [n for n in nodes if n not in set(internal)]
    for i, n in enumerate(inner):
        a = 2 * math.pi * i / max(len(inner), 1)
        pos[n] = (0.35 * math.cos(a), 0.35 * math.sin(a))
    for i, n in enumerate(outer):
        a = 2 * math.pi * i / max(len(outer), 1)
        pos[n] = (0.85 * math.cos(a), 0.85 * math.sin(a))
    return pos


def render():
    page_header("Network Topology", "Live host graph — node size = traffic, colour = threat level", ICON)

    col1, col2, col3 = st.columns(3)
    with col1:
        time_range = st.selectbox("Window",
            ["Last 15min", "Last 1h", "Last 6h", "Last 24h"], key="topo_time")
    with col2:
        min_pkt = st.slider("Min packets/edge", 1, 100, 5, key="topo_min")
    with col3:
        max_nodes = st.slider("Max nodes", 20, 150, 60, key="topo_nodes")

    win = {"Last 15min": "-15 minutes", "Last 1h": "-1 hours",
           "Last 6h": "-6 hours", "Last 24h": "-24 hours"}[time_range]

    edges_raw = db.fetchall(
        f"""SELECT src_ip, dst_ip, dst_port, protocol,
                   COUNT(*) as packets, SUM(length) as bytes
            FROM traffic WHERE timestamp >= datetime('now', '{win}')
            GROUP BY src_ip, dst_ip, dst_port HAVING packets >= {min_pkt}
            ORDER BY packets DESC LIMIT 500"""
    )
    if not edges_raw:
        empty_state("No traffic data for this window. Ensure the packet sniffer is running.", "🕸️")
        return

    node_pkts: defaultdict = defaultdict(int)
    node_bytes: defaultdict = defaultdict(int)
    edges = []
    for row in edges_raw:
        node_pkts[row["src_ip"]] += row["packets"]
        node_pkts[row["dst_ip"]] += row["packets"]
        node_bytes[row["src_ip"]] += row["bytes"] or 0
        edges.append(dict(row))

    top_nodes = sorted(node_pkts, key=lambda x: node_pkts[x], reverse=True)[:max_nodes]
    top_set   = set(top_nodes)
    edges     = [e for e in edges if e["src_ip"] in top_set and e["dst_ip"] in top_set]
    int_nodes = [n for n in top_nodes if is_internal(n)]
    pos_map   = _layout_nodes(top_nodes, int_nodes)

    alert_rows = db.fetchall(
        f"""SELECT src_ip, MAX(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3
            WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) as rank
            FROM alerts WHERE timestamp >= datetime('now', '{win}') AND src_ip != ''
            GROUP BY src_ip"""
    )
    sev_map = {4:"CRITICAL",3:"HIGH",2:"MEDIUM",1:"LOW",0:"INFO"}
    node_sev = {r["src_ip"]: sev_map.get(r["rank"],"INFO") for r in alert_rows}

    fig = go.Figure()
    max_pkt = max((e["packets"] for e in edges), default=1)

    # Edges
    for e in edges:
        if e["src_ip"] not in pos_map or e["dst_ip"] not in pos_map:
            continue
        x0, y0 = pos_map[e["src_ip"]]
        x1, y1 = pos_map[e["dst_ip"]]
        w = max(0.4, min(5.0, e["packets"] / max_pkt * 5))
        fig.add_trace(go.Scatter(
            x=[x0, x1, None], y=[y0, y1, None], mode="lines",
            line=dict(width=w, color="rgba(45,212,191,0.12)"),
            hoverinfo="skip", showlegend=False,
        ))

    # Edge labels (top 8)
    for e in sorted(edges, key=lambda x: x["packets"], reverse=True)[:8]:
        if e["src_ip"] not in pos_map or e["dst_ip"] not in pos_map:
            continue
        x0, y0 = pos_map[e["src_ip"]]
        x1, y1 = pos_map[e["dst_ip"]]
        fig.add_annotation(
            x=(x0+x1)/2, y=(y0+y1)/2,
            text=f":{e['dst_port']} {bytes_to_human(e['bytes'] or 0)}",
            font=dict(size=8, color="#334155"), showarrow=False,
        )

    # Nodes
    for label, group, sym in [("Internal", int_nodes, "circle"),
                               ("External", [n for n in top_nodes if not is_internal(n)], "diamond")]:
        for node in group:
            if node not in pos_map:
                continue
            x, y   = pos_map[node]
            sev     = node_sev.get(node)
            color   = SEV_COLORS.get(sev, "#2d3f5a")
            pkts    = node_pkts[node]
            size    = max(10, min(42, 10 + math.log1p(pkts) * 3.5))
            fig.add_trace(go.Scatter(
                x=[x], y=[y], mode="markers+text",
                marker=dict(size=size, color=color, symbol=sym,
                            line=dict(width=1.5, color="#0c0f1a"), opacity=0.88),
                text=".".join(node.split(".")[-2:]) if "." in node else node,
                textposition="top center",
                textfont=dict(size=8, color="#475569"),
                hovertext=(f"<b>{node}</b><br>Type: {label}<br>"
                           f"Packets: {pkts:,}<br>Bytes: {bytes_to_human(node_bytes[node])}<br>"
                           f"Threat: {sev or 'None'}"),
                hoverinfo="text", showlegend=False,
            ))

    fig.update_layout(
        height=600,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(14,20,35,0.95)",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1.15, 1.15]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1.15, 1.15]),
        margin=dict(l=0, r=0, t=0, b=0),
        font=dict(family="DM Sans", color=TEXT_MUTED),
        hoverlabel=dict(bgcolor=BG_RAISED, bordercolor=BORDER,
                        font=dict(family="IBM Plex Mono", size=11, color=TEXT_PRI)),
    )
    for ann, val in [
        ("● Internal host", TEAL), ("◆ External host", "#475569"),
        ("Colour = threat level", TEXT_MUTED),
    ]:
        fig.add_annotation(x=-1.1, y=1.1 - list(["● Internal host","◆ External host","Colour = threat level"]).index(ann) * 0.08,
                           text=ann, font=dict(size=10, color=val), showarrow=False, xanchor="left")

    st.plotly_chart(fig, use_container_width=True)
    st.markdown(f"<hr style='border-color:{BORDER};margin:4px 0 20px'>", unsafe_allow_html=True)

    col_l, col_r = st.columns(2)
    with col_l:
        section_title("Top Connections")
        df_e = pd.DataFrame(edges[:20])
        if not df_e.empty:
            df_e["bytes"] = df_e["bytes"].apply(bytes_to_human)
            df_e = df_e[["src_ip","dst_ip","dst_port","protocol","packets","bytes"]]
            df_e.columns = ["Source","Destination","Port","Protocol","Packets","Bytes"]
            st.dataframe(df_e, use_container_width=True, hide_index=True)
    with col_r:
        section_title("Node Summary")
        ndf = pd.DataFrame([{
            "IP": n, "Type": "Internal" if is_internal(n) else "External",
            "Packets": node_pkts[n], "Bytes": bytes_to_human(node_bytes[n]),
            "Threat": node_sev.get(n, "—"),
        } for n in top_nodes]).sort_values("Packets", ascending=False)
        st.dataframe(ndf, use_container_width=True, hide_index=True)
