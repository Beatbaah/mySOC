"""views/endpoint_monitor.py — Per-host activity monitoring"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
import plotly.express as px
from db import database as db
from utils.helpers import bytes_to_human, is_internal
from utils.ui import (
    chart_layout, section_title, kpi_card, empty_state,
    SEV_COLORS, TEAL, SKY, BORDER, BG_SURFACE, BG_RAISED,
    TEXT_MUTED, TEXT_PRI, TEXT_SEC, EMERALD, page_header,
)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>'


def render():
    page_header("Endpoint Monitor", "Per-host activity, connections and threat level", ICON)

    rows = db.fetchall(
        """SELECT src_ip as ip, COUNT(*) as packets, SUM(length) as bytes_out,
                  COUNT(DISTINCT dst_ip) as unique_dsts, COUNT(DISTINCT dst_port) as unique_ports,
                  MAX(timestamp) as last_seen, MIN(timestamp) as first_seen
           FROM traffic WHERE timestamp >= datetime('now', '-24 hours')
           GROUP BY src_ip ORDER BY packets DESC LIMIT 50"""
    )
    if not rows:
        empty_state("No endpoint data. Ensure the packet sniffer is running.", "💻")
        return

    df = pd.DataFrame([dict(r) for r in rows])
    df["type"] = df["ip"].apply(lambda ip: "Internal" if is_internal(ip) else "External")

    total_int  = len(df[df["type"] == "Internal"])
    total_ext  = len(df[df["type"] == "External"])
    high_ports = len(df[df["unique_ports"].astype(int) > 20])

    c1, c2, c3, c4 = st.columns(4)
    kpi_card(c1, "Total Endpoints",   len(df),     TEAL)
    kpi_card(c2, "Internal Hosts",    total_int,   SKY)
    kpi_card(c3, "External Hosts",    total_ext,   "#94a3b8")
    kpi_card(c4, "High Port Density", high_ports,  "#fbbf24" if high_ports else EMERALD)
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    col_f, _ = st.columns([2, 3])
    with col_f:
        ep_type = st.radio("Show", ["All", "Internal", "External"],
                           horizontal=True, key="ep_type")

    filtered = df if ep_type == "All" else df[df["type"] == ep_type]
    filtered = filtered.copy()
    filtered["bytes_out"] = filtered["bytes_out"].apply(bytes_to_human)
    display = filtered[["ip","type","packets","bytes_out","unique_dsts","unique_ports","last_seen"]].copy()
    display.columns = ["IP","Type","Packets","Data Out","Uniq Dsts","Uniq Ports","Last Seen"]
    st.dataframe(display, use_container_width=True, hide_index=True)

    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    section_title("Endpoint Deep-Dive", "Drill into a specific host's activity")

    all_ips = df["ip"].tolist()
    selected_ip = st.selectbox("Select endpoint", all_ips, key="ep_select")

    if selected_ip:
        col_l, col_r = st.columns(2)
        with col_l:
            section_title(f"Outbound Connections", f"From {selected_ip} (last 24h)")
            conn = db.fetchall(
                """SELECT dst_ip, dst_port, protocol, COUNT(*) as cnt, SUM(length) as bytes
                   FROM traffic WHERE src_ip = ? AND timestamp >= datetime('now', '-24 hours')
                   GROUP BY dst_ip, dst_port, protocol ORDER BY cnt DESC LIMIT 20""",
                (selected_ip,)
            )
            if conn:
                dfc = pd.DataFrame([dict(r) for r in conn])
                dfc["bytes"] = dfc["bytes"].apply(bytes_to_human)
                dfc.columns = ["Dst IP", "Port", "Protocol", "Packets", "Bytes"]
                st.dataframe(dfc, use_container_width=True, hide_index=True)
            else:
                empty_state("No outbound connections found")

        with col_r:
            section_title(f"Alerts", f"For {selected_ip}")
            alerts = db.fetchall(
                """SELECT timestamp, severity, alert_type, description, threat_score
                   FROM alerts WHERE src_ip = ? ORDER BY timestamp DESC LIMIT 20""",
                (selected_ip,)
            )
            if alerts:
                dfa = pd.DataFrame([dict(r) for r in alerts])
                dfa.columns = ["Time", "Severity", "Type", "Description", "Score"]
                st.dataframe(dfa, use_container_width=True, hide_index=True)
            else:
                st.markdown(f"""
                <div style="text-align:center;padding:30px;background:{BG_SURFACE};
                            border:1px solid {BORDER};border-radius:10px">
                  <div style="color:{EMERALD};font-weight:600;font-size:0.88rem">✓ Clean</div>
                  <div style="color:{TEXT_MUTED};font-size:0.75rem;margin-top:4px">
                    No alerts for this endpoint
                  </div>
                </div>
                """, unsafe_allow_html=True)

        port_rows = db.fetchall(
            """SELECT dst_port, COUNT(*) as cnt FROM traffic
               WHERE src_ip = ? AND timestamp >= datetime('now', '-24 hours')
               GROUP BY dst_port ORDER BY cnt DESC LIMIT 15""",
            (selected_ip,)
        )
        if port_rows:
            dfp = pd.DataFrame([dict(r) for r in port_rows])
            fig = px.bar(dfp, x="dst_port", y="cnt",
                         labels={"dst_port": "Destination Port", "cnt": "Packets"},
                         color="cnt", color_continuous_scale=["#1a2235", "#2dd4bf"])
            l = chart_layout(280, show_legend=False)
            l["coloraxis_showscale"] = False
            fig.update_layout(**l)
            fig.update_traces(marker_line_width=0)
            st.plotly_chart(fig, use_container_width=True)
