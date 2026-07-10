"""views/live_traffic.py"""
import sys as _sys; from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from db import database as db
from utils.helpers import bytes_to_human, port_service
from utils.ui import (chart_layout, kpi_card, section_title, empty_state,
                      TEAL, TEXT_MUTED, BG_SURFACE, BORDER, BG_RAISED,
                      TEXT_PRI, TEXT_SEC, SKY, EMERALD, page_header)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 16 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>'

def render():
    page_header("Live Traffic", "Real-time packet monitoring and flow analysis", ICON)

    c1,c2,c3 = st.columns([2,2,1])
    with c1: proto_filter = st.selectbox("Protocol", ["All","TCP","UDP","ICMP"], key="lt_proto")
    with c2: limit = st.slider("Max rows", 50, 500, 100, key="lt_limit")
    with c3:
        st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
        if st.checkbox("Auto-refresh", True, key="lt_r"):
            st.markdown('<meta http-equiv="refresh" content="5">', unsafe_allow_html=True)

    # Stats charts
    stats = db.get_traffic_stats(minutes=60)
    if stats:
        df_s = pd.DataFrame([dict(r) for r in stats])
        col_l, col_r = st.columns(2)
        with col_l:
            section_title("Packets / minute", "Last 60 minutes")
            fig = go.Figure(go.Scatter(x=df_s["minute"], y=df_s["packets"],
                mode="lines", line=dict(color=TEAL, width=2),
                fill="tozeroy", fillcolor="rgba(45,212,191,0.06)",
                hovertemplate="%{x}<br><b>%{y} packets</b><extra></extra>"))
            fig.update_layout(**chart_layout(260))
            st.plotly_chart(fig, use_container_width=True)
        with col_r:
            section_title("Bytes / minute", "Last 60 minutes")
            fig2 = go.Figure(go.Scatter(x=df_s["minute"], y=df_s["bytes"],
                mode="lines", line=dict(color=SKY, width=2),
                fill="tozeroy", fillcolor="rgba(56,189,248,0.06)",
                hovertemplate="%{x}<br><b>%{y:,.0f} bytes</b><extra></extra>"))
            fig2.update_layout(**chart_layout(260))
            st.plotly_chart(fig2, use_container_width=True)

    st.markdown(f"<hr style='border-color:{BORDER};margin:4px 0 20px'>", unsafe_allow_html=True)

    col_tt, col_dp = st.columns(2)
    with col_tt:
        section_title("Top Talkers", "Most active source IPs")
        talkers = db.get_top_talkers(10)
        if talkers:
            for r in talkers:
                b = bytes_to_human(r["bytes"] or 0)
                st.markdown(f"""
                <div style="display:flex;align-items:center;gap:10px;padding:8px 12px;
                            background:{BG_SURFACE};border:1px solid {BORDER};border-radius:8px;margin-bottom:4px">
                  <div style="flex:1;min-width:0">
                    <div style="font-family:'IBM Plex Mono',monospace;font-size:0.82rem;color:{TEAL}">{r['src_ip']}</div>
                    <div style="font-size:0.68rem;color:{TEXT_MUTED}">{r['packets']:,} packets</div>
                  </div>
                  <div style="font-size:0.78rem;font-weight:600;color:{TEXT_SEC};
                              font-family:'IBM Plex Mono',monospace">{b}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            empty_state("No traffic recorded yet")

    with col_dp:
        section_title("Top Destination Ports", "Service distribution")
        dp_rows = db.fetchall("SELECT dst_port, COUNT(*) as cnt FROM traffic WHERE dst_port>0 GROUP BY dst_port ORDER BY cnt DESC LIMIT 10")
        if dp_rows:
            max_c = max(r["cnt"] for r in dp_rows)
            for r in dp_rows:
                svc = port_service(r["dst_port"])
                pct = int(r["cnt"] / max_c * 100)
                st.markdown(f"""
                <div style="padding:8px 12px;background:{BG_SURFACE};border:1px solid {BORDER};border-radius:8px;margin-bottom:4px">
                  <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span style="font-size:0.8rem;color:{TEXT_PRI}">:{r['dst_port']} <span style="color:{TEXT_MUTED}">{svc}</span></span>
                    <span style="font-family:'IBM Plex Mono',monospace;font-size:0.75rem;color:{TEXT_MUTED}">{r['cnt']:,}</span>
                  </div>
                  <div style="background:{BG_RAISED};border-radius:3px;height:3px">
                    <div style="background:{SKY};height:100%;width:{pct}%;border-radius:3px"></div>
                  </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            empty_state("No port data yet")

    # Raw packets
    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    section_title("Packet Log", f"Latest {limit} packets")
    where = "" if proto_filter == "All" else f"WHERE protocol='{proto_filter}'"
    rows = db.fetchall(f"SELECT * FROM traffic {where} ORDER BY timestamp DESC LIMIT ?", (limit,))
    if rows:
        df = pd.DataFrame([dict(r) for r in rows])
        cols = ["timestamp","src_ip","dst_ip","src_port","dst_port","protocol","length","flags","ttl","country"]
        st.dataframe(df[[c for c in cols if c in df.columns]], use_container_width=True, hide_index=True)
    else:
        empty_state("No traffic data — ensure the packet sniffer is running", "📡")
