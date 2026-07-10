"""views/analytics.py — Security analytics with new design system"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from db import database as db
from utils.helpers import bytes_to_human
from utils.ui import (
    chart_layout, kpi_card, section_title, empty_state,
    SEV_COLORS, TEAL, SKY, BORDER, BG_SURFACE, BG_RAISED,
    TEXT_MUTED, TEXT_PRI, TEXT_SEC, EMERALD, CORAL, AMBER, page_header,
)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>'


def render():
    page_header("Analytics", "Trend analysis, attack heatmaps and security baselines", ICON)
    tab1, tab2, tab3 = st.tabs(["Trends", "Correlation", "Baselines"])
    with tab1: _trends()
    with tab2: _correlation()
    with tab3: _baselines()


def _trends():
    c1, c2 = st.columns(2)
    with c1: days = st.slider("Days back", 1, 30, 7, key="an_days")
    with c2: gran = st.selectbox("Granularity", ["hour", "day"], key="an_gran")
    fmt = "%Y-%m-%dT%H" if gran == "hour" else "%Y-%m-%d"
    rows = db.fetchall(
        f"""SELECT strftime('{fmt}', timestamp) as period, severity, COUNT(*) as cnt
            FROM alerts WHERE timestamp >= datetime('now', '-{days} days')
            GROUP BY period, severity ORDER BY period"""
    )
    section_title("Alert Volume Over Time", f"Last {days} days by severity")
    if rows:
        df = pd.DataFrame([dict(r) for r in rows])
        fig = px.area(df, x="period", y="cnt", color="severity",
                      color_discrete_map=SEV_COLORS, labels={"period": "", "cnt": "Alerts"})
        fig.update_layout(**chart_layout(320))
        fig.update_traces(line_width=1.5)
        st.plotly_chart(fig, use_container_width=True)
    else:
        empty_state(f"No alert data in the last {days} days", "📈")

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    section_title("Attack Heatmap", "Hour of day × day of week (last 30 days)")
    heat = db.fetchall(
        """SELECT strftime('%w', timestamp) as dow, strftime('%H', timestamp) as hod,
                  COUNT(*) as cnt
           FROM alerts WHERE timestamp >= datetime('now', '-30 days') GROUP BY dow, hod"""
    )
    if heat:
        df2 = pd.DataFrame([dict(r) for r in heat])
        df2["dow"] = df2["dow"].astype(int)
        df2["hod"] = df2["hod"].astype(int)
        pivot = df2.pivot(index="hod", columns="dow", values="cnt").fillna(0)
        days_labels = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
        pivot.columns = [days_labels[c] for c in pivot.columns]
        fig2 = px.imshow(pivot,
                         color_continuous_scale=["#0c1525", "#14b8a6", "#f43f5e"],
                         labels=dict(x="Day", y="Hour", color="Alerts"), aspect="auto")
        fig2.update_layout(**chart_layout(380, show_legend=False))
        st.plotly_chart(fig2, use_container_width=True)
    else:
        empty_state("Not enough data for heatmap yet", "🗓️")


def _correlation():
    section_title("Multi-Stage Attack Patterns",
                  "IPs using 2+ attack types in the last 7 days")
    rows = db.fetchall(
        """SELECT src_ip, COUNT(DISTINCT alert_type) as attack_types,
                  COUNT(*) as total_alerts, MAX(severity) as max_sev,
                  GROUP_CONCAT(DISTINCT alert_type) as types
           FROM alerts WHERE timestamp >= datetime('now', '-7 days') AND src_ip != ''
           GROUP BY src_ip HAVING attack_types >= 2
           ORDER BY attack_types DESC LIMIT 15"""
    )
    if rows:
        for r in rows:
            c = SEV_COLORS.get(r["max_sev"], TEXT_MUTED)
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:14px;padding:12px 16px;
                        background:{BG_SURFACE};border:1px solid {BORDER};
                        border-left:3px solid {c};border-radius:10px;margin-bottom:6px;
                        animation:pageIn 0.3s ease both">
              <div style="flex:1;min-width:0">
                <div style="font-family:'IBM Plex Mono',monospace;font-size:0.85rem;
                            color:{TEAL};margin-bottom:4px">{r['src_ip']}</div>
                <div style="font-size:0.72rem;color:{TEXT_MUTED};line-height:1.5">{r['types']}</div>
              </div>
              <div style="text-align:right;flex-shrink:0">
                <div style="font-size:1.6rem;font-weight:600;color:{c};
                            font-family:'IBM Plex Mono',monospace;line-height:1">{r['attack_types']}</div>
                <div style="font-size:0.6rem;color:{TEXT_MUTED};text-transform:uppercase;
                            letter-spacing:0.08em">attack types</div>
              </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="text-align:center;padding:40px;background:{BG_SURFACE};
                    border:1px solid {BORDER};border-radius:10px">
          <div style="font-size:2rem;margin-bottom:10px">✅</div>
          <div style="font-size:0.88rem;font-weight:600;color:{EMERALD}">No Multi-Stage Attacks Detected</div>
          <div style="font-size:0.75rem;color:{TEXT_MUTED};margin-top:4px">No IPs using multiple attack techniques in the last 7 days</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    section_title("Alert Type Correlation", "Co-occurrence across source IPs")
    cor_rows = db.fetchall(
        """SELECT alert_type, src_ip, COUNT(*) as cnt FROM alerts
           WHERE timestamp >= datetime('now', '-7 days')
           GROUP BY alert_type, src_ip HAVING cnt > 1 ORDER BY cnt DESC LIMIT 200"""
    )
    if cor_rows:
        df = pd.DataFrame([dict(r) for r in cor_rows])
        pivot = df.pivot_table(index="src_ip", columns="alert_type",
                               values="cnt", fill_value=0)
        if pivot.shape[1] > 1:
            corr = pivot.corr()
            fig = px.imshow(corr,
                            color_continuous_scale=["#f43f5e", "#1a2235", "#2dd4bf"],
                            zmin=-1, zmax=1)
            fig.update_layout(**chart_layout(380, show_legend=False))
            st.plotly_chart(fig, use_container_width=True)
        else:
            empty_state("Need at least 2 alert types for correlation", "🔗")
    else:
        empty_state("Insufficient data for correlation analysis", "🔗")


def _baselines():
    section_title("Traffic Baselines", "Average activity by hour of day (last 7 days)")
    rows = db.fetchall(
        """SELECT strftime('%H', timestamp) as hour, COUNT(*) as packets,
                  SUM(length) as bytes, AVG(length) as avg_len
           FROM traffic WHERE timestamp >= datetime('now', '-7 days')
           GROUP BY hour ORDER BY hour"""
    )
    if not rows:
        empty_state("Insufficient traffic data for baseline analysis", "📊")
        return
    df = pd.DataFrame([dict(r) for r in rows])
    df["hour"] = df["hour"].astype(int)
    fig = make_subplots(rows=2, cols=1,
                        subplot_titles=("Packets / Hour", "Bytes / Hour"),
                        shared_xaxes=True, vertical_spacing=0.14)
    fig.add_trace(go.Bar(x=df["hour"], y=df["packets"],
                         marker=dict(color=TEAL, opacity=0.85), name="Packets"), row=1, col=1)
    fig.add_trace(go.Bar(x=df["hour"], y=df["bytes"],
                         marker=dict(color=SKY, opacity=0.85), name="Bytes"), row=2, col=1)
    l = chart_layout(480, show_legend=False)
    l.update({"xaxis2": {"title": "Hour of Day", "gridcolor": "rgba(30,58,90,0.5)"},
              "yaxis":  {"gridcolor": "rgba(30,58,90,0.5)"},
              "yaxis2": {"gridcolor": "rgba(30,58,90,0.5)"}})
    fig.update_layout(**l)
    st.plotly_chart(fig, use_container_width=True)
    c1, c2, c3, c4 = st.columns(4)
    peak = int(df.loc[df["packets"].idxmax(), "hour"])
    c1.metric("Peak Hour",         f"{peak:02d}:00")
    c2.metric("Total Packets (7d)", f"{int(df['packets'].sum()):,}")
    c3.metric("Total Data (7d)",    bytes_to_human(int(df["bytes"].sum())))
    c4.metric("Avg Packet Size",    f"{df['avg_len'].mean():.0f} B")
