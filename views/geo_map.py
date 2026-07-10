"""views/geo_map.py — Geographic threat map"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from db import database as db
from utils.helpers import geolocate, is_private_ip
from utils.logger import get_logger
from utils.ui import (
    chart_layout, section_title, empty_state, SEV_COLORS,
    TEAL, BORDER, BG_SURFACE, BG_RAISED, TEXT_MUTED, TEXT_PRI, page_header,
)

log = get_logger(__name__)
ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>'


def render():
    page_header("Geo Map", "Geographic origin of threats and attack sources worldwide", ICON)
    col1, col2 = st.columns([3, 1])
    with col1:
        time_range = st.selectbox("Time range",
            ["Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 7 days", "All time"],
            key="geo_time")
    with col2:
        min_alerts = st.number_input("Min alerts per IP", min_value=1, value=1, key="geo_min")

    win = {"Last 1 hour": "-1 hours", "Last 6 hours": "-6 hours",
           "Last 24 hours": "-24 hours", "Last 7 days": "-7 days",
           "All time": "-100 years"}[time_range]

    rows = db.fetchall(
        f"""SELECT src_ip, COUNT(*) as cnt, MAX(severity) as max_sev, MAX(threat_score) as max_score
            FROM alerts WHERE timestamp >= datetime('now', '{win}') AND src_ip != ''
            GROUP BY src_ip HAVING cnt >= {min_alerts} ORDER BY cnt DESC LIMIT 200"""
    )
    if not rows:
        empty_state("No alert data for the selected time range", "🌍")
        return

    df_ips = pd.DataFrame([dict(r) for r in rows])
    with st.spinner("Geolocating IPs…"):
        geo_data = []
        for _, row in df_ips.iterrows():
            ip = row["src_ip"]
            geo = {"country": "Internal", "country_code": "INT", "city": "Internal",
                   "lat": 0.0, "lon": 0.0} if is_private_ip(ip) else geolocate(ip)
            geo_data.append({"ip": ip, "count": row["cnt"],
                              "severity": row["max_sev"], "score": row["max_score"], **geo})

    df = pd.DataFrame(geo_data)
    df_map = df[(df["lat"] != 0.0) | (df["lon"] != 0.0)].copy()

    if not df_map.empty:
        section_title("Attack Origins", "Geographic distribution of threat sources")
        fig = go.Figure()
        for sev, grp in df_map.groupby("severity"):
            fig.add_trace(go.Scattergeo(
                lon=grp["lon"], lat=grp["lat"],
                text=grp.apply(
                    lambda r: f"<b>{r['ip']}</b><br>{r['city']}, {r['country']}<br>Alerts: {r['count']}",
                    axis=1),
                mode="markers",
                marker=dict(
                    size=grp["count"].apply(lambda x: max(6, min(28, 6 + x * 0.6))),
                    color=SEV_COLORS.get(sev, TEXT_MUTED), opacity=0.8,
                    line=dict(width=1, color="rgba(0,0,0,0.4)")),
                name=sev, hoverinfo="text",
            ))
        fig.update_layout(
            geo=dict(bgcolor="rgba(12,15,26,0)", showland=True, landcolor="#1a2235",
                     showocean=True, oceancolor="#0c1525", showlakes=True, lakecolor="#0c1525",
                     showcoastlines=True, coastlinecolor="#1e3a5a",
                     showcountries=True, countrycolor="#162030", showframe=False,
                     projection_type="natural earth"),
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(family="DM Sans", color=TEXT_MUTED, size=11),
            height=500, margin=dict(l=0, r=0, t=0, b=0),
            legend=dict(bgcolor="rgba(26,34,53,0.9)", bordercolor=BORDER, borderwidth=1,
                        font=dict(size=10)),
            hoverlabel=dict(bgcolor=BG_RAISED, bordercolor=BORDER,
                            font=dict(family="IBM Plex Mono", size=11, color=TEXT_PRI)),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown(f"<hr style='border-color:{BORDER};margin:8px 0 20px'>", unsafe_allow_html=True)
    col_l, col_r = st.columns(2)
    with col_l:
        section_title("Alerts by Country")
        if not df.empty:
            c_agg = (df.groupby("country")
                     .agg(total=("count", "sum"), ips=("ip", "count"))
                     .sort_values("total", ascending=False).head(15).reset_index())
            fig2 = px.bar(c_agg, x="total", y="country", orientation="h",
                          color="total",
                          color_continuous_scale=["#1a2235", "#14b8a6", "#f43f5e"],
                          labels={"total": "Alerts", "country": ""})
            l = chart_layout(400, show_legend=False)
            l["coloraxis_showscale"] = False
            fig2.update_layout(**l)
            fig2.update_traces(marker_line_width=0)
            st.plotly_chart(fig2, use_container_width=True)
    with col_r:
        section_title("Top Threat IPs")
        display = df[["ip", "country", "city", "count", "severity", "score"]].copy()
        display.columns = ["IP", "Country", "City", "Alerts", "Severity", "Score"]
        st.dataframe(display.head(20), use_container_width=True, hide_index=True)
