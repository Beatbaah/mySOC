"""views/reports.py — Security report generation"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone, timedelta
from db import database as db
from utils.helpers import bytes_to_human
from utils.ui import (
    chart_layout, section_title, kpi_card, empty_state, sev_pill,
    SEV_COLORS, TEAL, BORDER, BG_SURFACE, BG_RAISED, TEXT_MUTED,
    TEXT_PRI, TEXT_SEC, EMERALD, CORAL, AMBER, page_header,
)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>'


def render():
    page_header("Reports", "Summary, weekly digest and executive security reports", ICON)
    tab1, tab2, tab3 = st.tabs(["Summary Report", "Weekly Digest", "Executive Report"])
    with tab1: _summary()
    with tab2: _weekly()
    with tab3: _executive()


def _summary():
    section_title("Custom Date Range Report")
    col1, col2 = st.columns(2)
    with col1: start = st.date_input("From", value=datetime.now(timezone.utc).date() - timedelta(days=7), key="rep_s")
    with col2: end   = st.date_input("To",   value=datetime.now(timezone.utc).date(), key="rep_e")

    if st.button("Generate Report", key="rep_gen", type="primary"):
        start_ts, end_ts = start.isoformat(), end.isoformat()
        alerts = db.fetchall(
            """SELECT severity, alert_type, COUNT(*) as cnt, AVG(threat_score) as avg_score
               FROM alerts WHERE date(timestamp) BETWEEN ? AND ?
               GROUP BY severity, alert_type ORDER BY cnt DESC""",
            (start_ts, end_ts)
        )
        traffic = db.fetchall(
            """SELECT COUNT(*) as packets, SUM(length) as bytes,
                      COUNT(DISTINCT src_ip) as unique_src, COUNT(DISTINCT dst_ip) as unique_dst
               FROM traffic WHERE date(timestamp) BETWEEN ? AND ?""",
            (start_ts, end_ts)
        )
        incidents = db.fetchall(
            """SELECT status, COUNT(*) as cnt FROM incidents
               WHERE date(created_at) BETWEEN ? AND ? GROUP BY status""",
            (start_ts, end_ts)
        )
        st.markdown(f"<hr style='border-color:{BORDER};margin:8px 0 20px'>", unsafe_allow_html=True)
        section_title(f"Report: {start} → {end}")

        if traffic and traffic[0]["packets"]:
            t = dict(traffic[0])
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total Packets",    f"{t['packets']:,}")
            c2.metric("Total Traffic",    bytes_to_human(t["bytes"] or 0))
            c3.metric("Unique Sources",   t["unique_src"])
            c4.metric("Unique Dests",     t["unique_dst"])

        if alerts:
            df_a = pd.DataFrame([dict(r) for r in alerts])
            df_a["avg_score"] = df_a["avg_score"].round(1)
            col_l, col_r = st.columns(2)
            with col_l:
                section_title("Alert Breakdown")
                df_a.columns = ["Severity", "Alert Type", "Count", "Avg Score"]
                st.dataframe(df_a, use_container_width=True, hide_index=True)
            with col_r:
                section_title("Severity Distribution")
                sev_totals = df_a.groupby("Severity")["Count"].sum().reset_index()
                fig = go.Figure(go.Pie(
                    labels=sev_totals["Severity"], values=sev_totals["Count"],
                    hole=0.6,
                    marker_colors=[SEV_COLORS.get(s, TEXT_MUTED) for s in sev_totals["Severity"]],
                ))
                fig.update_layout(**chart_layout(260, show_legend=True))
                st.plotly_chart(fig, use_container_width=True)

            csv = pd.DataFrame([dict(r) for r in alerts]).to_csv(index=False)
            st.download_button("Download CSV", data=csv,
                               file_name=f"soc_report_{start}_{end}.csv", mime="text/csv")
        else:
            empty_state("No alert data for this period")


def _weekly():
    section_title("Weekly Security Digest", "Last 7 days at a glance")
    rows = db.fetchall(
        """SELECT date(timestamp) as day, severity, COUNT(*) as cnt
           FROM alerts WHERE timestamp >= datetime('now', '-7 days')
           GROUP BY day, severity ORDER BY day"""
    )
    if not rows:
        empty_state("No data for the past 7 days", "📅")
        return

    df = pd.DataFrame([dict(r) for r in rows])
    fig = px.bar(df, x="day", y="cnt", color="severity",
                 color_discrete_map=SEV_COLORS,
                 labels={"day": "", "cnt": "Alerts"})
    fig.update_layout(**chart_layout(300))
    fig.update_traces(marker_line_width=0)
    st.plotly_chart(fig, use_container_width=True)

    daily = df.pivot_table(index="day", columns="severity", values="cnt", fill_value=0)
    daily["Total"] = daily.sum(axis=1)
    st.dataframe(daily, use_container_width=True)

    top = db.fetchall(
        """SELECT alert_type, COUNT(*) as cnt, MAX(threat_score) as max_score
           FROM alerts WHERE timestamp >= datetime('now', '-7 days')
           GROUP BY alert_type ORDER BY cnt DESC LIMIT 10"""
    )
    if top:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        section_title("Top Threat Types This Week")
        df_top = pd.DataFrame([dict(r) for r in top])
        df_top.columns = ["Alert Type", "Count", "Max Score"]
        st.dataframe(df_top, use_container_width=True, hide_index=True)


def _executive():
    section_title("Executive Security Report", "High-level posture for leadership")
    counts = db.get_alert_counts_by_severity()
    total  = sum(counts.values())
    open_i = len(db.get_incidents("OPEN"))
    crit   = counts.get("CRITICAL", 0)
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    weighted = sum(counts.get(k, 0) * w for k, w in weights.items())
    score    = min(100, int(weighted / max(total, 1) * 10))
    risk_c   = "#f43f5e" if score >= 70 else "#fbbf24" if score >= 40 else "#4ade80"
    risk_l   = "HIGH RISK" if score >= 70 else "MEDIUM RISK" if score >= 40 else "LOW RISK"

    st.markdown(f"""
    <div style="background:{BG_SURFACE};border:1px solid {BORDER};border-radius:14px;
                padding:32px;text-align:center;margin-bottom:20px;
                box-shadow:0 0 40px {risk_c}0d">
      <div style="font-size:4.5rem;font-weight:500;color:{risk_c};
                  font-family:'IBM Plex Mono',monospace;line-height:1">{score}</div>
      <div style="font-size:1rem;color:{risk_c};font-weight:700;
                  text-transform:uppercase;letter-spacing:0.1em;margin-top:6px">{risk_l}</div>
      <div style="color:{TEXT_MUTED};font-size:0.75rem;margin-top:6px">
        Overall Risk Score (0–100)
      </div>
      <div style="margin-top:14px;height:6px;background:{BG_RAISED};border-radius:6px;overflow:hidden">
        <div style="height:100%;width:{score}%;background:linear-gradient(to right,{risk_c}88,{risk_c});
                    border-radius:6px;transition:width 1s ease"></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    kpi_card(c1, "Total Alerts (30d)",  total,  TEAL)
    kpi_card(c2, "Critical Alerts",    crit,   "#f43f5e")
    kpi_card(c3, "Open Incidents",     open_i, "#fbbf24" if open_i > 0 else EMERALD)
    kpi_card(c4, "Risk Trend",         "↑" if score >= 50 else "↓", risk_c)

    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    section_title("Key Findings")
    findings = []
    if crit > 0:
        findings.append((f"{crit} critical alert(s) require immediate attention.", "#f43f5e"))
    if open_i > 0:
        findings.append((f"{open_i} open incident(s) pending resolution.", "#fbbf24"))
    top_type = db.fetchone(
        "SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type ORDER BY cnt DESC LIMIT 1"
    )
    if top_type:
        findings.append((f"Most frequent threat: {top_type['alert_type']} ({top_type['cnt']} occurrences)", TEAL))
    if not findings:
        findings.append(("No significant threats detected in the reporting period.", "#4ade80"))

    for msg, c in findings:
        st.markdown(f"""
        <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 14px;
                    background:{BG_SURFACE};border:1px solid {BORDER};
                    border-left:3px solid {c};border-radius:8px;margin-bottom:6px">
          <span style="color:{c};margin-top:1px">◆</span>
          <span style="font-size:0.83rem;color:{TEXT_SEC}">{msg}</span>
        </div>
        """, unsafe_allow_html=True)
