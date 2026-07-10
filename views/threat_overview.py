"""views/threat_overview.py"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from db import database as db
from utils.helpers import bytes_to_human
from utils.ui import (chart_layout, kpi_card, section_title, alert_card,
                      empty_state, SEV_COLORS, TEAL, TEXT_SEC, TEXT_MUTED,
                      BG_SURFACE, BORDER, BG_RAISED, TEXT_PRI, EMERALD,
                      CORAL, AMBER, SKY, page_header)

ICONS = {
    "shield": '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    "flame":  '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/></svg>',
    "alert":  '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    "target": '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
    "info":   '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
}

def render():
    page_header("Threat Overview", "Real-time security posture across all monitored systems", ICONS["shield"])

    counts = db.get_alert_counts_by_severity()
    total  = sum(counts.values())
    unacked = db.fetchone("SELECT COUNT(*) as c FROM alerts WHERE acknowledged=0")
    unacked_n = unacked["c"] if unacked else 0
    open_inc = len(db.get_incidents("OPEN"))

    # ── KPI row ───────────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    kpi_card(c1, "Total Alerts",    total,                       TEAL,          ICONS["shield"])
    kpi_card(c2, "Critical",        counts.get("CRITICAL", 0),  "#f43f5e",     ICONS["flame"])
    kpi_card(c3, "High",            counts.get("HIGH", 0),      "#fb923c",     ICONS["alert"])
    kpi_card(c4, "Unacknowledged",  unacked_n,                   "#fbbf24",     ICONS["target"])
    kpi_card(c5, "Open Incidents",  open_inc,                    "#60a5fa",     ICONS["info"])

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    # ── Charts row ────────────────────────────────────────────────────────────
    col_l, col_r = st.columns([3, 2])

    with col_l:
        section_title("Alert Timeline", "Last 24 hours by severity")
        rows = db.fetchall("""
            SELECT strftime('%H:%M', timestamp) as t, severity, COUNT(*) as cnt
            FROM alerts WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY t, severity ORDER BY t
        """)
        if rows:
            df = pd.DataFrame([dict(r) for r in rows])
            fig = px.bar(df, x="t", y="cnt", color="severity",
                         color_discrete_map=SEV_COLORS,
                         labels={"t": "", "cnt": "Alerts"})
            fig.update_layout(**chart_layout(height=260))
            fig.update_traces(marker_line_width=0)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.markdown(f"""
            <div style="background:{BG_SURFACE};border:1px solid {BORDER};border-radius:10px;
                        padding:40px;text-align:center;height:260px;display:flex;
                        align-items:center;justify-content:center;flex-direction:column;gap:8px">
              <div style="font-size:2rem;opacity:0.2">📊</div>
              <div style="font-size:0.82rem;color:{TEXT_MUTED}">No alerts in the last 24 hours</div>
              <div style="font-size:0.72rem;color:#1e3a5a">System is quiet</div>
            </div>
            """, unsafe_allow_html=True)

    with col_r:
        section_title("Distribution", "By severity level")
        if counts:
            fig2 = go.Figure(go.Pie(
                labels=list(counts.keys()),
                values=list(counts.values()),
                hole=0.65,
                marker_colors=[SEV_COLORS.get(k, TEXT_MUTED) for k in counts],
                textfont=dict(size=11, family="DM Sans"),
            ))
            fig2.update_layout(
                **chart_layout(height=260, show_legend=True),
                annotations=[dict(
                    text=f'<b style="font-size:18px">{total}</b><br><span style="font-size:11px">Total</span>',
                    x=0.5, y=0.5, font_size=13, showarrow=False,
                    font_color=TEXT_PRI,
                )],
            )
            st.plotly_chart(fig2, use_container_width=True)
        else:
            empty_state("No alert data yet", "🎯")

    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
    st.markdown(f"<hr style='border-color:{BORDER};margin:0 0 20px'>", unsafe_allow_html=True)

    # ── Bottom row: Top Attackers + Alert Types ────────────────────────────────
    col_a, col_b = st.columns(2)

    with col_a:
        section_title("Top Attacking IPs", "Most active threat sources")
        rows = db.fetchall("""
            SELECT src_ip, COUNT(*) as cnt, MAX(severity) as max_sev,
                   MAX(threat_score) as max_score
            FROM alerts WHERE src_ip != ''
            GROUP BY src_ip ORDER BY cnt DESC LIMIT 8
        """)
        if rows:
            for r in rows:
                c = SEV_COLORS.get(r["max_sev"], TEXT_MUTED)
                st.markdown(f"""
                <div style="display:flex;align-items:center;gap:10px;padding:8px 12px;
                            background:{BG_SURFACE};border:1px solid {BORDER};
                            border-radius:8px;margin-bottom:5px;transition:all 0.2s">
                  <div style="width:36px;height:36px;border-radius:8px;background:{BG_RAISED};
                              display:flex;align-items:center;justify-content:center;flex-shrink:0">
                    <span style="font-family:'IBM Plex Mono',monospace;font-size:0.65rem;
                                 color:{TEXT_MUTED}">{r['src_ip'].split('.')[-1]}</span>
                  </div>
                  <div style="flex:1;min-width:0">
                    <div style="font-family:'IBM Plex Mono',monospace;font-size:0.82rem;
                                color:{TEAL};font-weight:500">{r['src_ip']}</div>
                    <div style="font-size:0.68rem;color:{TEXT_MUTED}">{r['cnt']} alerts</div>
                  </div>
                  <div style="text-align:right">
                    <span class="sev-pill sev-{r['max_sev']}">{r['max_sev']}</span>
                  </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            empty_state("No attacker data yet", "🎯")

    with col_b:
        section_title("Alert Type Breakdown", "Attack patterns detected")
        rows2 = db.fetchall("""
            SELECT alert_type, COUNT(*) as cnt, AVG(threat_score) as avg_score
            FROM alerts GROUP BY alert_type ORDER BY cnt DESC LIMIT 8
        """)
        if rows2:
            max_cnt = max(r["cnt"] for r in rows2)
            for r in rows2:
                pct = int(r["cnt"] / max_cnt * 100)
                st.markdown(f"""
                <div style="padding:8px 12px;background:{BG_SURFACE};border:1px solid {BORDER};
                            border-radius:8px;margin-bottom:5px">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">
                    <span style="font-size:0.8rem;font-weight:500;color:{TEXT_PRI}">{r['alert_type']}</span>
                    <span style="font-family:'IBM Plex Mono',monospace;font-size:0.75rem;color:{TEXT_MUTED}">{r['cnt']}</span>
                  </div>
                  <div style="background:{BG_RAISED};border-radius:4px;height:3px;overflow:hidden">
                    <div style="background:linear-gradient(to right,{TEAL},{TEAL_DIM});
                                height:100%;width:{pct}%;border-radius:4px;
                                transition:width 0.6s ease"></div>
                  </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            empty_state("No alert type data", "📊")

    # ── Recent alerts ─────────────────────────────────────────────────────────
    st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
    st.markdown(f"<hr style='border-color:{BORDER};margin:0 0 20px'>", unsafe_allow_html=True)
    section_title("Recent Alerts", "Latest security events")

    recent = db.get_recent_alerts(limit=15)
    if recent:
        for i, r in enumerate(recent):
            alert_card(dict(r), idx=i)
    else:
        st.markdown(f"""
        <div style="text-align:center;padding:40px;background:{BG_SURFACE};
                    border:1px solid {BORDER};border-radius:10px">
          <div style="font-size:2rem;margin-bottom:10px">✅</div>
          <div style="font-size:0.9rem;font-weight:600;color:{EMERALD}">All Clear</div>
          <div style="font-size:0.78rem;color:{TEXT_MUTED};margin-top:4px">No alerts detected — system is operating normally</div>
        </div>
        """, unsafe_allow_html=True)

TEAL_DIM = "#14b8a6"
