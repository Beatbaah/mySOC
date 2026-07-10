"""views/shift_handover.py — Shift notes and handover reports"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
from datetime import datetime, timezone, timedelta
from db import database as db
from auth.authenticator import has_permission
from utils.ui import (
    chart_layout, section_title, kpi_card, empty_state,
    SEV_COLORS, TEAL, BORDER, BG_SURFACE, BG_RAISED,
    TEXT_MUTED, TEXT_PRI, TEXT_SEC, EMERALD, AMBER, page_header,
)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>'


def render():
    user = st.session_state.get("user", {})
    page_header("Shift Handover", "Document open items and notes for the incoming analyst", ICON)
    tab1, tab2, tab3 = st.tabs(["New Handover", "History", "Shift Summary"])
    with tab1: _new_handover(user)
    with tab2: _history()
    with tab3: _summary()


def _new_handover(user: dict):
    section_title("Create Handover Report", "Hand off context to the next shift")
    with st.form("handover_form"):
        col1, col2 = st.columns(2)
        with col1:
            outgoing = st.text_input("Outgoing Analyst", value=user.get("username", ""), key="ho_out")
        with col2:
            incoming = st.text_input("Incoming Analyst", placeholder="Name", key="ho_in")

        shift = st.selectbox("Shift", ["Day (06:00–14:00)", "Evening (14:00–22:00)", "Night (22:00–06:00)"], key="ho_shift")

        col_a, col_b = st.columns(2)
        with col_a:
            open_threats = st.text_area("Active Threats / Investigations",
                placeholder="e.g. Ongoing port scan from 45.33.32.156 — tracking in Incident #12",
                height=100, key="ho_threats")
            pending = st.text_area("Pending Actions for Next Shift",
                placeholder="e.g. Investigate beaconing from 192.168.1.50",
                height=80, key="ho_pending")
        with col_b:
            actions = st.text_area("Actions Taken This Shift",
                placeholder="e.g. Acknowledged 3 HIGH alerts, created incident for SYN flood",
                height=100, key="ho_actions")
            notes = st.text_area("Additional Notes", height=80, key="ho_notes")

        st.markdown(f"<div style='font-size:0.72rem;font-weight:600;color:{TEXT_MUTED};text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px'>System Status</div>", unsafe_allow_html=True)
        sc1, sc2, sc3, sc4 = st.columns(4)
        with sc1: sniffer_ok = st.checkbox("Capture running", value=st.session_state.get("sniffer_running", False), key="ho_sn")
        with sc2: syslog_ok  = st.checkbox("Syslog running",  value=st.session_state.get("syslog_running", False), key="ho_sy")
        with sc3: notif_ok   = st.checkbox("Alerts tested",   key="ho_notif")
        with sc4: ml_ok      = st.checkbox("ML trained",      value=st.session_state.get("ml_stats", {}).get("trained", False), key="ho_ml")

        open_incs = db.get_incidents("OPEN")
        inc_opts  = [f"#{r['id']} — {r['title']}" for r in open_incs]
        linked    = st.multiselect("Link Open Incidents", inc_opts, key="ho_incs")

        submitted = st.form_submit_button("Submit Handover Report", type="primary")

    if submitted:
        if not outgoing.strip() or not incoming.strip():
            st.error("Both outgoing and incoming analyst names are required.")
            return
        import json
        counts = db.get_alert_counts_by_severity()
        report = {
            "outgoing": outgoing, "incoming": incoming, "shift": shift,
            "open_threats": open_threats, "actions": actions,
            "pending": pending, "notes": notes,
            "system_status": {"sniffer": sniffer_ok, "syslog": syslog_ok,
                              "notif": notif_ok, "ml": ml_ok},
            "alert_counts": dict(counts),
            "linked_incidents": linked,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        db.insert("shift_handovers", {
            "outgoing_analyst": outgoing, "incoming_analyst": incoming,
            "shift_type": shift, "report_json": json.dumps(report),
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        db.audit(user.get("username", "?"), "handover_submitted",
                 f"outgoing={outgoing}, incoming={incoming}")
        st.success("Handover report submitted successfully.")
        st.balloons()


def _history():
    section_title("Handover History")
    rows = db.fetchall("SELECT * FROM shift_handovers ORDER BY created_at DESC LIMIT 50")
    if not rows:
        empty_state("No handover reports yet. Submit one above.", "🔄")
        return

    for row in rows:
        import json
        try:
            r = json.loads(row["report_json"])
        except Exception:
            r = {}
        with st.expander(
            f"{row['created_at'][:16]}  ·  {row['outgoing_analyst']} → {row['incoming_analyst']}  ·  {row['shift_type']}"
        ):
            col_l, col_r = st.columns(2)
            with col_l:
                if r.get("open_threats"):
                    st.markdown(f"**Active Threats**")
                    st.markdown(f'<div style="font-size:0.82rem;color:{TEXT_SEC};padding:8px;background:{BG_RAISED};border-radius:6px;border:1px solid {BORDER}">{r["open_threats"]}</div>', unsafe_allow_html=True)
                if r.get("actions"):
                    st.markdown("**Actions Taken**")
                    st.markdown(f'<div style="font-size:0.82rem;color:{TEXT_SEC};padding:8px;background:{BG_RAISED};border-radius:6px;border:1px solid {BORDER}">{r["actions"]}</div>', unsafe_allow_html=True)
            with col_r:
                if r.get("pending"):
                    st.markdown("**Pending**")
                    st.markdown(f'<div style="font-size:0.82rem;color:{TEXT_SEC};padding:8px;background:{BG_RAISED};border-radius:6px;border:1px solid {BORDER}">{r["pending"]}</div>', unsafe_allow_html=True)
                status = r.get("system_status", {})
                if status:
                    st.markdown("**System at Handover**")
                    s = " · ".join(f"{'✓' if v else '✗'} {k}" for k, v in status.items())
                    st.markdown(f'<div style="font-size:0.78rem;color:{TEXT_MUTED}">{s}</div>', unsafe_allow_html=True)

            counts = r.get("alert_counts", {})
            if counts:
                st.markdown("**Alert counts at handover**")
                cols = st.columns(len(counts))
                for i, (sev, cnt) in enumerate(counts.items()):
                    c = SEV_COLORS.get(sev, TEXT_MUTED)
                    cols[i].markdown(f'<div style="text-align:center"><div style="font-family:\'IBM Plex Mono\',monospace;font-size:1.1rem;color:{c}">{cnt}</div><div style="font-size:0.62rem;color:{TEXT_MUTED}">{sev}</div></div>', unsafe_allow_html=True)


def _summary():
    section_title("Shift Performance", "Alert response times vs SLA")
    c1, _ = st.columns(2)
    with c1: days = st.slider("Days", 1, 30, 7, key="ss_days")

    rows = db.fetchall(
        f"""SELECT severity,
                   AVG((julianday(ack_at) - julianday(timestamp)) * 24 * 60) as avg_min,
                   MIN((julianday(ack_at) - julianday(timestamp)) * 24 * 60) as min_min,
                   MAX((julianday(ack_at) - julianday(timestamp)) * 24 * 60) as max_min,
                   COUNT(*) as total
            FROM alerts WHERE acknowledged=1 AND timestamp >= datetime('now', '-{days} days')
              AND ack_at IS NOT NULL
            GROUP BY severity ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END"""
    )
    SLA = {"CRITICAL": 15, "HIGH": 60, "MEDIUM": 240, "LOW": 1440}
    if rows:
        section_title("Response Times vs SLA")
        df = pd.DataFrame([dict(r) for r in rows])
        df["avg_min"] = df["avg_min"].round(1).fillna(0)
        df["SLA"]     = df["severity"].map(SLA)
        df["Met"]     = df.apply(lambda r: "✅" if r["avg_min"] <= r["SLA"] else "❌", axis=1)
        df.columns    = ["Severity","Avg (min)","Min (min)","Max (min)","Total","SLA (min)","Met?"]
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        empty_state("No acknowledged alerts with timestamps in this period")

    vol = db.fetchall(
        f"""SELECT date(timestamp) as day, severity, COUNT(*) as cnt
            FROM alerts WHERE timestamp >= datetime('now', '-{days} days')
            GROUP BY day, severity ORDER BY day"""
    )
    if vol:
        import plotly.express as px
        df2 = pd.DataFrame([dict(r) for r in vol])
        fig = px.bar(df2, x="day", y="cnt", color="severity",
                     color_discrete_map=SEV_COLORS, labels={"day": "", "cnt": "Alerts"})
        fig.update_layout(**chart_layout(280))
        st.plotly_chart(fig, use_container_width=True)
