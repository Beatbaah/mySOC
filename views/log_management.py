"""views/log_management.py — Syslog, search, audit trail"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
from db import database as db
from utils.ui import (
    section_title, empty_state, SEV_COLORS, TEAL, BORDER,
    BG_SURFACE, BG_RAISED, TEXT_MUTED, TEXT_PRI, TEXT_SEC,
    EMERALD, AMBER, page_header,
)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/><line x1="8" y1="9" x2="10" y2="9"/></svg>'

FACILITY_NAMES = {0:"kernel",1:"user",2:"mail",3:"daemon",4:"auth",5:"syslog",
                  6:"lpr",7:"news",8:"uucp",9:"cron",10:"security"}
SEVERITY_NAMES = {0:"Emergency",1:"Alert",2:"Critical",3:"Error",
                  4:"Warning",5:"Notice",6:"Info",7:"Debug"}


def render():
    page_header("Log Management", "Syslog events, log search and complete audit trail", ICON)
    tab1, tab2, tab3 = st.tabs(["Syslog Events", "Log Search", "Audit Trail"])
    with tab1: _syslog()
    with tab2: _search()
    with tab3: _audit()


def _syslog():
    section_title("Syslog Events", "Received from firewalls, routers and network devices")
    col1, col2, col3 = st.columns(3)
    with col1:
        sev_opt = st.selectbox("Min Severity",
            ["All","Emergency(0)","Alert(1)","Critical(2)","Error(3)",
             "Warning(4)","Notice(5)","Info(6)","Debug(7)"], key="log_sev")
    with col2:
        src_filter = st.text_input("Source IP", placeholder="Filter by IP…", key="log_src")
    with col3:
        limit = st.number_input("Max rows", 50, 1000, 200, key="log_limit")

    clauses, params = [], []
    if sev_opt != "All":
        clauses.append("severity <= ?")
        params.append(int(sev_opt.split("(")[1].rstrip(")")))
    if src_filter.strip():
        clauses.append("source_ip = ?")
        params.append(src_filter.strip())
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

    rows = db.fetchall(
        f"SELECT * FROM syslog_events {where} ORDER BY timestamp DESC LIMIT ?",
        tuple(params) + (limit,)
    )
    if rows:
        df = pd.DataFrame([dict(r) for r in rows])
        df["facility"]  = df["facility"].apply(lambda x: FACILITY_NAMES.get(x, str(x)))
        df["sev_name"]  = df["severity"].apply(lambda x: SEVERITY_NAMES.get(x, str(x)))
        display = df[["timestamp","source_ip","hostname","program","facility","sev_name","message"]].copy()
        display.columns = ["Time","Source IP","Hostname","Program","Facility","Severity","Message"]
        st.dataframe(display, use_container_width=True, hide_index=True)
        st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
        col_a, col_b = st.columns(2)
        with col_a:
            section_title("By Severity")
            vc = df["sev_name"].value_counts().reset_index()
            vc.columns = ["Severity", "Count"]
            st.dataframe(vc, use_container_width=True, hide_index=True)
        with col_b:
            section_title("By Hostname")
            vh = df["hostname"].value_counts().head(10).reset_index()
            vh.columns = ["Hostname", "Count"]
            st.dataframe(vh, use_container_width=True, hide_index=True)
    else:
        empty_state("No syslog events. Configure devices to send UDP syslog to this system.", "📡")


def _search():
    section_title("Log Search", "Full-text search across alerts, syslog and audit log")
    query = st.text_input("Search term", placeholder="e.g. port scan, 192.168.1.1, SSH", key="log_q")
    search_in = st.multiselect("Search in", ["Alerts", "Syslog Events", "Audit Log"],
                               default=["Alerts", "Syslog Events"], key="log_in")

    if st.button("Search", key="log_search_btn", type="primary") and query.strip():
        term = f"%{query.strip()}%"
        if "Alerts" in search_in:
            rows = db.fetchall(
                """SELECT timestamp, severity, alert_type, src_ip, dst_ip, description
                   FROM alerts WHERE description LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR alert_type LIKE ?
                   ORDER BY timestamp DESC LIMIT 100""",
                (term, term, term, term)
            )
            section_title(f"Alerts — {len(rows)} results")
            if rows:
                st.dataframe(pd.DataFrame([dict(r) for r in rows]),
                             use_container_width=True, hide_index=True)
            else:
                empty_state("No matching alerts")

        if "Syslog Events" in search_in:
            rows2 = db.fetchall(
                """SELECT timestamp, source_ip, hostname, program, message FROM syslog_events
                   WHERE message LIKE ? OR hostname LIKE ? OR source_ip LIKE ? OR program LIKE ?
                   ORDER BY timestamp DESC LIMIT 100""",
                (term, term, term, term)
            )
            section_title(f"Syslog Events — {len(rows2)} results")
            if rows2:
                st.dataframe(pd.DataFrame([dict(r) for r in rows2]),
                             use_container_width=True, hide_index=True)
            else:
                empty_state("No matching syslog events")

        if "Audit Log" in search_in:
            rows3 = db.fetchall(
                """SELECT timestamp, username, action, detail, ip_address FROM audit_log
                   WHERE detail LIKE ? OR username LIKE ? OR action LIKE ?
                   ORDER BY timestamp DESC LIMIT 100""",
                (term, term, term)
            )
            section_title(f"Audit Log — {len(rows3)} results")
            if rows3:
                st.dataframe(pd.DataFrame([dict(r) for r in rows3]),
                             use_container_width=True, hide_index=True)
            else:
                empty_state("No matching audit entries")


def _audit():
    section_title("Audit Trail", "All user actions and system events")
    rows = db.fetchall("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 500")
    if rows:
        df = pd.DataFrame([dict(r) for r in rows])
        df.columns = ["ID", "Timestamp", "Username", "Action", "Detail", "IP Address"]
        st.dataframe(df.drop(columns=["ID"]), use_container_width=True, hide_index=True)
        st.caption(f"{len(rows)} entries shown (max 500)")
    else:
        empty_state("No audit events recorded yet. Login events will appear here.", "📋")
