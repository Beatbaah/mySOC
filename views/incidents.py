"""views/incidents.py — Incident lifecycle management"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
from datetime import datetime, timezone
from db import database as db
from auth.authenticator import has_permission
from utils.ui import (
    chart_layout, section_title, kpi_card, empty_state, sev_pill,
    SEV_COLORS, TEAL, BORDER, BG_SURFACE, BG_RAISED, TEXT_MUTED,
    TEXT_PRI, TEXT_SEC, EMERALD, CORAL, AMBER, SKY, page_header,
)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'

STATUS_COLORS = {
    "OPEN": "#f43f5e", "IN_PROGRESS": "#fbbf24",
    "RESOLVED": "#4ade80", "CLOSED": "#475569",
}
STATUS_ICONS = {
    "OPEN": "●", "IN_PROGRESS": "◐", "RESOLVED": "○", "CLOSED": "—",
}


def render():
    user = st.session_state.get("user", {})
    page_header("Incidents", "Track, investigate and resolve security incidents", ICON)
    tab1, tab2 = st.tabs(["Active Incidents", "Create Incident"])
    with tab1: _list_incidents(user)
    with tab2:
        if has_permission(user, "analyst"):
            _create_incident(user)
        else:
            st.warning("Analyst or Admin role required to create incidents.")


def _list_incidents(user: dict):
    col1, _ = st.columns([2, 3])
    with col1:
        status_filter = st.selectbox("Status",
            ["All", "OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"], key="inc_status")

    incidents = db.get_incidents(None if status_filter == "All" else status_filter)

    if not incidents:
        empty_state("No incidents found", "🚨")
        return

    df = pd.DataFrame([dict(r) for r in incidents])
    c1, c2, c3, c4 = st.columns(4)
    kpi_card(c1, "Total Incidents", len(df), TEAL)
    kpi_card(c2, "Open",       len(df[df["status"] == "OPEN"]),        "#f43f5e")
    kpi_card(c3, "In Progress", len(df[df["status"] == "IN_PROGRESS"]), "#fbbf24")
    kpi_card(c4, "Resolved",   len(df[df["status"] == "RESOLVED"]),    EMERALD)
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    for row in incidents:
        sev_c   = SEV_COLORS.get(row["severity"], TEXT_MUTED)
        stat_c  = STATUS_COLORS.get(row["status"], TEXT_MUTED)
        stat_ic = STATUS_ICONS.get(row["status"], "●")

        with st.expander(
            f"{stat_ic}  [{row['severity']}]  {row['title']}  —  {row['status']}"
        ):
            col_l, col_r = st.columns([3, 2])
            with col_l:
                st.markdown(f"""
                <div style="display:flex;flex-direction:column;gap:6px">
                  <div style="display:flex;gap:8px;align-items:center">
                    <span class="sev-pill sev-{row['severity']}">{row['severity']}</span>
                    <span style="font-size:0.72rem;color:{stat_c};font-weight:600;
                                 text-transform:uppercase">{row['status']}</span>
                  </div>
                  <div style="font-size:0.82rem;color:{TEXT_SEC};line-height:1.6">
                    {row['description'] or 'No description provided.'}
                  </div>
                  <div style="font-size:0.72rem;color:{TEXT_MUTED}">
                    Assigned to: <span style="color:{TEXT_SEC}">{row['assigned_to'] or 'Unassigned'}</span>
                    &nbsp;·&nbsp; Created: {row['created_at'][:16]}
                  </div>
                  {f'<div style="font-size:0.79rem;color:{TEXT_SEC};margin-top:6px;padding:8px;background:{BG_RAISED};border-radius:6px;border:1px solid {BORDER}"><b>Notes:</b> {row["notes"]}</div>' if row.get("notes") else ""}
                </div>
                """, unsafe_allow_html=True)

            with col_r:
                if has_permission(user, "analyst"):
                    statuses = ["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"]
                    new_status = st.selectbox("Update Status", statuses,
                                              index=statuses.index(row["status"]),
                                              key=f"inc_s_{row['id']}")
                    assignee = st.text_input("Assign To", value=row["assigned_to"] or "",
                                             key=f"inc_a_{row['id']}")
                    notes    = st.text_area("Notes", value=row["notes"] or "",
                                            key=f"inc_n_{row['id']}", height=80)
                    if st.button("Save Changes", key=f"inc_save_{row['id']}", type="primary"):
                        upd = {"status": new_status, "assigned_to": assignee, "notes": notes}
                        if new_status == "RESOLVED" and row["status"] != "RESOLVED":
                            upd["resolved_at"] = datetime.now(timezone.utc).isoformat()
                        db.update_incident(row["id"], upd)
                        db.audit(user.get("username", "?"), "incident_updated",
                                 f"id={row['id']}, status={new_status}")
                        st.success("Incident updated.")
                        st.rerun()


def _create_incident(user: dict):
    section_title("Create New Incident")
    with st.form("new_incident"):
        title       = st.text_input("Title", placeholder="Brief, descriptive title")
        description = st.text_area("Description", placeholder="Detailed description of the incident…", height=100)
        col1, col2 = st.columns(2)
        with col1: severity    = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        with col2: assigned_to = st.text_input("Assign To", placeholder="Analyst name or team")
        notes = st.text_area("Initial Notes", height=80)

        recent_alerts  = db.get_recent_alerts(limit=20)
        alert_options  = {
            f"[{r['severity']}] {r['alert_type']} — {r['src_ip']} ({r['timestamp'][:16]})": r["id"]
            for r in recent_alerts
        }
        selected_alerts = st.multiselect("Link Alerts", list(alert_options.keys()),
                                         key="inc_alert_link")
        alert_ids = ",".join(str(alert_options[a]) for a in selected_alerts)

        submitted = st.form_submit_button("Create Incident", type="primary")

    if submitted:
        if not title.strip():
            st.error("Title is required.")
            return
        iid = db.create_incident({
            "title": title.strip(), "description": description.strip(),
            "severity": severity, "status": "OPEN",
            "assigned_to": assigned_to.strip() or None,
            "notes": notes.strip() or None,
            "alert_ids": alert_ids or None,
        })
        db.audit(user.get("username", "?"), "incident_created",
                 f"id={iid}, title={title}")
        st.success(f"Incident #{iid} created successfully.")
        st.rerun()
