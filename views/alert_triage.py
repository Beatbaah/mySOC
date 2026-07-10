"""views/alert_triage.py"""
import sys as _sys; from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
from datetime import datetime, timezone
from db import database as db
from auth.authenticator import has_permission
from utils.ui import (chart_layout, kpi_card, section_title, sev_pill,
                      empty_state, SEV_COLORS, TEAL, TEXT_SEC, TEXT_MUTED,
                      BG_SURFACE, BORDER, BG_RAISED, TEXT_PRI, EMERALD,
                      CORAL, AMBER, SKY, page_header)

SLA_MINUTES = {"CRITICAL": 15, "HIGH": 60, "MEDIUM": 240, "LOW": 1440}
ICON_TARGET = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>'

def _age_min(ts):
    try:
        from datetime import datetime as _dt
        t = _dt.fromisoformat(ts.replace("Z","+00:00"))
        if t.tzinfo is None: t = t.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - t).total_seconds() / 60
    except: return 0.0

def _sla_html(sev, age):
    sla = SLA_MINUTES.get(sev, 1440)
    pct = age / sla * 100
    rem = max(0, sla - age)
    if pct >= 100:
        return f'<span class="sla-breach">⏰ OVERDUE</span>'
    elif pct >= 75:
        return f'<span class="sla-warn">⏱ {rem:.0f}m left</span>'
    else:
        return f'<span class="sla-ok">⏱ {rem:.0f}m left</span>'

def render():
    user = st.session_state.get("user", {})
    page_header("Alert Triage", "Prioritised queue with SLA tracking and one-click actions", ICON_TARGET)

    # Filters
    col1, col2, col3, col4 = st.columns([2,2,2,1])
    with col1:
        sev_filter = st.multiselect("Severity", ["CRITICAL","HIGH","MEDIUM","LOW","INFO"],
                                    default=["CRITICAL","HIGH"], key="tq_sev")
    with col2:
        ack_filter = st.radio("Status", ["Unacknowledged","Acknowledged","All"],
                              horizontal=True, key="tq_ack")
    with col3:
        time_filter = st.selectbox("Window", ["Last 1h","Last 6h","Last 24h","Last 7d","All time"], key="tq_time")
    with col4:
        st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
        auto_r = st.checkbox("Auto", True, key="tq_auto")
    if auto_r:
        st.markdown('<meta http-equiv="refresh" content="10">', unsafe_allow_html=True)

    win = {"Last 1h":"-1 hours","Last 6h":"-6 hours","Last 24h":"-24 hours","Last 7d":"-7 days","All time":"-100 years"}[time_filter]
    clauses = [f"timestamp >= datetime('now', '{win}')"]
    params = []
    if sev_filter:
        clauses.append(f"severity IN ({','.join('?'*len(sev_filter))})")
        params.extend(sev_filter)
    if ack_filter == "Unacknowledged": clauses.append("acknowledged=0")
    elif ack_filter == "Acknowledged": clauses.append("acknowledged=1")
    where = "WHERE " + " AND ".join(clauses)
    rows = db.fetchall(
        f"SELECT * FROM alerts {where} ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, timestamp ASC LIMIT 200",
        tuple(params)
    )

    # KPIs
    overdue  = sum(1 for r in rows if _age_min(r["timestamp"]) > SLA_MINUTES.get(r["severity"],9999) and not r["acknowledged"])
    critical = sum(1 for r in rows if r["severity"]=="CRITICAL" and not r["acknowledged"])
    high     = sum(1 for r in rows if r["severity"]=="HIGH" and not r["acknowledged"])
    c1,c2,c3,c4 = st.columns(4)
    kpi_card(c1, "In Queue",       len(rows),  TEAL,    ICON_TARGET)
    kpi_card(c2, "Unacked Critical", critical, "#f43f5e")
    kpi_card(c3, "Unacked High",   high,       "#fb923c")
    kpi_card(c4, "SLA Breached",   overdue,    CORAL if overdue > 0 else EMERALD)
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    if not rows:
        empty_state("No alerts match the current filters — great work! ✅", "🎯")
        return

    # Bulk actions
    if has_permission(user, "analyst"):
        with st.expander("⚡ Bulk Actions"):
            b1,b2,b3 = st.columns(3)
            with b1:
                if st.button("Acknowledge All Critical", key="bulk_crit", type="primary"):
                    ids = [r["id"] for r in rows if r["severity"]=="CRITICAL" and not r["acknowledged"]]
                    for aid in ids: db.acknowledge_alert(aid, user.get("username","?"))
                    st.success(f"Acknowledged {len(ids)} critical alerts."); st.rerun()
            with b2:
                if st.button("Acknowledge All High", key="bulk_high"):
                    ids = [r["id"] for r in rows if r["severity"]=="HIGH" and not r["acknowledged"]]
                    for aid in ids: db.acknowledge_alert(aid, user.get("username","?"))
                    st.success(f"Acknowledged {len(ids)} high alerts."); st.rerun()
            with b3:
                if st.button("Acknowledge All Visible", key="bulk_all"):
                    ids = [r["id"] for r in rows if not r["acknowledged"]]
                    for aid in ids: db.acknowledge_alert(aid, user.get("username","?"))
                    st.success(f"Acknowledged {len(ids)} alerts."); st.rerun()

    # Alert cards
    for i, row in enumerate(rows):
        age   = _age_min(row["timestamp"])
        sev   = row["severity"]
        c     = SEV_COLORS.get(sev, TEXT_MUTED)
        acked = bool(row["acknowledged"])
        op    = "0.45" if acked else "1"

        st.markdown(f"""
        <div style="background:{BG_SURFACE};border:1px solid {BORDER};border-left:3px solid {c};
                    border-radius:10px;padding:14px 16px;margin-bottom:8px;opacity:{op};
                    transition:all 0.2s;animation:slideIn 0.25s ease {i*0.03}s both">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:5px">
                <span class="sev-pill sev-{sev}">{sev}</span>
                <span style="font-size:0.85rem;font-weight:600;color:{TEXT_PRI}">{row['alert_type']}</span>
                <span style="font-size:0.7rem;color:{TEXT_MUTED}">#{row['id']}</span>
                <span style="font-size:0.7rem;color:{TEXT_MUTED}">{row['timestamp'][:16]}</span>
              </div>
              <div style="font-size:0.79rem;color:{TEXT_SEC};margin-bottom:8px">{(row['description'] or '')[:120]}</div>
              <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:center">
                <code style="background:{BG_RAISED};color:{TEAL};padding:2px 7px;border-radius:4px;
                             font-size:0.75rem;border:1px solid #162030">{row['src_ip'] or '—'}</code>
                <span style="color:{TEXT_MUTED};font-size:0.72rem">→</span>
                <code style="background:{BG_RAISED};color:{SKY};padding:2px 7px;border-radius:4px;
                             font-size:0.75rem;border:1px solid #162030">{row['dst_ip'] or '—'}</code>
                <span style="color:{TEXT_MUTED};font-size:0.7rem">{row['protocol'] or ''}</span>
                {_sla_html(sev, age)}
                {"<span style='color:" + EMERALD + ";font-size:0.7rem'>✓ " + str(row['ack_by']) + "</span>" if acked else ""}
              </div>
            </div>
            <div style="text-align:right;flex-shrink:0">
              <div style="font-family:'IBM Plex Mono',monospace;font-size:1.4rem;
                          font-weight:500;color:{c};line-height:1">{row['threat_score']}</div>
              <div style="font-size:0.6rem;color:{TEXT_MUTED};text-transform:uppercase;letter-spacing:0.08em">score</div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        if has_permission(user, "analyst") and not acked:
            a1,a2,a3,a4,_ = st.columns([1,1.2,1,1.2,3])
            with a1:
                if st.button("✓ Ack", key=f"ack_{row['id']}"):
                    db.acknowledge_alert(row["id"], user.get("username","?"))
                    db.audit(user.get("username"),"alert_acked",f"id={row['id']}"); st.rerun()
            with a2:
                if st.button("+ Incident", key=f"inc_{row['id']}"):
                    iid = db.create_incident({"title":f"[{sev}] {row['alert_type']} from {row['src_ip']}","description":row["description"],"severity":sev,"status":"OPEN","alert_ids":str(row["id"])})
                    db.acknowledge_alert(row["id"], user.get("username","?"))
                    st.success(f"Incident #{iid} created."); st.rerun()
            with a3:
                if st.button("PCAP", key=f"pcap_{row['id']}"):
                    try:
                        from pcap.pcap_writer import export_alert_pcap
                        path = export_alert_pcap(row["id"])
                        st.success(f"PCAP: {path.name}" if path else "No traffic data found.")
                    except Exception as e:
                        st.error(str(e))
            with a4:
                if st.button("Hunt IP", key=f"hunt_{row['id']}"):
                    st.session_state.page = "Threat Hunt"
                    st.session_state.hunt_prefill_ip = row["src_ip"]; st.rerun()
