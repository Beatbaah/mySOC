"""views/threat_hunt.py — IOC manager, beaconing, hunt queries, custom rules, PCAP"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
from engine.threat_hunter import (
    load_iocs, add_ioc, delete_ioc, import_iocs_csv, import_iocs_plaintext,
    check_ioc_hits_in_alerts, detect_beaconing, run_hunt, run_custom_hunt, HUNT_QUERIES,
)
from rules.custom_rules import get_rules_text, save_rules_text, load_rules
from pcap.pcap_writer import list_pcap_files, delete_pcap
from auth.authenticator import has_permission
from utils.helpers import bytes_to_human
from db import database as db
from utils.ui import (
    section_title, empty_state, info_row, SEV_COLORS,
    TEAL, BORDER, BG_SURFACE, BG_RAISED, TEXT_MUTED,
    TEXT_PRI, TEXT_SEC, EMERALD, CORAL, AMBER, page_header,
)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>'


def render():
    user = st.session_state.get("user", {})
    page_header("Threat Hunt", "Proactive IOC matching, beaconing detection and hunt queries", ICON)
    prefill = st.session_state.pop("hunt_prefill_ip", "")

    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["IOC Manager", "Beaconing", "Hunt Queries", "Custom Rules", "PCAP Library"]
    )
    with tab1: _ioc_manager(user, prefill)
    with tab2: _beaconing()
    with tab3: _hunt_queries()
    with tab4: _rules_editor(user)
    with tab5: _pcap_lib()


def _ioc_manager(user, prefill=""):
    section_title("IOC Manager", "Indicators of Compromise — matched against live alerts")
    tab_a, tab_b, tab_c = st.tabs(["IOC List", "Add IOC", "Import Feed"])

    with tab_a:
        iocs = load_iocs()
        if iocs:
            df = pd.DataFrame(iocs)
            cols = ["id","ioc_type","value","threat_type","source","confidence","added_at"]
            df = df[[c for c in cols if c in df.columns]]
            df.columns = ["ID","Type","Value","Threat","Source","Conf%","Added"]
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"{len(iocs)} IOCs in database")
            if has_permission(user, "analyst"):
                del_id = st.number_input("Delete by ID", 0, key="ioc_del")
                if st.button("Delete IOC", key="ioc_del_btn"):
                    if del_id > 0:
                        delete_ioc(del_id); st.rerun()
        else:
            empty_state("No IOCs loaded. Add them manually or import a feed.", "🎯")

        section_title("IOC Hits in Recent Alerts", "Alerts matching known malicious IPs")
        hits = check_ioc_hits_in_alerts()
        if hits:
            for h in hits:
                ioc = h["ioc"]
                c = CORAL
                st.markdown(f"""
                <div style="display:flex;align-items:center;gap:12px;padding:10px 14px;
                            background:{BG_SURFACE};border:1px solid {BORDER};
                            border-left:3px solid {c};border-radius:8px;margin-bottom:5px">
                  <div style="flex:1">
                    <div style="font-family:'IBM Plex Mono',monospace;font-size:0.83rem;color:{TEAL}">{h['ip']}</div>
                    <div style="font-size:0.7rem;color:{TEXT_MUTED}">{ioc.get('threat_type','unknown')} · Confidence: {ioc.get('confidence',0)}%</div>
                  </div>
                  <div style="text-align:right">
                    <div style="font-size:1rem;font-weight:600;color:{c}">{h['alert_count']}</div>
                    <div style="font-size:0.6rem;color:{TEXT_MUTED}">alerts</div>
                  </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown(f'<div style="padding:12px 14px;background:{BG_SURFACE};border:1px solid {BORDER};border-radius:8px;color:{EMERALD};font-size:0.82rem">✓ No IOC matches in recent alerts</div>', unsafe_allow_html=True)

    with tab_b:
        section_title("Add Single IOC")
        with st.form("add_ioc"):
            c1, c2, c3, c4 = st.columns([1.5, 3, 2, 1])
            with c1: ioc_type = st.selectbox("Type", ["ip","domain","hash","url"], key="ioc_t")
            with c2: value    = st.text_input("Value", value=prefill, placeholder="1.2.3.4", key="ioc_v")
            with c3: threat   = st.text_input("Threat Type", placeholder="malware, c2…", key="ioc_th")
            with c4: conf     = st.number_input("Conf%", 0, 100, 80, key="ioc_c")
            if st.form_submit_button("Add IOC", type="primary"):
                if value.strip():
                    add_ioc(ioc_type, value.strip(), threat.strip(), "manual", conf)
                    db.audit(user.get("username","?"), "ioc_added", f"{ioc_type}:{value}")
                    st.success(f"IOC added: {value}"); st.rerun()

    with tab_c:
        section_title("Import IOC Feed")
        source  = st.text_input("Source label", placeholder="abuse.ch, OpenPhish…", key="ioc_src")
        fmt     = st.radio("Format", ["CSV (type,value,threat_type,confidence)", "Plain text (one IP per line)"], key="ioc_fmt")
        content = st.text_area("Paste feed content", height=200, key="ioc_content")
        if st.button("Import Feed", key="ioc_import", type="primary"):
            if content.strip():
                if "CSV" in fmt:
                    added, skipped = import_iocs_csv(content, source=source or "import")
                else:
                    added, skipped = import_iocs_plaintext(content, source=source or "import")
                st.success(f"Imported {added} IOCs ({skipped} skipped)"); st.rerun()


def _beaconing():
    section_title("Beaconing Detection", "Regular-interval connections indicating C2 communication")
    col1, col2, col3 = st.columns(3)
    with col1: hours    = st.slider("Look-back (hours)", 1, 24, 6, key="bc_h")
    with col2: min_conn = st.slider("Min connections",   5, 50, 10, key="bc_min")
    with col3: max_jit  = st.slider("Max jitter %",      5, 30, 15, key="bc_j")

    if st.button("Run Beaconing Detection", key="bc_run", type="primary"):
        with st.spinner("Analysing connection intervals…"):
            results = detect_beaconing(min_connections=min_conn,
                                       max_jitter_pct=max_jit/100, hours_back=hours)
        if not results:
            st.markdown(f'<div style="padding:20px;text-align:center;background:{BG_SURFACE};border:1px solid {BORDER};border-radius:10px;color:{EMERALD}">✓ No beaconing patterns detected</div>', unsafe_allow_html=True)
        else:
            st.warning(f"{len(results)} potential beaconing host(s) detected.")
            for r in results:
                c = CORAL if r["confidence"] >= 85 else AMBER
                st.markdown(f"""
                <div style="padding:14px 16px;background:{BG_SURFACE};border:1px solid {BORDER};
                            border-left:3px solid {c};border-radius:10px;margin-bottom:8px">
                  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
                    <div>
                      <span style="font-family:'IBM Plex Mono',monospace;font-size:0.83rem;color:{TEAL}">{r['src_ip']}</span>
                      <span style="color:{TEXT_MUTED};font-size:0.8rem;margin:0 6px">→</span>
                      <span style="font-family:'IBM Plex Mono',monospace;font-size:0.83rem;color:{TEXT_SEC}">{r['dst_ip']}:{r['dst_port']}</span>
                    </div>
                    <div style="font-family:'IBM Plex Mono',monospace;font-size:1.3rem;font-weight:500;color:{c}">{r['confidence']}%</div>
                  </div>
                  <div style="font-size:0.72rem;color:{TEXT_MUTED}">
                    Interval: {r['interval_avg']}s ± {r['interval_std']}s &nbsp;·&nbsp;
                    Jitter: {r['jitter_pct']}% &nbsp;·&nbsp; Connections: {r['count']}
                  </div>
                </div>
                """, unsafe_allow_html=True)


def _hunt_queries():
    section_title("Threat Hunt Queries", "Pre-built SQL queries for common threat patterns")
    opts = {v["label"]: k for k, v in HUNT_QUERIES.items()}
    sel_label = st.selectbox("Select hunt", list(opts.keys()), key="hunt_sel")
    sel_key   = opts[sel_label]
    st.caption(HUNT_QUERIES[sel_key]["description"])

    if st.button("Run Hunt", key="hunt_run", type="primary"):
        with st.spinner("Running…"):
            rows, err = run_hunt(sel_key)
        if err:
            st.error(f"Query error: {err}")
        elif not rows:
            st.markdown(f'<div style="padding:16px;background:{BG_SURFACE};border:1px solid {BORDER};border-radius:8px;color:{EMERALD}">✓ Hunt returned no results — nothing suspicious found</div>', unsafe_allow_html=True)
        else:
            st.warning(f"{len(rows)} result(s) found.")
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    section_title("Custom SQL Hunt", "SELECT-only queries against traffic, alerts, syslog_events")
    sql = st.text_area("SQL query", height=120, key="hunt_sql",
                        placeholder="SELECT src_ip, COUNT(*) as cnt FROM traffic WHERE dst_port=4444 GROUP BY src_ip ORDER BY cnt DESC")
    if st.button("Run Custom Query", key="hunt_custom"):
        if sql.strip():
            rows, err = run_custom_hunt(sql)
            if err: st.error(f"Query error: {err}")
            elif not rows: st.info("Query returned no rows.")
            else: st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _rules_editor(user):
    section_title("Custom Detection Rules", "YAML-format rules — hot-reloaded, no restart needed")
    rules = load_rules()
    enabled = sum(1 for r in rules if r.get("enabled", True))
    col1, col2, _ = st.columns([1, 1, 3])
    col1.metric("Total Rules", len(rules))
    col2.metric("Active Rules", enabled)

    if not has_permission(user, "analyst"):
        st.warning("Analyst role required to edit rules.")
        st.code(get_rules_text(), language="yaml")
        return

    text = st.text_area("rules/custom_rules.yaml", value=get_rules_text(), height=450, key="rules_ed")
    col_a, col_b = st.columns([1, 4])
    with col_a:
        if st.button("Save Rules", key="rules_save", type="primary"):
            ok, err = save_rules_text(text)
            if ok:
                db.audit(user.get("username","?"), "custom_rules_saved")
                st.success("Rules saved and reloaded."); st.rerun()
            else:
                st.error(f"Parse error: {err}")
    with col_b:
        st.caption("Changes take effect immediately on the next packet.")

    if rules:
        st.markdown(f"<div style='height:12px'></div>", unsafe_allow_html=True)
        section_title("Rule Summary")
        df = pd.DataFrame([{"ID": r.get("id"), "Name": r.get("name"), "Severity": r.get("severity"),
                             "Enabled": "✓" if r.get("enabled", True) else "✗",
                             "Conditions": str(r.get("conditions", {})),
                             "Tags": ", ".join(r.get("tags", []))} for r in rules])
        st.dataframe(df, use_container_width=True, hide_index=True)


def _pcap_lib():
    section_title("PCAP Evidence Library", "Packet captures for forensic analysis in Wireshark")
    if st.button("Capture Current Buffer", key="pcap_dump", type="primary"):
        sniffer = st.session_state.get("sniffer_obj")
        if not sniffer:
            st.warning("Packet sniffer not running. Start it in Settings.")
        else:
            try:
                from pcap.pcap_writer import dump_buffer_to_pcap
                buf  = sniffer.get_buffer()
                path = dump_buffer_to_pcap(buf)
                st.success(f"Saved {len(buf)} packets → {path.name}"); st.rerun()
            except Exception as e:
                st.error(str(e))

    files = list_pcap_files()
    if not files:
        empty_state("No PCAP files yet. Export a buffer or click PCAP from the alert triage queue.", "📦")
        return

    section_title(f"Saved Captures ({len(files)} files)")
    for f in files:
        c1, c2, c3, c4 = st.columns([4, 1, 1, 1])
        with c1:
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:10px;padding:8px 0">
              <div>
                <div style="font-family:'IBM Plex Mono',monospace;font-size:0.82rem;color:{TEAL}">{f['name']}</div>
                <div style="font-size:0.68rem;color:{TEXT_MUTED}">{f['modified']} · {f['size_kb']} KB</div>
              </div>
            </div>
            """, unsafe_allow_html=True)
        with c2:
            try:
                from pathlib import Path
                data = Path(f["path"]).read_bytes()
                st.download_button("↓", data=data, file_name=f["name"],
                                   mime="application/octet-stream", key=f"dl_{f['name']}")
            except Exception:
                pass
        with c3:
            if st.button("🗑", key=f"del_{f['name']}"):
                delete_pcap(f["name"]); st.rerun()
