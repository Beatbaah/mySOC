"""views/threat_intel.py — IP and hash reputation lookups"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
from intel import abuseipdb, alienvault, virustotal
from db import database as db
from utils.helpers import is_valid_ip
from utils.ui import (
    section_title, empty_state, info_row,
    TEAL, BORDER, BG_SURFACE, BG_RAISED, TEXT_MUTED,
    TEXT_PRI, TEXT_SEC, EMERALD, CORAL, AMBER, page_header,
)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>'


def _score_color(score: int, max_bad: int = 75) -> str:
    if score >= max_bad: return CORAL
    if score >= 25:      return AMBER
    return EMERALD


def _score_card(col, label: str, value, subtitle: str, color: str):
    col.markdown(f"""
    <div style="background:{BG_SURFACE};border:1px solid {BORDER};border-radius:10px;
                padding:20px;text-align:center;box-shadow:0 2px 12px rgba(0,0,0,0.4)">
      <div style="font-family:'IBM Plex Mono',monospace;font-size:2.6rem;font-weight:500;
                  color:{color};line-height:1">{value}</div>
      <div style="font-size:0.72rem;color:{TEXT_MUTED};margin-top:4px;
                  text-transform:uppercase;letter-spacing:0.1em">{subtitle}</div>
      <div style="font-size:0.65rem;color:{TEXT_MUTED};margin-top:6px">{label}</div>
    </div>
    """, unsafe_allow_html=True)


def render():
    page_header("Threat Intel", "IP and file hash reputation across AbuseIPDB, OTX and VirusTotal", ICON)
    tab1, tab2, tab3 = st.tabs(["IP Lookup", "Hash Lookup", "Intel Cache"])
    with tab1: _ip_lookup()
    with tab2: _hash_lookup()
    with tab3: _cache()


def _ip_lookup():
    section_title("IP Reputation Lookup", "Queries three threat intel sources simultaneously")
    col1, col2 = st.columns([3, 1])
    with col1:
        ip = st.text_input("IP Address", placeholder="e.g. 45.33.32.156", key="ti_ip")
    with col2:
        st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
        force = st.checkbox("Force refresh", key="ti_force")

    if st.button("Look Up IP", key="ti_lookup", type="primary"):
        if not ip.strip():
            st.warning("Please enter an IP address.")
            return
        if not is_valid_ip(ip.strip()):
            st.error("Invalid IP address format.")
            return
        ip = ip.strip()

        col_a, col_b, col_c = st.columns(3)

        with col_a:
            st.markdown(f"<div style='font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:{TEXT_MUTED};margin-bottom:10px'>AbuseIPDB</div>", unsafe_allow_html=True)
            with st.spinner("Querying…"):
                r = abuseipdb.check_ip(ip, force_refresh=force)
            if "error" in r:
                st.error(r["error"])
            else:
                sc = r.get("abuseConfidenceScore", 0)
                _score_card(col_a, "Abuse Confidence", f"{sc}%", "Abuse Score", _score_color(sc))
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                info_row("Reports",     r.get("totalReports", 0))
                info_row("Country",     r.get("countryCode", "—"))
                info_row("ISP",         r.get("isp", "—"))
                info_row("Usage Type",  r.get("usageType", "—"))
                last = (r.get("lastReportedAt") or "Never")[:10]
                info_row("Last Report", last)

        with col_b:
            st.markdown(f"<div style='font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:{TEXT_MUTED};margin-bottom:10px'>AlienVault OTX</div>", unsafe_allow_html=True)
            with st.spinner("Querying…"):
                r2 = alienvault.check_ip(ip, force_refresh=force)
            if "error" in r2:
                st.error(r2["error"])
            else:
                pulses = r2.get("pulse_count", 0)
                _score_card(col_b, "Threat Pulses", pulses, "OTX Pulses", _score_color(pulses, 10))
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                info_row("Reputation",   r2.get("reputation", 0))
                info_row("Country",      r2.get("country", "—"))
                info_row("ASN",          r2.get("asn", "—"))
                info_row("Malware Hits", r2.get("malware_count", 0))

        with col_c:
            st.markdown(f"<div style='font-size:0.72rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:{TEXT_MUTED};margin-bottom:10px'>VirusTotal</div>", unsafe_allow_html=True)
            with st.spinner("Querying…"):
                r3 = virustotal.check_ip(ip, force_refresh=force)
            if "error" in r3:
                st.error(r3["error"])
            else:
                mal = r3.get("malicious", 0)
                _score_card(col_c, "Malicious Detections", mal, "VT Engines", _score_color(mal, 5))
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                info_row("Suspicious", r3.get("suspicious", 0))
                info_row("Harmless",   r3.get("harmless", 0))
                info_row("Country",    r3.get("country", "—"))
                info_row("ASN Owner",  r3.get("as_owner", "—"))


def _hash_lookup():
    section_title("File Hash Lookup", "MD5, SHA1 or SHA256 via VirusTotal")
    h = st.text_input("File Hash", placeholder="e.g. 44d88612fea8a8f36de82e1278abb02f", key="ti_hash")
    if st.button("Look Up Hash", key="ti_hash_btn", type="primary"):
        if not h.strip():
            st.warning("Please enter a hash.")
            return
        with st.spinner("Querying VirusTotal…"):
            r = virustotal.check_hash(h.strip())
        if "error" in r:
            st.error(r["error"])
        else:
            mal = r.get("malicious", 0)
            col1, col2 = st.columns([1, 2])
            with col1:
                total_engines = mal + r.get("suspicious", 0) + r.get("harmless", 0) + r.get("undetected", 0)
                _score_card(col1, "Detections", f"{mal}/{total_engines}", "Engines Flagged", _score_color(mal, 5))
            with col2:
                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
                info_row("File Name", r.get("name", "—"))
                info_row("File Type", r.get("type", "—"))
                info_row("File Size", f"{r.get('size', 0):,} bytes")
                info_row("Suspicious", r.get("suspicious", 0))
                info_row("Harmless",  r.get("harmless", 0))


def _cache():
    section_title("Cached Intel", "TTL-cached results reduce API calls")
    rows = db.fetchall(
        "SELECT ip, source, cached_at FROM threat_intel_cache ORDER BY cached_at DESC LIMIT 100"
    )
    if rows:
        import pandas as pd
        df = pd.DataFrame([dict(r) for r in rows])
        df["cached_at"] = pd.to_datetime(df["cached_at"], unit="s").dt.strftime("%Y-%m-%d %H:%M")
        df.columns = ["IP Address", "Source", "Cached At"]
        st.dataframe(df, use_container_width=True, hide_index=True)
        if st.button("Clear Cache", key="ti_clear"):
            db.execute("DELETE FROM threat_intel_cache")
            st.success("Cache cleared.")
            st.rerun()
    else:
        empty_state("No cached intel data yet. Run a lookup to populate the cache.", "🔎")
