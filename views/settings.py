"""views/settings.py — Admin: users, 2FA, vault, engine, alerts, database"""
import sys as _sys
from pathlib import Path as _Path
_r = str(_Path(__file__).resolve().parent.parent)
if _r not in _sys.path: _sys.path.insert(0, _r)

import streamlit as st
import pandas as pd
from datetime import datetime, timezone
import os
from db import database as db
from auth import authenticator as auth
import config
from utils.ui import (
    section_title, kpi_card, empty_state, info_row, SEV_COLORS,
    TEAL, BORDER, BG_SURFACE, BG_RAISED, TEXT_MUTED,
    TEXT_PRI, TEXT_SEC, EMERALD, CORAL, AMBER, page_header,
)

ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>'


def render():
    user = st.session_state.get("user", {})
    if not auth.has_permission(user, "admin"):
        st.warning("Administrator access required.")
        return
    page_header("Settings", "User management, 2FA, key vault, engine control and database", ICON)
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
        ["Users", "2FA / TOTP", "Key Vault", "Engine", "Alerts", "Database"]
    )
    with tab1: _users(user)
    with tab2: _totp(user)
    with tab3: _vault(user)
    with tab4: _engine()
    with tab5: _alert_cfg()
    with tab6: _db_tools(user)


# ── Users ──────────────────────────────────────────────────────────────────────
def _users(current_user):
    section_title("User Accounts")
    users = auth.list_users()
    if users:
        df = pd.DataFrame([dict(u) for u in users])
        df = df[["username","role","failed_attempts","last_login","created_at"]]
        df.columns = ["Username","Role","Failed Attempts","Last Login","Created"]
        st.dataframe(df, use_container_width=True, hide_index=True)

    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    section_title("Create User")
    with st.form("create_user"):
        c1, c2, c3 = st.columns(3)
        with c1: uname = st.text_input("Username", key="su_u")
        with c2: upass = st.text_input("Password", type="password", key="su_p")
        with c3: urole = st.selectbox("Role", ["viewer","analyst","admin"], key="su_r")
        if st.form_submit_button("Create User", type="primary"):
            if uname.strip() and upass.strip():
                ok = auth.create_user(uname.strip(), upass.strip(), urole)
                if ok: st.success(f"User '{uname}' created as {urole}."); st.rerun()
                else: st.error("Failed (username may exist).")

    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    c_pw, c_ul, c_del = st.columns(3)
    with c_pw:
        section_title("Change Password")
        with st.form("chpw"):
            cp_u = st.text_input("Username", key="cp_u")
            cp_p = st.text_input("New Password", type="password", key="cp_p")
            if st.form_submit_button("Change"):
                if cp_u.strip() and cp_p.strip():
                    auth.change_password(cp_u.strip(), cp_p.strip())
                    st.success(f"Password updated for '{cp_u}'.")
    with c_ul:
        section_title("Unlock Account")
        with st.form("unlock"):
            ul_u = st.text_input("Username to unlock", key="ul_u")
            if st.form_submit_button("Unlock"):
                if ul_u.strip():
                    auth.unlock_user(ul_u.strip()); st.success(f"'{ul_u}' unlocked.")
    with c_del:
        section_title("Delete User")
        with st.form("del_user"):
            del_u = st.text_input("Username to delete", key="del_u")
            ok_cb = st.checkbox("Confirm deletion", key="del_cb")
            if st.form_submit_button("Delete", type="primary"):
                if not del_u.strip(): st.error("Enter a username.")
                elif del_u.strip() == current_user.get("username"): st.error("Cannot delete yourself.")
                elif not ok_cb: st.error("Check the confirmation box.")
                else:
                    auth.delete_user(del_u.strip())
                    st.success(f"User '{del_u}' deleted."); st.rerun()


# ── TOTP ───────────────────────────────────────────────────────────────────────
def _totp(current_user):
    from auth.totp import enroll_user, confirm_enrollment, is_enrolled, revoke, generate_qr_b64

    section_title("Two-Factor Authentication", "TOTP via Google Authenticator, Authy, etc.")
    users = auth.list_users()
    col_l, col_r = st.columns(2)
    with col_l:
        section_title("Enroll a User")
        target = st.selectbox("Select user", [u["username"] for u in users], key="totp_tgt")
        enrolled = is_enrolled(target)
        if enrolled:
            st.markdown(f'<div style="color:{EMERALD};font-size:0.83rem;padding:8px 0">✓ {target} has 2FA enabled</div>', unsafe_allow_html=True)
            if st.button(f"Revoke 2FA for {target}", key="totp_rev"):
                revoke(target)
                db.audit(current_user.get("username"), "totp_revoked", f"target={target}")
                st.success(f"2FA revoked for {target}."); st.rerun()
        else:
            st.markdown(f'<div style="color:{AMBER};font-size:0.83rem;padding:8px 0">✗ {target} does not have 2FA</div>', unsafe_allow_html=True)
            if st.button(f"Start 2FA Enrollment for {target}", key="totp_start", type="primary"):
                secret, uri = enroll_user(target)
                st.session_state.update({"totp_pend_user": target, "totp_pend_secret": secret, "totp_pend_uri": uri})
                st.rerun()

    with col_r:
        section_title("2FA Status")
        rows = [{"Username": u["username"], "Role": u["role"],
                 "2FA": "✓ Enabled" if is_enrolled(u["username"]) else "✗ Disabled"}
                for u in users]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    pend_user = st.session_state.get("totp_pend_user")
    pend_sec  = st.session_state.get("totp_pend_secret")
    if pend_user and pend_sec:
        st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
        section_title(f"Scan QR Code — Enrolling `{pend_user}`")
        qr_b64 = generate_qr_b64(pend_user, pend_sec)
        c1, c2 = st.columns(2)
        with c1:
            if qr_b64:
                st.markdown(f'<img src="data:image/png;base64,{qr_b64}" style="width:200px;border:3px solid {BORDER};border-radius:8px">', unsafe_allow_html=True)
            else:
                st.info("Install `qrcode` and `Pillow` for QR display.")
        with c2:
            st.markdown("**Manual entry:**")
            st.code(pend_sec)
        with st.form("totp_confirm"):
            token = st.text_input("6-digit code", max_chars=6, key="totp_tok")
            if st.form_submit_button("Confirm & Activate 2FA", type="primary"):
                if confirm_enrollment(pend_user, token):
                    db.audit(current_user.get("username"), "totp_enrolled", f"target={pend_user}")
                    st.success(f"2FA activated for {pend_user}!")
                    for k in ["totp_pend_user", "totp_pend_secret", "totp_pend_uri"]:
                        st.session_state.pop(k, None)
                    st.rerun()
                else:
                    st.error("Invalid code. Please try again.")
        if st.button("Cancel", key="totp_cancel"):
            for k in ["totp_pend_user", "totp_pend_secret", "totp_pend_uri"]:
                st.session_state.pop(k, None)
            db.execute("DELETE FROM totp_secrets WHERE username=? AND confirmed=0", (pend_user,))
            st.rerun()


# ── Vault ──────────────────────────────────────────────────────────────────────
def _vault(current_user):
    from auth.vault import set_secret, list_keys, delete_secret, is_encrypted
    section_title("Encrypted Key Vault")
    enc = is_encrypted()
    if enc:
        st.markdown(f'<div style="color:{EMERALD};font-size:0.82rem;padding:6px 0">🔒 Vault is encrypted — VAULT_MASTER_KEY is set</div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div style="color:{AMBER};font-size:0.82rem;padding:6px 0">⚠ Vault in plaintext mode — set VAULT_MASTER_KEY to enable encryption</div>', unsafe_allow_html=True)

    with st.form("vault_form"):
        c1, c2 = st.columns(2)
        with c1:
            abuse = st.text_input("AbuseIPDB API Key",  type="password", key="v_abuse", placeholder="leave blank to keep")
            av    = st.text_input("AlienVault OTX Key", type="password", key="v_av",    placeholder="leave blank to keep")
            vt    = st.text_input("VirusTotal API Key", type="password", key="v_vt",    placeholder="leave blank to keep")
        with c2:
            smtp  = st.text_input("SMTP Password",      type="password", key="v_smtp",  placeholder="leave blank to keep")
            tg    = st.text_input("Telegram Bot Token", type="password", key="v_tg",    placeholder="leave blank to keep")
        if st.form_submit_button("Save to Vault", type="primary"):
            saved = []
            for key, val in [("abuseipdb_api_key",abuse),("alienvault_api_key",av),
                             ("virustotal_api_key",vt),("smtp_password",smtp),("telegram_bot_token",tg)]:
                if val.strip():
                    set_secret(key, val.strip()); saved.append(key)
            if saved:
                db.audit(current_user.get("username"), "vault_updated", f"keys={','.join(saved)}")
                st.success(f"Saved {len(saved)} secret(s).")
            else:
                st.info("No changes.")

    keys = list_keys()
    if keys:
        st.markdown(f"<div style='height:12px'></div>", unsafe_allow_html=True)
        section_title("Stored Keys")
        df = pd.DataFrame(keys)
        df.columns = ["Key", "Last Updated"]
        st.dataframe(df, use_container_width=True, hide_index=True)
        del_k = st.text_input("Delete key by name", key="vault_del")
        if st.button("Delete from Vault", key="vault_del_btn"):
            if del_k.strip():
                delete_secret(del_k.strip())
                db.audit(current_user.get("username"), "vault_key_deleted", f"key={del_k}")
                st.success(f"Key '{del_k}' deleted."); st.rerun()


# ── Engine ─────────────────────────────────────────────────────────────────────
def _engine():
    section_title("Detection Engine Control")
    col1, col2 = st.columns(2)

    with col1:
        section_title("Packet Sniffer")
        running = st.session_state.get("sniffer_running", False)
        stats   = st.session_state.get("sniffer_stats", {})
        if running:
            st.markdown(f'<div style="color:{EMERALD};font-size:0.83rem;margin-bottom:8px">● Running</div>', unsafe_allow_html=True)
            if stats:
                c1,c2,c3 = st.columns(3)
                c1.metric("Packets", f"{stats.get('packets',0):,}")
                c2.metric("PPS", stats.get("pps",0))
                c3.metric("KB", f"{stats.get('bytes',0)//1024:,}")
            if st.button("Stop Sniffer", key="stop_sn"):
                obj = st.session_state.get("sniffer_obj")
                if obj: obj.stop()
                st.session_state.sniffer_running = False; st.rerun()
        else:
            st.markdown(f'<div style="color:{TEXT_MUTED};font-size:0.83rem;margin-bottom:8px">○ Stopped</div>', unsafe_allow_html=True)
            iface = st.text_input("Interface (blank = auto)", key="sn_iface")
            demo  = st.checkbox("Demo mode (no root required)", True, key="sn_demo")
            if st.button("Start Sniffer", key="start_sn", type="primary"):
                _start_sniffer(iface.strip() or None, demo); st.rerun()

    with col2:
        section_title("Syslog Listener")
        sy_run = st.session_state.get("syslog_running", False)
        sy_stats = st.session_state.get("syslog_stats", {})
        if sy_run:
            st.markdown(f'<div style="color:{EMERALD};font-size:0.83rem;margin-bottom:8px">● Listening on :{config.SYSLOG_PORT}</div>', unsafe_allow_html=True)
            if sy_stats:
                c1, c2 = st.columns(2)
                c1.metric("Received", sy_stats.get("received", 0))
                c2.metric("Errors",   sy_stats.get("errors", 0))
            if st.button("Stop Syslog", key="stop_sy"):
                obj = st.session_state.get("syslog_obj")
                if obj: obj.stop()
                st.session_state.syslog_running = False; st.rerun()
        else:
            st.markdown(f'<div style="color:{TEXT_MUTED};font-size:0.83rem;margin-bottom:8px">○ Stopped</div>', unsafe_allow_html=True)
            if st.button("Start Syslog Listener", key="start_sy", type="primary"):
                _start_syslog(); st.rerun()

    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    section_title("ML Anomaly Engine")
    ml_stats = st.session_state.get("ml_stats", {})
    if ml_stats:
        c1,c2,c3 = st.columns(3)
        c1.metric("Status",    "Trained" if ml_stats.get("trained") else "Training…")
        c2.metric("Packets",   f"{ml_stats.get('total_packets',0):,}")
        c3.metric("Anomalies", ml_stats.get("anomalies",0))
    if st.button("Force Retrain", key="ml_rt"):
        ml = st.session_state.get("ml_obj")
        if ml:
            ok = ml.force_retrain()
            st.success("Retrained." if ok else "Insufficient data.")
        else:
            st.warning("ML engine not active.")

    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    section_title("Detection Thresholds")
    tdf = pd.DataFrame(list(config.DETECTION_THRESHOLDS.items()), columns=["Threshold","Value"])
    st.dataframe(tdf, use_container_width=True, hide_index=True)


# ── Alerts config ──────────────────────────────────────────────────────────────
def _alert_cfg():
    section_title("Email Alerts (SMTP)")
    c1, c2 = st.columns(2)
    with c1:
        info_row("Host",      config.SMTP_HOST or "Not configured")
        info_row("Port",      str(config.SMTP_PORT))
        info_row("From",      config.SMTP_FROM or "Not configured")
    with c2:
        info_row("Username",  config.SMTP_USER or "Not set")
        info_row("Password",  "✓ Set" if config.SMTP_PASSWORD else "✗ Not set")
        info_row("Recipients", ", ".join(r for r in config.ALERT_EMAIL_TO if r) or "None")

    if st.button("Send Test Email", key="test_em"):
        from alerts.email_alert import send_email_alert
        ok = send_email_alert("Test Alert", "<h2>Email alerts are working.</h2>")
        st.success("Sent!") if ok else st.error("Failed — check SMTP config in .env")

    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    section_title("Telegram Alerts")
    c3, c4 = st.columns(2)
    with c3: info_row("Bot Token", "✓ Set" if config.TELEGRAM_BOT_TOKEN else "✗ Not set")
    with c4: info_row("Chat IDs",  ", ".join(c for c in config.TELEGRAM_CHAT_IDS if c) or "None")
    if st.button("Send Test Telegram", key="test_tg"):
        from alerts.telegram_alert import send_telegram
        ok = send_telegram("✅ <b>MySOC</b> — Telegram alerts are working!")
        st.success("Sent!") if ok else st.error("Failed — check TELEGRAM_BOT_TOKEN in .env")

    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    section_title("Auto-Alert Rules")
    rows = [{"Severity": k, "Auto Alert": "✓" if v["auto_alert"] else "—",
             "Priority": v["priority"], "Color": v["color"]}
            for k, v in config.SEVERITY_LEVELS.items()]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    st.caption("CRITICAL and HIGH trigger email + Telegram automatically.")


# ── Database tools ─────────────────────────────────────────────────────────────
def _db_tools(current_user):
    section_title("Database Overview")
    tables = ["users","alerts","traffic","incidents","syslog_events","threat_intel_cache","audit_log"]
    rows_data = []
    for t in tables:
        try:
            row = db.fetchone(f"SELECT COUNT(*) as c FROM {t}")
            rows_data.append({"Table": t, "Rows": row["c"] if row else 0})
        except:
            rows_data.append({"Table": t, "Rows": "error"})
    st.dataframe(pd.DataFrame(rows_data), use_container_width=True, hide_index=True)

    try:
        size = os.path.getsize(config.DB_PATH)
        st.metric("Database size", f"{size/1024:.1f} KB")
    except:
        pass

    st.markdown(f"<hr style='border-color:{BORDER};margin:20px 0'>", unsafe_allow_html=True)
    section_title("Data Retention")
    st.warning("These operations are irreversible.")
    c1, c2, c3 = st.columns(3)
    with c1:
        days = st.number_input("Purge traffic older than N days", 1, value=30, key="purge_d")
        if st.button("Purge Old Traffic", key="purge_t"):
            db.execute("DELETE FROM traffic WHERE timestamp < datetime('now', ?)", (f"-{days} days",))
            db.audit(current_user.get("username"), "purge_traffic", f">{days}d")
            st.success(f"Traffic older than {days} days purged.")
    with c2:
        days2 = st.number_input("Purge acked alerts older than N days", 1, value=90, key="purge_a_d")
        if st.button("Purge Old Alerts", key="purge_a"):
            db.execute("DELETE FROM alerts WHERE timestamp < datetime('now', ?) AND acknowledged=1", (f"-{days2} days",))
            db.audit(current_user.get("username"), "purge_alerts", f">{days2}d")
            st.success(f"Acknowledged alerts older than {days2} days purged.")
    with c3:
        st.markdown("<div style='height:26px'></div>", unsafe_allow_html=True)
        if st.button("VACUUM Database", key="vacuum"):
            db.execute("VACUUM"); st.success("Database vacuumed.")


# ── Engine start helpers ────────────────────────────────────────────────────────
def _start_sniffer(iface, demo_mode):
    from engine.sniffer import PacketSniffer, DemoSniffer
    from engine.detection import DetectionEngine
    from engine.ml_anomaly import MLAnomalyDetector
    from alerts.alert_manager import AlertManager
    from utils.helpers import geolocate

    det = DetectionEngine()
    ml  = MLAnomalyDetector()
    am  = AlertManager()
    det.add_alert_callback(lambda r: am.dispatch({
        "severity": r.severity, "alert_type": r.rule_name,
        "src_ip": r.src_ip, "dst_ip": r.dst_ip, "src_port": r.src_port,
        "dst_port": r.dst_port, "protocol": r.protocol,
        "description": r.description, "raw_data": r.raw_data,
        "threat_score": r.threat_score,
    }))

    def on_pkt(pkt):
        det.process(pkt); ml.process(pkt)
        try:
            from rules.custom_rules import evaluate as ev; ev(pkt)
        except: pass
        geo = geolocate(pkt.src_ip)
        try:
            db.insert_traffic({"src_ip": pkt.src_ip, "dst_ip": pkt.dst_ip,
                               "src_port": pkt.src_port, "dst_port": pkt.dst_port,
                               "protocol": pkt.protocol, "length": pkt.length,
                               "flags": pkt.flags, "ttl": pkt.ttl,
                               "country": geo.get("country","")})
        except: pass

    sn = DemoSniffer() if demo_mode else PacketSniffer()
    sn.add_callback(on_pkt)
    sn.start(iface)
    st.session_state.update({"sniffer_obj": sn, "detection_obj": det,
                              "ml_obj": ml, "alert_mgr_obj": am,
                              "sniffer_running": True})


def _start_syslog():
    from engine.syslog_listener import SyslogListener
    sl = SyslogListener()
    if sl.start():
        st.session_state.update({"syslog_obj": sl, "syslog_running": True})
        st.success(f"Syslog listener started on UDP :{config.SYSLOG_PORT}")
    else:
        st.error(f"Failed to bind UDP port {config.SYSLOG_PORT}.")
