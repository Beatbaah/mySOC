"""
alerts/telegram_alert.py — Telegram bot alert sender
"""

import requests
from typing import List

import config
from utils.logger import get_logger

log = get_logger(__name__)

_BASE = "https://api.telegram.org/bot"


def send_telegram(message: str, chat_ids: List[str] = None) -> bool:
    if not config.TELEGRAM_BOT_TOKEN:
        log.warning("Telegram bot token not configured — skipping")
        return False

    ids = [c.strip() for c in (chat_ids or config.TELEGRAM_CHAT_IDS) if c.strip()]
    if not ids:
        return False

    success = True
    url = f"{_BASE}{config.TELEGRAM_BOT_TOKEN}/sendMessage"

    for chat_id in ids:
        try:
            resp = requests.post(url, json={
                "chat_id":    chat_id,
                "text":       message,
                "parse_mode": "HTML",
            }, timeout=10)
            if not resp.ok:
                log.warning("Telegram API error for %s: %s", chat_id, resp.text[:200])
                success = False
        except Exception as e:
            log.error("Telegram send failed for %s: %s", chat_id, e)
            success = False

    return success


def format_telegram_alert(alert: dict) -> str:
    sev   = alert.get("severity", "?")
    atype = alert.get("alert_type", "?")
    src   = alert.get("src_ip", "N/A")
    dst   = alert.get("dst_ip", "N/A")
    desc  = alert.get("description", "")

    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
             "LOW": "🟢", "INFO": "🔵"}.get(sev, "⚪")

    return (
        f"{emoji} <b>MY SOC ALERT</b>\n"
        f"<b>Severity:</b> {sev}\n"
        f"<b>Type:</b> {atype}\n"
        f"<b>Src:</b> <code>{src}</code>\n"
        f"<b>Dst:</b> <code>{dst}</code>\n"
        f"<b>Detail:</b> {desc}"
    )
