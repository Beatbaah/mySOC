"""
alerts/alert_manager.py — Central alert dispatcher
"""

import threading
import queue
from typing import Callable

import config
from alerts.email_alert import send_email_alert, format_alert_email
from alerts.telegram_alert import send_telegram, format_telegram_alert
from utils.logger import get_logger

log = get_logger(__name__)


class AlertManager:
    """
    Receives alert dicts, evaluates severity thresholds,
    dispatches notifications asynchronously.
    """

    def __init__(self):
        self._queue: queue.Queue = queue.Queue()
        self._callbacks: list[Callable] = []
        self._worker = threading.Thread(
            target=self._dispatch_loop, daemon=True, name="AlertManager"
        )
        self._worker.start()

    def add_callback(self, fn: Callable[[dict], None]) -> None:
        self._callbacks.append(fn)

    def dispatch(self, alert: dict) -> None:
        self._queue.put(alert)

    def _dispatch_loop(self) -> None:
        while True:
            try:
                alert = self._queue.get(timeout=1)
            except queue.Empty:
                continue

            # Fire UI callbacks
            for cb in self._callbacks:
                try:
                    cb(alert)
                except Exception as e:
                    log.debug("Alert UI callback error: %s", e)

            sev = alert.get("severity", "INFO")
            sev_cfg = config.SEVERITY_LEVELS.get(sev, {})

            if sev_cfg.get("auto_alert", False):
                self._send_notifications(alert)

    def _send_notifications(self, alert: dict) -> None:
        # Email
        try:
            subject, html = format_alert_email(alert)
            send_email_alert(subject, html)
        except Exception as e:
            log.error("Email dispatch error: %s", e)

        # Telegram
        try:
            msg = format_telegram_alert(alert)
            send_telegram(msg)
        except Exception as e:
            log.error("Telegram dispatch error: %s", e)
