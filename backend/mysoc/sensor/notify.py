"""Email and Telegram notifications for new high and critical alerts.

Runs on its own thread so a slow mail server never stalls detection, and
is capped per hour so an attack can't turn into a notification flood.
Credentials come from the encrypted secrets table (set in the console).
"""

import logging
import queue
import smtplib
import threading
import time
from email.message import EmailMessage

import httpx

from ..config import Settings
from ..db import session_scope
from ..models import Secret
from ..security import vault

log = logging.getLogger("mysoc.notify")


def get_secret(key: str) -> str:
    with session_scope() as s:
        row = s.get(Secret, key)
        return vault.decrypt(row.value) if row else ""


class Notifier:
    MAX_PER_HOUR = 30

    def __init__(self, settings: Settings):
        self.settings = settings
        self.q: queue.Queue = queue.Queue(maxsize=1000)
        self.sent: list[float] = []
        self.suppressed = 0
        threading.Thread(target=self._run, name="notifier", daemon=True).start()

    @property
    def configured(self) -> bool:
        s = self.settings
        return bool((s.smtp_host and s.alert_email_to) or s.telegram_chat_ids)

    def enqueue(self, alert_id: int, severity: str, title: str, description: str, src: str, dst: str) -> None:
        if not self.configured:
            return
        try:
            self.q.put_nowait((alert_id, severity, title, description, src, dst))
        except queue.Full:
            self.suppressed += 1

    def _run(self) -> None:
        while True:
            item = self.q.get()
            now = time.time()
            self.sent = [t for t in self.sent if now - t < 3600]
            if len(self.sent) >= self.MAX_PER_HOUR:
                self.suppressed += 1
                continue
            self.sent.append(now)
            try:
                self._send(*item)
            except Exception as e:
                log.warning("Notification for alert %s failed: %s", item[0], e)

    def _send(self, alert_id, severity, title, description, src, dst) -> None:
        s = self.settings
        subject = f"[mySOC {severity.upper()}] {title}"
        body = f"{description}\n\nSource: {src or '-'}\nTarget: {dst or '-'}\nAlert #{alert_id}: {s.public_origin}/alerts/{alert_id}\n"
        if s.smtp_host and s.alert_email_to:
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = subject, s.smtp_from or s.smtp_user, ", ".join(s.alert_email_to)
            msg.set_content(body)
            with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as smtp:
                smtp.starttls()
                if s.smtp_user:
                    smtp.login(s.smtp_user, get_secret("smtp_password"))
                smtp.send_message(msg)
        token = get_secret("telegram_bot_token") if s.telegram_chat_ids else ""
        for chat in s.telegram_chat_ids if token else []:
            httpx.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat, "text": f"{subject}\n\n{body}"},
                timeout=10,
            ).raise_for_status()
