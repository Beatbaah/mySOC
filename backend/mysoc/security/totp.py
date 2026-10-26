"""Authenticator-app codes (TOTP, RFC 6238)."""

import base64
import io
import time

import pyotp
import qrcode
import qrcode.image.svg

ISSUER = "mySOC"


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(username: str, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)


def qr_svg_data_uri(uri: str) -> str:
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


def verify(secret: str, code: str, last_step: int) -> int | None:
    """The time step of a valid code, or None. Allows one step of clock
    drift either way, and rejects any step at or before `last_step` so a
    code can't be used twice."""
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // totp.interval
    for step in (now_step - 1, now_step, now_step + 1):
        if step > last_step and totp.verify(code, for_time=step * totp.interval):
            return step
    return None
