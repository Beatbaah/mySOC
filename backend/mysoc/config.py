"""Settings, read once from the environment (and an optional .env file).

Every setting has a safe default for local development except the ones
that protect data: in production (MYSOC_ENV=production) the app refuses to
start without a vault key and a public origin, rather than running with
weak or missing secrets.
"""

from functools import lru_cache
from ipaddress import ip_network

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MYSOC_", env_file=".env", extra="ignore")

    env: str = "development"  # development | production
    database_url: str = "sqlite:///./mysoc.db"

    # Browser origin of the analyst console, for CORS and cookie scope.
    public_origin: str = "http://localhost:5173"

    # Sessions
    session_idle_minutes: int = 30
    session_max_hours: int = 12
    # Admins must use an authenticator app; set false only for local demos.
    require_mfa_for_admin: bool = True

    # Login throttling (per client IP and per account)
    login_max_attempts: int = 5
    login_window_seconds: int = 300
    account_lockout_minutes: int = 15

    # Encryption key for stored secrets (API keys, SMTP password). Required
    # in production. Generate with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    vault_key: str = ""

    # First run only: creates this admin if no users exist. Leave empty to
    # create the admin with `python -m mysoc.cli create-admin` instead.
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str = ""

    # Sensor
    sensor_source: str = "demo"  # demo | capture
    capture_interface: str | None = None
    syslog_enabled: bool = False
    syslog_port: int = 5514  # unprivileged; map 514 -> 5514 in Docker
    flow_window_seconds: int = 10
    internal_networks: list[str] = Field(default_factory=lambda: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
    allowlist_ips: list[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])
    # Identical alerts (same rule, source and target) within this window are
    # grouped into one alert with a count, not repeated.
    alert_dedup_minutes: int = 15

    # Retention
    flow_retention_days: int = 7
    log_retention_days: int = 30
    alert_retention_days: int = 180

    # Optional GeoLite2 City database for geolocation.
    geoip_db_path: str = ""

    # Notifications for HIGH and CRITICAL alerts
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_from: str = ""
    alert_email_to: list[str] = Field(default_factory=list)
    telegram_chat_ids: list[str] = Field(default_factory=list)

    @field_validator("internal_networks")
    @classmethod
    def _valid_networks(cls, v: list[str]) -> list[str]:
        for n in v:
            ip_network(n, strict=False)
        return v

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def cookie_secure(self) -> bool:
        return self.public_origin.startswith("https://")

    def check_production(self) -> None:
        if not self.is_production:
            return
        problems = []
        if not self.vault_key:
            problems.append("MYSOC_VAULT_KEY is required in production")
        if not self.public_origin.startswith("https://"):
            problems.append("MYSOC_PUBLIC_ORIGIN must be https:// in production")
        if not self.require_mfa_for_admin:
            problems.append("MYSOC_REQUIRE_MFA_FOR_ADMIN cannot be disabled in production")
        if problems:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.check_production()
    return s
