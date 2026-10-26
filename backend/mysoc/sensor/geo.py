"""Country lookup for external addresses, from an optional MaxMind
GeoLite2 database. Without one, countries are left blank (no network
calls: the sensor must not leak which addresses it sees)."""

import logging
from functools import lru_cache

log = logging.getLogger("mysoc.sensor")


class Geo:
    def __init__(self, db_path: str = "", fallback=None):
        self._reader = None
        self._fallback = fallback
        if db_path:
            try:
                import maxminddb

                self._reader = maxminddb.open_database(db_path)
                log.info("GeoIP database loaded from %s", db_path)
            except Exception as e:  # missing file or library: run without geo
                log.warning("GeoIP database not loaded (%s); countries will be blank", e)
        self.country = lru_cache(maxsize=100_000)(self._country)

    def _country(self, ip: str) -> str:
        if self._reader is not None:
            try:
                rec = self._reader.get(ip) or {}
                return (rec.get("country") or {}).get("iso_code", "") or ""
            except ValueError:
                return ""
        return self._fallback(ip) if self._fallback else ""
