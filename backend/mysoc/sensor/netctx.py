"""What counts as "our network"."""

from functools import lru_cache
from ipaddress import ip_address, ip_network


class NetContext:
    def __init__(self, internal: list[str], allowlist: list[str]):
        self._nets = [ip_network(n, strict=False) for n in internal]
        self._allow = set(allowlist)
        self.internal = lru_cache(maxsize=65536)(self._internal)

    def _internal(self, ip: str) -> bool:
        # Uses the configured ranges, not ipaddress.is_private: that also
        # counts documentation and other reserved ranges as private.
        try:
            addr = ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self._nets)

    def allowlisted(self, ip: str) -> bool:
        return ip in self._allow
