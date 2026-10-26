"""Flow records, and turning captured packets into them."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass(slots=True)
class FlowRecord:
    start: datetime
    end: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packets: int
    bytes: int
    tcp_flags: str = ""
    src_country: str = ""
    dst_country: str = ""


_FLAG_ORDER = "SAFRPU"


def _merge_flags(a: str, b: str) -> str:
    return "".join(c for c in _FLAG_ORDER if c in a or c in b)


class FlowAggregator:
    """Groups packets by 5-tuple. A flow is emitted when it has been idle
    for `idle` seconds or active for `active` seconds, the same scheme
    NetFlow/IPFIX exporters use."""

    def __init__(self, active: float = 10.0, idle: float = 2.0, max_flows: int = 200_000):
        self.active = timedelta(seconds=active)
        self.idle = timedelta(seconds=idle)
        self.max_flows = max_flows
        self._open: dict[tuple, FlowRecord] = {}

    def add(self, at: datetime, src: str, sport: int, dst: str, dport: int, proto: str, length: int, flags: str = "") -> None:
        key = (src, sport, dst, dport, proto)
        f = self._open.get(key)
        if f is None:
            if len(self._open) >= self.max_flows:
                return  # back-pressure: drop rather than exhaust memory
            self._open[key] = FlowRecord(at, at, src, sport, dst, dport, proto, 1, length, flags)
            return
        f.end = at
        f.packets += 1
        f.bytes += length
        if flags:
            f.tcp_flags = _merge_flags(f.tcp_flags, flags)

    def expire(self, now: datetime | None = None, everything: bool = False) -> list[FlowRecord]:
        now = now or datetime.now(UTC)
        done = [
            k for k, f in self._open.items()
            if everything or now - f.end >= self.idle or now - f.start >= self.active
        ]
        return [self._open.pop(k) for k in done]

    def __len__(self) -> int:
        return len(self._open)
