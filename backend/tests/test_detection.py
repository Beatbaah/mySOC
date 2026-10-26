from datetime import UTC, datetime, timedelta

from mysoc.sensor.alerts import AlertWriter, risk_score
from mysoc.sensor.detection.catalog import BUILTIN_RULES, MATCH_RULES
from mysoc.sensor.detection.detectors import DetectionEngine, RuleConfig, parse_failed_login
from mysoc.sensor.flows import FlowAggregator, FlowRecord
from mysoc.sensor.netctx import NetContext
from mysoc.sensor.sources.demo import DemoTraffic

T0 = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
NET = NetContext(["10.0.0.0/8"], ["10.0.0.1"])


def engine() -> DetectionEngine:
    e = DetectionEngine(NET)
    e.set_rules([RuleConfig(r["id"], r["name"], kind, True, r["severity"], dict(r["params"]))
                 for kind, rules in (("builtin", BUILTIN_RULES), ("match", MATCH_RULES)) for r in rules])
    return e


def flow(src, dst, dport, t=0.0, proto="TCP", packets=10, nbytes=1000, flags="SAF", sport=50000):
    at = T0 + timedelta(seconds=t)
    return FlowRecord(at, at + timedelta(seconds=1), src, sport, dst, dport, proto, packets, nbytes, flags)


def rules_fired(e, flows):
    return [f.rule_id for fl in flows for f in e.process_flow(fl)]


def test_port_scan_from_inside_is_high_from_outside_medium():
    e = engine()
    ext = [e.process_flow(flow("203.0.113.5", "10.0.0.10", p, t=p * 0.1, flags="S")) for p in range(1, 25)]
    found = [f for batch in ext for f in batch if f.rule_id == "NET-001"]
    assert len(found) == 1 and found[0].severity is None  # rule default (medium)
    e = engine()
    found = [f for p in range(1, 25) for f in e.process_flow(flow("10.0.0.50", "10.0.0.10", p, t=p * 0.1)) if f.rule_id == "NET-001"]
    assert found[0].severity == "high"


def test_scan_fires_once_per_window_not_per_packet():
    e = engine()
    fired = rules_fired(e, [flow("203.0.113.5", "10.0.0.10", p, t=p * 0.05, flags="S") for p in range(1, 200)])
    assert fired.count("NET-001") <= 2


def test_brute_force_and_remote_access():
    e = engine()
    fired = rules_fired(e, [flow("203.0.113.9", "10.0.0.20", 3389, t=i, sport=40000 + i) for i in range(20)])
    assert "NET-004" in fired and "NET-008" in fired


def test_remote_access_needs_a_completed_handshake():
    e = engine()
    assert "NET-008" not in rules_fired(e, [flow("203.0.113.9", "10.0.0.20", 3389, flags="S")])


def test_beaconing_regular_but_not_random():
    e = engine()
    regular = [flow("10.0.0.45", "198.51.100.77", 443, t=i * 45 + (i % 3)) for i in range(10)]
    assert "NET-009" in rules_fired(e, regular)
    import random

    rng = random.Random(1)
    e = engine()
    t, irregular = 0.0, []
    for _ in range(12):
        t += rng.uniform(5, 200)
        irregular.append(flow("10.0.0.46", "198.51.100.78", 443, t=t))
    assert "NET-009" not in rules_fired(e, irregular)


def test_exfil_threshold():
    e = engine()
    fired = rules_fired(e, [flow("10.0.0.45", "198.51.100.77", 443, t=i * 10, nbytes=2_000_000) for i in range(12)])
    assert "NET-006" in fired


def test_lateral_movement():
    e = engine()
    fired = rules_fired(e, [flow("10.0.0.45", f"10.0.1.{i}", 445, t=i * 5) for i in range(1, 7)])
    assert "NET-011" in fired


def test_syn_flood_from_many_sources():
    e = engine()
    flows = [flow(f"203.0.113.{i}", "10.0.0.10", 443, t=i * 0.05, packets=60, flags="S") for i in range(1, 60)]
    found = [f for fl in flows for f in e.process_flow(fl) if f.rule_id == "NET-002"]
    assert len(found) == 1 and found[0].evidence["sources"] > 1


def test_indicator_match():
    e = engine()
    e.set_indicators({"198.51.100.77": "C2"})
    assert "NET-010" in rules_fired(e, [flow("10.0.0.45", "198.51.100.77", 443)])


def test_allowlisted_source_is_ignored():
    e = engine()
    assert rules_fired(e, [flow("10.0.0.1", "203.0.113.5", 4444)]) == []


def test_match_rule_conditions():
    e = engine()
    assert "CUS-001" in rules_fired(e, [flow("10.0.0.5", "10.0.2.40", 23)])
    assert "CUS-001" not in rules_fired(e, [flow("10.0.0.5", "10.0.2.40", 23, flags="S")])


def test_disabled_rule_is_silent():
    e = engine()
    e.rules["NET-007"].enabled = False
    assert "NET-007" not in rules_fired(e, [flow("10.0.0.5", "203.0.113.5", 4444)])


def test_failed_login_parsing():
    assert parse_failed_login("Failed password for invalid user oracle from 198.51.100.4 port 51234 ssh2") == ("198.51.100.4", "oracle")
    assert parse_failed_login("Failed password for root from 2001:db8::1 port 22 ssh2") == ("2001:db8::1", "root")
    assert parse_failed_login("Accepted publickey for deploy from 10.0.0.3") is None


def test_log_brute_force():
    e = engine()
    found = []
    for i in range(10):
        found += e.process_log(T0 + timedelta(seconds=i), "10.0.0.30", "jump", f"Failed password for root from 198.51.100.4 port {i} ssh2")
    assert [f.rule_id for f in found] == ["LOG-001"]


def test_flow_aggregation():
    agg = FlowAggregator(active=10, idle=2)
    for i in range(5):
        agg.add(T0 + timedelta(seconds=i * 0.1), "10.0.0.5", 5000, "203.0.113.5", 443, "TCP", 100, "S" if i == 0 else "A")
    assert agg.expire(T0 + timedelta(seconds=1)) == []
    [f] = agg.expire(T0 + timedelta(seconds=5))
    assert f.packets == 5 and f.bytes == 500 and f.tcp_flags == "SA"


def test_risk_score_bounds():
    assert 0 <= risk_score("info", 1, "low", False) < risk_score("critical", 1000, "critical", True) <= 100


def test_dedup_folds_repeats(app):
    from mysoc import db
    from mysoc.models import Alert

    e = engine()
    writer = AlertWriter(dedup_minutes=15)
    meta = {"NET-007": {"tactic": "Command and Control", "technique": "T1571"}}
    for i in range(5):
        findings = e.process_flow(flow("10.0.0.5", "203.0.113.5", 4444, t=i * 60))
        with db.session_scope() as s:
            writer.write(s, findings, e.rules, meta)
    with db.session_scope() as s:
        alerts = s.query(Alert).filter_by(rule_id="NET-007").all()
        assert len(alerts) == 1 and alerts[0].count == 5 and alerts[0].mitre_technique == "T1571"


def test_demo_story_trips_every_story_rule():
    e = engine()
    e.set_indicators({"198.51.100.77": "C2", "203.0.113.66": "brute"})
    gen = DemoTraffic(T0, seed=5, story_offset=timedelta(seconds=10))
    fired = set()
    for ev in gen.until(T0 + timedelta(minutes=35)):
        if isinstance(ev, FlowRecord):
            fired |= {f.rule_id for f in e.process_flow(ev)}
        else:
            fired |= {f.rule_id for f in e.process_log(ev.at, ev.source_ip, ev.host, ev.message)}
    expected = {"NET-001", "NET-004", "NET-005", "NET-006", "NET-007", "NET-008", "NET-009", "NET-010", "NET-011", "LOG-001"}
    assert expected <= fired, expected - fired


def test_demo_background_is_quiet():
    """An hour of normal office traffic, no story: no network alerts."""
    e = engine()
    gen = DemoTraffic(T0, seed=9, story_offset=timedelta(days=1))
    fired = [f.rule_id for ev in gen.until(T0 + timedelta(hours=1)) if isinstance(ev, FlowRecord) for f in e.process_flow(ev)]
    assert fired == []
