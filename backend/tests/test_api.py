from datetime import timedelta

from mysoc import db
from mysoc.models import Alert, Flow


def seed_alert(**kw) -> int:
    now = db.utcnow()
    defaults = dict(rule_id="NET-007", title="Port 4444 traffic", severity="medium", risk_score=45, src_ip="10.20.0.45",
                    dst_ip="198.51.100.77", dst_port=4444, protocol="TCP", dedup_key=f"k{now.timestamp()}{kw}",
                    first_seen=now - timedelta(minutes=5), last_seen=now, count=1, status="new", evidence={})
    with db.session_scope() as s:
        a = Alert(**{**defaults, **kw})
        s.add(a)
        s.flush()
        return a.id


def test_alert_queue_filters(analyst):
    seed_alert(severity="critical", title="Exfil")
    seed_alert(severity="low", title="Odd flow", status="closed", disposition="benign")
    r = analyst.get("/api/alerts", params={"status": ["new", "in_progress"]}).json()
    assert r["total"] == 1 and r["items"][0]["title"] == "Exfil"
    assert analyst.get("/api/alerts", params={"severity": "low"}).json()["total"] == 1
    assert analyst.get("/api/alerts", params={"q": "exf"}).json()["total"] == 1


def test_closing_needs_a_disposition(analyst):
    aid = seed_alert()
    assert analyst.patch(f"/api/alerts/{aid}", json={"status": "closed"}).status_code == 400
    r = analyst.patch(f"/api/alerts/{aid}", json={"status": "closed", "disposition": "true_positive"})
    assert r.status_code == 200 and r.json()["closedBy"] == "ana"


def test_taking_an_alert_assigns_it(analyst):
    aid = seed_alert()
    r = analyst.patch(f"/api/alerts/{aid}", json={"status": "in_progress"}).json()
    assert r["assignee"]["username"] == "ana"


def test_case_from_alerts_raises_severity_and_records_timeline(analyst):
    a1 = seed_alert(severity="critical")
    a2 = seed_alert(severity="medium")
    r = analyst.post("/api/cases", json={"title": "Workstation 45 compromise", "severity": "low", "alertIds": [a1, a2]})
    assert r.status_code == 201
    case = analyst.get(f"/api/cases/{r.json()['id']}").json()
    assert case["case"]["severity"] == "critical"
    assert {e["kind"] for e in case["events"]} >= {"created", "alert_linked", "severity"}
    assert all(a["status"] == "in_progress" for a in case["alerts"])
    note = analyst.post(f"/api/cases/{r.json()['id']}/notes", json={"body": "Isolated the host."})
    assert note.status_code == 201


def test_alert_detail_includes_context(analyst):
    aid = seed_alert()
    now = db.utcnow()
    with db.session_scope() as s:
        s.add(Flow(start=now - timedelta(minutes=2), end=now, src_ip="10.20.0.45", src_port=50000, dst_ip="198.51.100.77",
                   dst_port=4444, protocol="TCP", packets=10, bytes=1000))
    r = analyst.get(f"/api/alerts/{aid}").json()
    assert len(r["flows"]) == 1


def test_entity_page(analyst):
    seed_alert()
    r = analyst.get("/api/entities/ip/10.20.0.45")
    assert r.status_code == 200 and r.json()["internal"] is True
    assert analyst.get("/api/entities/ip/not-an-ip").status_code == 400


def test_rule_tuning_is_validated(admin):
    assert admin.patch("/api/rules/NET-001", json={"params": {"distinct_ports": 30}}).json()["params"]["distinct_ports"] == 30
    assert admin.patch("/api/rules/NET-001", json={"params": {"evil": 1}}).status_code == 400
    assert admin.patch("/api/rules/NET-001", json={"params": {"distinct_ports": "lots"}}).status_code == 400
    bad = admin.post("/api/rules", json={"name": "Bad rule", "conditions": {"__class__": 1}})
    assert bad.status_code == 400
    ok = admin.post("/api/rules", json={"name": "FTP out", "conditions": {"dst_port": 21, "dst_internal": False}})
    assert ok.status_code == 201 and ok.json()["id"].startswith("CUS-")
    assert admin.delete("/api/rules/NET-001").status_code == 400


def test_analyst_cannot_tune_rules(analyst):
    assert analyst.patch("/api/rules/NET-001", json={"enabled": False}).status_code == 403


def test_indicator_validation_and_import(analyst):
    assert analyst.post("/api/indicators", json={"value": "not an indicator!"}).status_code == 400
    ok = analyst.post("/api/indicators", json={"value": "EVIL.example.com", "threat": "C2"})
    assert ok.status_code == 201 and ok.json()["kind"] == "domain" and ok.json()["value"] == "evil.example.com"
    assert analyst.post("/api/indicators", json={"value": "evil.example.com"}).status_code == 409
    r = analyst.post("/api/indicators/import", json={"text": "203.0.113.9,brute,60\n# comment\nbad value\n" + "a" * 64}).json()
    assert r == {"added": 2, "skipped": 0, "invalid": 1}


def test_csv_export_neutralises_formulas(analyst):
    seed_alert(title="=HYPERLINK(\"http://evil\")")
    body = analyst.get("/api/reports/alerts.csv").text
    assert "'=HYPERLINK" in body


def test_hunt_parameters_are_bounded(analyst):
    assert analyst.post("/api/hunts/beaconing/run", json={"params": {"hours": 99999}}).status_code == 400
    assert analyst.post("/api/hunts/beaconing/run", json={"params": {"sql": 1}}).status_code == 400
    assert analyst.post("/api/hunts/nope/run", json={}).status_code == 404
    r = analyst.post("/api/hunts/large_uploads/run", json={"params": {"hours": 24}})
    assert r.status_code == 200 and r.json()["rows"] == []


def test_secrets_are_write_only_and_encrypted(admin):
    assert admin.put("/api/settings/secrets/virustotal_api_key", json={"value": "vt-secret-123"}).status_code == 200
    view = admin.get("/api/settings").json()
    assert "vt-secret-123" not in str(view)
    assert next(x for x in view["secrets"] if x["key"] == "virustotal_api_key")["set"] is True
    from mysoc.models import Secret

    with db.session_scope() as s:
        assert s.get(Secret, "virustotal_api_key").value != "vt-secret-123"
    assert admin.put("/api/settings/secrets/anything", json={"value": "x"}).status_code == 404


def test_new_user_gets_one_time_password(admin, app):
    r = admin.post("/api/users", json={"username": "bob", "role": "analyst"}).json()
    from .conftest import sign_in

    bob = sign_in(app, "bob", r["temporaryPassword"])
    assert bob.get("/api/auth/me").json()["user"]["mustChangePassword"] is True


def test_overview_and_reports(analyst):
    seed_alert(severity="high", mitre_tactic="Command and Control")
    o = analyst.get("/api/overview", params={"hours": 24}).json()
    assert o["kpis"]["openTotal"] == 1 and o["tactics"][0]["tactic"] == "Command and Control"
    rep = analyst.get("/api/reports/summary", params={"days": 7}).json()
    assert rep["totals"]["alerts"] == 1


def test_time_buckets_group_rows(analyst):
    now = db.utcnow()
    with db.session_scope() as s:
        for i in range(30):
            s.add(Flow(start=now - timedelta(seconds=i * 20), end=now, src_ip="10.20.0.45", src_port=50000 + i,
                       dst_ip="198.51.100.77", dst_port=443, protocol="TCP", packets=1, bytes=100))
    act = analyst.get("/api/entities/ip/10.20.0.45", params={"hours": 1}).json()["traffic"]["activity"]
    assert 1 <= len(act) <= 3 and sum(a["flows"] for a in act) == 30
    seed_alert(first_seen=now - timedelta(minutes=10))
    tl = analyst.get("/api/overview", params={"hours": 24}).json()["timeline"]
    assert sum(b["medium"] for b in tl) == 1
