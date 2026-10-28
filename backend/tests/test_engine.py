from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from app.engine import correlate, detect, risk_score


def event(i, **kwargs):
    base = {"id": i, "fingerprint": f"fp-{i}", "timestamp": datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc) + timedelta(minutes=i), "source": "test", "host": "host-a", "user": "alex", "src_ip": "192.0.2.1", "dst_ip": None, "dst_port": None, "event_type": None, "action": None, "status": None, "process_name": None, "process_command_line": None, "process_hash": None, "destination_domain": None, "raw_event": {}}
    base.update(kwargs)
    return base


def test_risk_score_severity_boundaries_and_contributors():
    assert risk_score("Low")[0:2] == (15, "Low")
    assert risk_score("Medium")[0:2] == (35, "Medium")
    assert risk_score("High")[0:2] == (60, "High")
    assert risk_score("Critical")[0:2] == (80, "Critical")
    score, severity, factors = risk_score("High", event_count=4, known_ioc=True)
    assert (score, severity) == (84, "Critical")
    assert factors["repeated evidence"] == 9 and factors["local test IOC match"] == 15


def test_risk_severity_cutoffs_are_inclusive_on_the_expected_side():
    assert risk_score("Low", event_count=4)[0:2] == (24, "Low")
    assert risk_score("Low", event_count=5)[0:2] == (27, "Medium")
    assert risk_score("Medium", event_count=5)[0:2] == (47, "Medium")
    assert risk_score("Medium", event_count=6)[0:2] == (50, "High")
    assert risk_score("High", event_count=5)[0:2] == (72, "High")
    assert risk_score("High", event_count=6)[0:2] == (75, "Critical")


def test_failed_login_threshold_and_failed_then_success():
    failed = [event(i, event_type="authentication", status="failed") for i in range(1, 6)]
    rules = {x["rule_id"] for x in detect(failed)}
    assert "AUTH-001" in rules and "AUTH-004" not in rules
    success = event(6, event_type="authentication", status="success")
    rules = {x["rule_id"] for x in detect(failed + [success])}
    assert "AUTH-002" in rules


def test_windows_security_event_ids_are_recognized_as_auth_outcomes():
    failures = [event(i, event_id="4625") for i in range(1, 6)]
    success = event(6, event_id="4624")
    rules = {x["rule_id"] for x in detect(failures + [success])}
    assert {"AUTH-001", "AUTH-002"}.issubset(rules)


def test_brute_force_threshold_and_power_shell_rule():
    failed = [event(i, event_type="authentication", status="failed") for i in range(1, 9)]
    process = event(20, process_name="powershell.exe", process_command_line="powershell -EncodedCommand AAA")
    rules = {x["rule_id"] for x in detect(failed + [process])}
    assert {"AUTH-001", "AUTH-004", "PROC-001"}.issubset(rules)


def test_scan_dns_hash_and_process_chain_rules():
    ports = [event(i, dst_port=p) for i, p in enumerate([21,22,23,25,53,80,443,3389], 1)]
    other = [event(20, process_name="powershell.exe", process_command_line="-enc AAA", raw_event={"parent_process":"WINWORD.EXE"}), event(21, destination_domain="a"*70 + ".invalid"), event(22, process_name="eicar.com", process_hash="44d88612fea8a8f36de82e1278abb02f")]
    rules = {x["rule_id"] for x in detect(ports + other)}
    assert {"NET-001", "PROC-001", "PROC-003", "DNS-001", "IOC-001"}.issubset(rules)


def test_correlation_is_time_bounded_and_explains_relationship():
    items = [event(1), event(2, host="host-a"), event(80, host="host-b", user="other", src_ip="198.51.100.8")]
    result = correlate(items, window_minutes=30)
    assert len(result) == 1
    assert result[0]["entity_type"] in {"user", "host", "src_ip"}
    assert "does not establish causation" in result[0]["uncertainty"]
