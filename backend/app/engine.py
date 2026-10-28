"""Deterministic detections, risk scoring, and evidence-based correlations."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re

def _setting_int(name, default, low=1, high=10000):
    try:
        value = int(os.getenv(name, str(default)))
        return value if low <= value <= high else default
    except ValueError:
        return default

FAILED_LOGIN_WINDOW_MINUTES = _setting_int("FAILED_LOGIN_WINDOW_MINUTES", 15, 1, 1440)
FAILED_LOGIN_THRESHOLD = _setting_int("FAILED_LOGIN_THRESHOLD", 5, 2, 1000)
BRUTE_FORCE_THRESHOLD = _setting_int("BRUTE_FORCE_THRESHOLD", 8, 3, 1000)
PORT_SCAN_THRESHOLD = _setting_int("PORT_SCAN_THRESHOLD", 8, 2, 1000)
CORRELATION_WINDOW_MINUTES = _setting_int("CORRELATION_WINDOW_MINUTES", 30, 1, 1440)

RULES = {
    "AUTH-001": {"name": "Repeated failed logins", "description": "Several authentication failures were observed for the same identity or source within the configured time window.", "severity": "Medium", "mitre": [{"id": "T1110", "name": "Brute Force"}], "confidence": "Moderate: time-window threshold", "threshold": FAILED_LOGIN_THRESHOLD},
    "AUTH-002": {"name": "Failed login followed by success", "description": "A successful authentication followed recent failures for the same account and source.", "severity": "High", "mitre": [{"id": "T1078", "name": "Valid Accounts"}], "confidence": "Moderate: temporal sequence observed", "threshold": 1},
    "AUTH-004": {"name": "Possible brute-force activity", "description": "A high volume of failed authentication attempts came from one source against the same account within the configured time window.", "severity": "High", "mitre": [{"id": "T1110", "name": "Brute Force"}], "confidence": "Moderate: configurable attempt threshold", "threshold": BRUTE_FORCE_THRESHOLD},
    "PROC-001": {"name": "Suspicious PowerShell arguments", "description": "PowerShell command arguments include encoded or remote-content execution indicators.", "severity": "High", "mitre": [{"id": "T1059.001", "name": "PowerShell"}], "confidence": "Low to moderate: command-line heuristic", "threshold": 1},
    "PROC-002": {"name": "Suspicious command execution", "description": "Command execution includes an interpreter and a suspicious download or encoded execution pattern.", "severity": "High", "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}], "confidence": "Low to moderate: command-line heuristic", "threshold": 1},
    "NET-001": {"name": "Port-scan indicators", "description": "One source contacted many destination ports in the configured time window.", "severity": "High", "mitre": [{"id": "T1046", "name": "Network Service Discovery"}], "confidence": "Moderate: distinct-port threshold", "threshold": PORT_SCAN_THRESHOLD},
    "DNS-001": {"name": "Unusual DNS query", "description": "A DNS query has characteristics commonly used by generated or tunneled names.", "severity": "Medium", "mitre": [{"id": "T1071.004", "name": "DNS"}], "confidence": "Low: lexical heuristic", "threshold": 1},
    "AUTH-003": {"name": "Unusual login source", "description": "A login source differs from a prior baseline with at least three distinct observed sources.", "severity": "Medium", "mitre": [{"id": "T1078", "name": "Valid Accounts"}], "confidence": "Low: local historical baseline", "threshold": 3},
    "PROC-003": {"name": "Suspicious process chain", "description": "An office or script host is recorded as the parent of a command interpreter.", "severity": "High", "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}], "confidence": "Moderate: parent and child process fields present", "threshold": 1},
    "IOC-001": {"name": "Local test IOC hash match", "description": "A process hash matched the clearly labeled local test IOC list.", "severity": "Critical", "mitre": [], "confidence": "High: exact match in local test dataset; not external reputation", "threshold": 1},
    "ACCT-001": {"name": "Account activity anomaly", "description": "The account has an unusually high count of failed authentication events in available history.", "severity": "High", "mitre": [{"id": "T1110", "name": "Brute Force"}], "confidence": "Moderate: local historical count", "threshold": 20},
    "MULTI-001": {"name": "Repeated suspicious activity", "description": "Multiple distinct detection signals affect the same host, account, or source.", "severity": "High", "mitre": [], "confidence": "Moderate: multiple independent rule matches", "threshold": 2},
}
PS_PATTERN = re.compile(r"(?i)(-enc(?:odedcommand)?\b|frombase64string|downloadstring|invoke-webrequest|\biex\b|hidden\s+-nop|\b-ep\s+bypass)")
SHELL_PATTERN = re.compile(r"(?i)(curl\s+.{0,80}\|\s*(?:sh|bash)|wget\s+.{0,80}\|\s*(?:sh|bash)|certutil\s+-urlcache|bitsadmin\s+/transfer|rundll32\s+javascript:|regsvr32\s+/s\s+/n\s+/u\s+/i:)")
SUSPICIOUS_DOMAIN = re.compile(r"(?i)^(?:[a-z0-9]{35,}|[a-z0-9-]{50,})\.")
TEST_HASH_FILE = Path(__file__).resolve().parents[2] / "data" / "test_ioc_hashes.txt"
TEST_HASHES = {line.strip().lower() for line in TEST_HASH_FILE.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")} if TEST_HASH_FILE.exists() else set()

def risk_score(base, event_count=1, known_ioc=False):
    weights = {"severity": {"Low": 15, "Medium": 35, "High": 60, "Critical": 80}}
    score = weights["severity"].get(base, 15)
    repeated = min(max(event_count - 1, 0) * 3, 15)
    ioc = 15 if known_ioc else 0
    total = min(score + repeated + ioc, 100)
    severity = "Critical" if total >= 75 else "High" if total >= 50 else "Medium" if total >= 25 else "Low"
    return total, severity, {"base severity": score, "repeated evidence": repeated, "local test IOC match": ioc, "formula": "min(severity base + min(3 × additional events, 15) + local test IOC bonus, 100)"}

def _value(event, field):
    return getattr(event, field, None) if not isinstance(event, dict) else event.get(field)

def detect(events, historic_events=None):
    """Return alert candidates from normalized dicts or Event ORM records."""
    candidates = []
    hist = list(historic_events or events)
    grouped = defaultdict(list)
    for event in events:
        user, ip, host = _value(event, "user"), _value(event, "src_ip"), _value(event, "host")
        status = str(_value(event, "status") or "").lower()
        typ = str(_value(event, "event_type") or "").lower()
        event_id = str(_value(event, "event_id") or "").lower()
        action = str(_value(event, "action") or "").lower()
        is_auth = "login" in typ or "auth" in typ or "logon" in typ or "login" in action or "auth" in action or event_id in {"4624", "4625"}
        failed = status in {"failed", "failure", "denied", "invalid", "0"} or "fail" in action or event_id == "4625"
        succeeded = status in {"success", "succeeded", "ok", "allowed", "1"} or "success" in action or event_id == "4624"
        if is_auth and failed:
            grouped[(user or "unknown-user", ip or "unknown-source")].append(event)
        command = str(_value(event, "process_command_line") or "")
        proc = str(_value(event, "process_name") or "").lower()
        if proc.endswith("powershell.exe") or "powershell" in proc:
            if PS_PATTERN.search(command): candidates.append(_candidate("PROC-001", [event], {"command": command[:500]}))
        if SHELL_PATTERN.search(command): candidates.append(_candidate("PROC-002", [event], {"command": command[:500]}))
        if proc and _value(event, "process_hash") in TEST_HASHES:
            candidates.append(_candidate("IOC-001", [event], {"hash": _value(event, "process_hash"), "match": "Local EICAR test signature dataset"}, known_ioc=True))
        domain = str(_value(event, "destination_domain") or "")
        if domain and (len(domain) > 60 or SUSPICIOUS_DOMAIN.match(domain)):
            candidates.append(_candidate("DNS-001", [event], {"domain": domain, "reason": "long or high-entropy-looking label"}))
        parent = str(_value(event, "parent_process") or "").lower()
        raw = _value(event, "raw_event") or {}
        parent = parent or (str(raw.get("parent_process") or raw.get("parentImage") or "").lower() if isinstance(raw, dict) else "")
        if parent and any(x in parent for x in ("winword", "excel", "outlook", "wscript", "cscript")) and any(x in proc for x in ("powershell", "cmd.exe", "wscript", "cscript")):
            candidates.append(_candidate("PROC-003", [event], {"parent_process": parent, "process_name": proc}))
    for (user, ip), failures_all in grouped.items():
        failures = _largest_recent_window(failures_all)
        if len(failures) >= RULES["AUTH-001"]["threshold"]:
            candidates.append(_candidate("AUTH-001", failures, {"user": user, "source_ip": ip, "failed_attempts": len(failures)}))
        if len(failures) >= RULES["AUTH-004"]["threshold"]:
            candidates.append(_candidate("AUTH-004", failures, {"user": user, "source_ip": ip, "failed_attempts": len(failures)}))
        if len(failures) >= RULES["ACCT-001"]["threshold"]:
            candidates.append(_candidate("ACCT-001", failures, {"user": user, "historical_failed_attempts": len(failures)}))
        for success in events:
            if str(_value(success, "user") or "unknown-user") == user and str(_value(success, "src_ip") or "unknown-source") == ip:
                status = str(_value(success, "status") or "").lower()
                if status in {"success", "succeeded", "ok", "allowed", "1"} or str(_value(success, "event_id") or "") == "4624":
                    fail_times = [_value(e, "timestamp") for e in failures]
                    success_time = _value(success, "timestamp")
                    if success_time and any(t and timedelta(0) <= success_time - t <= timedelta(minutes=30) for t in fail_times):
                        candidates.append(_candidate("AUTH-002", failures + [success], {"user": user, "source_ip": ip, "failures": len(failures), "sequence": "failed authentication followed by success within 30 minutes"})); break
    ports = defaultdict(list)
    for event in events:
        src = _value(event, "src_ip")
        port = _value(event, "dst_port")
        if src and port is not None: ports[src].append(event)
    for src, group_all in ports.items():
        group = _largest_recent_window(group_all)
        unique = { _value(e, "dst_port") for e in group }
        if len(unique) >= RULES["NET-001"]["threshold"]:
            sample = [e for e in group if _value(e, "dst_port") in list(unique)[:50]]
            candidates.append(_candidate("NET-001", sample, {"source_ip": src, "distinct_destination_ports": len(unique)}))
    # A new source is only anomalous when enough distinct source history exists.
    by_user = defaultdict(set)
    for event in hist:
        if _value(event, "user") and _value(event, "src_ip"): by_user[_value(event, "user")].add(_value(event, "src_ip"))
    for event in events:
        user, src = _value(event, "user"), _value(event, "src_ip")
        typ = str(_value(event, "event_type") or "").lower()
        status = str(_value(event, "status") or "").lower()
        event_id = str(_value(event, "event_id") or "")
        if user and src and ("login" in typ or "auth" in typ or event_id == "4624") and (status in {"success", "succeeded", "ok", "allowed", "1"} or event_id == "4624") and len(by_user[user] - {src}) >= 3:
            candidates.append(_candidate("AUTH-003", [event], {"user": user, "source_ip": src, "known_sources": len(by_user[user] - {src})}))
    # Aggregate rule IDs per entity to reduce noisy per-event alerts.
    signals = defaultdict(list)
    for candidate in candidates:
        ev = candidate["events"]
        entity = next((_value(e, "user") for e in ev if _value(e, "user")), None) or next((_value(e, "host") for e in ev if _value(e, "host")), None) or next((_value(e, "src_ip") for e in ev if _value(e, "src_ip")), None)
        if entity: signals[entity].append(candidate)
    for entity, group in signals.items():
        rules = {c["rule_id"] for c in group}
        if len(rules) >= RULES["MULTI-001"]["threshold"]:
            evs = {str(_value(e, "fingerprint") or _value(e, "id")): e for c in group for e in c["events"]}
            candidates.append(_candidate("MULTI-001", list(evs.values()), {"entity": entity, "distinct_rules": sorted(rules)}))
    # Stable deduplication within a batch.
    unique = {}
    for item in candidates:
        key = item["dedupe_key"]
        unique[key] = item
    return list(unique.values())

def _candidate(rule_id, events, evidence, known_ioc=False):
    rule = RULES[rule_id]
    fingerprints = sorted(str(_value(e, "fingerprint") or _value(e, "id")) for e in events)
    dedupe_key = hashlib.sha256((rule_id + ":" + ":".join(fingerprints)).encode()).hexdigest()
    score, severity, breakdown = risk_score(rule["severity"], len(events), known_ioc)
    return {"rule_id": rule_id, "name": rule["name"], "description": rule["description"], "base_severity": rule["severity"], "severity": severity, "risk_score": score, "risk_breakdown": breakdown, "confidence": rule["confidence"], "mitre": rule["mitre"], "recommendations": ["Validate the relevant raw events and time range.", "Check related identity, host, and network telemetry.", "Escalate to L2 when corroborating evidence supports it."], "evidence": evidence, "events": events, "dedupe_key": dedupe_key}

def _largest_recent_window(events, window_minutes=FAILED_LOGIN_WINDOW_MINUTES):
    timed = [(event, _value(event, "timestamp")) for event in events if _value(event, "timestamp") is not None]
    timed = [(event, ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)) for event, ts in timed]
    best = []
    for _, anchor in timed:
        recent = [event for event, ts in timed if timedelta(0) <= anchor - ts <= timedelta(minutes=window_minutes)]
        if len(recent) > len(best): best = recent
    return best

def correlate(events, window_minutes=CORRELATION_WINDOW_MINUTES):
    """Group events sharing an observed user, host, or IP in a bounded time window."""
    buckets = defaultdict(list)
    for event in events:
        keys = [(field, _value(event, field)) for field in ("user", "host", "src_ip") if _value(event, field)]
        for key in keys: buckets[key].append(event)
    groups = []
    seen = set()
    def normalized_time(event):
        value = _value(event, "timestamp")
        if value is None: return None
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    for (field, value), group in buckets.items():
        group = sorted(group, key=lambda e: normalized_time(e) or datetime.min.replace(tzinfo=timezone.utc))
        if len(group) < 2: continue
        slices = []
        for event in group:
            ts = normalized_time(event)
            if slices and ts and slices[-1][-1]["_ts"] and ts - slices[-1][-1]["_ts"] <= timedelta(minutes=window_minutes):
                slices[-1].append({"event": event, "_ts": ts})
            else: slices.append([{"event": event, "_ts": ts}])
        for part in slices:
            evs = [x["event"] for x in part]
            ids = tuple(sorted(str(_value(e, "fingerprint") or _value(e, "id")) for e in evs))
            if len(evs) > 1 and ids not in seen:
                seen.add(ids); groups.append({"entity_type": field, "entity": value, "events": evs, "event_ids": [int(_value(e, "id")) for e in evs if _value(e, "id")], "why": f"Shared {field} {value} within {window_minutes} minutes", "uncertainty": "Temporal and entity linkage supports investigation; correlation alone does not establish causation."})
    return groups
