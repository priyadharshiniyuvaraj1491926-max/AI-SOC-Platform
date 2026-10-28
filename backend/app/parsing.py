"""Safe, deterministic parsing and normalization for uploaded security logs."""
import csv
import hashlib
import io
import ipaddress
import json
import re
from datetime import datetime, timezone

ALIASES = {
    "event_id": ("event_id", "eventid", "event_uuid", "record_id", "uuid"),
    "timestamp": ("timestamp", "time", "event_time", "@timestamp", "date", "datetime", "created_at"),
    "source": ("source", "vendor", "product", "data_source", "log_source"),
    "host": ("host", "hostname", "computer", "device", "machine", "endpoint"),
    "user": ("user", "username", "account", "user_name", "principal", "subject_user_name"),
    "src_ip": ("src_ip", "source_ip", "client_ip", "ip_address", "ip", "remote_addr", "sourceaddress"),
    "dst_ip": ("dst_ip", "destination_ip", "dest_ip", "server_ip", "destinationaddress"),
    "src_port": ("src_port", "source_port", "client_port"),
    "dst_port": ("dst_port", "destination_port", "dest_port", "server_port"),
    "event_type": ("event_type", "type", "event", "event_code", "eventcode", "event_name", "category", "operation"),
    "action": ("action", "activity", "command", "operation_name"),
    "status": ("status", "result", "outcome", "authentication_result", "login_status"),
    "process_name": ("process_name", "process", "image", "process_path", "application"),
    "process_command_line": ("process_command_line", "command_line", "cmdline", "processcommandline", "commandline"),
    "process_hash": ("process_hash", "hash", "sha256", "sha1", "md5", "file_hash"),
    "destination_domain": ("destination_domain", "domain", "query", "dns_query", "fqdn", "hostname_query"),
}

def parse_timestamp(value):
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    try:
        dt = datetime.fromtimestamp(float(text), tz=timezone.utc) if re.fullmatch(r"\d{10}(?:\.\d+)?", text) else datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None

def _get(row, names):
    lowered = {str(k).strip().lower().replace("-", "_"): v for k, v in row.items() if k is not None}
    for alias in names:
        if alias in lowered and lowered[alias] not in (None, ""):
            return lowered[alias]
    return None

def normalize_event(row, raw=None):
    if not isinstance(row, dict):
        raise ValueError("Event must be a JSON object or CSV row")
    out = {key: _get(row, aliases) for key, aliases in ALIASES.items()}
    out["timestamp"] = parse_timestamp(out["timestamp"])
    for field in ("src_ip", "dst_ip"):
        if out[field]:
            try:
                out[field] = str(ipaddress.ip_address(str(out[field]).strip()))
            except ValueError:
                out[field] = None
    for field in ("src_port", "dst_port"):
        try:
            number = int(out[field]) if out[field] is not None else None
            out[field] = number if number is not None and 0 <= number <= 65535 else None
        except (ValueError, TypeError):
            out[field] = None
    if out["process_hash"]:
        digest = re.sub(r"\s", "", str(out["process_hash"])).lower()
        out["process_hash"] = digest if re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", digest) else None
    for key, value in list(out.items()):
        if value is not None and key not in {"timestamp", "src_port", "dst_port"}:
            out[key] = str(value).strip()[:2000] or None
    out["raw_event"] = raw if raw is not None else row
    canonical = json.dumps({k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in out.items()}, sort_keys=True, default=str)
    out["fingerprint"] = hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()
    return out

LOG_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d(?:T|\s)\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?|\d{4}-\d\d-\d\d)\s+(?P<rest>.*)$")
KV_RE = re.compile(r"([A-Za-z_][\w.-]*)=(?:\"([^\"]*)\"|'([^']*)'|([^\s]+))")

def parse_content(filename, content):
    """Return normalized records, per-record errors, and line/row count."""
    suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    text = content.decode("utf-8-sig", errors="replace")
    records, errors = [], []
    if suffix == "json":
        try:
            doc = json.loads(text)
            rows = doc if isinstance(doc, list) else [doc]
            for index, row in enumerate(rows, 1):
                try: records.append(normalize_event(row, row))
                except ValueError as exc: errors.append({"row": index, "error": str(exc)})
            return records, errors, len(rows)
        except json.JSONDecodeError as exc:
            return [], [{"row": exc.lineno, "error": f"Malformed JSON: {exc.msg}"}], max(1, len(text.splitlines()))
    if suffix == "jsonl":
        lines = text.splitlines()
        for index, line in enumerate(lines, 1):
            if not line.strip(): continue
            try:
                row = json.loads(line)
                records.append(normalize_event(row, row))
            except (json.JSONDecodeError, ValueError) as exc:
                errors.append({"row": index, "error": f"Invalid JSONL row: {str(exc)[:180]}"})
        return records, errors, len(lines)
    if suffix == "csv":
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            return [], [{"row": 1, "error": "CSV header row is missing"}], 0
        try:
            for index, row in enumerate(reader, 2):
                if None in row:
                    errors.append({"row": index, "error": "Row has more columns than the header"}); continue
                try: records.append(normalize_event(row, row))
                except ValueError as exc: errors.append({"row": index, "error": str(exc)})
        except csv.Error as exc:
            errors.append({"row": reader.line_num, "error": f"Malformed CSV: {exc}"})
        return records, errors, max(reader.line_num, 1)
    if suffix in {"txt", "log"}:
        lines = text.splitlines()
        for index, line in enumerate(lines, 1):
            if not line.strip(): continue
            match = LOG_RE.match(line.strip())
            row = {}
            for found in KV_RE.findall(match.group("rest") if match else line):
                row[found[0]] = next((v for v in found[1:] if v), "")
            if match: row["timestamp"] = match.group("ts")
            if not row:
                errors.append({"row": index, "severity": "warning", "error": "Line preserved as raw evidence; no documented key=value fields found"})
                row = {"event_type": "unstructured_log_line", "raw_line": line}
            records.append(normalize_event(row, {"line": line, **row}))
        return records, errors, len(lines)
    raise ValueError("Unsupported file format. Use .txt, .log, .json, .jsonl, or .csv")
