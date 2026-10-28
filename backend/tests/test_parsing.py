import json
import pytest
from app.parsing import parse_content


def test_json_object_and_alias_normalization():
    rows, errors, seen = parse_content("one.json", b'{"@timestamp":"2026-10-27T10:00:00Z","hostname":"host-a","username":"analyst","source_ip":"203.0.113.9","event":"authentication","status":"failed"}')
    assert not errors and seen == 1 and len(rows) == 1
    assert rows[0]["host"] == "host-a" and rows[0]["user"] == "analyst"
    assert rows[0]["src_ip"] == "203.0.113.9" and rows[0]["timestamp"].isoformat() == "2026-10-27T10:00:00+00:00"
    assert rows[0]["raw_event"]["status"] == "failed"
    event_id, errors, _ = parse_content("win.json", b'{"EventID":4625,"hostname":"host-a"}')
    assert event_id[0]["event_id"] == "4625" and event_id[0]["event_type"] is None


def test_json_array_and_malformed_json():
    rows, errors, seen = parse_content("array.json", b'[{"host":"a"},{"host":"b"}]')
    assert len(rows) == 2 and not errors and seen == 2
    rows, errors, _ = parse_content("bad.json", b'{"broken":')
    assert rows == [] and "Malformed JSON" in errors[0]["error"]


def test_jsonl_keeps_good_rows_and_reports_bad_lines():
    rows, errors, seen = parse_content("events.jsonl", b'{"host":"a"}\nnot-json\n{"host":"b"}\n')
    assert len(rows) == 2 and len(errors) == 1 and errors[0]["row"] == 2 and seen == 3


def test_csv_aliases_missing_fields_and_invalid_ip():
    rows, errors, seen = parse_content("events.csv", b"time,computer,source_ip,destination_port,user_name\n2026-10-27T10:00:00Z,ws-1,not-an-ip,443,alex\n")
    assert not errors and seen == 2
    assert rows[0]["host"] == "ws-1" and rows[0]["src_ip"] is None and rows[0]["dst_port"] == 443
    assert rows[0]["user"] == "alex"


def test_text_log_extracts_timestamp_key_values_and_keeps_raw_line():
    rows, errors, _ = parse_content("events.log", b'2026-10-27 10:00:00Z host=ws-1 user=alex src_ip=192.0.2.4 status=failed')
    assert rows[0]["host"] == "ws-1" and rows[0]["user"] == "alex"
    assert rows[0]["src_ip"] == "192.0.2.4" and rows[0]["timestamp"].isoformat() == "2026-10-27T10:00:00+00:00"
    rows, errors, _ = parse_content("raw.txt", b"unstructured source evidence")
    assert len(rows) == 1 and rows[0]["raw_event"]["line"] == "unstructured source evidence"
    assert "preserved as raw evidence" in errors[0]["error"]


def test_unsupported_extension_is_rejected():
    with pytest.raises(ValueError, match="Unsupported file format"):
        parse_content("payload.exe", b"not executed")
