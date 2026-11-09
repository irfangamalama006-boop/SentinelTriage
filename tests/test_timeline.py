
from sentineltriage.timeline import (
    build_timeline,
    normalize_timestamp,
    write_timeline_json,
)


def test_timeline_sorts_events_by_timestamp():
    events = [
        {"timestamp": "2026-10-22T10:00:05Z", "event": "YARA scan"},
        {"timestamp": "2026-10-22T10:00:01Z", "event": "File inventory"},
    ]

    result = build_timeline(events)

    assert result["timed_events"] == 2
    assert result["timeline"][0]["event"] == "File inventory"
    assert result["timeline"][1]["event"] == "YARA scan"


def test_invalid_timestamp_is_not_invented():
    events = [
        {"event": "Unknown time"},
        {"timestamp": "not-a-timestamp", "event": "Invalid time"},
    ]

    result = build_timeline(events)

    assert result["timed_events"] == 0
    assert result["unplaced_count"] == 2


def test_naive_timestamp_is_not_assumed_utc():
    assert normalize_timestamp("2026-10-22T10:00:00") is None


def test_write_timeline_json(tmp_path):
    output = tmp_path / "timeline.json"
    events = [
        {"timestamp": "2026-10-22T10:00:00Z", "event": "Test event"}
    ]

    write_timeline_json(events, str(output))

    import json
    saved = json.loads(output.read_text(encoding="utf-8"))

    assert saved["total_events"] == 1
    assert saved["timed_events"] == 1
