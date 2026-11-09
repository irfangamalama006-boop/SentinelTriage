
"""Timeline utilities for SentinelTriage investigation reports."""

from datetime import datetime, timezone
from pathlib import Path
import json


def normalize_timestamp(value):
    """Normalize a valid timestamp to UTC ISO-8601.

    Returns None when the value is missing or invalid.
    """
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )

        # Do not silently treat an unknown local time as UTC.
        if parsed.tzinfo is None:
            return None

        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return None


def build_timeline(events):
    """Validate and sort supplied events by their timestamps.

    This function does not invent timestamps. Events with missing or
    invalid timestamps are returned separately for manual review.
    """
    if not isinstance(events, list):
        raise TypeError("events harus berupa list.")

    timeline = []
    unplaced = []

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            unplaced.append({
                "index": index,
                "reason": "Event bukan objek/dictionary.",
                "event": event,
            })
            continue

        timestamp = normalize_timestamp(event.get("timestamp"))

        item = dict(event)
        item["source_index"] = index

        if timestamp is None:
            unplaced.append({
                "index": index,
                "reason": "Timestamp tidak tersedia atau tidak valid.",
                "event": item,
            })
            continue

        item["timestamp_utc"] = timestamp
        timeline.append(item)

    timeline.sort(key=lambda item: item["timestamp_utc"])

    return {
        "timeline": timeline,
        "unplaced_events": unplaced,
        "total_events": len(events),
        "timed_events": len(timeline),
        "unplaced_count": len(unplaced),
    }


def write_timeline_json(events, output_path):
    """Write a timeline result as UTF-8 JSON."""
    result = build_timeline(events)

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )

    return str(path)
