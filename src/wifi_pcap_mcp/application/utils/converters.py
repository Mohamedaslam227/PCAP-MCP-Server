"""Small conversion helpers used by analysis services."""

from datetime import UTC, datetime
from typing import Any


def as_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def as_float(value: Any) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def epoch_to_iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=UTC).isoformat()

def packet_timestamp(packet: Any) -> float | None:
    frame_info = getattr(packet, "frame_info", None)
    values = (
        getattr(frame_info, "time_epoch", None),
        getattr(packet, "sniff_timestamp", None),
    )
    for value in values:
        try:
            return float(value)
        except (TypeError, ValueError):
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(
                        value.replace("Z", "+00:00")
                    ).timestamp()
                except ValueError:
                    continue
    return None

