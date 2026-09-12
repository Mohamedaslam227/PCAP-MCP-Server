"""Capture analysis MCP tools."""

from typing import Any

from wifi_pcap_mcp.bootstrap import analysis_service


def get_summary(capture_id: str) -> dict[str, Any]:
    """Produce a quick packet-level overview of a loaded capture.

    This iterates through the full capture and is useful as the first analysis
    call after loading. It reports packet count, observed protocol-layer names,
    first/last Unix timestamps, and duration.

    Args:
        capture_id: ID of a currently loaded capture.

    Returns:
        Packet count, sorted protocols, start/end timestamps, and duration.
    """
    return analysis_service.summary(capture_id)


def get_capture_metadata(capture_id: str) -> dict[str, Any]:
    """Inspect PCAP/PCAPNG container and capture-interface metadata.

    Use this for file format, encapsulation, snap length, timestamp precision,
    capture origin, comments, time range, and per-interface information. The
    result comes primarily from Capinfos and does not return packet dissections.

    Args:
        capture_id: ID of a currently loaded capture.

    Returns:
        File, timing, capture-host, and interface metadata when available.
    """
    return analysis_service.metadata(capture_id)


def get_capture_statistics(capture_id: str) -> dict[str, Any]:
    """Calculate aggregate traffic rates and packet-size statistics.

    This combines Capinfos totals with a TShark pass over frame lengths. Use it
    to assess capture volume, duration, average traffic rate, and minimum,
    maximum, and average packet sizes.

    Args:
        capture_id: ID of a currently loaded capture.

    Returns:
        Packet/byte totals, file size, timing, rates, and packet-size metrics.
    """
    return analysis_service.statistics(capture_id)


def get_capture_interfaces(capture_id: str) -> dict[str, Any]:
    """List capture interfaces or radio adapters stored in the file.

    This is a focused view of ``get_capture_metadata`` for multi-interface
    PCAPNG files. Interface fields depend on what the capture writer recorded.

    Args:
        capture_id: ID of a currently loaded capture.

    Returns:
        Interface count and available names, link types, snap lengths,
        timestamp precision, operating systems, and packet counts.
    """
    return analysis_service.interfaces(capture_id)


def get_capture_time_range(
    capture_id: str,
    bucket_count: int = 20,
) -> dict[str, Any]:
    """Divide the capture time range into packet and byte-count buckets.

    Use this to locate bursts, quiet intervals, or the portion of a capture
    worth filtering in more detail. Every packet is assigned to one evenly
    sized time bucket.

    Args:
        capture_id: ID of a currently loaded capture.
        bucket_count: Number of buckets to generate, from 1 through 100.
            Defaults to 20.

    Returns:
        Overall time range plus timestamped packet/byte totals per bucket.
    """
    return analysis_service.time_range(capture_id, bucket_count)


def validate_capture(
    capture_id: str,
    example_limit: int = 20,
) -> dict[str, Any]:
    """Validate capture readability and identify common packet-quality issues.

    Checks malformed packets, captured-length truncation, missing core frame
    fields, severe decode failures, unsupported protocols, timestamps, and
    strict chronological order. Issue categories can overlap.

    Args:
        capture_id: ID of a currently loaded capture.
        example_limit: Maximum frame numbers retained for each issue, from 0
            through 100. Counts always include all matches.

    Returns:
        Overall validity/readability, packet count, time-order status, and issue
        counts with example frame numbers.
    """
    return analysis_service.validate(capture_id, example_limit)
