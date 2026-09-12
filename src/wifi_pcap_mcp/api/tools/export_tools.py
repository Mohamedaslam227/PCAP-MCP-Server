"""Capture export MCP tools."""

from typing import Any

from wifi_pcap_mcp.bootstrap import export_service


def export_filtered_capture(
    capture_id: str,
    filter_expression: str,
    output_path: str,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Write packets matching a display filter to a new capture file.

    The export uses a temporary file and replaces the destination only after
    TShark succeeds. It never allows the source capture to be overwritten.
    Configured decryption keys are applied while filtering.

    Args:
        capture_id: ID of a currently loaded capture.
        filter_expression: Non-empty Wireshark display filter selecting packets.
        output_path: Destination ending in ``.pcap`` or ``.pcapng``. Its parent
            directory must already exist and be writable by the server.
        overwrite: Allow replacement of an existing destination when true.
            Defaults to false.

    Returns:
        Capture ID, normalized filter, resolved output path, name, and size.
    """
    return export_service.export_filtered(
        capture_id,
        filter_expression,
        output_path,
        overwrite,
    )
