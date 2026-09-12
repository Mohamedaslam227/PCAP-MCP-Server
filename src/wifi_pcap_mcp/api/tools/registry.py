"""Central MCP tool catalog and registration."""

from typing import Any

from wifi_pcap_mcp.api.error_boundary import tool_boundary

from .analysis_tools import (
    get_capture_interfaces,
    get_capture_metadata,
    get_capture_statistics,
    get_capture_time_range,
    get_summary,
    validate_capture,
)
from .capture_tools import (
    list_loaded_captures,
    load_capture,
    reload_capture,
    set_decryption_keys,
    unload_capture,
)
from .export_tools import export_filtered_capture
from .packet_tools import (
    dissect_packet,
    filter_packets,
    get_ap_packets,
    get_client_packets,
    get_flow_packets,
    get_packet_by_number,
    get_packet_timeline,
    get_packets_between_frames,
    get_packets_by_time_range,
    get_related_packets,
    get_transaction_packets,
)

TOOL_FUNCTIONS = (
    load_capture,
    list_loaded_captures,
    unload_capture,
    reload_capture,
    set_decryption_keys,
    export_filtered_capture,
    get_summary,
    get_capture_metadata,
    get_capture_statistics,
    validate_capture,
    get_capture_interfaces,
    get_capture_time_range,
    filter_packets,
    dissect_packet,
    get_packet_by_number,
    get_packets_by_time_range,
    get_packets_between_frames,
    get_related_packets,
    get_packet_timeline,
    get_flow_packets,
    get_client_packets,
    get_ap_packets,
    get_transaction_packets,
)


def register_tools(server: Any) -> None:
    """Register all tools through the shared response and error boundary."""
    for function in TOOL_FUNCTIONS:
        server.tool()(tool_boundary(function))
