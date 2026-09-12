"""Packet MCP tools."""

from typing import Any

from wifi_pcap_mcp.bootstrap import packet_service


def filter_packets(
    capture_id: str,
    filter_expression: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Find packets using a Wireshark/TShark display-filter expression.

    Use standard display filters such as ``dns``, ``tcp.port == 443``,
    ``wlan.fc.retry == 1``, or ``frame.number >= 10 && frame.number <= 20``.
    This returns summaries rather than complete field trees; use
    ``dissect_packet`` on interesting frame numbers for full details.

    Args:
        capture_id: ID of a currently loaded capture.
        filter_expression: Non-empty Wireshark display filter. This is not a
            BPF/libpcap capture filter.
        limit: Maximum results to return, from 1 through 1000. Defaults to 100.

    Returns:
        Normalized filter, match count returned, and packet summaries containing
        frame number, Unix timestamp, protocols, and textual dissection.
    """
    return packet_service.filter(capture_id, filter_expression, limit)


def dissect_packet(capture_id: str, packet_number: int) -> dict[str, Any]:
    """Return the decoded protocol layers and fields for one frame.

    Frame numbers are the one-based ``frame.number`` values shown by Wireshark.
    Use ``filter_packets`` or validation example frames to discover relevant
    numbers. A valid but absent frame is a successful result with
    ``found=false`` rather than an error.

    Args:
        capture_id: ID of a currently loaded capture.
        packet_number: Positive, one-based Wireshark frame number.

    Returns:
        Capture/frame identity, found flag, packet summary, and decoded fields
        grouped by protocol layer when the frame exists.
    """
    return packet_service.dissect(capture_id, packet_number)


def get_packet_by_number(
    capture_id: str,
    packet_number: int,
) -> dict[str, Any]:
    """Retrieve and fully decode one packet by its Wireshark frame number.

    This is a lookup-oriented alias of ``dissect_packet``. Frame numbers are
    one-based values from ``frame.number``; an absent frame returns
    ``found=false`` instead of raising an error.

    Args:
        capture_id: ID of a currently loaded capture.
        packet_number: Positive frame.number value.

    Returns:
        Capture/frame identity, found flag, packet summary, timestamp,
        protocol list, and decoded fields grouped by layer.
    """
    return packet_service.get_by_number(capture_id, packet_number)


def get_packets_by_time_range(
    capture_id: str,
    start_time: float,
    end_time: float,
    limit: int = 1000,
) -> dict[str, Any]:
    """Retrieve packets whose Unix timestamps fall within an inclusive range.

    Times use seconds since the Unix epoch, matching ``frame.time_epoch`` in
    Wireshark. Results are summaries; call ``dissect_packet`` when full decoded
    fields are required for an individual frame.

    Args:
        capture_id: ID of a currently loaded capture.
        start_time: Inclusive Unix epoch start time.
        end_time: Inclusive Unix epoch end time.
        limit: Maximum number of packets, from 1 through 1000.

    Returns:
        Requested range, normalized display filter, returned packet count,
        truncation flag, and packet summaries.
    """
    return packet_service.by_time_range(capture_id, start_time, end_time, limit)


def get_packets_between_frames(
    capture_id: str,
    start_frame: int,
    end_frame: int,
    limit: int = 1000,
) -> dict[str, Any]:
    """Retrieve packets in an inclusive Wireshark frame-number range.

    Both range boundaries are included. Results contain compact packet
    summaries so a caller can select individual frames for detailed dissection
    without decoding every field in the requested range.

    Args:
        capture_id: ID of a currently loaded capture.
        start_frame: Inclusive first frame number.
        end_frame: Inclusive last frame number.
        limit: Maximum number of packets, from 1 through 1000.

    Returns:
        Requested frame range, generated display filter, returned count,
        truncation flag, and packet summaries.
    """
    return packet_service.between_frames(
        capture_id, start_frame, end_frame, limit
    )


def get_related_packets(
    capture_id: str,
    packet_number: int,
    window_seconds: float = 10.0,
    limit: int = 500,
) -> dict[str, Any]:
    """Find packets related to a selected packet or connection event.

    Correlation prefers exact TCP/UDP stream or DNS/DHCP transaction IDs, then
    falls back to Wi-Fi client/BSSID, IP, or Ethernet endpoints. Endpoint-based
    results are explicitly marked as heuristic and bounded by time.

    Args:
        capture_id: ID of a currently loaded capture.
        packet_number: Positive, one-based source frame number.
        window_seconds: Seconds before and after the source packet to search;
            must be greater than zero and no more than 3600.
        limit: Maximum results to return, from 1 through 1000.

    Returns:
        Source-frame status, correlation method and confidence, generated
        display filter, truncation flag, and related packet summaries.
    """
    return packet_service.related(
        capture_id, packet_number, window_seconds, limit
    )


def get_packet_timeline(
    capture_id: str,
    filter_expression: str = "",
    limit: int = 1000,
) -> dict[str, Any]:
    """Generate a chronological timeline of packet events.

    The optional expression is a Wireshark display filter, not a capture
    filter. Events include deltas from the previous timestamp and elapsed time
    from the first returned event, making exchanges easier to inspect.

    Args:
        capture_id: ID of a currently loaded capture.
        filter_expression: Optional Wireshark display filter.
        limit: Maximum number of timeline events.

    Returns:
        Ordered events containing frame, timestamp, delta, elapsed time,
        protocols, textual summary, result count, and truncation status.
    """
    return packet_service.timeline(capture_id, filter_expression, limit)


def get_flow_packets(
    capture_id: str,
    flow_type: str,
    flow_id: int,
    limit: int = 1000,
) -> dict[str, Any]:
    """Retrieve packets belonging to a decoded transport or application flow.

    Flow IDs are TShark stream identifiers, not port numbers. TLS and HTTP
    flows use their underlying ``tcp.stream`` and additionally require the
    selected application protocol to be present on the packet.

    Args:
        capture_id: ID of a currently loaded capture.
        flow_type: One of tcp, udp, quic, tls, or http.
        flow_id: Non-negative TShark stream identifier.
        limit: Maximum results to return, from 1 through 1000.

    Returns:
        Normalized flow type and ID, generated display filter, packet count,
        truncation flag, and matching packet summaries.
    """
    return packet_service.flow(capture_id, flow_type, flow_id, limit)


def get_client_packets(
    capture_id: str,
    client_mac: str,
    limit: int = 1000,
) -> dict[str, Any]:
    """Retrieve IEEE 802.11 packets involving a Wi-Fi client MAC address.

    The query uses ``wlan.addr`` so it matches the client in any applicable
    transmitter, receiver, source, or destination address role. Hyphenated and
    colon-separated MAC input is accepted and normalized.

    Args:
        capture_id: ID of a currently loaded capture.
        client_mac: Client MAC address such as ``aa:bb:cc:dd:ee:ff``.
        limit: Maximum results to return, from 1 through 1000.

    Returns:
        Normalized client MAC, generated display filter, packet count,
        truncation flag, and matching packet summaries.
    """
    return packet_service.client_packets(capture_id, client_mac, limit)


def get_ap_packets(
    capture_id: str,
    bssid: str,
    limit: int = 1000,
) -> dict[str, Any]:
    """Retrieve IEEE 802.11 packets associated with an access-point BSSID.

    The query uses the decoded ``wlan.bssid`` field and therefore requires an
    IEEE 802.11 capture containing that field. Hyphenated and colon-separated
    MAC input is accepted and normalized before filtering.

    Args:
        capture_id: ID of a currently loaded capture.
        bssid: AP/BSSID MAC address such as ``aa:bb:cc:dd:ee:ff``.
        limit: Maximum results to return, from 1 through 1000.

    Returns:
        Normalized BSSID, generated display filter, packet count, truncation
        flag, and matching packet summaries.
    """
    return packet_service.ap_packets(capture_id, bssid, limit)


def get_transaction_packets(
    capture_id: str,
    transaction_type: str,
    transaction_key: str,
    limit: int = 1000,
) -> dict[str, Any]:
    """Retrieve packets belonging to a DNS, DHCP, TCP, EAPOL, or ARP exchange.

    DNS and DHCP keys may be decimal or ``0x``-prefixed transaction IDs; TCP
    uses a stream number. Because EAPOL and ARP lack a universal transaction
    number, their keys are a client MAC and IPv4 protocol address respectively.

    Args:
        capture_id: ID of a currently loaded capture.
        transaction_type: One of dns, dhcp, tcp, eapol, or arp.
        transaction_key: Protocol-specific ID, stream, MAC, or IPv4 address.
        limit: Maximum results to return, from 1 through 1000.

    Returns:
        Normalized transaction type and key, generated display filter, packet
        count, truncation flag, and matching packet summaries.
    """
    return packet_service.transaction(
        capture_id, transaction_type, transaction_key, limit
    )
