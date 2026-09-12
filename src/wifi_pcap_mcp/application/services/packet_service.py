"""Packet filtering, dissection, lookup, and correlation use cases."""

from ipaddress import IPv4Address, ip_address
import logging
import math
import re
from typing import Any

from wifi_pcap_mcp.application.utils.converters import packet_timestamp
from wifi_pcap_mcp.schemas.errors import ValidationError
from wifi_pcap_mcp.schemas.ports import PacketAnalyzer
from wifi_pcap_mcp.schemas.repositories import CaptureRepository
from wifi_pcap_mcp.config import FLOW_FIELDS, MAC_PATTERN

logger = logging.getLogger(__name__)




class PacketService:
    def __init__(self, repository: CaptureRepository, tshark: PacketAnalyzer) -> None:
        self._repository = repository
        self._tshark = tshark

    def filter(
        self, capture_id: str, filter_expression: str, limit: int = 100
    ) -> dict[str, Any]:
        self._validate_limit(limit)
        normalized_filter = filter_expression.strip()
        if not normalized_filter:
            raise ValidationError("filter_expression must not be empty")

        capture_info = self._repository.get(capture_id)
        packets: list[dict[str, Any]] = []
        truncated = False
        with self._tshark.open_capture(
            capture_info, display_filter=normalized_filter
        ) as capture:
            for packet in capture:
                if len(packets) == limit:
                    truncated = True
                    break
                packets.append(self._packet_summary(packet))
        return {
            "capture_id": capture_info.capture_id,
            "filter_expression": normalized_filter,
            "packet_count": len(packets),
            "limit": limit,
            "truncated": truncated,
            "packets": packets,
        }

    def dissect(self, capture_id: str, packet_number: int) -> dict[str, Any]:
        if packet_number < 1:
            raise ValidationError("packet_number must be greater than zero")
        capture_info = self._repository.get(capture_id)
        with self._tshark.open_capture(
            capture_info, display_filter=f"frame.number == {packet_number}"
        ) as capture:
            packet = next(iter(capture), None)
            if packet is None:
                return {
                    "capture_id": capture_info.capture_id,
                    "packet_number": packet_number,
                    "found": False,
                    "packet": None,
                }

            layers: dict[str, dict[str, str | None]] = {}
            for layer in packet.layers:
                fields: dict[str, str | None] = {}
                for field_name in getattr(layer, "field_names", []):
                    try:
                        fields[field_name] = str(getattr(layer, field_name))
                    except (AttributeError, TypeError, ValueError):
                        logger.debug(
                            "Could not decode field %s", field_name, exc_info=True
                        )
                        fields[field_name] = None
                layers[layer.layer_name] = fields

            summary = self._packet_summary(packet)
            summary["layers"] = layers
            return {
                "capture_id": capture_info.capture_id,
                "packet_number": packet_number,
                "found": True,
                "packet": summary,
            }

    def get_by_number(self, capture_id: str, packet_number: int) -> dict[str, Any]:
        return self.dissect(capture_id, packet_number)

    def by_time_range(
        self,
        capture_id: str,
        start_time: float,
        end_time: float,
        limit: int = 1000,
    ) -> dict[str, Any]:
        self._validate_finite_number("start_time", start_time)
        self._validate_finite_number("end_time", end_time)
        if start_time > end_time:
            raise ValidationError("start_time must not be greater than end_time")

        expression = (
            f"frame.time_epoch >= {start_time:.9f} && "
            f"frame.time_epoch <= {end_time:.9f}"
        )
        result = self.filter(capture_id, expression, limit)
        result.update({"start_time": start_time, "end_time": end_time})
        return result

    def between_frames(
        self,
        capture_id: str,
        start_frame: int,
        end_frame: int,
        limit: int = 1000,
    ) -> dict[str, Any]:
        if start_frame < 1:
            raise ValidationError("start_frame must be greater than zero")
        if end_frame < start_frame:
            raise ValidationError("end_frame must not be less than start_frame")

        expression = f"frame.number >= {start_frame} && frame.number <= {end_frame}"
        result = self.filter(capture_id, expression, limit)
        result.update({"start_frame": start_frame, "end_frame": end_frame})
        return result

    def related(
        self,
        capture_id: str,
        packet_number: int,
        window_seconds: float = 10.0,
        limit: int = 500,
    ) -> dict[str, Any]:
        if packet_number < 1:
            raise ValidationError("packet_number must be greater than zero")
        self._validate_finite_number("window_seconds", window_seconds)
        if window_seconds <= 0 or window_seconds > 3600:
            raise ValidationError(
                "window_seconds must be greater than 0 and at most 3600"
            )
        self._validate_limit(limit)

        capture_info = self._repository.get(capture_id)
        with self._tshark.open_capture(
            capture_info, display_filter=f"frame.number == {packet_number}"
        ) as capture:
            source = next(iter(capture), None)
            if source is None:
                return {
                    "capture_id": capture_info.capture_id,
                    "packet_number": packet_number,
                    "found": False,
                    "correlation": None,
                    "packets": [],
                }
            timestamp = packet_timestamp(source)
            correlation_filter, method, confidence = self._correlation_filter(source)

        clauses = [f"frame.number == {packet_number}"]
        if correlation_filter:
            clauses.append(f"({correlation_filter})")
        expression = f"({' || '.join(clauses)})"
        if timestamp is not None:
            expression += (
                f" && frame.time_epoch >= {timestamp - window_seconds:.9f}"
                f" && frame.time_epoch <= {timestamp + window_seconds:.9f}"
            )

        result = self.filter(capture_id, expression, limit)
        result.update(
            {
                "packet_number": packet_number,
                "found": True,
                "window_seconds": window_seconds,
                "correlation": {
                    "method": method,
                    "confidence": confidence,
                    "source_timestamp": timestamp,
                },
            }
        )
        return result

    def timeline(
        self,
        capture_id: str,
        filter_expression: str = "",
        limit: int = 1000,
    ) -> dict[str, Any]:
        self._validate_limit(limit)
        capture_info = self._repository.get(capture_id)
        normalized_filter = filter_expression.strip()
        parameters = {"display_filter": normalized_filter} if normalized_filter else {}
        summaries: list[dict[str, Any]] = []
        truncated = False
        with self._tshark.open_capture(capture_info, **parameters) as capture:
            for packet in capture:
                if len(summaries) == limit:
                    truncated = True
                    break
                summaries.append(self._packet_summary(packet))

        summaries.sort(
            key=lambda packet: (
                packet["timestamp"] is None,
                packet["timestamp"] or 0.0,
                packet["frame_number"] or 0,
            )
        )
        first_timestamp = next(
            (item["timestamp"] for item in summaries if item["timestamp"] is not None),
            None,
        )
        previous_timestamp: float | None = None
        events: list[dict[str, Any]] = []
        for summary in summaries:
            timestamp = summary["timestamp"]
            event = dict(summary)
            event["delta_seconds"] = (
                timestamp - previous_timestamp
                if timestamp is not None and previous_timestamp is not None
                else None
            )
            event["elapsed_seconds"] = (
                timestamp - first_timestamp
                if timestamp is not None and first_timestamp is not None
                else None
            )
            if timestamp is not None:
                previous_timestamp = timestamp
            events.append(event)

        return {
            "capture_id": capture_info.capture_id,
            "filter_expression": normalized_filter or None,
            "event_count": len(events),
            "limit": limit,
            "truncated": truncated,
            "events": events,
        }

    def flow(
        self,
        capture_id: str,
        flow_type: str,
        flow_id: int,
        limit: int = 1000,
    ) -> dict[str, Any]:
        normalized_type = flow_type.strip().lower()
        specification = FLOW_FIELDS.get(normalized_type)
        if specification is None:
            raise ValidationError(
                "flow_type must be one of: tcp, udp, quic, tls, http"
            )
        if flow_id < 0:
            raise ValidationError("flow_id must be zero or greater")

        field_name, protocol_filter = specification
        expression = f"{field_name} == {flow_id}"
        if protocol_filter:
            expression = f"{protocol_filter} && {expression}"
        result = self.filter(capture_id, expression, limit)
        result.update({"flow_type": normalized_type, "flow_id": flow_id})
        return result

    def client_packets(
        self, capture_id: str, client_mac: str, limit: int = 1000
    ) -> dict[str, Any]:
        normalized_mac = self._normalize_mac(client_mac, "client_mac")
        result = self.filter(capture_id, f"wlan.addr == {normalized_mac}", limit)
        result["client_mac"] = normalized_mac
        return result

    def ap_packets(
        self, capture_id: str, bssid: str, limit: int = 1000
    ) -> dict[str, Any]:
        normalized_bssid = self._normalize_mac(bssid, "bssid")
        result = self.filter(capture_id, f"wlan.bssid == {normalized_bssid}", limit)
        result["bssid"] = normalized_bssid
        return result

    def transaction(
        self,
        capture_id: str,
        transaction_type: str,
        transaction_key: str,
        limit: int = 1000,
    ) -> dict[str, Any]:
        normalized_type = transaction_type.strip().lower()
        normalized_key = transaction_key.strip()
        if not normalized_key:
            raise ValidationError("transaction_key must not be empty")

        if normalized_type == "dns":
            identifier = self._parse_identifier(normalized_key, "DNS", 0xFFFF)
            expression = f"dns.id == 0x{identifier:x}"
            normalized_key = f"0x{identifier:x}"
        elif normalized_type == "dhcp":
            identifier = self._parse_identifier(normalized_key, "DHCP", 0xFFFFFFFF)
            expression = f"dhcp.id == 0x{identifier:x}"
            normalized_key = f"0x{identifier:x}"
        elif normalized_type == "tcp":
            identifier = self._parse_identifier(normalized_key, "TCP stream", None)
            expression = f"tcp.stream == {identifier}"
            normalized_key = str(identifier)
        elif normalized_type == "eapol":
            normalized_key = self._normalize_mac(normalized_key, "transaction_key")
            expression = f"eapol && wlan.addr == {normalized_key}"
        elif normalized_type == "arp":
            try:
                address = ip_address(normalized_key)
            except ValueError as error:
                raise ValidationError(
                    "transaction_key must be a valid IPv4 address for ARP"
                ) from error
            if not isinstance(address, IPv4Address):
                raise ValidationError(
                    "transaction_key must be an IPv4 address for ARP"
                )
            normalized_key = str(address)
            expression = (
                f"arp.src.proto_ipv4 == {normalized_key} || "
                f"arp.dst.proto_ipv4 == {normalized_key}"
            )
        else:
            raise ValidationError(
                "transaction_type must be one of: dns, dhcp, tcp, eapol, arp"
            )

        result = self.filter(capture_id, f"({expression})", limit)
        result.update(
            {
                "transaction_type": normalized_type,
                "transaction_key": normalized_key,
            }
        )
        return result

    def _correlation_filter(self, packet: Any) -> tuple[str | None, str, str]:
        tcp_stream = self._field_value(packet, "tcp", "stream")
        if tcp_stream and tcp_stream.isdigit():
            return f"tcp.stream == {tcp_stream}", "tcp.stream", "exact"

        dhcp_id = self._field_value(packet, "dhcp", "id")
        if dhcp_id:
            return f"dhcp.id == {dhcp_id}", "dhcp.id", "exact"

        dns_id = self._field_value(packet, "dns", "id")
        if dns_id:
            return f"dns.id == {dns_id}", "dns.id", "exact"

        udp_stream = self._field_value(packet, "udp", "stream")
        if udp_stream and udp_stream.isdigit():
            return f"udp.stream == {udp_stream}", "udp.stream", "exact"

        bssid = self._valid_packet_mac(self._field_value(packet, "wlan", "bssid"))
        wlan_addresses = [
            self._valid_packet_mac(self._field_value(packet, "wlan", name))
            for name in ("sa", "da", "ta", "ra")
        ]
        client = next(
            (
                address
                for address in wlan_addresses
                if address and address != bssid and not address.startswith("ff:ff")
            ),
            None,
        )
        if bssid and client:
            return (
                f"wlan.bssid == {bssid} && wlan.addr == {client}",
                "wlan.client_bssid",
                "heuristic",
            )

        for layer_name, display_name in (("ip", "ip"), ("ipv6", "ipv6")):
            source = self._valid_packet_ip(
                self._field_value(packet, layer_name, "src")
            )
            destination = self._valid_packet_ip(
                self._field_value(packet, layer_name, "dst")
            )
            if source and destination:
                return (
                    f"{display_name}.addr == {source} && "
                    f"{display_name}.addr == {destination}",
                    f"{display_name}.endpoints",
                    "heuristic",
                )

        source_mac = self._valid_packet_mac(self._field_value(packet, "eth", "src"))
        destination_mac = self._valid_packet_mac(
            self._field_value(packet, "eth", "dst")
        )
        if source_mac and destination_mac:
            return (
                f"eth.addr == {source_mac} && eth.addr == {destination_mac}",
                "ethernet.endpoints",
                "heuristic",
            )
        return None, "source_frame_only", "none"

    @staticmethod
    def _field_value(packet: Any, layer_name: str, field_name: str) -> str | None:
        layer = getattr(packet, layer_name, None)
        value = getattr(layer, field_name, None) if layer is not None else None
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized or None

    @staticmethod
    def _normalize_mac(value: str, field_name: str) -> str:
        normalized = value.strip().lower().replace("-", ":")
        if not MAC_PATTERN.fullmatch(normalized):
            raise ValidationError(
                f"{field_name} must be a MAC address such as aa:bb:cc:dd:ee:ff"
            )
        return normalized

    @staticmethod
    def _valid_packet_mac(value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.lower().replace("-", ":")
        return normalized if MAC_PATTERN.fullmatch(normalized) else None

    @staticmethod
    def _valid_packet_ip(value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return str(ip_address(value))
        except ValueError:
            return None

    @staticmethod
    def _parse_identifier(value: str, label: str, maximum: int | None) -> int:
        try:
            identifier = int(value, 0)
        except ValueError as error:
            raise ValidationError(f"{label} identifier must be an integer") from error
        if identifier < 0 or (maximum is not None and identifier > maximum):
            suffix = f" through {maximum}" if maximum is not None else " or greater"
            raise ValidationError(f"{label} identifier must be 0{suffix}")
        return identifier

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if limit < 1 or limit > 1000:
            raise ValidationError("limit must be between 1 and 1000")

    @staticmethod
    def _validate_finite_number(name: str, value: float) -> None:
        if not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValidationError(f"{name} must be a finite number")

    @staticmethod
    def _packet_summary(packet: Any) -> dict[str, Any]:
        frame_number = None
        try:
            frame_number = int(packet.frame_info.number)
        except (AttributeError, TypeError, ValueError):
            logger.debug("Packet has no valid frame number", exc_info=True)
        return {
            "frame_number": frame_number,
            "timestamp": packet_timestamp(packet),
            "protocols": [
                layer.layer_name
                for layer in getattr(packet, "layers", [])
                if getattr(layer, "layer_name", None)
            ],
            "summary": str(packet),
        }
