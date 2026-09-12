"""Capture-wide analysis use cases."""

from typing import Any

from wifi_pcap_mcp.application.utils.converters import as_float, as_int, epoch_to_iso, packet_timestamp
from wifi_pcap_mcp.schemas.errors import ValidationError
from wifi_pcap_mcp.schemas.models import CaptureInfo
from wifi_pcap_mcp.schemas.ports import PacketAnalyzer
from wifi_pcap_mcp.schemas.repositories import CaptureRepository


def metadata_number(
    metadata: dict[str, Any],
    key: str,
    converter: type[int] | type[float],
) -> int | float | None:
    raw_value = metadata.get(key)
    if raw_value is None:
        return None
    try:
        return converter(str(raw_value).split()[0])
    except (ValueError, TypeError):
        return None


def base_time_values(
    metadata: dict[str, Any],
) -> tuple[float | None, float | None, float | None]:
    return (
        metadata_number(metadata, "earliest_packet_time", float),
        metadata_number(metadata, "latest_packet_time", float),
        metadata_number(metadata, "capture_duration", float),
    )


class AnalysisService:
    def __init__(self, repository: CaptureRepository, tshark: PacketAnalyzer) -> None:
        self._repository = repository
        self._tshark = tshark

    def summary(self, capture_id: str) -> dict[str, Any]:
        capture_info = self._repository.get(capture_id)
        packet_count = 0
        protocols: set[str] = set()
        first_timestamp: float | None = None
        last_timestamp: float | None = None

        with self._tshark.open_capture(capture_info) as capture:
            for packet in capture:
                packet_count += 1
                protocols.update(
                    layer.layer_name
                    for layer in getattr(packet, "layers", [])
                    if getattr(layer, "layer_name", None)
                )
                timestamp = packet_timestamp(packet)
                if timestamp is not None:
                    first_timestamp = (
                        timestamp
                        if first_timestamp is None
                        else min(first_timestamp, timestamp)
                    )
                    last_timestamp = (
                        timestamp
                        if last_timestamp is None
                        else max(last_timestamp, timestamp)
                    )

        duration = (
            last_timestamp - first_timestamp
            if first_timestamp is not None and last_timestamp is not None
            else None
        )
        return {
            "capture_id": capture_info.capture_id,
            "packet_count": packet_count,
            "protocols": sorted(protocols),
            "start_time": first_timestamp,
            "end_time": last_timestamp,
            "duration": duration,
        }

    def metadata(self, capture_id: str) -> dict[str, Any]:
        capture = self._repository.get(capture_id)
        info = self._tshark.capinfos(capture)
        start, end, duration = base_time_values(info)
        interfaces = [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "description": item.get("description"),
                "link_type": item.get("encapsulation"),
                "snaplen": as_int(item.get("capture_length")),
                "timestamp_precision": item.get("time_precision"),
                "operating_system": item.get("operating_system"),
                "packet_count": as_int(item.get("number_of_packets")),
            }
            for item in info.get("interfaces", [])
        ]
        return {
            "capture_id": capture.capture_id,
            "file_path": str(capture.file_path),
            "file_name": capture.file_path.name,
            "file_format": info.get("file_type"),
            "file_size": metadata_number(info, "file_size", int),
            "encapsulation": info.get("file_encapsulation"),
            "link_layer_type": info.get("file_encapsulation"),
            "snaplen": info.get("packet_size_limit"),
            "timestamp_precision": info.get("file_timestamp_precision"),
            "packet_count": metadata_number(info, "number_of_packets", int),
            "capture_comments": info.get("capture_comment"),
            "capture_hardware": info.get("capture_hardware"),
            "capture_operating_system": info.get("capture_oper_sys"),
            "capture_application": info.get("capture_application"),
            "start_time_epoch": start,
            "start_time": epoch_to_iso(start),
            "end_time_epoch": end,
            "end_time": epoch_to_iso(end),
            "duration_seconds": duration,
            "interface_count": metadata_number(info, "number_of_interfaces_in_file", int),
            "interfaces": interfaces,
        }

    def statistics(self, capture_id: str) -> dict[str, Any]:
        capture = self._repository.get(capture_id)
        info = self._tshark.capinfos(capture)
        start, end, duration = base_time_values(info)
        sizes = (
            as_int(row["frame.len"])
            for row in self._tshark.iter_fields(capture, ["frame.len"])
        )
        valid_sizes = [size for size in sizes if size is not None]
        return {
            "capture_id": capture.capture_id,
            "total_packets": metadata_number(info, "number_of_packets", int),
            "total_bytes": metadata_number(info, "data_size", int),
            "file_size_bytes": metadata_number(info, "file_size", int),
            "duration_seconds": duration,
            "start_time_epoch": start,
            "end_time_epoch": end,
            "packets_per_second": metadata_number(info, "average_packet_rate", float),
            "bytes_per_second": metadata_number(info, "data_byte_rate", float),
            "bits_per_second": metadata_number(info, "data_bit_rate", float),
            "average_packet_size": metadata_number(info, "average_packet_size", float),
            "minimum_packet_size": min(valid_sizes, default=None),
            "maximum_packet_size": max(valid_sizes, default=None),
        }

    def interfaces(self, capture_id: str) -> dict[str, Any]:
        metadata = self.metadata(capture_id)
        return {
            "capture_id": metadata["capture_id"],
            "interface_count": metadata["interface_count"],
            "interfaces": metadata["interfaces"],
        }

    def time_range(self, capture_id: str, bucket_count: int = 20) -> dict[str, Any]:
        if bucket_count < 1 or bucket_count > 100:
            raise ValidationError("bucket_count must be between 1 and 100")
        capture = self._repository.get(capture_id)
        info = self._tshark.capinfos(capture)
        start, end, duration = base_time_values(info)
        distribution: list[dict[str, Any]] = []

        if start is not None and end is not None:
            effective_duration = max(end - start, 0.0)
            width = effective_duration / bucket_count if effective_duration > 0 else 1.0
            packet_counts = [0] * bucket_count
            byte_counts = [0] * bucket_count
            for row in self._tshark.iter_fields(capture, ["frame.time_epoch", "frame.len"]):
                timestamp = as_float(row["frame.time_epoch"])
                if timestamp is None:
                    continue
                packet_size = as_int(row["frame.len"]) or 0
                index = 0 if effective_duration == 0 else int((timestamp - start) / width)
                index = max(0, min(index, bucket_count - 1))
                packet_counts[index] += 1
                byte_counts[index] += packet_size

            for index in range(bucket_count):
                bucket_start = start + index * width
                bucket_end = end if index == bucket_count - 1 else bucket_start + width
                distribution.append(
                    {
                        "bucket": index,
                        "start_time_epoch": bucket_start,
                        "start_time": epoch_to_iso(bucket_start),
                        "end_time_epoch": bucket_end,
                        "end_time": epoch_to_iso(bucket_end),
                        "packet_count": packet_counts[index],
                        "byte_count": byte_counts[index],
                    }
                )

        return {
            "capture_id": capture.capture_id,
            "first_packet_epoch": start,
            "first_packet": epoch_to_iso(start),
            "last_packet_epoch": end,
            "last_packet": epoch_to_iso(end),
            "duration_seconds": duration,
            "strict_time_order": info.get("strict_time_order"),
            "bucket_count": bucket_count,
            "distribution": distribution,
        }

    def validate(self, capture_id: str, example_limit: int = 20) -> dict[str, Any]:
        if example_limit < 0 or example_limit > 100:
            raise ValidationError("example_limit must be between 0 and 100")
        capture = self._repository.get(capture_id)

        info = self._tshark.capinfos(capture)

        checks = {
            "malformed_packets": "_ws.malformed",
            "truncated_packets": "frame.cap_len < frame.len",
            "missing_packet_info": (
                "!frame.number || !frame.time_epoch || "
                "!frame.len || !frame.cap_len"
            ),
            "decode_failures": "_ws.expert.severity == 8388608",
            "unsupported_protocols": '_ws.expert.message contains "not implemented"',
        }
        issues: dict[str, Any] = {}
        for name, display_filter in checks.items():
            count, frames = self._find_issue_frames(capture, display_filter, example_limit)
            issues[name] = {"count": count, "example_frames": frames}

        chronological = str(info.get("strict_time_order", "")).lower() == "true"
        issues["invalid_timestamps"] = {
            "count": issues["missing_packet_info"]["count"],
            "strict_time_order": chronological,
        }
        serious_count = sum(
            issues[name]["count"]
            for name in (
                "malformed_packets",
                "truncated_packets",
                "missing_packet_info",
                "decode_failures",
            )
        )
        return {
            "capture_id": capture.capture_id,
            "valid": serious_count == 0,
            "readable": True,
            "packet_count": metadata_number(info, "number_of_packets", int),
            "strict_time_order": chronological,
            "issues_are_overlapping": True,
            "issues": issues,
        }

    def _find_issue_frames(
        self,
        capture: CaptureInfo,
        display_filter: str,
        example_limit: int,
    ) -> tuple[int, list[int]]:
        count = 0
        examples: list[int] = []
        for row in self._tshark.iter_fields(capture, ["frame.number"], display_filter):
            count += 1
            number = as_int(row["frame.number"])
            if number is not None and len(examples) < example_limit:
                examples.append(number)
        return count, examples
