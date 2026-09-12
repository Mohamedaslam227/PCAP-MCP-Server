"""Filtered capture export use case."""

from typing import Any

from wifi_pcap_mcp.schemas.ports import CaptureFileGateway, PacketAnalyzer
from wifi_pcap_mcp.schemas.repositories import CaptureRepository


class ExportService:
    def __init__(
        self,
        repository: CaptureRepository,
        file_system: CaptureFileGateway,
        tshark: PacketAnalyzer,
    ) -> None:
        self._repository = repository
        self._file_system = file_system
        self._tshark = tshark

    def export_filtered(
        self,
        capture_id: str,
        filter_expression: str,
        output_path: str,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        capture = self._repository.get(capture_id)
        destination = self._file_system.validate_output(output_path)
        self._tshark.export(
            capture,
            filter_expression,
            destination,
            overwrite=overwrite,
        )
        return {
            "status": "success",
            "capture_id": capture.capture_id,
            "filter_expression": filter_expression.strip(),
            "output_path": str(destination),
            "file_name": destination.name,
            "file_size": destination.stat().st_size,
        }
