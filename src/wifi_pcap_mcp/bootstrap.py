"""Composition root for long-lived application dependencies."""

from wifi_pcap_mcp.application.services.analysis_service import AnalysisService
from wifi_pcap_mcp.application.services.capture_service import CaptureService
from wifi_pcap_mcp.application.services.export_service import ExportService
from wifi_pcap_mcp.application.services.packet_service import PacketService
from wifi_pcap_mcp.adapters.file_handlers.capture_repository import InMemoryCaptureRepository
from wifi_pcap_mcp.adapters.file_handlers.file_system import CaptureFileSystem
from wifi_pcap_mcp.adapters.tshark import TsharkClient

repository = InMemoryCaptureRepository()
file_system = CaptureFileSystem()
tshark = TsharkClient()

capture_service = CaptureService(repository, file_system)
packet_service = PacketService(repository, tshark)
analysis_service = AnalysisService(repository, tshark)
export_service = ExportService(repository, file_system, tshark)
