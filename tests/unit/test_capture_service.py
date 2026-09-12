from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from wifi_pcap_mcp.application.services.capture_service import CaptureService
from wifi_pcap_mcp.schemas.errors import CaptureNotFoundError, ValidationError
from wifi_pcap_mcp.adapters.file_handlers.capture_repository import InMemoryCaptureRepository
from wifi_pcap_mcp.adapters.file_handlers.file_system import CaptureFileSystem


class CaptureServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = CaptureService(
            InMemoryCaptureRepository(),
            CaptureFileSystem(),
        )
        self.temporary_directory = TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def make_capture(self, suffix: str = ".pcapng") -> Path:
        capture_file = self.directory / f"capture{suffix}"
        capture_file.write_bytes(b"capture")
        return capture_file

    def test_load_and_list_capture(self) -> None:
        loaded = self.service.load(" office ", str(self.make_capture()))
        captures = self.service.list_all()
        self.assertEqual(loaded["status"], "loaded")
        self.assertEqual(loaded["capture_id"], "office")
        self.assertEqual(captures["capture_count"], 1)

    def test_loading_same_id_is_idempotent(self) -> None:
        capture_file = self.make_capture(".pcap")
        self.service.load("office", str(capture_file))
        result = self.service.load("office", str(capture_file))
        self.assertEqual(result["status"], "already_loaded")

    def test_empty_capture_id_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            self.service.load(" ", str(self.make_capture(".pcap")))

    def test_unknown_capture_has_specific_error(self) -> None:
        with self.assertRaises(CaptureNotFoundError):
            self.service.unload("missing")


if __name__ == "__main__":
    unittest.main()
