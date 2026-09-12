"""Capture path validation isolated from application workflows."""

from pathlib import Path

from wifi_pcap_mcp.config import SUPPORTED_OUTPUT_TYPES
from wifi_pcap_mcp.schemas.errors import FileAccessError, UnsupportedCaptureError


class CaptureFileSystem:
    def validate_input(self, file_path: str) -> Path:
        try:
            path = Path(file_path).expanduser().resolve()
        except (OSError, RuntimeError) as error:
            raise FileAccessError(f"Invalid file path: {file_path}") from error

        if not path.exists():
            raise FileAccessError(
                f"Capture file was not found: {file_path}",
                details={"file_path": file_path},
            )
        if not path.is_file():
            raise FileAccessError(
                f"Capture path is not a file: {file_path}",
                details={"file_path": file_path},
            )
        if path.suffix.lower() not in SUPPORTED_OUTPUT_TYPES:
            raise UnsupportedCaptureError(
                "Only .pcap and .pcapng files are supported",
                details={"suffix": path.suffix.lower()},
            )
        return path

    def validate_output(self, output_path: str) -> Path:
        destination = Path(output_path).expanduser().resolve()
        if destination.suffix.lower() not in SUPPORTED_OUTPUT_TYPES:
            raise UnsupportedCaptureError(
                "output_path must end with .pcap or .pcapng",
                details={"suffix": destination.suffix.lower()},
            )
        if not destination.parent.exists():
            raise FileAccessError(
                f"Output directory does not exist: {destination.parent}"
            )
        if not destination.parent.is_dir():
            raise FileAccessError(
                f"Output parent is not a directory: {destination.parent}"
            )
        return destination
