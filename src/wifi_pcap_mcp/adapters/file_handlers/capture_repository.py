"""Thread-safe in-memory capture repository."""

from threading import RLock

from wifi_pcap_mcp.schemas.errors import CaptureNotFoundError
from wifi_pcap_mcp.schemas.models import CaptureInfo
from wifi_pcap_mcp.schemas.validation import normalize_capture_id


class InMemoryCaptureRepository:
    def __init__(self) -> None:
        self._captures: dict[str, CaptureInfo] = {}
        self._lock = RLock()

    def register(self, capture: CaptureInfo) -> tuple[CaptureInfo, bool]:
        with self._lock:
            existing = self._captures.get(capture.capture_id)
            if existing is not None:
                return existing, False
            self._captures[capture.capture_id] = capture
            return capture, True

    def get(self, capture_id: str) -> CaptureInfo:
        normalized = normalize_capture_id(capture_id)
        with self._lock:
            capture = self._captures.get(normalized)
        if capture is None:
            raise CaptureNotFoundError(
                f"Capture '{normalized}' is not loaded",
                details={"capture_id": normalized},
            )
        return capture

    def list_all(self) -> tuple[CaptureInfo, ...]:
        with self._lock:
            return tuple(sorted(self._captures.values(), key=lambda item: item.capture_id))

    def save(self, capture: CaptureInfo) -> CaptureInfo:
        with self._lock:
            if capture.capture_id not in self._captures:
                raise CaptureNotFoundError(
                    f"Capture '{capture.capture_id}' is not loaded",
                    details={"capture_id": capture.capture_id},
                )
            self._captures[capture.capture_id] = capture
        return capture

    def remove(self, capture_id: str) -> CaptureInfo:
        normalized = normalize_capture_id(capture_id)
        with self._lock:
            capture = self._captures.pop(normalized, None)
        if capture is None:
            raise CaptureNotFoundError(
                f"Capture '{normalized}' is not loaded",
                details={"capture_id": normalized},
            )
        return capture
