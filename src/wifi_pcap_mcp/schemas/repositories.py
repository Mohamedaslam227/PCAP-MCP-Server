"""Repository contracts used by application services."""

from typing import Protocol

from .models import CaptureInfo


class CaptureRepository(Protocol):
    def register(self, capture: CaptureInfo) -> tuple[CaptureInfo, bool]: ...

    def get(self, capture_id: str) -> CaptureInfo: ...

    def list_all(self) -> tuple[CaptureInfo, ...]: ...

    def save(self, capture: CaptureInfo) -> CaptureInfo: ...

    def remove(self, capture_id: str) -> CaptureInfo: ...
