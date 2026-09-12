"""External capability contracts required by application services."""

from contextlib import AbstractContextManager
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

from .models import CaptureInfo


class CaptureFileGateway(Protocol):
    def validate_input(self, file_path: str) -> Path: ...

    def validate_output(self, output_path: str) -> Path: ...


class PacketAnalyzer(Protocol):
    def open_capture(
        self,
        capture: CaptureInfo,
        **kwargs: Any,
    ) -> AbstractContextManager[Any]: ...

    def capinfos(self, capture: CaptureInfo) -> dict[str, Any]: ...

    def iter_fields(
        self,
        capture: CaptureInfo,
        fields: list[str],
        display_filter: str | None = None,
    ) -> Iterator[dict[str, str]]: ...

    def export(
        self,
        capture: CaptureInfo,
        filter_expression: str,
        destination: Path,
        *,
        overwrite: bool,
    ) -> None: ...
