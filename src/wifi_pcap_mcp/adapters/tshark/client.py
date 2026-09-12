"""Resource-safe facade over PyShark, TShark, and Capinfos."""

import asyncio
import csv
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
import subprocess
import tempfile
from typing import Any
from uuid import uuid4

import pyshark

from wifi_pcap_mcp.schemas.errors import ExportError, TsharkExecutionError, ValidationError
from wifi_pcap_mcp.schemas.models import CaptureInfo, DecryptionKey

from .executable import creation_flags, find_capinfos, find_tshark
from .parsers import parse_capinfos


def decryption_parameters(keys: tuple[DecryptionKey, ...]) -> list[str]:
    if not keys:
        return []
    parameters = ["-o", "wlan.enable_decryption:TRUE"]
    for key in keys:
        parameters.extend(["-o", f'uat:80211_keys:"{key.key_type}","{key.value}"'])
    return parameters


class TsharkClient:
    def __init__(self, tshark_path: str | None = None) -> None:
        self._configured_path = tshark_path

    @property
    def executable(self) -> str:
        return self._configured_path or find_tshark()

    @contextmanager
    def open_capture(self, capture: CaptureInfo, **kwargs: Any) -> Iterator[Any]:
        existing = kwargs.pop("custom_parameters", [])
        if isinstance(existing, dict):
            parameters = [str(item) for pair in existing.items() for item in pair]
        else:
            parameters = list(existing)
        parameters.extend(decryption_parameters(capture.decryption_keys))
        if parameters:
            kwargs["custom_parameters"] = parameters

        event_loop = asyncio.new_event_loop()
        try:
            try:
                reader = pyshark.FileCapture(
                    input_file=str(capture.file_path),
                    tshark_path=self.executable,
                    eventloop=event_loop,
                    keep_packets=False,
                    use_json=True,
                    **kwargs,
                )
            except (OSError, RuntimeError) as error:
                raise TsharkExecutionError(
                    "TShark could not read the capture",
                    details={"capture_id": capture.capture_id},
                ) from error
            yield reader
        finally:
            if "reader" in locals():
                reader.close()
            if not event_loop.is_closed():
                event_loop.close()

    def capinfos(self, capture: CaptureInfo) -> dict[str, Any]:
        command = [find_capinfos(self.executable), "-A", "-M", "-S", str(capture.file_path)]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
                errors="replace",
                creationflags=creation_flags(),
            )
        except OSError as error:
            raise TsharkExecutionError("Capinfos could not be started") from error

        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "Unknown error"
            raise TsharkExecutionError(
                "Capinfos failed to inspect the capture",
                details={"exit_code": result.returncode, "reason": message},
            )
        return parse_capinfos(result.stdout)

    def iter_fields(
        self,
        capture: CaptureInfo,
        fields: list[str],
        display_filter: str | None = None,
    ) -> Iterator[dict[str, str]]:
        command = [
            self.executable,
            "-n",
            *decryption_parameters(capture.decryption_keys),
            "-r",
            str(capture.file_path),
        ]
        if display_filter:
            command.extend(["-Y", display_filter])
        command.append("-T")
        command.append("fields")
        for field in fields:
            command.extend(["-e", field])
        command.extend(
            [
                "-E",
                "header=n",
                "-E",
                "separator=/t",
                "-E",
                "quote=d",
                "-E",
                "occurrence=f",
            ]
        )

        stderr_file = tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace")
        process: subprocess.Popen[str] | None = None
        try:
            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=stderr_file,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=creation_flags(),
                )
            except OSError as error:
                raise TsharkExecutionError("TShark could not be started") from error

            if process.stdout is None:
                raise TsharkExecutionError("TShark stdout was unavailable")
            reader = csv.reader(process.stdout, delimiter="\t", quotechar='"')
            for values in reader:
                padded = values + [""] * (len(fields) - len(values))
                yield dict(zip(fields, padded, strict=False))

            return_code = process.wait()
            stderr_file.seek(0)
            reason = _safe_process_reason(capture, stderr_file.read().strip())
            if return_code != 0:
                raise TsharkExecutionError(
                    "TShark failed to inspect packet fields",
                    details={"exit_code": return_code, "reason": reason},
                )
        finally:
            if process is not None:
                if process.stdout is not None:
                    process.stdout.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait()
            stderr_file.close()

    def export(
        self,
        capture: CaptureInfo,
        filter_expression: str,
        destination: Path,
        *,
        overwrite: bool,
    ) -> None:
        normalized_filter = filter_expression.strip()
        if not normalized_filter:
            raise ValidationError("filter_expression must not be empty")
        if destination == capture.file_path:
            raise ValidationError("output_path cannot overwrite the source capture")
        if destination.exists() and not overwrite:
            raise ValidationError(f"Output file already exists: {destination}")

        temporary = destination.with_name(
            f".{destination.stem}.{uuid4().hex}.tmp{destination.suffix}"
        )
        command = [
            self.executable,
            "-n",
            *decryption_parameters(capture.decryption_keys),
            "-r",
            str(capture.file_path),
            "-Y",
            normalized_filter,
            "-w",
            str(temporary),
        ]
        try:
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    creationflags=creation_flags(),
                )
            except OSError as error:
                raise TsharkExecutionError("TShark export could not be started") from error
            if result.returncode != 0:
                raise ExportError(
                    "Filtered export failed",
                    details={
                        "exit_code": result.returncode,
                        "reason": _safe_process_reason(
                            capture,
                            result.stderr.strip() or "Unknown TShark error",
                        ),
                    },
                )
            if not temporary.is_file():
                raise ExportError("TShark finished without creating an output file")
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
def _safe_process_reason(capture: CaptureInfo, reason: str) -> str:
    """Avoid returning subprocess text that could echo configured keys."""
    if capture.decryption_keys:
        return "TShark reported an error while decryption was configured"
    return reason
