"""Capture lifecycle use cases."""

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from wifi_pcap_mcp.config import SUPPORTED_KEY_TYPES
from wifi_pcap_mcp.schemas.errors import ValidationError
from wifi_pcap_mcp.schemas.models import CaptureInfo, DecryptionKey
from wifi_pcap_mcp.schemas.ports import CaptureFileGateway
from wifi_pcap_mcp.schemas.repositories import CaptureRepository
from wifi_pcap_mcp.schemas.validation import normalize_capture_id


class CaptureService:
    def __init__(
        self,
        repository: CaptureRepository,
        file_system: CaptureFileGateway,
    ) -> None:
        self._repository = repository
        self._file_system = file_system

    def load(self, capture_id: str, file_path: str) -> dict[str, Any]:
        normalized_id = normalize_capture_id(capture_id)
        path = self._file_system.validate_input(file_path)
        stat = path.stat()
        candidate = CaptureInfo(
            capture_id=normalized_id,
            file_path=path,
            file_size=stat.st_size,
            modified_time=stat.st_mtime,
            loaded_at=datetime.now(UTC),
        )
        capture, created = self._repository.register(candidate)
        return {
            "status": "loaded" if created else "already_loaded",
            "capture_id": capture.capture_id,
            "file_path": str(capture.file_path),
            "file_name": capture.file_path.name,
            "file_size": capture.file_size,
        }

    def list_all(self) -> dict[str, Any]:
        captures = [
            {
                "capture_id": capture.capture_id,
                "file_path": str(capture.file_path),
                "file_name": capture.file_path.name,
                "file_size": capture.file_size,
                "modified_time": capture.modified_time,
                "loaded_at": capture.loaded_at.isoformat(),
                "revision": capture.revision,
                "decryption_configured": bool(capture.decryption_keys),
                "decryption_key_count": len(capture.decryption_keys),
            }
            for capture in self._repository.list_all()
        ]
        return {"status": "success", "capture_count": len(captures), "captures": captures}

    def unload(self, capture_id: str) -> dict[str, Any]:
        capture = self._repository.remove(capture_id)
        return {"status": "success", "capture_id": capture.capture_id, "unloaded": True}

    def reload(self, capture_id: str, clear_decryption_keys: bool = False) -> dict[str, Any]:
        existing = self._repository.get(capture_id)
        path = self._file_system.validate_input(str(existing.file_path))
        stat = path.stat()
        updated = replace(
            existing,
            file_path=path,
            file_size=stat.st_size,
            modified_time=stat.st_mtime,
            loaded_at=datetime.now(UTC),
            revision=existing.revision + 1,
            decryption_keys=() if clear_decryption_keys else existing.decryption_keys,
        )
        self._repository.save(updated)
        return {
            "status": "success",
            "capture_id": updated.capture_id,
            "file_path": str(updated.file_path),
            "file_size": updated.file_size,
            "loaded_at": updated.loaded_at.isoformat(),
            "revision": updated.revision,
            "reloaded": True,
        }

    def set_decryption_keys(
        self,
        capture_id: str,
        keys: list[dict[str, str]],
        replace_existing: bool = True,
    ) -> dict[str, Any]:
        existing = self._repository.get(capture_id)
        validated: list[DecryptionKey] = []
        for item in keys:
            key_type = item.get("key_type", "").strip().lower()
            value = item.get("value", "").strip()
            if key_type not in SUPPORTED_KEY_TYPES:
                raise ValidationError(
                    f"Unsupported decryption key type: {key_type}",
                    details={"supported_types": sorted(SUPPORTED_KEY_TYPES)},
                )
            if not value:
                raise ValidationError("Decryption key value must not be empty")
            if any(character in value for character in ('"', "\r", "\n", "\0")):
                raise ValidationError("Decryption key contains unsupported characters")
            validated.append(DecryptionKey(key_type=key_type, value=value))

        configured = (
            tuple(validated)
            if replace_existing
            else existing.decryption_keys + tuple(validated)
        )
        updated = replace(
            existing,
            decryption_keys=configured,
            revision=existing.revision + 1,
        )
        self._repository.save(updated)
        return {
            "status": "success",
            "capture_id": updated.capture_id,
            "decryption_configured": bool(configured),
            "decryption_key_count": len(configured),
            "decryption_key_types": sorted({key.key_type for key in configured}),
        }
