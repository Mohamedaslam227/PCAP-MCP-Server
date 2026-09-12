"""Core immutable application models."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class DecryptionKey:
    """One Wireshark IEEE 802.11 decryption-key entry."""

    key_type: str
    value: str


@dataclass(frozen=True, slots=True)
class CaptureInfo:
    """Metadata and session configuration for a registered capture."""

    capture_id: str
    file_path: Path
    file_size: int
    modified_time: float
    loaded_at: datetime
    revision: int = 0
    decryption_keys: tuple[DecryptionKey, ...] = ()
