"""Validation shared by domain-facing adapters and services."""

from .errors import ValidationError


def normalize_capture_id(capture_id: str) -> str:
    normalized = capture_id.strip()
    if not normalized:
        raise ValidationError("capture_id must not be empty")
    return normalized
