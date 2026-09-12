"""Stable application errors exposed through the MCP boundary."""

from typing import Any


class ApplicationError(Exception):
    """Base class for expected, client-safe failures."""

    code = "APPLICATION_ERROR"
    retryable = False

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ValidationError(ApplicationError):
    code = "VALIDATION_ERROR"


class CaptureNotFoundError(ApplicationError):
    code = "CAPTURE_NOT_FOUND"


class FileAccessError(ApplicationError):
    code = "FILE_ACCESS_ERROR"


class UnsupportedCaptureError(ApplicationError):
    code = "UNSUPPORTED_CAPTURE_FORMAT"


class DependencyNotFoundError(ApplicationError):
    code = "DEPENDENCY_NOT_FOUND"


class TsharkExecutionError(ApplicationError):
    code = "TSHARK_EXECUTION_ERROR"
    retryable = True


class ExportError(ApplicationError):
    code = "EXPORT_ERROR"
