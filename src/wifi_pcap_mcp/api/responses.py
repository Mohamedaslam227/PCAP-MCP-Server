"""Consistent MCP response construction."""

from typing import Any

from wifi_pcap_mcp.schemas.errors import ApplicationError


def success_response(data: Any) -> dict[str, Any]:
    return {"ok": True, "data": data, "error": None}


def error_response(error: ApplicationError) -> dict[str, Any]:
    return {
        "ok": False,
        "data": None,
        "error": {
            "code": error.code,
            "message": error.message,
            "details": error.details,
            "retryable": error.retryable,
        },
    }


def internal_error_response(error_id: str) -> dict[str, Any]:
    return {
        "ok": False,
        "data": None,
        "error": {
            "code": "INTERNAL_ERROR",
            "message": "An unexpected internal error occurred.",
            "details": {"error_id": error_id},
            "retryable": False,
        },
    }
