"""The only layer that converts exceptions into MCP responses."""

from collections.abc import Callable
from functools import wraps
import logging
from typing import Any, ParamSpec, TypeVar
from uuid import uuid4

from wifi_pcap_mcp.schemas.errors import ApplicationError

from .responses import error_response, internal_error_response, success_response

P = ParamSpec("P")
R = TypeVar("R")
logger = logging.getLogger(__name__)


def tool_boundary(function: Callable[P, R]) -> Callable[P, dict[str, Any]]:
    """Convert every tool result and failure to the shared response envelope."""

    @wraps(function)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> dict[str, Any]:
        try:
            return success_response(function(*args, **kwargs))
        except ApplicationError as error:
            logger.info("Tool %s failed: %s", function.__name__, error.code)
            return error_response(error)
        except Exception:
            error_id = uuid4().hex
            logger.exception(
                "Unexpected failure in tool %s; error_id=%s",
                function.__name__,
                error_id,
            )
            return internal_error_response(error_id)

    return wrapped
