"""Capture lifecycle MCP tools."""

from typing import Any

from wifi_pcap_mcp.bootstrap import capture_service


def load_capture(capture_id: str, file_path: str) -> dict[str, Any]:
    """Register a local packet-capture file for subsequent analysis.

    Call this before using tools that accept ``capture_id``. The server stores
    the resolved path and file metadata in memory, but does not copy, modify, or
    keep the capture open. Loading an existing ID is idempotent and reports
    ``already_loaded``.

    Args:
        capture_id: Non-empty session-unique name chosen by the caller, such as
            ``office_wifi``. Leading and trailing whitespace is removed.
        file_path: Local path to an existing ``.pcap`` or ``.pcapng`` file that
            is accessible to the MCP server process.

    Returns:
        Load status, normalized capture ID, resolved path, file name, and size.
    """
    return capture_service.load(capture_id, file_path)


def list_loaded_captures() -> dict[str, Any]:
    """List every capture registered in the current MCP server session.

    Use this to discover available capture IDs or confirm load/reload/unload
    operations. It reads only in-memory metadata and never rescans capture
    contents. Decryption-key values are never returned.

    Returns:
        Capture count and metadata for each capture, including path, size,
        modification/load times, revision, and decryption-key configuration.
    """
    return capture_service.list_all()


def unload_capture(capture_id: str) -> dict[str, Any]:
    """Remove a loaded capture from the current server session.

    This forgets the capture metadata and any configured decryption keys. It
    never deletes or changes the source PCAP/PCAPNG file.

    Args:
        capture_id: ID previously supplied to ``load_capture``.

    Returns:
        The removed capture ID and an ``unloaded`` confirmation flag.
    """
    return capture_service.unload(capture_id)


def reload_capture(
    capture_id: str,
    clear_decryption_keys: bool = False,
) -> dict[str, Any]:
    """Refresh a loaded capture after its source file changes.

    The tool verifies the original file again, updates its path, size,
    modification time, and load time, and increments the capture revision. It
    does not scan packets during the reload.

    Args:
        capture_id: ID of a currently loaded capture.
        clear_decryption_keys: When true, remove all keys stored for this
            capture. The default preserves them.

    Returns:
        Refreshed metadata, new revision number, and a ``reloaded`` flag.
    """
    return capture_service.reload(capture_id, clear_decryption_keys)


def set_decryption_keys(
    capture_id: str,
    keys: list[dict[str, str]],
    replace_existing: bool = True,
) -> dict[str, Any]:
    """Configure Wi-Fi decryption keys for later packet analysis.

    Keys exist only in server memory and are passed to TShark whenever the
    capture is read. Secret values are never included in tool responses or
    normal logs. Supported key types are ``wep``, ``wpa-pwd``, ``wpa-psk``,
    ``tk``, and ``msk``.

    Args:
        capture_id: ID of a currently loaded capture.
        keys: Key objects containing ``key_type`` and ``value``. For example,
            ``[{"key_type": "wpa-pwd", "value": "password:SSID"}]``.
        replace_existing: Replace existing keys when true; append when false.
            Passing an empty list with true clears all keys.

    Returns:
        Capture ID, configured key count, and key types. Values are omitted.
    """
    return capture_service.set_decryption_keys(capture_id, keys, replace_existing)
