"""Pure parsers and conversion helpers for Wireshark output."""

import re
from typing import Any


def parse_capinfos(output: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    interfaces: list[dict[str, Any]] = []
    current_interface: dict[str, Any] | None = None
    interface_pattern = re.compile(r"^Interface #(\d+) info:$")

    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue

        match = interface_pattern.match(stripped)
        if match:
            current_interface = {"id": int(match.group(1))}
            interfaces.append(current_interface)
            continue
        if ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        normalized_key = key.strip().lower().replace(" ", "_").replace("-", "_")
        if current_interface is not None and raw_line[:1].isspace():
            current_interface[normalized_key] = value.strip()
        else:
            current_interface = None
            metadata[normalized_key] = value.strip()

    metadata["interfaces"] = interfaces
    return metadata
