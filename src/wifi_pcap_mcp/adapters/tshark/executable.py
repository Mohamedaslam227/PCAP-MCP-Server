"""Wireshark command-line executable discovery."""

import os
from pathlib import Path
import shutil

from wifi_pcap_mcp.schemas.errors import DependencyNotFoundError


def find_tshark() -> str:
    candidates = [os.environ.get("TSHARK_PATH"), shutil.which("tshark")]
    if os.name == "nt":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        candidates.append(str(Path(program_files) / "Wireshark" / "tshark.exe"))

    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())

    raise DependencyNotFoundError(
        "TShark was not found. Install Wireshark, add TShark to PATH, "
        "or set TSHARK_PATH."
    )


def find_capinfos(tshark_path: str) -> str:
    tshark = Path(tshark_path)
    executable_name = "capinfos.exe" if tshark.suffix.lower() == ".exe" else "capinfos"
    adjacent = tshark.with_name(executable_name)
    if adjacent.is_file():
        return str(adjacent)

    discovered = shutil.which(executable_name)
    if discovered:
        return str(Path(discovered).resolve())

    raise DependencyNotFoundError(
        "Capinfos was not found. Install Wireshark command-line tools or add "
        "their directory to PATH."
    )


def creation_flags() -> int:
    import subprocess

    return getattr(subprocess, "CREATE_NO_WINDOW", 0)
