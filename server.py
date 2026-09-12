"""Backward-compatible launcher for the packaged MCP server."""

from pathlib import Path
import sys

# Support `python server.py` before the project has been installed.
source_directory = Path(__file__).resolve().parent / "src"
if str(source_directory) not in sys.path:
    sys.path.insert(0, str(source_directory))

from wifi_pcap_mcp.server import create_server, main  # noqa: E402

mcp = create_server()

if __name__ == "__main__":
    main()
