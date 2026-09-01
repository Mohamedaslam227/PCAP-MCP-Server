"""MCP server construction and runtime configuration."""

import logging
import sys

from mcp.server import MCPServer

from wifi_pcap_mcp.presentation.tools import register_tools


def create_server() -> MCPServer:
    server = MCPServer("WiFi PCAP Analyzer MCP")
    register_tools(server)
    return server


def main() -> None:
    # MCP stdio owns stdout; application logs must go to stderr.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    create_server().run(transport="stdio")
