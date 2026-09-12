# WiFi PCAP Analyzer MCP

A local MCP server for inspecting Wi-Fi PCAP and PCAPNG files through
PyShark, TShark, and Capinfos.

## Architecture

```text
MCP API tools
        ↓
application services
        ↓
domain contracts and models
        ↓
filesystem, repository, and TShark adapters
```

The code uses a standard `src` package layout:

```text
src/wifi_pcap_mcp/
├── server.py                 Composition and MCP runtime
├── api/                     MCP tools, responses, and the error boundary
├── application/services/    Capture, packet, analysis, and export workflows
├── domain/                  Models, repository contracts, typed errors
├── adapters/                Filesystem, repository, TShark, and Capinfos adapters
└── config/                  Shared configuration constants
```

Every registered tool passes through `api/error_boundary.py`. Expected
application failures receive stable error codes, while unexpected failures are
logged to stderr with an error ID and returned without a traceback. Successful
and failed calls share this envelope:

```json
{"ok": true, "data": {}, "error": null}
```

The repository stores capture metadata and keys, not live PyShark readers. A
fresh reader is created and closed for each analysis call.

For a full tool catalog, end-to-end prompts, useful Wireshark filters, and
structured error tests, see [MCP Server Testing Guide](docs/MCP_TESTING.md).

## Prerequisites

- VS Code with GitHub Copilot and GitHub Copilot Chat
- Python 3.13 for Windows
- Wireshark with TShark installed

On Windows, install Wireshark with **TShark** selected. Create the virtual
environment and install the project:

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe" -m venv .venv-windows
& ".\.venv-windows\Scripts\python.exe" -m pip install -e .
```

The server checks `PATH`, `TSHARK_PATH`, and the standard
`C:\Program Files\Wireshark\tshark.exe` location, so TShark does not have to be
on `PATH` when Wireshark is installed in its default directory.

## Connect to GitHub Copilot in VS Code

The parent workspace already contains `.vscode/mcp.json`. Open the `MCP` folder
(the parent of this directory) in VS Code, then:

1. Open the Command Palette with `Ctrl+Shift+P`.
2. Run **MCP: List Servers**.
3. Select **wifiPcapAnalyzer**, then select **Start**.
4. Review and accept VS Code's trust prompt.
5. Open Copilot Chat, select **Agent**, and use **Configure Tools** to confirm
   that `load_capture`, `get_summary`, `filter_packets`, and `dissect_packet`
   are enabled.

The workspace configuration launches
`.venv-windows\Scripts\python.exe` directly. It does not use WSL.

## Try it

Use an absolute Windows path so the server can find the capture reliably:

```text
Load the Wi-Fi capture at C:\captures\sample.pcap with capture ID sample-wifi,
summarize it, and identify the most useful Wireshark display filters for
investigating it.
```

Copilot should first call `load_capture`. That tool returns a `capture_id`.
Copilot can pass that ID to the other tools.

## Troubleshooting

- **Server does not start:** run **MCP: List Servers** >
  **wifiPcapAnalyzer** > **Show Output**.
- **`tshark` not found:** install Wireshark/TShark, or set `TSHARK_PATH` to the
  full path of `tshark.exe` before starting VS Code.
- **Python path changed:** recreate `.venv-windows`, then update `command` in
  `.vscode/mcp.json` if the workspace was moved.
- **Tools changed but Copilot shows the old list:** run **MCP: Reset Cached
  Tools**, then restart the server.

## Run without Copilot

From this directory, start the stdio server with either command:

```powershell
& ".\.venv-windows\Scripts\python.exe" server.py
& ".\.venv-windows\Scripts\wifi-pcap-mcp.exe"
```

The command appears to wait without printing anything; that is normal for a
stdio MCP server because it is waiting for an MCP client.
