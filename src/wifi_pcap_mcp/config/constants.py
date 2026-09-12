"""Values shared across application layers."""

import re

SUPPORTED_KEY_TYPES = frozenset({"wep", "wpa-pwd", "wpa-psk", "tk", "msk"})
SUPPORTED_OUTPUT_TYPES = frozenset({".pcap", ".pcapng"})

MAC_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
FLOW_FIELDS = {
    "tcp": ("tcp.stream", None),
    "udp": ("udp.stream", None),
    "quic": ("quic.connection.number", "quic"),
    "tls": ("tcp.stream", "tls"),
    "http": ("tcp.stream", "http"),
}
