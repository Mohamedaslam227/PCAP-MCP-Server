import unittest

from wifi_pcap_mcp.adapters.tshark.parsers import parse_capinfos


class CapinfosParserTests(unittest.TestCase):
    def test_includes_interface_blocks(self) -> None:
        output = """File type: Wireshark/... - pcapng
Number of packets: 12
Interface #0 info:
    Name: wlan0
    Encapsulation: IEEE 802.11
"""
        result = parse_capinfos(output)
        self.assertEqual(result["number_of_packets"], "12")
        self.assertEqual(
            result["interfaces"],
            [{"id": 0, "name": "wlan0", "encapsulation": "IEEE 802.11"}],
        )


if __name__ == "__main__":
    unittest.main()
