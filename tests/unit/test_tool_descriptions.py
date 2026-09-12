import inspect
import unittest

from wifi_pcap_mcp.api.error_boundary import tool_boundary
from wifi_pcap_mcp.api.tools.registry import TOOL_FUNCTIONS


class ToolDescriptionTests(unittest.TestCase):
    def test_every_registered_tool_has_a_detailed_description(self) -> None:
        self.assertEqual(len(TOOL_FUNCTIONS), 23)
        for function in TOOL_FUNCTIONS:
            with self.subTest(tool=function.__name__):
                description = inspect.getdoc(function)
                self.assertIsNotNone(description)
                self.assertGreater(len(description or ""), 150)
                self.assertIn("Returns:", description or "")

    def test_error_boundary_preserves_mcp_metadata(self) -> None:
        for function in TOOL_FUNCTIONS:
            with self.subTest(tool=function.__name__):
                wrapped = tool_boundary(function)
                self.assertEqual(wrapped.__name__, function.__name__)
                self.assertEqual(inspect.getdoc(wrapped), inspect.getdoc(function))
                self.assertEqual(inspect.signature(wrapped), inspect.signature(function))


if __name__ == "__main__":
    unittest.main()
