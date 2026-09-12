import unittest

from wifi_pcap_mcp.schemas.errors import ValidationError
from wifi_pcap_mcp.api.error_boundary import tool_boundary


class ToolBoundaryTests(unittest.TestCase):
    def test_wraps_success(self) -> None:
        @tool_boundary
        def example() -> dict[str, int]:
            return {"value": 7}

        self.assertEqual(
            example(),
            {"ok": True, "data": {"value": 7}, "error": None},
        )

    def test_maps_expected_error(self) -> None:
        @tool_boundary
        def example() -> None:
            raise ValidationError("bad input", details={"field": "limit"})

        response = example()
        self.assertFalse(response["ok"])
        self.assertEqual(
            response["error"],
            {
                "code": "VALIDATION_ERROR",
                "message": "bad input",
                "details": {"field": "limit"},
                "retryable": False,
            },
        )

    def test_hides_unexpected_error(self) -> None:
        @tool_boundary
        def example() -> None:
            raise RuntimeError("sensitive internal information")

        response = example()
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "INTERNAL_ERROR")
        self.assertNotIn("sensitive", response["error"]["message"])
        self.assertTrue(response["error"]["details"]["error_id"])


if __name__ == "__main__":
    unittest.main()
