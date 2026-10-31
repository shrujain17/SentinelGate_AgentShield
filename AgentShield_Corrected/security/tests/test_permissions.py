import unittest
from security.permissions import (
    SecurityVerdict,
    evaluate_permission,
    ALLOWED_TOOLS,
    REQUIRE_APPROVAL_TOOLS,
    ABSOLUTE_DENY_TOOLS,
)


class TestPermissions(unittest.TestCase):

    def test_allowed_tools(self):
        """Pre-approved tools must return ALLOW."""
        for tool in ["read_email", "read_document"]:
            result = evaluate_permission(tool)
            self.assertEqual(result.verdict, SecurityVerdict.ALLOW)
            self.assertFalse(result.is_absolute_deny)

    def test_absolute_deny_tools(self):
        """Absolute deny tools must return DENY."""
        result = evaluate_permission("read_private_file")
        self.assertEqual(result.verdict, SecurityVerdict.DENY)
        self.assertTrue(result.is_absolute_deny)

    def test_absolute_deny_cannot_be_overridden_by_approval(self):
        """User approval must NOT override absolute deny tools."""
        result = evaluate_permission("read_private_file", user_approved=True)
        self.assertEqual(result.verdict, SecurityVerdict.DENY)
        self.assertTrue(result.is_absolute_deny)

    def test_require_approval_without_approval(self):
        """High-impact tools must return REQUIRE_APPROVAL when not approved."""
        for tool in ["send_email", "delete_file"]:
            result = evaluate_permission(tool, user_approved=False)
            self.assertEqual(result.verdict, SecurityVerdict.REQUIRE_APPROVAL)
            self.assertFalse(result.is_absolute_deny)
            self.assertFalse(result.user_approved)

    def test_require_approval_with_approval(self):
        """High-impact tools must return ALLOW when user_approved=True."""
        for tool in ["send_email", "delete_file"]:
            result = evaluate_permission(tool, user_approved=True)
            self.assertEqual(result.verdict, SecurityVerdict.ALLOW)
            self.assertFalse(result.is_absolute_deny)
            self.assertTrue(result.user_approved)

    def test_unknown_tools_denied_by_default(self):
        """Unknown tools must return DENY (fail closed)."""
        unknown_tools = ["bash_command", "drop_database", "exfiltrate_data", "unknown_tool"]
        for tool in unknown_tools:
            result = evaluate_permission(tool)
            self.assertEqual(result.verdict, SecurityVerdict.DENY)
            self.assertTrue(result.is_absolute_deny)

    def test_unknown_tools_cannot_be_overridden_by_approval(self):
        """Approval cannot grant access to unknown tools."""
        result = evaluate_permission("malicious_unregistered_tool", user_approved=True)
        self.assertEqual(result.verdict, SecurityVerdict.DENY)
        self.assertTrue(result.is_absolute_deny)

    def test_invalid_and_empty_inputs_fail_closed(self):
        """Invalid inputs (None, empty, whitespace) must fail closed with DENY."""
        for invalid in [None, "", "   "]:
            result = evaluate_permission(invalid)
            self.assertEqual(result.verdict, SecurityVerdict.DENY)
            self.assertTrue(result.is_absolute_deny)


if __name__ == "__main__":
    unittest.main()
