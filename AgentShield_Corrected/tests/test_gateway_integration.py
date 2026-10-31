"""
Unit & Integration Tests for AGENTSHIELD Gateway Adapters
Requirements Covered:
  - 1. Public tool cannot read restricted_document.txt.
  - 2. Public tool cannot access arbitrary filenames.
  - 7. Restricted-file access being denied by the mock gateway.
  - 8. Multiple approvals receive unique IDs.
  - 9. Approval tickets cannot be reused.
  - 10. Expired approval tickets are rejected.
  - 11. File-read failures do not return successful execution.
  - 12. HTTP 500 responses cannot authorise actions.
  - 13. Malformed gateway responses fail closed.
  - 14. Approval-resumption responses are validated.
"""

import json
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from backend.agent.agent import AgentShieldAgent
from backend.agent.gateway_client import (
    HttpGatewayClient,
    MockGatewayAdapter,
    get_gateway_client,
)
from backend.agent.schemas import (
    ApprovalResumeRequest,
    DecisionType,
    GatewayRequest,
    GatewayResponse,
    InstructionProvenance,
    TaskStatus,
)


class TestGatewayIntegration(unittest.TestCase):
    """
    Test suite for the Gateway Client contracts, allowlists, and zero-trust policies.
    """

    def setUp(self):
        self.mock_gateway = MockGatewayAdapter()

    def test_01_public_tool_cannot_read_restricted_document(self):
        """
        Requirement 1: Public document reading tool cannot read restricted_document.txt.
        """
        req = GatewayRequest(
            tool="read_public_document",
            arguments={"filename": "restricted_document.txt"},
            source="user_task",
            agent_id="agent_01",
            provenance=InstructionProvenance.USER_DIRECT,
        )

        resp = self.mock_gateway.evaluate_and_execute(req)

        self.assertEqual(resp.decision, DecisionType.DENY)
        self.assertFalse(resp.executed)
        self.assertIn("not in the public documents allowlist", resp.reason)
        self.assertIsNone(resp.result)

    def test_02_public_tool_cannot_access_arbitrary_filenames(self):
        """
        Requirement 2: Public tool cannot access arbitrary or unapproved filenames.
        """
        # Testing unauthorized arbitrary filename
        req_arbitrary = GatewayRequest(
            tool="read_public_document",
            arguments={"filename": "arbitrary_secret_file.conf"},
        )
        resp_arbitrary = self.mock_gateway.evaluate_and_execute(req_arbitrary)
        self.assertEqual(resp_arbitrary.decision, DecisionType.DENY)
        self.assertFalse(resp_arbitrary.executed)

        # Testing path traversal attempt
        req_traversal = GatewayRequest(
            tool="read_public_document",
            arguments={"filename": "../../windows/system32/config/SAM"},
        )
        resp_traversal = self.mock_gateway.evaluate_and_execute(req_traversal)
        self.assertEqual(resp_traversal.decision, DecisionType.DENY)
        self.assertFalse(resp_traversal.executed)

    def test_07_restricted_file_access_denied_by_gateway(self):
        """
        Requirement 7: Restricted-file access being denied by the mock gateway.
        """
        req = GatewayRequest(
            tool="read_restricted_file",
            arguments={"filename": "restricted_document.txt"},
            source="user_task",
            agent_id="agent_01",
            provenance=InstructionProvenance.USER_DIRECT,
        )

        resp = self.mock_gateway.evaluate_and_execute(req)

        self.assertEqual(resp.decision, DecisionType.DENY)
        self.assertFalse(resp.executed)
        self.assertIn("Zero-Trust Policy Violation", resp.reason)
        self.assertIsNone(resp.result)

    def test_08_multiple_approvals_receive_unique_ids(self):
        """
        Requirement 8: Multiple approval requests receive distinct, unique IDs.
        """
        req1 = GatewayRequest(
            tool="send_external_message",
            arguments={"recipient": "auditor1@external.io"},
        )
        req2 = GatewayRequest(
            tool="send_external_message",
            arguments={"recipient": "auditor2@external.io"},
        )

        resp1 = self.mock_gateway.evaluate_and_execute(req1)
        resp2 = self.mock_gateway.evaluate_and_execute(req2)

        self.assertEqual(resp1.decision, DecisionType.REQUIRE_APPROVAL)
        self.assertEqual(resp2.decision, DecisionType.REQUIRE_APPROVAL)
        self.assertIsNotNone(resp1.approval_id)
        self.assertIsNotNone(resp2.approval_id)
        # Unique IDs must not match
        self.assertNotEqual(resp1.approval_id, resp2.approval_id)

    def test_09_approval_tickets_cannot_be_reused(self):
        """
        Requirement 9: Approval tickets are single-use and cannot be reused.
        """
        req = GatewayRequest(
            tool="send_external_message",
            arguments={"recipient": "auditor@external.io"},
        )
        init_resp = self.mock_gateway.evaluate_and_execute(req)
        approval_id = init_resp.approval_id

        # First use: authorized
        resume_req = ApprovalResumeRequest(approval_id=approval_id, approved=True)
        first_resp = self.mock_gateway.resume_approval(resume_req)
        self.assertEqual(first_resp.decision, DecisionType.ALLOW)
        self.assertTrue(first_resp.executed)

        # Second use: must be rejected!
        second_resp = self.mock_gateway.resume_approval(resume_req)
        self.assertEqual(second_resp.decision, DecisionType.DENY)
        self.assertFalse(second_resp.executed)
        self.assertIn("not found or has already been consumed", second_resp.reason)

    def test_10_expired_approval_tickets_are_rejected(self):
        """
        Requirement 10: Expired approval tickets are rejected.
        """
        # Short TTL adapter (0.01 seconds)
        short_ttl_gw = MockGatewayAdapter(approval_ttl_seconds=0.01)
        req = GatewayRequest(
            tool="send_external_message",
            arguments={"recipient": "auditor@external.io"},
        )
        init_resp = short_ttl_gw.evaluate_and_execute(req)
        approval_id = init_resp.approval_id

        # Sleep past expiration
        time.sleep(0.03)

        resume_req = ApprovalResumeRequest(approval_id=approval_id, approved=True)
        expired_resp = short_ttl_gw.resume_approval(resume_req)

        self.assertEqual(expired_resp.decision, DecisionType.DENY)
        self.assertFalse(expired_resp.executed)
        self.assertIn("has expired", expired_resp.reason)

    def test_11_file_read_failures_do_not_return_successful_execution(self):
        """
        Requirement 11: File-read failures do not return successful execution.
        """
        with patch.object(self.mock_gateway, "_safe_read_sample_file", return_value=(None, "Simulated disk failure")):
            req = GatewayRequest(
                tool="read_public_document",
                arguments={"filename": "public_document.txt"},
            )
            resp = self.mock_gateway.evaluate_and_execute(req)

            # Must NOT return ALLOW or executed=True
            self.assertEqual(resp.decision, DecisionType.DENY)
            self.assertFalse(resp.executed)
            self.assertIn("Gateway File Read Failure", resp.reason)

    def test_12_http_500_responses_cannot_authorise_actions(self):
        """
        Requirement 12: An HTTP 500 error response cannot authorize actions,
        even if the response body contains contradictory ALLOW JSON.
        """
        remote_client = HttpGatewayClient(gateway_url="http://mock-gateway.local/execute")

        # Simulating HTTP 500 error from gateway
        http_500_err = urllib.error.HTTPError(
            url="http://mock-gateway.local/execute",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=None,
        )

        with patch("urllib.request.urlopen", side_effect=http_500_err):
            req = GatewayRequest(tool="read_public_document", arguments={"filename": "public_document.txt"})
            resp = remote_client.evaluate_and_execute(req)

            # Must FAIL-CLOSED (DENY)
            self.assertEqual(resp.decision, DecisionType.DENY)
            self.assertFalse(resp.executed)
            self.assertIn("HTTP Error 500", resp.reason)

    def test_13_malformed_gateway_responses_fail_closed(self):
        """
        Requirement 13: Malformed or contradictory gateway responses (e.g. ALLOW with executed=False) fail closed.
        """
        bad_response = GatewayResponse(
            decision=DecisionType.ALLOW,
            reason="Contradictory response",
            executed=False,
        )
        from backend.agent.schemas import validate_gateway_response
        error = validate_gateway_response(bad_response)
        self.assertIsNotNone(error)
        self.assertIn("ALLOW but executed is False", error)

    def test_14_approval_resumption_responses_are_validated(self):
        """
        Requirement 14: Contradictory approval resumption responses fail closed in the Agent.
        """
        bad_gateway = MagicMock()
        # Initial call requires approval
        bad_gateway.evaluate_and_execute.return_value = GatewayResponse(
            decision=DecisionType.REQUIRE_APPROVAL,
            reason="Need supervisor",
            executed=False,
            approval_id="approval_val_test",
        )
        # Resumption returns contradiction: DENY with executed=True
        bad_gateway.resume_approval.return_value = GatewayResponse(
            decision=DecisionType.DENY,
            reason="Blocked but executed!",
            executed=True,
        )

        agent = AgentShieldAgent(ai_provider="mock", gateway_client=bad_gateway)
        agent.run("Send external message", scenario="D")

        # Resume approval
        resumed = agent.resume_approval("approval_val_test", approved=True)

        # Must fail-closed to BLOCKED due to contradiction
        self.assertEqual(resumed.status, TaskStatus.BLOCKED)
        self.assertIn("Gateway Contradiction during approval resumption", resumed.final_response)


if __name__ == "__main__":
    unittest.main()
