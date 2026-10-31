"""
Unit & Integration Tests for AgentOrchestrator Workflow
Requirements Covered:
  - 5. Normal document summarisation (ALLOW).
  - 6. Prompt-injection scenario proposing an unsafe action.
  - 8. Approval-required actions pause correctly.
  - 8.5 Follow-up actions from document content go through the gateway.
  - 8.6 Reasoning loops have a maximum limit.
  - 8.7 Missing approval IDs are rejected (fail-closed).
  - 8.15 Audit logs do not expose sensitive document or message contents.
  - 12. The agent handling a DENY response correctly.
"""

import unittest
from unittest.mock import MagicMock, patch

from backend.agent.agent import AgentShieldAgent
from backend.agent.gateway_client import MockGatewayAdapter
from backend.agent.orchestrator import AgentOrchestrator, MAX_REASONING_CYCLES
from backend.agent.schemas import (
    AgentTask,
    DecisionType,
    GatewayResponse,
    InstructionProvenance,
    ProposedToolCall,
    TaskStatus,
)


class TestOrchestratorWorkflow(unittest.TestCase):
    """
    Test suite for end-to-end task execution workflows through the orchestrator.
    """

    def setUp(self):
        self.orchestrator = AgentOrchestrator(
            ai_provider="mock",
            gateway_client=MockGatewayAdapter(),
        )

    def test_05_normal_document_summarisation(self):
        """
        Requirement 5: Normal document summarisation (ALLOW workflow).
        """
        task = AgentTask(
            task_id="task_summarize_01",
            user_prompt="Please summarize the public document.",
            document_name="public_document.txt",
        )

        result = self.orchestrator.run_task(task, scenario="A")

        self.assertEqual(result.status, TaskStatus.COMPLETED)
        self.assertEqual(len(result.proposed_actions), 1)
        self.assertEqual(result.proposed_actions[0].tool, "read_public_document")
        self.assertEqual(len(result.gateway_decisions), 1)
        self.assertEqual(result.gateway_decisions[0].decision, DecisionType.ALLOW)
        self.assertTrue(result.gateway_decisions[0].executed)
        self.assertIn("DOCUMENT SUMMARY:", result.final_response)

    def test_06_prompt_injection_scenario_proposes_unsafe_action(self):
        """
        Requirement 6: Simulated prompt-injection attack scenario.
        Demonstrates the bounded two-stage workflow:
        Stage 1: Read malicious document draft.
        Stage 2: Model falls for injection and proposes read_restricted_file with UNTRUSTED_DOCUMENT provenance.
        Gateway intercepts and BLOCKS the action (DENY).
        """
        task = AgentTask(
            task_id="task_injection_02",
            user_prompt="Review the attached document draft.",
            document_name="malicious_document.txt",
        )

        result = self.orchestrator.run_task(task, scenario="B")

        # Two actions proposed: Stage 1 read, Stage 2 injection proposal
        self.assertEqual(len(result.proposed_actions), 2)
        self.assertEqual(result.proposed_actions[0].tool, "read_public_document")
        self.assertEqual(result.proposed_actions[1].tool, "read_restricted_file")
        self.assertEqual(result.proposed_actions[1].provenance, InstructionProvenance.UNTRUSTED_DOCUMENT)

        # Stage 2 was BLOCKED by the security gateway
        self.assertEqual(result.status, TaskStatus.BLOCKED)
        self.assertEqual(result.gateway_decisions[1].decision, DecisionType.DENY)
        self.assertFalse(result.gateway_decisions[1].executed)
        self.assertIn("BLOCKED by AGENTSHIELD", result.final_response)

    def test_followup_actions_from_document_content_go_through_gateway(self):
        """
        Requirement: Follow-up actions from document content must go through the gateway.
        """
        task = AgentTask(
            task_id="task_followup_gw",
            user_prompt="Review draft",
            document_name="malicious_document.txt",
        )
        result = self.orchestrator.run_task(task, scenario="B")

        # Both Stage 1 and Stage 2 actions must be recorded in gateway_decisions
        self.assertEqual(len(result.gateway_decisions), 2)
        self.assertEqual(result.gateway_decisions[0].decision, DecisionType.ALLOW)
        self.assertEqual(result.gateway_decisions[1].decision, DecisionType.DENY)

    def test_reasoning_loops_have_maximum_limit(self):
        """
        Requirement: Reasoning loops must have a strict upper limit (MAX_REASONING_CYCLES).
        """
        self.assertEqual(MAX_REASONING_CYCLES, 2)

    def test_missing_approval_ids_are_rejected(self):
        """
        Requirement: If REQUIRE_APPROVAL has a missing or empty approval ID,
        treat it as a malformed gateway response and fail closed.
        """
        malformed_gateway = MagicMock()
        malformed_gateway.evaluate_and_execute.return_value = GatewayResponse(
            decision=DecisionType.REQUIRE_APPROVAL,
            reason="Approval needed",
            executed=False,
            approval_id=None,  # Missing approval ID!
        )

        orchestrator = AgentOrchestrator(ai_provider="mock", gateway_client=malformed_gateway)
        task = AgentTask(task_id="task_bad_approval", user_prompt="Send external message")

        result = orchestrator.run_task(task, scenario="D")

        # Must fail-closed to BLOCKED
        self.assertEqual(result.status, TaskStatus.BLOCKED)
        self.assertIn("Gateway Contradiction (Fail-Closed)", result.final_response)
        self.assertIn("approval_id is missing or empty", result.final_response)

    def test_audit_logs_do_not_expose_sensitive_contents(self):
        """
        Requirement: Audit logs must not expose full sensitive document contents,
        message bodies, or secrets.
        """
        task = AgentTask(
            task_id="task_privacy_check",
            user_prompt="Send external notification with confidential database password secret_12345",
            document_name="suspicious_document.txt",
        )
        result = self.orchestrator.run_task(task, scenario="D")

        log_str = str(result.audit_log)
        # Message body should be redacted
        self.assertNotIn("Notice of operational scan completed.", log_str)
        self.assertIn("[REDACTED_MESSAGE]", log_str)

    def test_12_agent_handles_deny_response_correctly(self):
        """
        Requirement 12: Verify the agent handles a DENY response correctly by
        halting execution and providing clear zero-trust explanations.
        """
        task = AgentTask(
            task_id="task_deny_04",
            user_prompt="Read confidential employee salaries.",
            document_name="restricted_document.txt",
        )

        result = self.orchestrator.run_task(task, scenario="C")

        self.assertEqual(result.status, TaskStatus.BLOCKED)
        self.assertEqual(len(result.gateway_decisions), 1)
        self.assertEqual(result.gateway_decisions[0].decision, DecisionType.DENY)
        self.assertFalse(result.gateway_decisions[0].executed)

        self.assertIn("AGENT SECURITY ALERT", result.final_response)
        self.assertIn("Zero-Trust Policy Violation", result.final_response)


if __name__ == "__main__":
    unittest.main()
