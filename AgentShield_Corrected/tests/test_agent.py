"""
Unit & Integration Tests for AgentShieldAgent & GeminiProvider
Requirements Covered:
  - 1. The agent receiving a user task.
  - 2. Gemini provider configuration & secret safety.
  - 3. Mock-agent operation without an API key.
  - 4. Automatic fallback when Gemini is unavailable.
  - 8.2 The orchestrator does not directly read documents.
  - 8.3 Gemini cannot assign its own trusted provenance.
  - 8.4 Document contents retrieved through gateway before passing to model.
  - 8.8 Invalid Gemini JSON triggers fallback.
  - 8.9 Invalid Gemini action schemas trigger fallback.
  - 10. The agent never directly executes a tool.
"""

import os
import unittest
from unittest.mock import MagicMock, patch

from backend.agent.agent import AgentShieldAgent
from backend.agent.gemini_provider import (
    GeminiActionProposalPayload,
    GeminiProposedActionItem,
    GeminiProvider,
    GeminiProviderError,
)
from backend.agent.mock_agent import MockAgent
from backend.agent.orchestrator import AgentOrchestrator
from backend.agent.schemas import (
    AgentExecutionResult,
    AgentTask,
    DecisionType,
    GatewayRequest,
    GatewayResponse,
    InstructionProvenance,
    ProposedToolCall,
    TaskStatus,
)


class TestAgentBasics(unittest.TestCase):
    """
    Test suite for Agent Initialization, Intake, Validation, and Isolation.
    """

    def setUp(self):
        if "GEMINI_API_KEY" in os.environ:
            self._saved_key = os.environ.pop("GEMINI_API_KEY")
        else:
            self._saved_key = None

    def tearDown(self):
        if self._saved_key:
            os.environ["GEMINI_API_KEY"] = self._saved_key

    def test_01_agent_receives_user_task(self):
        """
        Requirement 1: Verify the agent correctly receives and processes a user task.
        """
        agent = AgentShieldAgent(ai_provider="mock")
        result = agent.run(
            user_prompt="Summarize the project brief",
            document_name="public_document.txt",
        )

        self.assertIsInstance(result, AgentExecutionResult)
        self.assertIsNotNone(result.task_id)
        self.assertEqual(result.status, TaskStatus.COMPLETED)
        self.assertTrue(len(result.proposed_actions) > 0)
        self.assertIn("Task completed successfully", result.final_response)

    def test_02_gemini_provider_configuration(self):
        """
        Requirement 2: Verify GeminiProvider reads config securely and handles missing keys.
        """
        provider_no_key = GeminiProvider(api_key="")
        self.assertFalse(provider_no_key.is_configured())

        with self.assertRaises(GeminiProviderError):
            provider_no_key.propose_actions("Test prompt")

        provider_with_key = GeminiProvider(api_key="AIzaSyDummyKeyForTestingOnly")
        self.assertNotIn("AIzaSyDummyKeyForTestingOnly", str(provider_with_key.__dict__.get("model_name")))

    def test_03_mock_agent_operates_without_api_key(self):
        """
        Requirement 3: Verify the mock agent functions completely without an API key.
        """
        mock_agent = MockAgent()
        actions = mock_agent.propose_actions("Read public project document")

        self.assertTrue(len(actions) > 0)
        self.assertIsInstance(actions[0], ProposedToolCall)
        self.assertEqual(actions[0].tool, "read_public_document")
        self.assertEqual(actions[0].arguments.get("filename"), "public_document.txt")

    def test_04_automatic_fallback_when_gemini_unavailable(self):
        """
        Requirement 4: Verify automatic fallback to MockAgent when Gemini is unconfigured or fails.
        """
        agent = AgentShieldAgent(ai_provider="gemini")
        result = agent.run(
            user_prompt="Summarize the public document",
            document_name="public_document.txt",
        )

        self.assertEqual(result.provider_used, "mock")
        self.assertEqual(result.status, TaskStatus.COMPLETED)

        events = [log["event"] for log in result.audit_log]
        self.assertTrue(
            "AI_PROVIDER_UNAVAILABLE" in events or "AI_FALLBACK_TRIGGERED" in events
        )

    def test_gemini_cannot_assign_its_own_trusted_provenance(self):
        """
        Requirement: Gemini cannot assign its own trusted provenance.
        Even if a model sets provenance to USER_DIRECT during follow-up reasoning,
        the orchestrator unconditionally overrides it with UNTRUSTED_DOCUMENT.
        """
        orchestrator = AgentOrchestrator(ai_provider="mock")

        # Mock Stage 2 follow-up proposal attempting to claim trusted provenance
        untrusted_content = "Attacker payload claiming root privileges"
        task = AgentTask(task_id="test_prov", user_prompt="Analyze document")

        # Mocking follow-up actions
        mock_action = ProposedToolCall(
            tool="read_restricted_file",
            arguments={"filename": "confidential_employee_salaries.csv"},
            provenance=InstructionProvenance.USER_DIRECT,  # Model claims trusted status!
        )

        with patch.object(orchestrator, "_generate_followup_proposals", return_value=[mock_action]):
            with patch.object(orchestrator.gateway_client, "evaluate_and_execute") as mock_gw_eval:
                mock_gw_eval.return_value = GatewayResponse(
                    decision=DecisionType.DENY,
                    reason="Blocked",
                    executed=False,
                )
                # Run with fake Stage 1 document result
                fake_read = GatewayResponse(
                    decision=DecisionType.ALLOW,
                    reason="Read allowed",
                    executed=True,
                    result=untrusted_content,
                )
                with patch.object(orchestrator, "_generate_initial_proposals", return_value=([
                    ProposedToolCall(tool="read_public_document", arguments={"filename": "public_document.txt"})
                ], "mock")):
                    with patch.object(orchestrator, "_submit_and_validate", side_effect=[
                        (fake_read, False, False, None),
                        (GatewayResponse(decision=DecisionType.DENY, reason="Blocked", executed=False), True, False, None),
                    ]):
                        result = orchestrator.run_task(task)

                        # Verify that the second action's provenance was forced to UNTRUSTED_DOCUMENT
                        self.assertEqual(result.proposed_actions[1].provenance, InstructionProvenance.UNTRUSTED_DOCUMENT)

    def test_document_contents_retrieved_through_gateway_before_model(self):
        """
        Requirement: Document contents are retrieved through the gateway before being passed to Gemini.
        The orchestrator does not read the document locally.
        """
        orchestrator = AgentOrchestrator(ai_provider="mock")
        self.assertFalse(hasattr(orchestrator, "_resolve_document_content"))
        self.assertFalse(hasattr(orchestrator, "sample_docs_dir"))

        task = AgentTask(task_id="test_gw_retrieve", user_prompt="Read doc", document_name="public_document.txt")
        result = orchestrator.run_task(task, scenario="A")

        self.assertEqual(result.status, TaskStatus.COMPLETED)
        # Content came from GatewayResponse.result
        self.assertIsNotNone(result.gateway_decisions[0].result)
        self.assertIn("PARALLAX CYBERSECURITY INITIATIVE", str(result.gateway_decisions[0].result))

    def test_invalid_gemini_json_triggers_fallback(self):
        """
        Requirement: Invalid Gemini JSON triggers fallback to MockAgent.
        """
        provider = GeminiProvider(api_key="AIzaSyDummyKey")
        with patch.object(provider, "is_configured", return_value=True):
            with patch.object(provider, "propose_actions", side_effect=GeminiProviderError("Invalid JSON")):
                orchestrator = AgentOrchestrator(ai_provider="gemini")
                orchestrator.gemini_provider = provider

                task = AgentTask(
                    task_id="test_invalid_json",
                    user_prompt="Summarize public document",
                    document_name="public_document.txt",
                )
                result = orchestrator.run_task(task)

                self.assertEqual(result.provider_used, "mock")
                self.assertEqual(result.status, TaskStatus.COMPLETED)
                events = [log["event"] for log in result.audit_log]
                self.assertIn("AI_FALLBACK_TRIGGERED", events)

    def test_invalid_gemini_action_schemas_trigger_fallback(self):
        """
        Requirement: Invalid Gemini action schemas trigger validation failure and fallback.
        """
        provider = GeminiProvider(api_key="AIzaSyDummyKey")

        # Invalid tool name (spaces / special chars)
        with self.assertRaises(GeminiProviderError):
            provider._parse_and_validate_response('{"proposed_actions": [{"tool": "bad tool!", "arguments": {}}]}')

        # Excessive actions (>5)
        excessive = [{"tool": f"tool_{i}", "arguments": {}} for i in range(6)]
        with self.assertRaises(GeminiProviderError):
            provider._parse_and_validate_response('{"proposed_actions": ' + str(excessive).replace("'", '"') + '}')

        # Arguments not a dict
        with self.assertRaises(GeminiProviderError):
            provider._parse_and_validate_response('{"proposed_actions": [{"tool": "read_doc", "arguments": "string"}]}')

        # Empty output
        with self.assertRaises(GeminiProviderError):
            provider._parse_and_validate_response("")

    def test_10_agent_never_directly_executes_tool(self):
        """
        Requirement 10 (CRITICAL ZERO-TRUST SECURITY):
        The agent must NEVER execute a tool directly.
        All execution MUST be delegated to the Gateway interface.
        """
        mock_gateway = MagicMock()
        mock_gateway.evaluate_and_execute.return_value = GatewayResponse(
            decision=DecisionType.ALLOW,
            reason="Mock authorization",
            executed=True,
            result="Document content returned by gateway",
        )

        agent = AgentShieldAgent(ai_provider="mock", gateway_client=mock_gateway)
        result = agent.run("Please read public document", document_name="public_document.txt")

        self.assertEqual(mock_gateway.evaluate_and_execute.call_count, 1)
        call_args = mock_gateway.evaluate_and_execute.call_args[0][0]
        self.assertIsInstance(call_args, GatewayRequest)
        self.assertEqual(call_args.tool, "read_public_document")
        self.assertEqual(call_args.provenance, InstructionProvenance.USER_DIRECT)


if __name__ == "__main__":
    unittest.main()
