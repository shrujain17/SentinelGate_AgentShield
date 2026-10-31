"""
AGENTSHIELD - AI Agent Orchestration Module
Agent Orchestrator (Person 1: Agent Orchestration)

Coordinates the bounded two-stage zero-trust agent workflow:
  Stage 1: Intake user task & propose initial tool actions (USER_DIRECT provenance).
  Stage 2: Receive gateway-authorized document contents, pass to AI as UNTRUSTED DATA,
           and submit any follow-up proposals (UNTRUSTED_DOCUMENT provenance) back to Gateway.
  Stage 3: Isolated text-only summarization with zero tool privileges.

CRITICAL SECURITY MANDATES:
  1. Zero Direct Tool or File Execution: Agent has zero local file/tool execution capabilities.
  2. Bounded Reasoning Cycles: Strict MAX_REASONING_CYCLES=2 to prevent infinite loops.
  3. Trusted Provenance Determination: Provenance is set by application execution context.
     The model can NEVER assign its own trusted status.
  4. Shared Fail-Closed Validation: Contradictory gateway responses fail closed.
  5. Audit Log Privacy: Sensitive message bodies, document texts, and secrets are redacted.
"""

from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional

from backend.agent.gateway_client import (
    MockGatewayAdapter,
    SecurityGatewayInterface,
    get_gateway_client,
)
from backend.agent.gemini_provider import GeminiProvider, GeminiProviderError
from backend.agent.mock_agent import MockAgent
from backend.agent.schemas import (
    AgentExecutionResult,
    AgentTask,
    DecisionType,
    GatewayRequest,
    GatewayResponse,
    InstructionProvenance,
    ProposedToolCall,
    TaskStatus,
    validate_gateway_response,
)

logger = logging.getLogger("agentshield.orchestrator")

MAX_REASONING_CYCLES = 2


class AgentOrchestrator:
    """
    Coordinates agent task intake, reasoning provider dispatch, gateway mediation,
    and post-execution summarization under zero-trust constraints.
    """

    def __init__(
        self,
        ai_provider: Optional[str] = None,
        gateway_client: Optional[SecurityGatewayInterface] = None,
        agent_id: str = "agent_01",
    ):
        self.agent_id = agent_id

        env_provider = os.environ.get("AI_PROVIDER", "mock").lower()
        self.preferred_provider = (ai_provider or env_provider).lower()

        self.gemini_provider = GeminiProvider(agent_id=self.agent_id)
        self.mock_agent = MockAgent(default_agent_id=self.agent_id)
        self.gateway_client = gateway_client or get_gateway_client()

    def run_task(
        self,
        task: AgentTask,
        scenario: Optional[str] = None,
    ) -> AgentExecutionResult:
        """
        Execute the end-to-end zero-trust agent workflow with bounded reasoning cycles.
        """
        audit_log: List[Dict[str, Any]] = []
        start_time = datetime.now(timezone.utc).isoformat()

        self._audit(
            audit_log,
            event="TASK_RECEIVED",
            details={
                "task_id": task.task_id,
                "user_prompt_preview": task.user_prompt[:80],
                "document_reference": task.document_name,
                "start_time": start_time,
            },
        )

        all_proposed_actions: List[ProposedToolCall] = []
        all_gateway_decisions: List[GatewayResponse] = []
        tool_results: List[Dict[str, Any]] = []
        blocked_reasons: List[str] = []
        paused_for_approval = False
        active_approval_id: Optional[str] = None
        final_status = TaskStatus.COMPLETED
        returned_document_content: Optional[str] = None
        provider_used = "mock"

        # -------------------------------------------------------------
        # STAGE 1: Initial Tool Proposal (Application Context: USER_DIRECT)
        # For uploaded documents, a server-issued scan ID has already caused
        # the API to verify the extraction hash and ALLOW/reviewer state. Do not
        # re-open a sample file by name; consume only that gateway-released text.
        # -------------------------------------------------------------
        if task.document_content is not None:
            stage1_actions: List[ProposedToolCall] = []
            provider_used = "gemini" if self.preferred_provider == "gemini" and self.gemini_provider.is_configured() else "mock"
            returned_document_content = task.document_content
            self._audit(
                audit_log,
                event="SCANNED_UPLOAD_RECEIVED_AS_UNTRUSTED_DATA",
                details={"document_reference": task.document_name, "content_length": len(task.document_content)},
            )
        else:
            stage1_actions, provider_used = self._generate_initial_proposals(
                prompt=task.user_prompt,
                document_reference=task.document_name,
                scenario=scenario,
                audit_log=audit_log,
            )

        if not stage1_actions and task.document_content is None:
            self._audit(audit_log, event="NO_ACTIONS_PROPOSED", details={})
            return AgentExecutionResult(
                task_id=task.task_id,
                status=TaskStatus.COMPLETED,
                provider_used=provider_used,
                proposed_actions=[],
                gateway_decisions=[],
                final_response="Task analyzed. No external tool invocations were required.",
                audit_log=audit_log,
            )

        # Process Stage 1 Actions through Gateway
        for action in stage1_actions:
            # Provenance is assigned by application context (USER_DIRECT), never trusting model
            action.provenance = InstructionProvenance.USER_DIRECT
            all_proposed_actions.append(action)

            decision_resp, is_blocked, is_paused, approval_id = self._submit_and_validate(
                action=action,
                provenance=InstructionProvenance.USER_DIRECT,
                audit_log=audit_log,
                blocked_reasons=blocked_reasons,
            )
            all_gateway_decisions.append(decision_resp)

            if is_blocked:
                final_status = TaskStatus.BLOCKED
                break
            if is_paused:
                final_status = TaskStatus.PAUSED_FOR_APPROVAL
                paused_for_approval = True
                active_approval_id = approval_id
                break

            # If action was allowed and executed, record result
            tool_results.append({
                "tool": action.tool,
                "arguments": self._sanitize_dict(action.arguments),
                "result_preview": str(decision_resp.result)[:100] if decision_resp.result else None,
            })

            # Check if gateway authorized and executed a document read
            if action.tool in ("read_public_document", "summarize_public_document") and decision_resp.result:
                returned_document_content = str(decision_resp.result)

        # -------------------------------------------------------------
        # STAGE 2: Document Reasoning Workflow (Follow-up Actions)
        # Bounded by MAX_REASONING_CYCLES=2 to prevent infinite loops.
        # -------------------------------------------------------------
        if final_status == TaskStatus.COMPLETED and returned_document_content:
            self._audit(
                audit_log,
                event="STAGE_2_DOCUMENT_REASONING_STARTED",
                details={"content_length": len(returned_document_content)},
            )

            stage2_actions = self._generate_followup_proposals(
                user_prompt=task.user_prompt,
                untrusted_content=returned_document_content,
                scenario=scenario,
                audit_log=audit_log,
            )

            for followup_action in stage2_actions:
                # CRITICAL SECURITY FIX: Any action derived from untrusted document
                # content is UNCONDITIONALLY assigned UNTRUSTED_DOCUMENT provenance!
                followup_action.provenance = InstructionProvenance.UNTRUSTED_DOCUMENT
                all_proposed_actions.append(followup_action)

                decision_resp, is_blocked, is_paused, approval_id = self._submit_and_validate(
                    action=followup_action,
                    provenance=InstructionProvenance.UNTRUSTED_DOCUMENT,
                    audit_log=audit_log,
                    blocked_reasons=blocked_reasons,
                )
                all_gateway_decisions.append(decision_resp)

                if is_blocked:
                    final_status = TaskStatus.BLOCKED
                    break
                if is_paused:
                    final_status = TaskStatus.PAUSED_FOR_APPROVAL
                    paused_for_approval = True
                    active_approval_id = approval_id
                    break

                tool_results.append({
                    "tool": followup_action.tool,
                    "arguments": self._sanitize_dict(followup_action.arguments),
                    "result_preview": str(decision_resp.result)[:100] if decision_resp.result else None,
                })

        # -------------------------------------------------------------
        # STAGE 3: Isolated Text-Only Summarization
        # -------------------------------------------------------------
        summary_text = None
        if final_status == TaskStatus.COMPLETED and returned_document_content:
            summary_text = self._summarize_content(
                user_prompt=task.user_prompt,
                content=returned_document_content,
                provider_used=provider_used,
                audit_log=audit_log,
            )

        final_response_text = self.mock_agent.generate_final_response(
            user_prompt=task.user_prompt,
            tool_results=tool_results,
            blocked_reasons=blocked_reasons,
            summary_text=summary_text,
            paused_for_approval=paused_for_approval,
            approval_id=active_approval_id,
        )

        self._audit(
            audit_log,
            event="TASK_FINISHED",
            details={
                "final_status": final_status.value,
                "paused_for_approval": paused_for_approval,
                "approval_id": active_approval_id,
                "actions_count": len(all_proposed_actions),
            },
        )

        return AgentExecutionResult(
            task_id=task.task_id,
            status=final_status,
            provider_used=provider_used,
            proposed_actions=all_proposed_actions,
            gateway_decisions=all_gateway_decisions,
            final_response=final_response_text,
            approval_id=active_approval_id,
            audit_log=audit_log,
        )

    def _submit_and_validate(
        self,
        action: ProposedToolCall,
        provenance: InstructionProvenance,
        audit_log: List[Dict[str, Any]],
        blocked_reasons: List[str],
    ) -> tuple[GatewayResponse, bool, bool, Optional[str]]:
        """
        Submit a proposed action to the gateway and apply shared gateway response validation.
        Returns: (decision_resp, is_blocked, is_paused, approval_id)
        """
        self._audit(
            audit_log,
            event="SUBMITTING_TO_GATEWAY",
            details={
                "tool": action.tool,
                "arguments": self._sanitize_dict(action.arguments),
                "rationale": action.rationale,
                "provenance": provenance.value,
            },
        )

        gateway_req = GatewayRequest(
            tool=action.tool,
            arguments=action.arguments,
            source=action.source,
            agent_id=self.agent_id,
            provenance=provenance,
        )

        decision_resp = self.gateway_client.evaluate_and_execute(gateway_req)

        # Shared Gateway Response Validation
        val_error = validate_gateway_response(decision_resp)
        if val_error:
            logger.error(f"Gateway response validation contradiction: {val_error}")
            self._audit(
                audit_log,
                event="GATEWAY_VALIDATION_CONTRADICTION",
                details={"error": val_error, "decision": decision_resp.decision.value},
            )
            blocked_reasons.append(f"Gateway Contradiction (Fail-Closed): {val_error}")
            return decision_resp, True, False, None

        self._audit(
            audit_log,
            event="GATEWAY_DECISION_RECEIVED",
            details={
                "tool": action.tool,
                "decision": decision_resp.decision.value,
                "executed": decision_resp.executed,
                "reason": decision_resp.reason,
                "approval_id": decision_resp.approval_id,
            },
        )

        if decision_resp.decision == DecisionType.ALLOW:
            return decision_resp, False, False, None

        elif decision_resp.decision == DecisionType.DENY:
            blocked_reasons.append(
                f"Action '{action.tool}' was DENIED by AGENTSHIELD: {decision_resp.reason}"
            )
            return decision_resp, True, False, None

        elif decision_resp.decision == DecisionType.REQUIRE_APPROVAL:
            # Validated: approval_id is guaranteed non-empty by validate_gateway_response
            return decision_resp, False, True, decision_resp.approval_id

        return decision_resp, True, False, None

    def _generate_initial_proposals(
        self,
        prompt: str,
        document_reference: Optional[str],
        scenario: Optional[str],
        audit_log: List[Dict[str, Any]],
    ) -> tuple[List[ProposedToolCall], str]:
        if self.preferred_provider == "gemini":
            if self.gemini_provider.is_configured():
                try:
                    self._audit(audit_log, event="AI_PROVIDER_INVOKED", details={"stage": 1, "provider": "gemini"})
                    actions = self.gemini_provider.propose_actions(prompt, document_reference)
                    return actions, "gemini"
                except GeminiProviderError as g_err:
                    logger.warning(f"Gemini Stage 1 failed: {g_err}. Falling back to MockAgent.")
                    self._audit(audit_log, event="AI_FALLBACK_TRIGGERED", details={"error": str(g_err)})
            else:
                logger.info("Gemini provider not configured. Using MockAgent.")
                self._audit(
                    audit_log,
                    event="AI_PROVIDER_UNAVAILABLE",
                    details={"reason": "Missing GEMINI_API_KEY or SDK", "using": "mock"},
                )

        self._audit(audit_log, event="AI_PROVIDER_INVOKED", details={"stage": 1, "provider": "mock", "scenario": scenario})
        actions = self.mock_agent.propose_actions(prompt, document_reference, scenario=scenario)
        return actions, "mock"

    def _generate_followup_proposals(
        self,
        user_prompt: str,
        untrusted_content: str,
        scenario: Optional[str],
        audit_log: List[Dict[str, Any]],
    ) -> List[ProposedToolCall]:
        if self.preferred_provider == "gemini":
            if self.gemini_provider.is_configured():
                try:
                    self._audit(audit_log, event="AI_PROVIDER_INVOKED", details={"stage": 2, "provider": "gemini"})
                    return self.gemini_provider.analyze_and_propose_followup(user_prompt, untrusted_content)
                except GeminiProviderError as g_err:
                    logger.warning(f"Gemini Stage 2 failed: {g_err}. Falling back to MockAgent.")
                    self._audit(audit_log, event="AI_FALLBACK_TRIGGERED", details={"stage": 2, "error": str(g_err)})
            else:
                self._audit(
                    audit_log,
                    event="AI_PROVIDER_UNAVAILABLE",
                    details={"reason": "Missing GEMINI_API_KEY or SDK", "using": "mock"},
                )

        self._audit(audit_log, event="AI_PROVIDER_INVOKED", details={"stage": 2, "provider": "mock", "scenario": scenario})
        return self.mock_agent.analyze_and_propose_followup(user_prompt, untrusted_content, scenario=scenario)

    def _summarize_content(
        self,
        user_prompt: str,
        content: str,
        provider_used: str,
        audit_log: List[Dict[str, Any]],
    ) -> str:
        self._audit(audit_log, event="SUMMARIZATION_STARTED", details={"provider": provider_used})

        if provider_used == "gemini" and self.gemini_provider.is_configured():
            try:
                summary = self.gemini_provider.summarize_untrusted_content(user_prompt, content)
                self._audit(audit_log, event="SUMMARIZATION_COMPLETED", details={"provider": "gemini"})
                return summary
            except GeminiProviderError as e:
                logger.warning(f"Gemini summarization failed: {e}. Falling back to Mock summarizer.")
                self._audit(audit_log, event="SUMMARIZATION_FALLBACK", details={"error": str(e)})

        summary = self.mock_agent.summarize_untrusted_content(user_prompt, content)
        self._audit(audit_log, event="SUMMARIZATION_COMPLETED", details={"provider": "mock"})
        return summary

    def _sanitize_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive arguments (passwords, message bodies, keys) for audit privacy."""
        sanitized = {}
        for k, v in d.items():
            lower_k = k.lower()
            if any(term in lower_k for term in ["message", "body", "secret", "password", "token", "key"]):
                sanitized[k] = f"[REDACTED_{k.upper()}]"
            else:
                sanitized[k] = v
        return sanitized

    def _audit(self, audit_log: List[Dict[str, Any]], event: str, details: Dict[str, Any]) -> None:
        """Record privacy-safe structured debug and audit metadata."""
        audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "details": details,
        })
