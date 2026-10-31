"""
AGENTSHIELD - AI Agent Orchestration Module
High-Level Agent Interface (Person 1: Agent Orchestration)

This file provides the primary high-level `AgentShieldAgent` class.
Other backend services (FastAPI routes, CLI runners, testing suites) can import
and use this class directly without dealing with lower-level orchestration details.

Security Features:
  - Dispatches tasks to the Zero-Trust AgentOrchestrator.
  - Links human approval tickets to the exact single action that was paused.
  - Submits approval decisions to the Security Gateway for verification and execution.
  - Validates gateway responses with shared zero-trust response validation.
  - Never assumes success without explicit gateway confirmation (ALLOW with executed=True).
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional
import uuid

from backend.agent.gateway_client import SecurityGatewayInterface, get_gateway_client
from backend.agent.orchestrator import AgentOrchestrator
from backend.agent.schemas import (
    AgentExecutionResult,
    AgentTask,
    ApprovalResumeRequest,
    DecisionType,
    GatewayResponse,
    PendingApprovalItem,
    ProposedToolCall,
    TaskStatus,
    validate_gateway_response,
)

logger = logging.getLogger("agentshield.agent")


class AgentShieldAgent:
    """
    High-level agent interface for the AGENTSHIELD zero-trust defense system.
    """

    def __init__(
        self,
        ai_provider: Optional[str] = None,
        gateway_client: Optional[SecurityGatewayInterface] = None,
        agent_id: str = "agent_01",
    ):
        self.agent_id = agent_id
        self.orchestrator = AgentOrchestrator(
            ai_provider=ai_provider,
            gateway_client=gateway_client,
            agent_id=self.agent_id,
        )
        # Store pending approvals: maps approval_id -> PendingApprovalItem
        self._pending_approvals: Dict[str, PendingApprovalItem] = {}

    def run(
        self,
        user_prompt: str,
        document_name: Optional[str] = None,
        document_content: Optional[str] = None,
        scenario: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> AgentExecutionResult:
        """
        Execute an agent task through the zero-trust pipeline.
        """
        effective_task_id = task_id or f"task_{uuid.uuid4().hex[:8]}"

        task = AgentTask(
            task_id=effective_task_id,
            user_prompt=user_prompt,
            document_name=document_name,
            document_content=document_content,
        )

        result = self.orchestrator.run_task(task, scenario=scenario)

        # If paused for approval, locate the exact single action that triggered approval
        if result.status == TaskStatus.PAUSED_FOR_APPROVAL and result.approval_id:
            pending_action = None
            for idx, decision in enumerate(result.gateway_decisions):
                if decision.decision == DecisionType.REQUIRE_APPROVAL:
                    if idx < len(result.proposed_actions):
                        pending_action = result.proposed_actions[idx]
                    break

            if pending_action:
                self._pending_approvals[result.approval_id] = PendingApprovalItem(
                    approval_id=result.approval_id,
                    task_id=effective_task_id,
                    tool_call=pending_action,
                )

        return result

    def resume_approval(
        self,
        approval_id: str,
        approved: bool,
        operator_notes: Optional[str] = None,
    ) -> AgentExecutionResult:
        """
        Process human-in-the-loop supervisor approval through the security gateway.

        CRITICAL SECURITY INVARIANTS:
          1. The decision must be validated and executed BY THE SECURITY GATEWAY.
          2. The approval is strictly bound to the exact single pending action.
          3. We NEVER claim success unless the gateway confirms ALLOW and executed=True.
          4. Gateway responses are checked with shared response validation.
          5. Contradictory responses (e.g. DENY with executed=True) fail closed.
        """
        audit_log: list = []
        timestamp = datetime.now(timezone.utc).isoformat()

        if approval_id not in self._pending_approvals:
            # Check SQLite database for persistent approval record
            try:
                from database import SessionLocal
                import models
                with SessionLocal() as db_session:
                    db_rec = (
                        db_session.query(models.ApprovalRequestModel)
                        .filter(
                            (models.ApprovalRequestModel.ticket_id == approval_id)
                            | (models.ApprovalRequestModel.id == (int(approval_id) if approval_id.isdigit() else -1))
                        )
                        .first()
                    )
                    if db_rec:
                        try:
                            payload_data = json.loads(db_rec.payload)
                            arguments = payload_data.get("arguments", {}) if isinstance(payload_data, dict) else {}
                        except Exception:
                            arguments = {}
                        self._pending_approvals[approval_id] = PendingApprovalItem(
                            approval_id=db_rec.ticket_id,
                            task_id=f"task_{db_rec.id}",
                            tool_call=ProposedToolCall(
                                tool=db_rec.tool_name,
                                arguments=arguments,
                                source="approval_queue",
                                agent_id=db_rec.agent_id,
                                provenance=InstructionProvenance.USER_DIRECT,
                            ),
                        )
            except Exception as e:
                logger.debug(f"Could not load approval from DB: {e}")

        if approval_id not in self._pending_approvals:
            return AgentExecutionResult(
                task_id=f"resumed_{approval_id}",
                status=TaskStatus.FAILED,
                provider_used=self.orchestrator.preferred_provider,
                proposed_actions=[],
                gateway_decisions=[],
                final_response=f"Error: Approval ticket '{approval_id}' was not found or has expired.",
                audit_log=[{
                    "timestamp": timestamp,
                    "event": "APPROVAL_NOT_FOUND",
                    "details": {"approval_id": approval_id},
                }],
            )

        pending_item = self._pending_approvals[approval_id]

        # Submit formal approval request to the Security Gateway
        resume_req = ApprovalResumeRequest(
            approval_id=approval_id,
            approved=approved,
            operator_notes=operator_notes,
        )

        # Gateway evaluates and executes if authorized
        gateway_resp = self.orchestrator.gateway_client.resume_approval(resume_req)

        # Validate gateway response with shared validator
        val_error = validate_gateway_response(gateway_resp)
        if val_error:
            logger.error(f"Approval resumption gateway validation failed: {val_error}")
            audit_log.append({
                "timestamp": timestamp,
                "event": "APPROVAL_GATEWAY_VALIDATION_CONTRADICTION",
                "details": {"error": val_error, "decision": gateway_resp.decision.value},
            })
            return AgentExecutionResult(
                task_id=pending_item.task_id,
                status=TaskStatus.BLOCKED,
                provider_used=self.orchestrator.preferred_provider,
                proposed_actions=[pending_item.tool_call],
                gateway_decisions=[gateway_resp],
                final_response=f"Gateway Contradiction during approval resumption: {val_error}",
                approval_id=approval_id,
                audit_log=audit_log,
            )

        audit_log.append({
            "timestamp": timestamp,
            "event": "APPROVAL_DECISION_PROCESSED_BY_GATEWAY",
            "details": {
                "approval_id": approval_id,
                "approved": approved,
                "operator_notes": operator_notes,
                "gateway_decision": gateway_resp.decision.value,
                "executed": gateway_resp.executed,
                "reason": gateway_resp.reason,
            },
        })

        # Only pop once verified
        if gateway_resp.decision in (DecisionType.ALLOW, DecisionType.DENY):
            self._pending_approvals.pop(approval_id, None)

        if gateway_resp.decision == DecisionType.ALLOW:
            return AgentExecutionResult(
                task_id=pending_item.task_id,
                status=TaskStatus.COMPLETED,
                provider_used=self.orchestrator.preferred_provider,
                proposed_actions=[pending_item.tool_call],
                gateway_decisions=[gateway_resp],
                final_response=(
                    f"[APPROVAL GRANTED] Action authorized and executed by Security Gateway.\n"
                    f"Tool '{pending_item.tool_call.tool}' completed. Reason: {gateway_resp.reason}"
                ),
                approval_id=approval_id,
                audit_log=audit_log,
            )

        elif gateway_resp.decision == DecisionType.DENY:
            return AgentExecutionResult(
                task_id=pending_item.task_id,
                status=TaskStatus.BLOCKED,
                provider_used=self.orchestrator.preferred_provider,
                proposed_actions=[pending_item.tool_call],
                gateway_decisions=[gateway_resp],
                final_response=(
                    f"[APPROVAL REJECTED / BLOCKED] Gateway denied action execution.\n"
                    f"Reason: {gateway_resp.reason}"
                ),
                approval_id=approval_id,
                audit_log=audit_log,
            )

        else:
            return AgentExecutionResult(
                task_id=pending_item.task_id,
                status=TaskStatus.PAUSED_FOR_APPROVAL,
                provider_used=self.orchestrator.preferred_provider,
                proposed_actions=[pending_item.tool_call],
                gateway_decisions=[gateway_resp],
                final_response=(
                    f"[AGENT PAUSED] Gateway requires continued supervisor authorization.\n"
                    f"Reason: {gateway_resp.reason}"
                ),
                approval_id=approval_id,
                audit_log=audit_log,
            )
