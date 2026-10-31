"""
AGENTSHIELD - AI Agent Orchestration Module
Schemas and Data Contracts (Person 1: Agent Orchestration)

This file defines all data structures used by the AI Agent and the Gateway Interface.
Strict typing ensures predictable JSON serialization and safe contract enforcement.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DecisionType(str, Enum):
    """
    Decisions returned exclusively by the AGENTSHIELD Security Gateway.
    The agent NEVER makes security decisions independently.
    """
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class TaskStatus(str, Enum):
    """
    High-level lifecycle status of an agent execution run.
    """
    COMPLETED = "COMPLETED"                      # Actions allowed and task finished
    BLOCKED = "BLOCKED"                          # Action was denied by security policy
    PAUSED_FOR_APPROVAL = "PAUSED_FOR_APPROVAL"  # Waiting for human approval
    FAILED = "FAILED"                            # System, validation, or contract failure


class InstructionProvenance(str, Enum):
    """
    Tracks the origin and trust classification of instructions and data.
    Enforces that untrusted document text or tool outputs cannot masquerade
    as user-authorized requests.
    """
    USER_DIRECT = "user_direct"                          # User-authorized direct instruction
    UNTRUSTED_DOCUMENT = "untrusted_document"            # Content from third-party/external document
    UNTRUSTED_TOOL_OUTPUT = "untrusted_tool_output"      # Content returned from a tool execution
    APPLICATION_SECURITY_POLICY = "application_security_policy"  # Trusted internal security rule
    SUPERVISOR_APPROVAL = "supervisor_approval"          # Human-in-the-loop authorization


class ProposedToolCall(BaseModel):
    """
    Represents an action proposed by the reasoning model (Gemini or Mock).
    CRITICAL: This is only a PROPOSAL. The agent cannot execute it directly.
    """
    tool: str = Field(..., description="Name of the tool the model requests to execute")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments for the requested tool")
    source: str = Field(default="user_task", description="Origin identifier (for backward compatibility)")
    agent_id: str = Field(default="agent_01", description="Identifier of the requesting agent")
    rationale: Optional[str] = Field(default=None, description="Model rationale or reasoning behind the request")
    provenance: InstructionProvenance = Field(
        default=InstructionProvenance.UNTRUSTED_DOCUMENT,
        description="Assigned trust level based on verified origin (not model self-declaration)",
    )


class GatewayRequest(BaseModel):
    """
    Contract sent from the Agent Orchestrator to the AGENTSHIELD Security Gateway.
    """
    tool: str = Field(..., description="Requested tool name")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments for tool invocation")
    source: str = Field(default="user_task", description="Origin context of the invocation (backward-compatible)")
    agent_id: str = Field(default="agent_01", description="Unique agent identifier")
    provenance: InstructionProvenance = Field(
        default=InstructionProvenance.USER_DIRECT,
        description="Instruction origin trust tier for gateway policy evaluation",
    )


class GatewayResponse(BaseModel):
    """
    Contract returned by the AGENTSHIELD Security Gateway to the Agent Orchestrator.
    """
    decision: DecisionType = Field(..., description="ALLOW, DENY, or REQUIRE_APPROVAL")
    reason: str = Field(..., description="Security explanation or policy rule triggered")
    executed: bool = Field(default=False, description="True only if tool was executed by gateway")
    result: Optional[Any] = Field(default=None, description="Result payload if executed")
    approval_id: Optional[str] = Field(default=None, description="Approval ticket ID if REQUIRE_APPROVAL")


def validate_gateway_response(response: Any) -> Optional[str]:
    """
    Shared gateway response validator used by both Orchestrator and Agent.
    Returns None if valid, or an error string describing the security contradiction.

    Enforces:
      - ALLOW requires executed=True.
      - DENY requires executed=False.
      - REQUIRE_APPROVAL requires executed=False AND a valid, non-empty approval_id.
      - Contradictory responses (e.g. DENY with executed=True) are flagged as security incidents.
    """
    if not isinstance(response, GatewayResponse):
        return "Gateway response is not an instance of GatewayResponse."

    # Rule 1: ALLOW requires executed=True
    if response.decision == DecisionType.ALLOW:
        if not response.executed:
            return "Contradictory Gateway Response: Decision is ALLOW but executed is False."

    # Rule 2: DENY requires executed=False
    elif response.decision == DecisionType.DENY:
        if response.executed:
            return "SECURITY INCIDENT: Contradictory Gateway Response - Decision is DENY but executed is True!"

    # Rule 3: REQUIRE_APPROVAL requires executed=False and valid, non-empty approval_id
    elif response.decision == DecisionType.REQUIRE_APPROVAL:
        if response.executed:
            return "Contradictory Gateway Response: Decision is REQUIRE_APPROVAL but executed is True."
        if not response.approval_id or not response.approval_id.strip():
            return "Malformed Gateway Response: Decision is REQUIRE_APPROVAL but approval_id is missing or empty."

    else:
        return f"Unknown Gateway Decision: {response.decision}"

    return None


class ApprovalResumeRequest(BaseModel):
    """
    Request submitted to the Security Gateway to resolve a pending human approval ticket.
    """
    approval_id: str = Field(..., description="Unique approval ticket ID")
    approved: bool = Field(..., description="True if authorized by human supervisor, False if rejected")
    operator_notes: Optional[str] = Field(default=None, description="Notes or justification from operator")


class PendingApprovalItem(BaseModel):
    """
    Internal representation of an action suspended waiting for human approval.
    Binds the approval ticket to the exact single action that was paused.
    """
    approval_id: str
    task_id: str
    tool_call: ProposedToolCall


class AgentTask(BaseModel):
    """
    A user task dispatched to the agent orchestrator.
    """
    task_id: str = Field(..., description="Unique task execution ID")
    user_prompt: str = Field(..., description="User's original instruction")
    document_name: Optional[str] = Field(default=None, description="Associated document filename (optional)")
    document_content: Optional[str] = Field(
        default=None,
        description="Optional pre-supplied document content (treated strictly as untrusted)",
    )


class AgentExecutionResult(BaseModel):
    """
    The final output returned by the Agent Orchestrator.
    """
    task_id: str = Field(..., description="Unique task execution ID")
    status: TaskStatus = Field(..., description="Final status: COMPLETED, BLOCKED, PAUSED_FOR_APPROVAL, FAILED")
    provider_used: str = Field(..., description="AI provider used: 'gemini' or 'mock'")
    proposed_actions: List[ProposedToolCall] = Field(default_factory=list, description="All tools proposed by the model")
    gateway_decisions: List[GatewayResponse] = Field(default_factory=list, description="Decisions returned by the gateway")
    final_response: str = Field(..., description="Human-readable response message for the user")
    approval_id: Optional[str] = Field(default=None, description="Approval ID if paused for approval")
    audit_log: List[Dict[str, Any]] = Field(default_factory=list, description="Step-by-step audit trail for debugging")
