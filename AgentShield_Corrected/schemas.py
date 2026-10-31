"""
AgentShield - Pydantic Schemas (Pydantic v2)

Defines unified request validation and response serialization schemas for the AgentShield
Security Gateway, ensuring strong type safety and explicit API contracts across all modules.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class GatewayDecision(str, Enum):
    """Possible outcomes of the Security Gateway permission evaluation."""
    ALLOWED = "ALLOWED"
    ALLOW = "ALLOW"
    DENIED = "DENIED"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ApprovalStatus(str, Enum):
    """Lifecycle statuses for approval requests."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ApprovalAction(str, Enum):
    """Permitted human reviewer actions on an approval request."""
    APPROVE = "APPROVE"
    REJECT = "REJECT"


class ToolExecutionRequest(BaseModel):
    """
    Request payload sent by an AI agent, orchestrator, or dashboard to execute a specific tool.
    Accepts both Person 1 ('tool', 'source') and Person 3 ('tool_name', 'context_source') contracts.
    """
    agent_id: str = Field(
        default="agent-01",
        description="Unique identifier of the AI agent requesting tool execution.",
        examples=["agent-customer-support-01"],
    )
    tool_name: Optional[str] = Field(
        default=None,
        description="Name of the tool to be executed.",
        examples=["read_email"],
    )
    tool: Optional[str] = Field(
        default=None,
        description="Alias for tool_name (Person 1 contract compatibility).",
    )
    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key-value arguments provided to the tool.",
        examples=[{"folder": "inbox", "limit": 10}],
    )
    parameters: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Alias for arguments.",
    )
    context_source: Optional[str] = Field(
        default=None,
        description="Optional origin context (e.g. ticket ID, session ID).",
        examples=["slack-channel-support-ops"],
    )
    source: Optional[str] = Field(
        default=None,
        description="Alias for context_source.",
    )
    provenance: Optional[str] = Field(
        default="user_direct",
        description="Trust level: 'user_direct', 'untrusted_document', 'supervisor_approval'.",
    )
    user_approved: bool = Field(
        default=False,
        description="Whether human supervisor has pre-approved this tool call.",
    )

    @model_validator(mode="before")
    @classmethod
    def unify_aliases(cls, values: Any) -> Any:
        if isinstance(values, dict):
            # Unify tool name
            if not values.get("tool_name") and values.get("tool"):
                values["tool_name"] = values["tool"]
            elif not values.get("tool") and values.get("tool_name"):
                values["tool"] = values["tool_name"]

            # Unify arguments / parameters
            if not values.get("arguments") and values.get("parameters"):
                values["arguments"] = values["parameters"]
            elif not values.get("parameters") and values.get("arguments"):
                values["parameters"] = values["arguments"]

            # Unify context source
            if not values.get("context_source") and values.get("source"):
                values["context_source"] = values["source"]
            elif not values.get("source") and values.get("context_source"):
                values["source"] = values["context_source"]
        return values

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "agent_id": "agent-financial-bot-07",
                "tool_name": "read_document",
                "arguments": {"document_id": "security_policy_v1"},
                "context_source": "user-prompt-session-883",
            }
        }
    )


class GatewayExecuteRequest(BaseModel):
    """
    Contract sent from the Agent Orchestrator (Person 1) to the Security Gateway.
    """
    tool: str = Field(..., description="Requested tool name")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments for tool invocation")
    source: str = Field(default="user_task", description="Origin context of the invocation")
    agent_id: str = Field(default="agent_01", description="Unique agent identifier")
    provenance: str = Field(
        default="user_direct",
        description="Instruction origin trust tier for gateway policy evaluation",
    )


class GatewayExecuteResponse(BaseModel):
    """
    Contract returned by the Security Gateway to the Agent Orchestrator (Person 1).
    Enforces strict zero-trust invariants:
      - ALLOW requires executed=True
      - DENY requires executed=False
      - REQUIRE_APPROVAL requires executed=False and approval_id
    """
    decision: str = Field(..., description="ALLOW, DENY, or REQUIRE_APPROVAL")
    reason: str = Field(..., description="Security explanation or policy rule triggered")
    executed: bool = Field(default=False, description="True only if tool was executed by gateway")
    result: Optional[Any] = Field(default=None, description="Result payload if executed")
    approval_id: Optional[str] = Field(default=None, description="Approval ticket ID if REQUIRE_APPROVAL")


class GatewayApprovalResumeRequest(BaseModel):
    """
    Request submitted to the Security Gateway to resolve a pending human approval ticket (Person 1).
    """
    approval_id: str = Field(..., description="Unique approval ticket ID")
    approved: bool = Field(..., description="True if authorized by human supervisor, False if rejected")
    operator_notes: Optional[str] = Field(default=None, description="Notes or justification from operator")


class ApprovalResolutionRequest(BaseModel):
    """
    Request payload sent by a human supervisor to resolve a pending approval (Person 3).
    """
    action: ApprovalAction = Field(
        ...,
        description="Decision action: 'APPROVE' to execute the tool, or 'REJECT' to block it.",
        examples=["APPROVE"],
    )
    reviewer_notes: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Optional human supervisor rationale or remarks.",
        examples=["Verified recipient is internal staff."],
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "APPROVE",
                "reviewer_notes": "Reviewed and cleared for execution.",
            }
        }
    )


class ToolExecutionResponse(BaseModel):
    """
    Response returned by the gateway after evaluating tool invocation permissions.
    """
    decision: GatewayDecision = Field(..., description="Gateway decision: ALLOWED, DENIED, or REQUIRE_APPROVAL.")
    status: str = Field(..., description="High-level execution status: EXECUTED, BLOCKED, or PAUSED_FOR_APPROVAL.")
    message: str = Field(..., description="Summary explanation of the decision or policy rule.")
    approval_id: Optional[Any] = Field(None, description="Approval ID if execution is paused pending supervisor review.")
    result: Optional[Any] = Field(None, description="Output returned by the tool if executed immediately.")
    audit_id: Optional[int] = Field(None, description="Database ID of the corresponding audit log record.")
    executed: bool = Field(default=False, description="Whether tool was executed.")
    risk_score: float = Field(default=0.0, description="Risk score from threat analyzer.")
    threats_detected: List[str] = Field(default_factory=list, description="Threat patterns detected.")


class ApprovalResponse(BaseModel):
    """
    Serialized view of an approval request in the system.
    """
    id: int
    ticket_id: Optional[str] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    agent_id: str
    tool_name: str
    payload: Dict[str, Any]
    status: ApprovalStatus
    reviewer_notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ApprovalResolutionResponse(BaseModel):
    """
    Response returned following the resolution of an approval request.
    """
    approval_id: Any
    status: ApprovalStatus
    message: str
    execution_result: Optional[Any] = Field(None, description="Result of tool execution if approved.")
    audit_id: Optional[int] = Field(None, description="ID of the audit log entry created during resolution.")


class AuditLogResponse(BaseModel):
    """
    Serialized view of a security audit log record.
    """
    id: int
    timestamp: datetime
    agent_id: str
    tool_name: str
    payload: Dict[str, Any]
    decision: GatewayDecision
    reason: Optional[str] = None
    risk_score: Optional[float] = 0.0
    threats: Optional[List[str]] = Field(default_factory=list)
    provenance: Optional[str] = "user_direct"
    event_hash: Optional[str] = None
    previous_hash: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AgentRunRequest(BaseModel):
    """
    Payload to trigger an AI agent task execution through the Zero-Trust Gateway.
    """
    user_prompt: str = Field(..., description="The high-level prompt or instruction for the AI agent.")
    document_name: Optional[str] = Field(default=None, description="Optional associated sample document.")
    document_content: Optional[str] = Field(default=None, description="Legacy field retained for compatibility; public API rejects direct document text.")
    document_scan_id: Optional[str] = Field(default=None, description="Server-issued ID of a scanned document. Only ALLOW or approved REVIEW scans can be processed.")
    scenario: Optional[str] = Field(default=None, description="Preset scenario code ('A', 'B', 'C', 'D').")
    ai_provider: Optional[str] = Field(default="mock", description="Reasoning provider: 'mock' or 'gemini'.")


class ThreatAnalyzeRequest(BaseModel):
    """
    Payload for interactive threat detection testing in the Threat Center UI.
    """
    payloads: List[str] = Field(..., description="List of strings or prompt snippets to evaluate.")


class DocumentReviewRequest(BaseModel):
    """Human review decision for a quarantined document."""
    approved: bool = Field(..., description="Approve or reject the quarantined document for agent processing")
    reviewer_notes: Optional[str] = Field(default=None, max_length=1000)
