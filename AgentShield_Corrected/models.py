"""
AgentShield - SQLAlchemy ORM Models

Defines persistent models for:
- AuditLog: Immutable security audit trail recording every tool invocation attempt and policy decision.
- ApprovalRequestModel: Human-in-the-loop approval requests for high-risk / destructive actions.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Float
from database import Base


class AuditLog(Base):
    """
    Represents an immutable security audit entry recorded by the AgentShield gateway.

    Columns:
        id: Primary key (autoincrementing integer).
        timestamp: UTC timestamp when the evaluation/action occurred.
        agent_id: Identifier of the invoking AI agent or assistant.
        tool_name: The tool that was evaluated/executed.
        payload: JSON-encoded string containing arguments and context parameters.
        decision: Security gateway decision ('ALLOWED', 'DENIED', 'REQUIRE_APPROVAL').
        reason: Policy rationale, rejection explanation, or execution metadata.
        risk_score: Computed threat risk score (0.0 to 1.0).
        threats: Detected threat labels (JSON-encoded list).
        provenance: Instruction trust level ('user_direct', 'untrusted_document', etc.).
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    agent_id = Column(String(255), nullable=False, index=True)
    tool_name = Column(String(255), nullable=False, index=True)
    payload = Column(Text, nullable=False)
    decision = Column(String(50), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    risk_score = Column(Float, default=0.0, nullable=True)
    threats = Column(Text, default="[]", nullable=True)
    provenance = Column(String(100), default="user_direct", nullable=True)
    event_hash = Column(String(64), nullable=True, index=True)
    previous_hash = Column(String(64), nullable=True)

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} timestamp='{self.timestamp}' "
            f"agent='{self.agent_id}' tool='{self.tool_name}' decision='{self.decision}'>"
        )


class ApprovalRequestModel(Base):
    """
    Represents a staged tool execution request requiring human-in-the-loop approval.

    Columns:
        id: Primary key (autoincrementing integer).
        created_at: UTC timestamp when the approval request was generated.
        expires_at: Expiration timestamp for the approval ticket (TTL).
        ticket_id: Non-predictable unique ticket string (e.g. 'approval_7a8f9c1b').
        agent_id: Identifier of the AI agent requesting tool execution.
        tool_name: The tool requiring human authorization.
        payload: JSON-encoded string containing tool arguments and execution context.
        status: Current lifecycle state ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED').
        reviewer_notes: Remarks submitted by supervisor during resolution.
    """
    __tablename__ = "approval_requests"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    expires_at = Column(DateTime(timezone=True), nullable=True)
    ticket_id = Column(String(255), nullable=True, index=True)
    agent_id = Column(String(255), nullable=False, index=True)
    tool_name = Column(String(255), nullable=False, index=True)
    payload = Column(Text, nullable=False)
    status = Column(String(50), default="PENDING", nullable=False, index=True)
    reviewer_notes = Column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<ApprovalRequestModel id={self.id} ticket_id='{self.ticket_id}' "
            f"agent='{self.agent_id}' tool='{self.tool_name}' status='{self.status}'>"
        )


class DocumentScanRecord(Base):
    """Provenance and policy outcome for a real, uploaded document.

    The extracted full text is stored in a private UUID-named file, not in audit
    payloads. The database contains only a short preview and redacted findings.
    """
    __tablename__ = "document_scans"

    id = Column(String(64), primary_key=True, index=True)
    original_filename = Column(String(255), nullable=False)
    file_extension = Column(String(16), nullable=False)
    mime_type = Column(String(160), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    extracted_content_sha256 = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    extraction_status = Column(String(32), nullable=False, default="EXTRACTED")
    scan_status = Column(String(32), nullable=False, default="SCANNED")
    decision = Column(String(16), nullable=False, index=True)
    review_status = Column(String(24), nullable=False, default="NOT_REQUIRED")
    risk_score = Column(Float, nullable=False, default=0.0)
    threats_detected = Column(Text, nullable=False, default="[]")
    findings = Column(Text, nullable=False, default="[]")
    preview_text = Column(Text, nullable=False, default="")
    extracted_text_path = Column(String(512), nullable=True)
    extraction_warnings = Column(Text, nullable=False, default="[]")

    def __repr__(self) -> str:
        return f"<DocumentScanRecord id={self.id} file='{self.original_filename}' decision='{self.decision}'>"
