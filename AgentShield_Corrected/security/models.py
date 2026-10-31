import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from security.permissions import SecurityVerdict


class ToolRequest(BaseModel):
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    user_approved: bool = False
    agent_id: Optional[str] = "agent-primary"
    session_id: Optional[str] = None
    context: Optional[str] = None


class SecurityDecision(BaseModel):
    verdict: SecurityVerdict
    reason: str
    tool_name: str
    is_absolute_deny: bool = False
    risk_score: float = 0.0
    threats_detected: List[str] = Field(default_factory=list)
    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_allowed(self) -> bool:
        """True only when the gateway explicitly authorizes execution."""
        return self.verdict == SecurityVerdict.ALLOW
