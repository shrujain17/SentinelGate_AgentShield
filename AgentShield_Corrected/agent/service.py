"""Product service: plans synthetic actions and routes them through security."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent.tools import SyntheticToolExecutor
from security.audit import AuditLogger
from security.gateway import SecurityGateway
from security.models import SecurityDecision, ToolRequest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class AgentShieldService:
    """Coordinates the simulated agent, security gateway, and safe demo tools."""

    def __init__(self, audit_log_path: str | Path | None = None) -> None:
        log_path = audit_log_path or PROJECT_ROOT / "audit" / "security_audit.jsonl"
        self.gateway = SecurityGateway(audit_logger=AuditLogger(log_path))
        self.tools = SyntheticToolExecutor()

    def process_tool_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Authorize one API request and execute it only when permission is ALLOW."""
        if not isinstance(payload, dict):
            decision = self.gateway.evaluate(payload)
            return self._response(decision, None)

        # Do not let a string such as "true" be interpreted as user approval.
        safe_payload = dict(payload)
        safe_payload["user_approved"] = payload.get("user_approved") is True
        try:
            request = ToolRequest(
                tool_name=safe_payload.get("tool_name", ""),
                parameters=safe_payload.get("parameters", {}),
                context=safe_payload.get("context"),
                user_approved=safe_payload["user_approved"],
                agent_id=str(safe_payload.get("agent_id", "dashboard-agent")),
                session_id=str(safe_payload.get("session_id", "demo-session")),
            )
        except Exception:
            # Reuse the gateway's fail-closed validation path for malformed data.
            decision = self.gateway.evaluate(safe_payload)
            return self._response(decision, None)
        decision, execution = self.gateway.authorize_and_execute(request, self.tools.execute)
        return self._response(decision, execution)

    def process_agent_message(self, message: str, user_approved: bool = False) -> dict[str, Any]:
        """Use a transparent local fallback planner for the demo agent.

        The message is also passed as untrusted context, so any injection attempt
        is checked by the same security gateway before a tool can run.
        """
        message = str(message or "").strip()
        lower_message = message.lower()
        if "email" in lower_message and any(word in lower_message for word in ("send", "reply", "write")):
            tool_name = "send_email"
            parameters = {"to": "demo.client@example.test", "subject": "AgentShield demo", "body": message}
        elif "delete" in lower_message or "remove" in lower_message:
            tool_name = "delete_file"
            parameters = {"target": "draft.txt"}
        elif "document" in lower_message or "brief" in lower_message or "plan" in lower_message:
            tool_name = "read_document"
            parameters = {"document_id": "project-brief"}
        elif "email" in lower_message or "inbox" in lower_message:
            tool_name = "read_email"
            parameters = {"query": ""}
        else:
            tool_name = "unknown_tool"
            parameters = {"message": message}

        return self.process_tool_request(
            {
                "tool_name": tool_name,
                "parameters": parameters,
                "context": message,
                "user_approved": user_approved,
                "agent_id": "local-fallback-agent",
            }
        )

    def audit_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return [self._decision_to_dict(record) for record in self.gateway.get_audit_logs(limit=limit)]

    @staticmethod
    def _response(decision: SecurityDecision, execution: Any) -> dict[str, Any]:
        return {
            "decision": AgentShieldService._decision_to_dict(decision),
            "execution": execution,
            "executed": decision.is_allowed and execution is not None,
        }

    @staticmethod
    def _decision_to_dict(decision: SecurityDecision) -> dict[str, Any]:
        if hasattr(decision, "model_dump"):
            return decision.model_dump(mode="json")
        return decision.dict()
