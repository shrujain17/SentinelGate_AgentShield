"""Synthetic tools for the AgentShield demo. They never access real data."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from security.models import ToolRequest


SYNTHETIC_EMAILS = [
    {
        "id": "email-001",
        "from": "demo.client@example.test",
        "subject": "Quarterly project update",
        "preview": "Please share the latest project summary by Friday.",
    },
    {
        "id": "email-002",
        "from": "team@example.test",
        "subject": "Sprint planning notes",
        "preview": "The next sprint starts on Monday. Review the demo tasks.",
    },
    {
        "id": "email-003",
        "from": "events@example.test",
        "subject": "Hackathon schedule",
        "preview": "Final presentations begin at 4:00 PM.",
    },
]

SYNTHETIC_DOCUMENTS = {
    "project-brief": {
        "id": "project-brief",
        "title": "AgentShield project brief",
        "content": "AgentShield protects AI agent tool calls with deterministic policy checks.",
    },
    "security-plan": {
        "id": "security-plan",
        "title": "Security plan",
        "content": "Unknown tools are denied. High-impact actions require explicit approval.",
    },
}


class SyntheticToolExecutor:
    """Executes only safe, local demonstrations after the gateway allows them."""

    def __init__(self) -> None:
        self._demo_files = {"draft.txt", "old_report.txt"}

    def execute(self, request: ToolRequest) -> dict[str, Any]:
        tool_name = request.tool_name.strip().lower()
        if tool_name == "read_email":
            return self._read_email(request.parameters)
        if tool_name == "read_document":
            return self._read_document(request.parameters)
        if tool_name == "send_email":
            return self._send_email(request.parameters)
        if tool_name == "delete_file":
            return self._delete_demo_file(request.parameters)
        # The gateway should stop anything else before this point.
        raise ValueError(f"No synthetic executor is registered for '{tool_name}'.")

    @staticmethod
    def _read_email(parameters: dict[str, Any]) -> dict[str, Any]:
        query = str(parameters.get("query", "")).strip().lower()
        emails = SYNTHETIC_EMAILS
        if query:
            emails = [
                email
                for email in emails
                if query in f"{email['from']} {email['subject']} {email['preview']}".lower()
            ]
        return {"status": "ok", "source": "synthetic", "emails": deepcopy(emails)}

    @staticmethod
    def _read_document(parameters: dict[str, Any]) -> dict[str, Any]:
        document_id = str(parameters.get("document_id", "project-brief")).strip().lower()
        document = SYNTHETIC_DOCUMENTS.get(document_id)
        if not document:
            return {
                "status": "not_found",
                "message": "Only synthetic project documents are available in this demo.",
                "available_documents": sorted(SYNTHETIC_DOCUMENTS),
            }
        return {"status": "ok", "source": "synthetic", "document": deepcopy(document)}

    @staticmethod
    def _send_email(parameters: dict[str, Any]) -> dict[str, Any]:
        recipient = str(parameters.get("to", "")).strip()
        if "@" not in recipient:
            return {"status": "invalid_recipient", "message": "Provide a synthetic email recipient."}
        return {
            "status": "simulated_send_complete",
            "message_id": f"demo-{uuid4()}",
            "recipient": recipient,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "note": "No real email was sent.",
        }

    def _delete_demo_file(self, parameters: dict[str, Any]) -> dict[str, Any]:
        target = str(parameters.get("target", "draft.txt")).strip()
        if target not in self._demo_files:
            return {
                "status": "not_found",
                "message": "The target is not a synthetic demo file.",
                "available_demo_files": sorted(self._demo_files),
            }
        self._demo_files.remove(target)
        return {
            "status": "simulated_delete_complete",
            "target": target,
            "remaining_demo_files": sorted(self._demo_files),
            "note": "No real file was deleted.",
        }
