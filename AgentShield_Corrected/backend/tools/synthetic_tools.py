"""
AgentShield - Synthetic Tool Execution Sandbox
All tool executions are safe, local, and isolated. No real-world destructive
actions, outbound network packets, or file modifications occur.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SAMPLE_DOCS_DIR = PROJECT_ROOT / "data" / "sample_documents"

PUBLIC_DOCUMENTS_ALLOWLIST: Set[str] = {
    "public_document.txt",
    "malicious_document.txt",
}

RESTRICTED_DOCUMENTS_BLOCKLIST: Set[str] = {
    "restricted_document.txt",
    "confidential_employee_salaries.csv",
    "master_database_admin_password",
    "shadow",
    "passwd",
    ".env",
    "id_rsa",
}

SYNTHETIC_EMAILS: List[Dict[str, Any]] = [
    {
        "id": "msg_001",
        "sender": "partner-success@example.com",
        "subject": "Q4 Partnership Roadmap Sync",
        "date": "2026-10-30T10:15:00Z",
        "preview": "Looking forward to our roadmap alignment discussion today...",
    },
    {
        "id": "msg_002",
        "sender": "alerts@infrastructure.internal",
        "subject": "Weekly Gateway Health Report: 99.99% Uptime",
        "date": "2026-10-30T08:00:00Z",
        "preview": "All security gateway proxies reported nominal latency...",
    },
    {
        "id": "msg_003",
        "sender": "security-officer@company.test",
        "subject": "PARALLAX Hackathon Security Baseline v2.4",
        "date": "2026-10-30T07:30:00Z",
        "preview": "Please verify all agent tool calls pass through AgentShield.",
    },
]

SYNTHETIC_DOCUMENTS: Dict[str, Dict[str, Any]] = {
    "security_policy_v1": {
        "document_id": "security_policy_v1",
        "title": "Corporate AI Tool Security Baseline v2.4",
        "classification": "INTERNAL",
        "content_length_chars": 1420,
        "excerpt": "Autonomous AI agents interacting with external resources must route all tool calls through AgentShield...",
    },
    "project-brief": {
        "document_id": "project-brief",
        "title": "AgentShield Project Brief",
        "classification": "PUBLIC",
        "content_length_chars": 890,
        "excerpt": "AgentShield protects AI agent tool calls with deterministic zero-trust policy checks...",
    },
    "release_notes_v2.4.md": {
        "document_id": "release_notes_v2.4.md",
        "title": "AgentShield v2.4 Release Notes",
        "classification": "PUBLIC",
        "content_length_chars": 1420,
        "excerpt": "AgentShield v2.4 introduces deterministic fail-closed gateway policies and HITL staging...",
    },
}


class SyntheticToolExecutor:
    """
    Executes mock tools deterministically within synthetic boundaries.
    """

    def __init__(self, sample_docs_dir: Optional[Path] = None):
        self.sample_docs_dir = Path(sample_docs_dir) if sample_docs_dir else SAMPLE_DOCS_DIR
        self._demo_files = {"draft.txt", "old_report.txt", "temp_scratch.log"}

    def execute(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dispatches tool execution to the safe synthetic handler.
        Raises ValueError or PermissionError for disallowed tools.
        """
        clean_name = tool_name.strip().lower()

        if clean_name == "read_email":
            return self._read_email(arguments)
        elif clean_name == "read_document":
            return self._read_document(arguments)
        elif clean_name in ("read_public_document", "summarize_public_document"):
            return self._read_public_document(arguments)
        elif clean_name == "send_email":
            return self._send_email(arguments)
        elif clean_name == "delete_file":
            return self._delete_file(arguments)
        elif clean_name in ("send_external_message", "dispatch_external_alert"):
            return self._send_external_message(clean_name, arguments)
        elif clean_name == "execute_system_command":
            return self._execute_system_command(arguments)
        elif clean_name in ("read_private_file", "read_restricted_file", "read_secret", "access_confidential_db"):
            raise PermissionError(f"Tool '{clean_name}' is in the absolute-deny list and cannot be executed.")
        else:
            raise ValueError(f"No executable mock handler available for tool '{tool_name}'.")

    def _read_email(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        folder = arguments.get("folder", "inbox")
        limit = int(arguments.get("limit", 2))
        query = str(arguments.get("query", "")).strip().lower()

        emails = SYNTHETIC_EMAILS
        if query:
            emails = [
                e for e in emails
                if query in f"{e['sender']} {e['subject']} {e['preview']}".lower()
            ]

        selected = deepcopy(emails[:limit])
        return {
            "status": "success",
            "folder": folder,
            "count": len(selected),
            "messages": selected,
        }

    def _read_document(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        doc_id = str(arguments.get("document_id", "security_policy_v1")).strip()
        doc = SYNTHETIC_DOCUMENTS.get(doc_id)
        if doc:
            return {
                "status": "success",
                **deepcopy(doc),
            }
        return {
            "status": "success",
            "document_id": doc_id,
            "title": f"Synthetic Document: {doc_id}",
            "classification": "INTERNAL",
            "content_length_chars": 1200,
            "excerpt": f"Synthetic contents for document identifier '{doc_id}' retrieved from local sandbox.",
        }

    def _read_public_document(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        filename = arguments.get("filename")
        if not filename or not isinstance(filename, str):
            raise ValueError("Tool requires a valid string 'filename' argument.")

        clean_filename = Path(filename).name  # Prevent directory traversal

        # Deny blocked/restricted documents
        if clean_filename.lower() in {f.lower() for f in RESTRICTED_DOCUMENTS_BLOCKLIST}:
            raise PermissionError(f"Document '{clean_filename}' is strictly confidential and restricted.")

        # Check explicit public allowlist
        if clean_filename not in PUBLIC_DOCUMENTS_ALLOWLIST:
            raise PermissionError(f"Document '{clean_filename}' is not in the public allowlist.")

        file_path = self.sample_docs_dir / clean_filename
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(f"Allowlisted document '{clean_filename}' was not found in sample documents.")

        try:
            content = file_path.read_text(encoding="utf-8")
            return {
                "status": "success",
                "filename": clean_filename,
                "classification": "PUBLIC",
                "content_length": len(content),
                "content": content,
            }
        except Exception as e:
            raise IOError(f"Error reading sample file '{clean_filename}': {str(e)}")

    def _send_email(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        recipient = arguments.get("recipient") or arguments.get("to") or "user@example.com"
        subject = arguments.get("subject", "(No Subject)")
        body = arguments.get("body", "")
        return {
            "status": "dispatched",
            "recipient": recipient,
            "subject": subject,
            "dispatch_timestamp": datetime.now(timezone.utc).isoformat(),
            "delivery_reference": f"smtp_tx_{uuid4().hex[:10]}",
            "note": "Synthetic email dispatched in simulation sandbox. No real email was sent.",
        }

    def _delete_file(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = arguments.get("file_path") or arguments.get("target") or "/data/temp_scratch.log"
        target_name = Path(file_path).name
        if target_name in self._demo_files:
            self._demo_files.remove(target_name)
        return {
            "status": "deleted",
            "file_path": file_path,
            "bytes_reclaimed": 4096,
            "deletion_timestamp": datetime.now(timezone.utc).isoformat(),
            "note": "Synthetic file deletion simulated. No real file was modified on disk.",
        }

    def _send_external_message(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        recipient = arguments.get("recipient", "external auditor")
        return {
            "status": "dispatched",
            "tool": tool_name,
            "recipient": recipient,
            "dispatch_timestamp": datetime.now(timezone.utc).isoformat(),
            "note": "Synthetic outbound message dispatched. No real network transmission occurred.",
        }

    def _execute_system_command(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        command = arguments.get("command", "")
        return {
            "status": "executed",
            "command": command,
            "stdout": f"[SIMULATED] Command '{command}' executed safely within synthetic sandbox.",
            "stderr": "",
            "returncode": 0,
            "execution_timestamp": datetime.now(timezone.utc).isoformat(),
            "note": "Synthetic system command simulation. No real host process was executed.",
        }
