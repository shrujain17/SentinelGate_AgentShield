"""
AGENTSHIELD - AI Agent Orchestration Module
Gateway Client Interface & Adapters (Person 1: Agent Orchestration)

This file defines the bridge between the AI Agent and the AGENTSHIELD Security Gateway.

CRITICAL SECURITY RULES:
  1. The AI agent NEVER directly executes tools or accesses files.
  2. Every action must be sent to this gateway interface.
  3. Public document reading tools are restricted to an explicit public allowlist.
  4. Missing files or read failures return DENY with executed=False.
  5. Approval IDs are uniquely generated, expire after a TTL, and are strictly single-use.
  6. HTTP error statuses (4xx, 5xx) and connection failures FAIL-CLOSED (DENY).
"""

import abc
from datetime import datetime, timezone, timedelta
import json
import logging
import os
from pathlib import Path
import time
from typing import Any, Dict, Optional, Set, Tuple
import urllib.error
import urllib.request
import uuid

from backend.agent.schemas import (
    ApprovalResumeRequest,
    DecisionType,
    GatewayRequest,
    GatewayResponse,
    InstructionProvenance,
    validate_gateway_response,
)

logger = logging.getLogger("agentshield.gateway_client")


class SecurityGatewayInterface(abc.ABC):
    """
    Abstract interface for the AGENTSHIELD Security Gateway.
    Person 2's actual security gateway will fulfill this contract.
    """

    @abc.abstractmethod
    def evaluate_and_execute(self, request: GatewayRequest) -> GatewayResponse:
        """
        Evaluate tool request against security policies and execute if authorized.
        """
        pass

    @abc.abstractmethod
    def resume_approval(self, approval_request: ApprovalResumeRequest) -> GatewayResponse:
        """
        Submit human supervisor approval decision to the security gateway.
        """
        pass


class GatewayPendingApproval:
    """
    Gateway-side record for a high-impact action suspended pending supervisor review.
    Binds the approval ticket to the exact requested action, arguments, and timestamp.
    """

    def __init__(self, approval_id: str, request: GatewayRequest, ttl_seconds: float = 300.0):
        self.approval_id = approval_id
        self.request = request
        self.created_at = time.time()
        self.expires_at = self.created_at + ttl_seconds

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class MockGatewayAdapter(SecurityGatewayInterface):
    """
    Temporary mock gateway adapter for local development and offline testing.

    Simulates GATEWAY-SIDE behavior (Person 2's role).
    Enforces strict zero-trust allowlists, expiring approvals, and fail-closed handling.
    """

    # Explicit allowlist of documents permissible for public tools
    PUBLIC_DOCUMENTS_ALLOWLIST: Set[str] = {
        "public_document.txt",
        "malicious_document.txt",  # Public third-party attachment submitted for analysis
    }

    def __init__(self, sample_docs_dir: Optional[Path] = None, approval_ttl_seconds: float = 300.0):
        if sample_docs_dir is None:
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.sample_docs_dir = base_dir / "data" / "sample_documents"
        else:
            self.sample_docs_dir = Path(sample_docs_dir)

        self.approval_ttl_seconds = approval_ttl_seconds
        # Gateway-side pending approval state: maps approval_id -> GatewayPendingApproval
        self._pending_approvals: Dict[str, GatewayPendingApproval] = {}

    def evaluate_and_execute(self, request: GatewayRequest) -> GatewayResponse:
        """
        Simulate gateway policy evaluation and sandboxed execution.
        """
        try:
            tool_name = request.tool.strip()

            # Rule 1: Public document tools with strict allowlist verification
            if tool_name in ("read_public_document", "summarize_public_document"):
                filename = request.arguments.get("filename")
                if not filename or not isinstance(filename, str):
                    return GatewayResponse(
                        decision=DecisionType.DENY,
                        reason=f"Policy Violation: Tool '{tool_name}' requires a valid string 'filename' argument.",
                        executed=False,
                    )

                clean_name = Path(filename).name  # Prevent directory traversal

                # Check explicit public allowlist
                if clean_name not in self.PUBLIC_DOCUMENTS_ALLOWLIST:
                    return GatewayResponse(
                        decision=DecisionType.DENY,
                        reason=(
                            f"Zero-Trust Policy Violation: Document '{clean_name}' is not in the "
                            f"public documents allowlist. Access denied."
                        ),
                        executed=False,
                    )

                # Attempt sandboxed file read
                content, error = self._safe_read_sample_file(clean_name)
                if error or content is None:
                    return GatewayResponse(
                        decision=DecisionType.DENY,
                        reason=f"Gateway File Read Failure: {error or 'File not accessible.'}",
                        executed=False,
                    )

                return GatewayResponse(
                    decision=DecisionType.ALLOW,
                    reason=f"Policy Policy-001: Tool '{tool_name}' authorized for public document '{clean_name}'.",
                    executed=True,
                    result=content,
                )

            # Rule 2: Strictly forbidden sensitive data tools (Zero-Trust violation)
            if tool_name in ("read_restricted_file", "read_secret", "access_confidential_db"):
                target = (
                    request.arguments.get("filename")
                    or request.arguments.get("secret_name")
                    or "restricted resource"
                )
                return GatewayResponse(
                    decision=DecisionType.DENY,
                    reason=f"Zero-Trust Policy Violation: Unauthorized attempt to access restricted target '{target}'.",
                    executed=False,
                    result=None,
                )

            # Rule 3: High-impact actions requiring human approval with unique expiring IDs
            if tool_name in ("send_external_message", "dispatch_external_alert", "execute_system_command"):
                recipient = request.arguments.get("recipient", "external endpoint")
                # Generate unique non-predictable approval ID
                unique_approval_id = f"approval_{uuid.uuid4().hex[:12]}"
                # Store bound pending approval item with TTL
                self._pending_approvals[unique_approval_id] = GatewayPendingApproval(
                    approval_id=unique_approval_id,
                    request=request,
                    ttl_seconds=self.approval_ttl_seconds,
                )

                # Persist to central SQLite database for Approval Centre UI visibility
                try:
                    from database import SessionLocal
                    import models
                    with SessionLocal() as db_session:
                        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.approval_ttl_seconds)
                        payload_data = {
                            "tool": tool_name,
                            "arguments": request.arguments,
                            "source": request.source or "agent_task",
                            "agent_id": request.agent_id or "agent_01",
                            "provenance": request.provenance.value if hasattr(request.provenance, "value") else str(request.provenance),
                        }
                        db_approval = models.ApprovalRequestModel(
                            ticket_id=unique_approval_id,
                            agent_id=request.agent_id or "agent_01",
                            tool_name=tool_name,
                            payload=json.dumps(payload_data, default=str),
                            status="PENDING",
                            created_at=datetime.now(timezone.utc),
                            expires_at=expires_at,
                        )
                        db_session.add(db_approval)
                        db_session.commit()
                except Exception as db_err:
                    logger.debug(f"Could not persist pending approval to SQLite: {db_err}")

                return GatewayResponse(
                    decision=DecisionType.REQUIRE_APPROVAL,
                    reason=f"Policy Policy-HIL-01: High-impact action '{tool_name}' to '{recipient}' requires human supervisor approval.",
                    executed=False,
                    approval_id=unique_approval_id,
                    result=None,
                )

            # Rule 4: Unknown tool -> Default Deny (Fail-Closed)
            return GatewayResponse(
                decision=DecisionType.DENY,
                reason=f"Zero-Trust Violation: Tool '{tool_name}' is not recognized or permitted.",
                executed=False,
                result=None,
            )

        except Exception as e:
            logger.error(f"MockGateway encountered error: {e}. Enforcing FAIL-CLOSED.")
            return GatewayResponse(
                decision=DecisionType.DENY,
                reason=f"Gateway Fail-Closed Protection: Internal evaluation error ({str(e)})",
                executed=False,
                result=None,
            )

    def resume_approval(self, approval_request: ApprovalResumeRequest) -> GatewayResponse:
        """
        Verify approval ticket, check expiration, enforce single-use, and execute if approved.
        """
        try:
            approval_id = approval_request.approval_id

            # Check existence and single-use
            if approval_id not in self._pending_approvals:
                # Check DB as fallback
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
                        if db_rec and db_rec.status == "PENDING":
                            try:
                                payload_data = json.loads(db_rec.payload)
                                arguments = payload_data.get("arguments", {})
                            except Exception:
                                arguments = {}
                            self._pending_approvals[approval_id] = GatewayPendingApproval(
                                approval_id=db_rec.ticket_id,
                                request=GatewayRequest(
                                    tool=db_rec.tool_name,
                                    arguments=arguments,
                                    source="approval_queue",
                                    agent_id=db_rec.agent_id,
                                    provenance=InstructionProvenance.USER_DIRECT,
                                ),
                                ttl_seconds=self.approval_ttl_seconds,
                            )
                except Exception:
                    pass

            if approval_id not in self._pending_approvals:
                return GatewayResponse(
                    decision=DecisionType.DENY,
                    reason=f"Gateway Error: Approval ticket '{approval_id}' was not found or has already been consumed.",
                    executed=False,
                )

            # Pop ticket immediately to enforce single-use
            pending_item = self._pending_approvals.pop(approval_id)

            # Also sync resolved status to database if record exists
            try:
                from database import SessionLocal
                import models
                with SessionLocal() as db_session:
                    db_rec = (
                        db_session.query(models.ApprovalRequestModel)
                        .filter(
                            (models.ApprovalRequestModel.ticket_id == approval_id)
                            | (models.ApprovalRequestModel.ticket_id == pending_item.approval_id)
                        )
                        .first()
                    )
                    if db_rec and db_rec.status == "PENDING":
                        db_rec.status = "APPROVED" if approval_request.approved else "REJECTED"
                        db_rec.reviewer_notes = approval_request.operator_notes
                        db_session.commit()
            except Exception:
                pass

            # Check expiry
            if pending_item.is_expired():
                return GatewayResponse(
                    decision=DecisionType.DENY,
                    reason=f"Gateway Error: Approval ticket '{approval_id}' has expired.",
                    executed=False,
                )

            # If supervisor rejected
            if not approval_request.approved:
                return GatewayResponse(
                    decision=DecisionType.DENY,
                    reason=(
                        f"Action '{pending_item.request.tool}' rejected by human supervisor. "
                        f"Notes: {approval_request.operator_notes or 'No reason provided.'}"
                    ),
                    executed=False,
                )

            # Authorized execution by gateway
            recipient = pending_item.request.arguments.get("recipient", "external auditor")
            return GatewayResponse(
                decision=DecisionType.ALLOW,
                reason=f"Supervisor authorization confirmed. Tool '{pending_item.request.tool}' executed by gateway.",
                executed=True,
                result={
                    "status": "dispatched",
                    "tool": pending_item.request.tool,
                    "recipient": recipient,
                    "operator_notes": approval_request.operator_notes,
                },
            )

        except Exception as e:
            logger.error(f"MockGateway approval resumption error: {e}")
            return GatewayResponse(
                decision=DecisionType.DENY,
                reason=f"Gateway Fail-Closed Protection during approval resumption: {str(e)}",
                executed=False,
            )

    def _safe_read_sample_file(self, clean_name: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Safely retrieve document text for allowlisted sample files.
        Returns (content, error). Never invents content on failure.
        """
        file_path = self.sample_docs_dir / clean_name
        if not file_path.exists() or not file_path.is_file():
            return None, f"File '{clean_name}' does not exist on disk."

        try:
            content = file_path.read_text(encoding="utf-8")
            return content, None
        except Exception as e:
            return None, f"Error reading file '{clean_name}': {str(e)}"


class HttpGatewayClient(SecurityGatewayInterface):
    """
    Remote HTTP client connecting to Person 2's actual AGENTSHIELD Security Gateway.
    Fails closed on any 4xx/5xx HTTP error, network timeout, or contradictory payload.
    """

    def __init__(
        self,
        gateway_url: Optional[str] = None,
        approval_resume_url: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        auth_token: Optional[str] = None,
    ):
        self.gateway_url = (
            gateway_url
            or os.environ.get("GATEWAY_URL")
            or "http://localhost:8000/api/v1/gateway/execute"
        )
        self.approval_resume_url = (
            approval_resume_url
            or os.environ.get("GATEWAY_APPROVAL_URL")
            or "http://localhost:8000/api/v1/gateway/approvals/resume"
        )
        self.timeout_seconds = float(
            timeout_seconds or os.environ.get("GATEWAY_TIMEOUT", "5.0")
        )
        self.auth_token = auth_token or os.environ.get("GATEWAY_AUTH_TOKEN", "")

    def evaluate_and_execute(self, request: GatewayRequest) -> GatewayResponse:
        return self._post_json(self.gateway_url, request.model_dump())

    def resume_approval(self, approval_request: ApprovalResumeRequest) -> GatewayResponse:
        return self._post_json(self.approval_resume_url, approval_request.model_dump())

    def _post_json(self, url: str, payload_dict: Dict[str, Any]) -> GatewayResponse:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "AgentShield-Orchestrator/1.0",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        payload_bytes = json.dumps(payload_dict).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload_bytes,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                status_code = resp.status if hasattr(resp, "status") else resp.getcode()
                # HTTP status must be 2xx to authorize
                if status_code < 200 or status_code >= 300:
                    return GatewayResponse(
                        decision=DecisionType.DENY,
                        reason=f"Gateway HTTP Error status {status_code} (Fail-Closed).",
                        executed=False,
                    )

                resp_bytes = resp.read()
                data = json.loads(resp_bytes.decode("utf-8"))
                parsed = GatewayResponse.model_validate(data)

                # Shared response validation
                validation_error = validate_gateway_response(parsed)
                if validation_error:
                    logger.error(f"Gateway response validation failed: {validation_error}")
                    return GatewayResponse(
                        decision=DecisionType.DENY,
                        reason=f"Gateway Response Contradiction (Fail-Closed): {validation_error}",
                        executed=False,
                    )

                return parsed

        except urllib.error.HTTPError as http_err:
            logger.error(f"Gateway HTTP error {http_err.code}: {http_err.reason}")
            # CRITICAL SECURITY FIX: HTTP 4xx and 5xx MUST FAIL CLOSED. Never accept ALLOW from HTTP error!
            return GatewayResponse(
                decision=DecisionType.DENY,
                reason=f"Gateway HTTP Error {http_err.code} (Fail-Closed): {http_err.reason}",
                executed=False,
            )

        except (urllib.error.URLError, TimeoutError) as conn_err:
            logger.error(f"Gateway connection failure: {conn_err}. Enforcing FAIL-CLOSED.")
            return GatewayResponse(
                decision=DecisionType.DENY,
                reason=f"Gateway Unreachable (Fail-Closed): {str(conn_err)}",
                executed=False,
            )

        except Exception as general_err:
            logger.error(f"Unexpected gateway client error: {general_err}. Enforcing FAIL-CLOSED.")
            return GatewayResponse(
                decision=DecisionType.DENY,
                reason=f"Gateway Error (Fail-Closed): {str(general_err)}",
                executed=False,
            )


def get_gateway_client(
    gateway_type: Optional[str] = None,
    gateway_url: Optional[str] = None,
) -> SecurityGatewayInterface:
    effective_type = (gateway_type or os.environ.get("GATEWAY_TYPE", "mock")).lower()

    if effective_type in ("remote", "http", "live"):
        return HttpGatewayClient(gateway_url=gateway_url)

    return MockGatewayAdapter()
