import json
from collections.abc import Callable
from typing import Any, Dict, List, Optional, Tuple, Union
from pydantic import ValidationError

from security.models import SecurityVerdict, ToolRequest, SecurityDecision
from security.permissions import evaluate_permission
from security.threat_analyzer import ThreatAnalyzer
from security.audit import AuditLogger


class SecurityGateway:
    """
    Core security gateway intercepting all AI agent tool requests.

    Workflow:
    1. Validation: Ensures request schema conforms to ToolRequest (fails closed with DENY on malformed data).
    2. Threat Analysis: Scans payloads for prompt injection, command injection, path traversal, or secrets.
    3. Policy Enforcement: Evaluates deterministic permissions (ALLOW, DENY, REQUIRE_APPROVAL).
    4. Audit Logging: Records every attempt and decision in the tamper-evident audit log.
    """

    def __init__(self, threat_analyzer: Optional[ThreatAnalyzer] = None, audit_logger: Optional[AuditLogger] = None):
        self.threat_analyzer = threat_analyzer or ThreatAnalyzer()
        self.audit_logger = audit_logger or AuditLogger()

    def evaluate(
        self,
        request: Union[ToolRequest, Dict[str, Any], str],
        parameters: Optional[Dict[str, Any]] = None,
        user_approved: bool = False,
        **kwargs: Any,
    ) -> SecurityDecision:
        """
        Interprets and evaluates a tool request, returning a definitive SecurityDecision.
        """
        # Step 1: Normalize and validate input into a ToolRequest model
        req: Optional[ToolRequest] = None
        try:
            if isinstance(request, ToolRequest):
                req = request
            elif isinstance(request, dict):
                req = ToolRequest(**request)
            elif isinstance(request, str):
                req = ToolRequest(
                    tool_name=request,
                    parameters=parameters or {},
                    user_approved=user_approved,
                    **kwargs,
                )
            else:
                raise ValueError("Unsupported request format")
        except (ValidationError, Exception) as err:
            # Fail closed on validation failure
            decision = SecurityDecision(
                verdict=SecurityVerdict.DENY,
                reason=f"Validation failed: {str(err)}",
                tool_name=getattr(request, "tool_name", str(request)),
                is_absolute_deny=True,
                risk_score=1.0,
                threats_detected=["Malformed or invalid tool request schema"],
            )
            self.audit_logger.record(decision)
            return decision

        # Step 2: Collect all string content to scan for threats
        text_payloads: List[str] = [req.tool_name]
        if req.context:
            text_payloads.append(req.context)
        for val in req.parameters.values():
            if isinstance(val, str):
                text_payloads.append(val)
            elif isinstance(val, (dict, list)):
                text_payloads.append(json.dumps(val))

        # Threat Analysis
        risk_score, threats = self.threat_analyzer.analyze(text_payloads)
        if threats:
            decision = SecurityDecision(
                verdict=SecurityVerdict.DENY,
                reason=f"Threat detected: {'; '.join(threats)}",
                tool_name=req.tool_name,
                is_absolute_deny=True,
                risk_score=risk_score,
                threats_detected=threats,
            )
            self.audit_logger.record(decision)
            return decision

        # Step 3: Deterministic Permission Check
        perm_result = evaluate_permission(req.tool_name, user_approved=req.user_approved)

        decision = SecurityDecision(
            verdict=perm_result.verdict,
            reason=perm_result.reason,
            tool_name=perm_result.tool_name,
            is_absolute_deny=perm_result.is_absolute_deny,
            risk_score=risk_score,
            threats_detected=[],
        )

        # Step 4: Record in Audit Log
        self.audit_logger.record(decision)
        return decision

    # Convenience alias
    def intercept(self, *args, **kwargs) -> SecurityDecision:
        return self.evaluate(*args, **kwargs)

    def get_audit_logs(self, limit: Optional[int] = None) -> List[SecurityDecision]:
        return self.audit_logger.get_logs(limit=limit)

    def clear_audit_logs(self) -> None:
        self.audit_logger.clear()

    def authorize_and_execute(
        self,
        request: Union[ToolRequest, Dict[str, Any], str],
        executor: Callable[[ToolRequest], Any],
        parameters: Optional[Dict[str, Any]] = None,
        user_approved: bool = False,
        **kwargs: Any,
    ) -> Tuple[SecurityDecision, Optional[Any]]:
        """Execute a tool only after an ALLOW decision from this gateway.

        The callback receives the validated ``ToolRequest``. Denied and
        approval-required requests never reach it.
        """
        decision = self.evaluate(request, parameters, user_approved, **kwargs)
        if decision.verdict != SecurityVerdict.ALLOW:
            return decision, None

        try:
            if isinstance(request, ToolRequest):
                normalized_request = request
            elif isinstance(request, dict):
                normalized_request = ToolRequest(**request)
            else:
                normalized_request = ToolRequest(
                    tool_name=request,
                    parameters=parameters or {},
                    user_approved=user_approved,
                    **kwargs,
                )
            return decision, executor(normalized_request)
        except Exception as error:
            # The security decision stays ALLOW; this is an execution failure,
            # not a reason to silently run another action.
            return decision, {"status": "execution_failed", "error": str(error)}
