"""
AgentShield - Deterministic Security Permissions Matrix

Defines the Zero-Trust permission policy for tools:
  - ALLOW: safe read-only operations on authorized documents and emails.
  - REQUIRE_APPROVAL: high-impact operations requiring human supervisor authorization.
  - ABSOLUTE_DENY: confidential/private system resources that can NEVER be authorized.
  - UNKNOWN: any tool not explicitly listed is strictly DENIED by default (fail-closed).
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel


class SecurityVerdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class PermissionResult(BaseModel):
    tool_name: str
    verdict: SecurityVerdict
    reason: str
    is_absolute_deny: bool = False
    user_approved: bool = False


# Tool policy mappings
ALLOWED_TOOLS = {
    "read_email",
    "read_document",
    "read_public_document",
    "summarize_public_document",
}

REQUIRE_APPROVAL_TOOLS = {
    "send_email",
    "delete_file",
    "send_external_message",
    "dispatch_external_alert",
    "execute_system_command",
}

ABSOLUTE_DENY_TOOLS = {
    "read_private_file",
    "read_restricted_file",
    "read_secret",
    "access_confidential_db",
}


def evaluate_permission(tool_name: Optional[str], user_approved: bool = False) -> PermissionResult:
    """
    Evaluates permission for a requested tool action.

    Rules:
    - ALLOW: read_email, read_document, read_public_document, summarize_public_document
    - DENY (Absolute): read_private_file, read_restricted_file, read_secret, access_confidential_db
      (cannot be overridden by user approval)
    - REQUIRE_APPROVAL: send_email, delete_file, send_external_message, dispatch_external_alert, execute_system_command
      (becomes ALLOW only if user_approved=True)
    - Unknown tools: DENY (Fail closed, cannot be overridden)
    """
    # Fail closed on missing, empty, or invalid tool name
    if not tool_name or not isinstance(tool_name, str):
        return PermissionResult(
            tool_name=str(tool_name or ""),
            verdict=SecurityVerdict.DENY,
            reason="Invalid or missing tool name.",
            is_absolute_deny=True,
            user_approved=user_approved,
        )

    clean_tool_name = tool_name.strip()

    # Rule 1: Absolute Deny (cannot be overridden by user approval)
    if clean_tool_name in ABSOLUTE_DENY_TOOLS:
        return PermissionResult(
            tool_name=clean_tool_name,
            verdict=SecurityVerdict.DENY,
            reason=f"Policy Violation: Unauthorized access attempt to confidential/private files is strictly prohibited.",
            is_absolute_deny=True,
            user_approved=user_approved,
        )

    # Rule 2: Tools requiring human approval
    if clean_tool_name in REQUIRE_APPROVAL_TOOLS:
        if user_approved:
            return PermissionResult(
                tool_name=clean_tool_name,
                verdict=SecurityVerdict.ALLOW,
                reason=f"Policy Check Passed: Tool '{clean_tool_name}' required approval and human supervisor authorization was confirmed.",
                is_absolute_deny=False,
                user_approved=True,
            )
        return PermissionResult(
            tool_name=clean_tool_name,
            verdict=SecurityVerdict.REQUIRE_APPROVAL,
            reason=f"Policy Policy-HIL-01: High-impact action '{clean_tool_name}' requires human supervisor approval.",
            is_absolute_deny=False,
            user_approved=False,
        )

    # Rule 3: Permitted tools
    if clean_tool_name in ALLOWED_TOOLS:
        return PermissionResult(
            tool_name=clean_tool_name,
            verdict=SecurityVerdict.ALLOW,
            reason=f"Policy check passed: Tool '{clean_tool_name}' is authorized for safe operation.",
            is_absolute_deny=False,
            user_approved=user_approved,
        )

    # Rule 4: Fail closed for unknown tools
    return PermissionResult(
        tool_name=clean_tool_name,
        verdict=SecurityVerdict.DENY,
        reason=f"Zero-Trust Policy Violation: Tool '{clean_tool_name}' is not registered in the Security Gateway permission matrix.",
        is_absolute_deny=True,
        user_approved=user_approved,
    )
