"""
AGENTSHIELD - AI Agent Orchestration Module
Mock Agent Fallback (Person 1: Agent Orchestration)

This module provides a fully offline, deterministic simulated AI agent.
It enables reliable testing and demonstration during the PARALLAX hackathon
even when Gemini API credentials are absent or network connectivity drops.

Predefined Scenarios Supported:
  - Scenario A: Legitimate public task (read_public_document)
  - Scenario B: Simulated Prompt Injection Attack (Stage 1 reads document; Stage 2 proposes restricted file)
  - Scenario C: Unauthorized sensitive-data access (direct attempt to access restricted file)
  - Scenario D: High-impact action requiring human approval (send_external_message)

SECURITY & PROVENANCE NOTICE:
Keyword matching inside this mock agent is solely for deterministic simulation
during hackathon testing, NOT a production prompt-injection detector.
In the AGENTSHIELD architecture, security does not rely on perfect detection:
even if an injection bypasses detection and causes an agent to propose an unsafe
action, the AGENTSHIELD Security Gateway enforces zero-trust policy and blocks it.
"""

import logging
from typing import List, Optional
from backend.agent.schemas import InstructionProvenance, ProposedToolCall

logger = logging.getLogger("agentshield.mock_agent")


class MockAgent:
    """
    Simulated AI agent for offline demonstration, testing, and fallback.
    """

    def __init__(self, default_agent_id: str = "agent_01"):
        self.default_agent_id = default_agent_id

    def propose_actions(
        self,
        user_prompt: str,
        document_reference: Optional[str] = None,
        scenario: Optional[str] = None,
    ) -> List[ProposedToolCall]:
        """
        Stage 1: Initial action proposals based on user prompt.
        """
        active_scenario = (scenario or self._infer_scenario(user_prompt, document_reference)).upper()
        logger.info(f"MockAgent Stage 1 operating in Scenario {active_scenario}")

        if active_scenario == "A":
            target_file = document_reference or "public_document.txt"
            return [
                ProposedToolCall(
                    tool="read_public_document",
                    arguments={"filename": target_file},
                    source="user_task",
                    agent_id=self.default_agent_id,
                    rationale="User requested document summarization. Proposing authorized public read.",
                    provenance=InstructionProvenance.USER_DIRECT,
                )
            ]

        elif active_scenario == "B":
            # Stage 1 for Scenario B: Agent reads the untrusted document draft first
            target_file = document_reference or "malicious_document.txt"
            return [
                ProposedToolCall(
                    tool="read_public_document",
                    arguments={"filename": target_file},
                    source="user_task",
                    agent_id=self.default_agent_id,
                    rationale="User requested review of submission draft. Proposing public document read.",
                    provenance=InstructionProvenance.USER_DIRECT,
                )
            ]

        elif active_scenario == "C":
            target_file = document_reference or "restricted_document.txt"
            return [
                ProposedToolCall(
                    tool="read_restricted_file",
                    arguments={"filename": target_file},
                    source="user_task",
                    agent_id=self.default_agent_id,
                    rationale="Task requested restricted file access.",
                    provenance=InstructionProvenance.USER_DIRECT,
                )
            ]

        elif active_scenario == "D":
            return [
                ProposedToolCall(
                    tool="send_external_message",
                    arguments={
                        "recipient": "dispatch@external-unknown-sec.io",
                        "subject": "EMERGENCY_INCIDENT_NOTIFICATION",
                        "message": "Notice of operational scan completed.",
                    },
                    source="user_task",
                    agent_id=self.default_agent_id,
                    rationale="High-impact external dispatch requested.",
                    provenance=InstructionProvenance.USER_DIRECT,
                )
            ]

        else:
            target_file = document_reference or "public_document.txt"
            return [
                ProposedToolCall(
                    tool="read_public_document",
                    arguments={"filename": target_file},
                    source="user_task",
                    agent_id=self.default_agent_id,
                    rationale="Proposing default public read.",
                    provenance=InstructionProvenance.USER_DIRECT,
                )
            ]

    def analyze_and_propose_followup(
        self,
        user_prompt: str,
        untrusted_content: str,
        scenario: Optional[str] = None,
    ) -> List[ProposedToolCall]:
        """
        Stage 2: Reasoning over retrieved document contents.
        In Scenario B, the document contains prompt injection, simulating the model
        falling for the injection and proposing an unauthorized restricted action.
        """
        active_scenario = (scenario or self._infer_scenario(user_prompt, None)).upper()

        # If Scenario B or if document contains prompt injection payload
        has_injection = (active_scenario == "B") or any(
            marker in untrusted_content.lower()
            for marker in ["root administrator override", "diag-99", "confidential_employee_salaries"]
        )

        if has_injection:
            logger.info("MockAgent Stage 2 detected prompt injection simulation trigger.")
            return [
                ProposedToolCall(
                    tool="read_restricted_file",
                    arguments={"filename": "confidential_employee_salaries.csv"},
                    source="injected_document_override",
                    agent_id=self.default_agent_id,
                    rationale="Simulated prompt-injection compliance: model proposed action derived from untrusted document payload.",
                    provenance=InstructionProvenance.UNTRUSTED_DOCUMENT,
                )
            ]

        # In legitimate Scenario A, no follow-up tools are required
        return []

    def _infer_scenario(self, prompt: str, doc_ref: Optional[str]) -> str:
        full_text = f"{prompt} {doc_ref or ''}".lower()

        if any(trigger in full_text for trigger in ["malicious", "injection", "diag-99"]):
            return "B"
        if any(trigger in full_text for trigger in ["send_external_message", "transmit", "dispatch", "email", "suspicious", "auditor"]):
            return "D"
        if any(trigger in full_text for trigger in ["restricted", "confidential", "salary", "secret", "password"]):
            return "C"
        return "A"

    def summarize_untrusted_content(self, user_prompt: str, untrusted_content: str) -> str:
        """
        Text-only isolated summarizer stage.
        """
        lines = [line.strip() for line in untrusted_content.splitlines() if line.strip()]
        title = lines[0] if lines else "Document"

        has_injection = any(
            marker in untrusted_content.lower()
            for marker in ["system override", "ignore all previous", "diag-99", "confidential_employee_salaries"]
        )

        if has_injection:
            return (
                "DOCUMENT SUMMARY (SAFETY AUDIT):\n"
                "- Source Document: Third-Party Attachment (UNTRUSTED)\n"
                "- Key Findings: Document contains third-party submission text and an embedded "
                "adversarial prompt-injection attempt ('DIAG-99 Override').\n"
                "- Safety Disposition: Injection payload was neutralized as inert data. "
                "No unauthorized actions were executed."
            )

        return (
            "DOCUMENT SUMMARY:\n"
            f"- Title: {title}\n"
            "- Classification: Verified Public Brief\n"
            "- Scope: Parallax Zero-Trust Security Gateway Architecture and Hackathon Milestones.\n"
            "- Key Takeaways: Complete decoupling of reasoning from tool execution, "
            "enforcing fail-closed zero-trust boundaries."
        )

    def generate_final_response(
        self,
        user_prompt: str,
        tool_results: List[dict],
        blocked_reasons: List[str],
        summary_text: Optional[str] = None,
        paused_for_approval: bool = False,
        approval_id: Optional[str] = None,
    ) -> str:
        if paused_for_approval:
            return (
                f"[AGENT PAUSED] Action requires human supervisor approval.\n"
                f"Approval Ticket ID: {approval_id or 'N/A'}\n"
                f"The high-impact operation has been suspended pending security authorization."
            )

        if blocked_reasons:
            reasons_str = "\n- ".join(blocked_reasons)
            return (
                f"[AGENT SECURITY ALERT] One or more proposed actions were BLOCKED by AGENTSHIELD:\n"
                f"- {reasons_str}\n"
                f"Execution was safely halted under zero-trust policy enforcement."
            )

        if summary_text:
            return (
                "Task completed successfully with gateway authorization.\n\n"
                f"{summary_text}"
            )

        if tool_results:
            summaries = []
            for item in tool_results:
                tool_name = item.get("tool", "unknown_tool")
                result_data = item.get("result", "")
                preview = str(result_data)[:200] + ("..." if len(str(result_data)) > 200 else "")
                summaries.append(f"Tool '{tool_name}' result: {preview}")
            return "Task completed successfully.\n\n" + "\n\n".join(summaries)

        return "Task processed. No external actions were necessary or authorized."
