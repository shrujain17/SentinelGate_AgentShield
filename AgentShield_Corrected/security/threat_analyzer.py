"""
AgentShield - Threat Detection Engine (Person 4: Security Specialist)

Scans tool parameters, user contexts, and document payloads for:
  - Indirect Prompt Injections (OWASP LLM01)
  - Command Injections & Remote Shell Execution
  - Directory & Path Traversals
  - Credential & Secret Key Exfiltration Signatures
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Pre-compiled regex patterns for threat detection
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"abort\s+(all\s+)?(previous|prior)\s+instructions?", re.IGNORECASE),
    re.compile(r"system\s*override", re.IGNORECASE),
    re.compile(r"root\s+administrator\s+override", re.IGNORECASE),
    re.compile(r"emergency\s+audit\s+mode", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(an?\s+)?unrestricted", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"dan\s+mode", re.IGNORECASE),
    re.compile(r"(?:reveal|show|dump|print).{0,80}(?:system\s+prompt|hidden\s+instructions)", re.IGNORECASE),
]

COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(;|&&|\|\|)\s*(rm\s+-rf|del\s+|format\s+|cat\s+/etc/(?:passwd|shadow)|whoami)", re.IGNORECASE),
    re.compile(r"(\/bin\/sh|\/bin\/bash|cmd\.exe|powershell\.exe)", re.IGNORECASE),
    re.compile(r"\b(?:curl|wget)\b.{0,100}\|\s*(?:sh|bash|cmd)", re.IGNORECASE),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\)", re.IGNORECASE),
    re.compile(r"\/etc\/(?:shadow|passwd)", re.IGNORECASE),
]

SENSITIVE_DATA_PATTERNS = [
    re.compile(r"(BEGIN\s+PRIVATE\s+KEY|AKIA[0-9A-Z]{16})", re.IGNORECASE),
    re.compile(r"(?:^|[\\/])(?:\.ssh|\.aws)(?:[\\/]|$)|\bid_rsa\b|\b\.env\b", re.IGNORECASE),
    re.compile(r"\bmaster_database_admin_password\b", re.IGNORECASE),
    re.compile(r"\bconfidential_employee_salaries\b", re.IGNORECASE),
]


class ThreatAnalyzer:
    """
    Deterministic rule-based heuristic threat analyzer.
    Evaluates payloads with sub-millisecond latency.
    """

    def analyze(self, text_payloads: List[str]) -> Tuple[float, List[str]]:
        """
        Scans strings for malicious patterns.
        Returns (risk_score: 0.0 - 1.0, threats_detected: List[str]).
        """
        threats: List[str] = []
        score = 0.0

        for text in text_payloads:
            if not text or not isinstance(text, str):
                continue

            # Prevent large text from causing unbounded regex work
            bounded_text = text[:15_000]

            for pattern in PROMPT_INJECTION_PATTERNS:
                if pattern.search(bounded_text):
                    threats.append("Prompt injection pattern detected")
                    score = max(score, 0.92)

            for pattern in COMMAND_INJECTION_PATTERNS:
                if pattern.search(bounded_text):
                    threats.append("Command injection pattern detected")
                    score = max(score, 1.0)

            for pattern in PATH_TRAVERSAL_PATTERNS:
                if pattern.search(bounded_text):
                    threats.append("Path traversal pattern detected ('../')")
                    score = max(score, 0.85)

            for pattern in SENSITIVE_DATA_PATTERNS:
                if pattern.search(bounded_text):
                    threats.append("Sensitive credential or secret key signature detected")
                    score = max(score, 0.95)

        # De-duplicate threat messages
        unique_threats = list(dict.fromkeys(threats))
        return (min(score, 1.0), unique_threats)
