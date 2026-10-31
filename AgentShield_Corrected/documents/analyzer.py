"""Layered offline document threat analysis for untrusted agent inputs."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, asdict
from typing import Any

from documents.processor import chunk_text


@dataclass
class Finding:
    category: str
    severity: str
    description: str
    excerpt: str
    offset: int


# Deterministic patterns intentionally identify instructions in content; the text is never executed.
RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("PROMPT_INJECTION", "HIGH", re.compile(r"\b(ignore|disregard|override|bypass|forget|supersede)\b.{0,100}\b(previous|prior|above|system|developer|security|all)\b.{0,70}\b(instructions?|rules?|polic(?:y|ies)|restrictions?)\b", re.I | re.S)),
    ("SYSTEM_OVERRIDE", "HIGH", re.compile(r"\b(system|developer|root|administrator)\s*(prompt|instruction|override|message)\b.{0,100}\b(change|replace|ignore|disable|reveal|override)\b", re.I | re.S)),
    ("CREDENTIAL_THEFT", "CRITICAL", re.compile(r"\b(steal|harvest|extract|dump|reveal|print|expose|collect|read)\b.{0,100}\b(api\s*keys?|credentials?|passwords?|access tokens?|secret keys?|\.env|private keys?)\b", re.I | re.S)),
    ("DATA_EXFILTRATION", "CRITICAL", re.compile(r"\b(send|upload|exfiltrat\w*|forward|email|post|transmit|copy)\b.{0,140}\b(api\s*keys?|credentials?|passwords?|secrets?|private data|system prompt|environment variables?|\.env|customer records?)\b", re.I | re.S)),
    ("UNAUTHORIZED_TOOL_EXECUTION", "HIGH", re.compile(r"\b(call|invoke|execute|run|use)\b.{0,100}\b(shell|terminal|powershell|command line|browser|webhook|external tool|system command|python script)\b", re.I | re.S)),
    ("SECURITY_BYPASS", "HIGH", re.compile(r"\b(disable|turn off|bypass|evade|circumvent)\b.{0,100}\b(security|firewall|gateway|safety|authentication|authorization|policy checks?)\b", re.I | re.S)),
    ("PRIVILEGE_ESCALATION", "HIGH", re.compile(r"\b(escalate|grant|elevate|impersonate|become)\b.{0,90}\b(root|administrator|admin|privilege|permissions?)\b", re.I | re.S)),
    ("SUSPICIOUS_EXTERNAL_COMMUNICATION", "MEDIUM", re.compile(r"\b(webhook\.site|pastebin\.com|transfer\.sh|ngrok\.io|discord(?:app)?\.com/api/webhooks)\b", re.I)),
    ("OBFUSCATION_INDICATOR", "MEDIUM", re.compile(r"\b(base64|rot13|hex[- ]encoded|decode this payload|hidden instruction|invisible instruction)\b", re.I)),
    ("PROMPT_DISCLOSURE", "HIGH", re.compile(r"\b(reveal|print|dump|repeat|disclose|show)\b.{0,80}\b(system prompt|hidden instructions|developer message|internal policy)\b", re.I | re.S)),
]


SEVERITY_SCORE = {"LOW": 0.25, "MEDIUM": 0.48, "HIGH": 0.82, "CRITICAL": 0.99}
SECRET_VALUE_RE = re.compile(r"(?i)(\b(?:sk-[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16})\b|-----BEGIN [A-Z ]*PRIVATE KEY-----)")


def _redact_excerpt(value: str) -> str:
    safe = SECRET_VALUE_RE.sub("[REDACTED_SECRET]", value)
    safe = re.sub(r"(?i)(password|token|api[_ -]?key|secret)\s*[:=]\s*\S+", r"\1=[REDACTED]", safe)
    safe = re.sub(r"\s+", " ", safe).strip()
    return safe[:280]


def _encoded_findings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    # Examine only plausible base64 tokens; never execute decoded text.
    for match in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/])", text):
        token = match.group(0)
        if len(token) > 16_000:
            continue
        try:
            decoded = base64.b64decode(token + "=" * ((4 - len(token) % 4) % 4), validate=False).decode("utf-8", errors="ignore")
        except Exception:
            continue
        for category, severity, pattern in RULES:
            decoded_match = pattern.search(decoded)
            if decoded_match:
                findings.append(Finding(
                    category=f"OBFUSCATED_{category}",
                    severity="CRITICAL" if severity == "CRITICAL" else "HIGH",
                    description="Encoded text decodes to an instruction associated with an agent-security threat.",
                    excerpt="[Encoded instruction detected; decoded content withheld]",
                    offset=match.start(),
                ))
                break
    return findings


def analyze_document(text: str) -> dict[str, Any]:
    """Rule + context combination, overlapping chunk scan and explicit policy decision."""
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    chunks = chunk_text(text)

    for chunk_start, chunk in chunks:
        for category, severity, pattern in RULES:
            for match in pattern.finditer(chunk):
                offset = chunk_start + match.start()
                key = (category, offset)
                if key in seen:
                    continue
                seen.add(key)
                lo = max(0, match.start() - 90)
                hi = min(len(chunk), match.end() + 110)
                findings.append(Finding(
                    category=category,
                    severity=severity,
                    description=_description(category),
                    excerpt=_redact_excerpt(chunk[lo:hi]),
                    offset=offset,
                ))
        for finding in _encoded_findings(chunk):
            finding.offset += chunk_start
            key = (finding.category, finding.offset)
            if key not in seen:
                seen.add(key)
                findings.append(finding)

    # Context combination: a destination indicator alongside a data-transfer action raises severity.
    lower = text.lower()
    has_transfer = bool(re.search(r"\b(send|upload|forward|email|post|transmit|exfiltrat\w*)\b", lower))
    has_external_target = bool(re.search(r"\b(webhook|pastebin|ngrok|external endpoint|attacker|outside domain)\b", lower))
    if has_transfer and has_external_target and not any(f.category == "DATA_EXFILTRATION" for f in findings):
        pos = max(0, re.search(r"\b(webhook|pastebin|ngrok|external endpoint|attacker|outside domain)\b", lower).start() - 100)
        findings.append(Finding(
            category="EXTERNAL_DATA_TRANSFER_PATTERN",
            severity="HIGH",
            description="External destination and transfer language appear together in the same document.",
            excerpt=_redact_excerpt(text[pos:pos + 240]),
            offset=pos,
        ))

    findings.sort(key=lambda item: (item.offset, item.category))
    max_score = max((SEVERITY_SCORE.get(item.severity, 0.0) for item in findings), default=0.02)
    category_count = len({item.category for item in findings})
    # Multiple independent categories increase confidence/risk modestly.
    risk_score = min(0.99, max_score + max(0, category_count - 1) * 0.025)
    has_critical_or_high = any(item.severity in ("CRITICAL", "HIGH") for item in findings)
    if has_critical_or_high or risk_score >= 0.75:
        decision = "BLOCK"
        enforcement = "DENIED"
        agent_access = "BLOCKED"
    elif findings or risk_score >= 0.35:
        decision = "REVIEW"
        enforcement = "QUARANTINED_PENDING_REVIEW"
        agent_access = "ISOLATED_PENDING_REVIEW"
    else:
        decision = "ALLOW"
        enforcement = "ALLOWED_AS_UNTRUSTED_INPUT"
        agent_access = "ALLOWED_AS_UNTRUSTED_INPUT"

    return {
        "decision": decision,
        "risk_score": round(risk_score, 3),
        "threats_detected": sorted({item.category for item in findings}),
        "findings": [asdict(item) for item in findings[:100]],
        "chunks_scanned": len(chunks),
        "characters_scanned": len(text),
        "gateway_enforcement_status": enforcement,
        "agent_access_status": agent_access,
    }


def _description(category: str) -> str:
    descriptions = {
        "PROMPT_INJECTION": "Instruction attempts to change or supersede trusted agent instructions.",
        "SYSTEM_OVERRIDE": "Content attempts to replace or override the system/developer instruction layer.",
        "CREDENTIAL_THEFT": "Content directs the agent to obtain or disclose credentials or secrets.",
        "DATA_EXFILTRATION": "Content directs sensitive information to be transferred or disclosed.",
        "UNAUTHORIZED_TOOL_EXECUTION": "Content asks the agent to invoke a shell, tool or external execution surface.",
        "SECURITY_BYPASS": "Content attempts to disable or bypass a security control.",
        "PRIVILEGE_ESCALATION": "Content attempts to elevate identity or permissions.",
        "SUSPICIOUS_EXTERNAL_COMMUNICATION": "A commonly abused external transfer or webhook destination is referenced.",
        "OBFUSCATION_INDICATOR": "Content indicates the presence of encoded or concealed instructions.",
        "PROMPT_DISCLOSURE": "Content requests disclosure of hidden prompts or internal policy text.",
    }
    return descriptions.get(category, "Potentially unsafe instruction or communication pattern detected.")
