"""Append-only audit logging for AgentShield decisions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, List, Optional

from security.models import SecurityDecision


class AuditLogger:
    """Records decisions in memory and, optionally, in a hash-chained JSONL file.

    Only the decision metadata is stored. Tool parameters are deliberately not
    logged here so secrets or message content do not leak into the audit trail.
    """

    def __init__(self, log_path: Optional[str | Path] = None):
        self._records: List[SecurityDecision] = []
        self.log_path = Path(log_path) if log_path else None
        self._last_hash = self._read_last_hash()

    def record(self, decision: SecurityDecision) -> None:
        """Appends a new decision to the audit log."""
        self._records.append(decision)
        if self.log_path:
            self._append_to_file(decision)

    def get_logs(self, limit: Optional[int] = None) -> List[SecurityDecision]:
        """Returns recorded logs, latest first."""
        logs = list(reversed(self._records))
        if limit is not None:
            return logs[:limit]
        return logs

    def clear(self) -> None:
        """Clears the in-memory test view without deleting the persistent log."""
        self._records.clear()

    @property
    def count(self) -> int:
        return len(self._records)

    def _append_to_file(self, decision: SecurityDecision) -> None:
        assert self.log_path is not None
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        event: dict[str, Any] = {
            "event_type": "security_decision",
            "decision": self._decision_to_dict(decision),
            "previous_hash": self._last_hash,
        }
        canonical = json.dumps(event, sort_keys=True, separators=(",", ":"), default=str)
        event_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        event["event_hash"] = event_hash
        with self.log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(event, default=str) + "\n")
        self._last_hash = event_hash

    def _read_last_hash(self) -> str:
        if not self.log_path or not self.log_path.exists():
            return ""
        try:
            last_line = self.log_path.read_text(encoding="utf-8").strip().splitlines()[-1]
            return str(json.loads(last_line).get("event_hash", ""))
        except (IndexError, OSError, json.JSONDecodeError):
            # A damaged log should not prevent the gateway from making a safe decision.
            return ""

    @staticmethod
    def _decision_to_dict(decision: SecurityDecision) -> dict[str, Any]:
        if hasattr(decision, "model_dump"):
            return decision.model_dump(mode="json")
        return decision.dict()
