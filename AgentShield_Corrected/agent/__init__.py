"""
AgentShield Agent Module
Provides both low-level agent orchestration and high-level service interfaces.
"""

from agent.service import AgentShieldService
from backend.agent.agent import AgentShieldAgent
from backend.agent.orchestrator import AgentOrchestrator
from backend.agent.schemas import (
    AgentTask,
    AgentExecutionResult,
    TaskStatus,
    InstructionProvenance,
    ProposedToolCall,
)

__all__ = [
    "AgentShieldService",
    "AgentShieldAgent",
    "AgentOrchestrator",
    "AgentTask",
    "AgentExecutionResult",
    "TaskStatus",
    "InstructionProvenance",
    "ProposedToolCall",
]
