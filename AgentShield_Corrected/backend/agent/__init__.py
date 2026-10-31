"""
AGENTSHIELD - AI Agent Orchestration Module (Person 1)
"""

from backend.agent.agent import AgentShieldAgent
from backend.agent.gateway_client import (
    HttpGatewayClient,
    MockGatewayAdapter,
    SecurityGatewayInterface,
    get_gateway_client,
)
from backend.agent.gemini_provider import GeminiProvider, GeminiProviderError
from backend.agent.mock_agent import MockAgent
from backend.agent.orchestrator import AgentOrchestrator
from backend.agent.schemas import (
    AgentExecutionResult,
    AgentTask,
    ApprovalResumeRequest,
    DecisionType,
    GatewayRequest,
    GatewayResponse,
    InstructionProvenance,
    PendingApprovalItem,
    ProposedToolCall,
    TaskStatus,
    validate_gateway_response,
)

__all__ = [
    "AgentShieldAgent",
    "AgentOrchestrator",
    "GeminiProvider",
    "GeminiProviderError",
    "MockAgent",
    "SecurityGatewayInterface",
    "MockGatewayAdapter",
    "HttpGatewayClient",
    "get_gateway_client",
    "AgentTask",
    "AgentExecutionResult",
    "ProposedToolCall",
    "GatewayRequest",
    "GatewayResponse",
    "ApprovalResumeRequest",
    "PendingApprovalItem",
    "InstructionProvenance",
    "DecisionType",
    "TaskStatus",
    "validate_gateway_response",
]
