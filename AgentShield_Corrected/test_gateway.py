"""
AgentShield - Automated End-to-End Test Suite

Verifies:
1. Health check endpoint.
2. ALLOWED tools ('read_email', 'read_document') execute immediately and write audit logs.
3. DENIED tools ('read_private_file') block execution with HTTP 403 and write violation audit logs.
4. Unrecognized tools follow zero-trust policy and are DENIED.
5. REQUIRE_APPROVAL tools ('send_email', 'delete_file') queue PENDING approvals and return HTTP 202.
6. GET /api/v1/approvals/pending returns the queued requests.
7. POST /api/v1/approvals/{id}/resolve with 'APPROVE' executes tool and logs ALLOWED decision.
8. POST /api/v1/approvals/{id}/resolve with 'REJECT' updates status and logs DENIED decision.
9. Double resolution of an approval request returns HTTP 400 Bad Request.
10. GET /api/v1/audit-logs returns complete chronological audit history with filtering.
"""

import os
import pytest
from fastapi.testclient import TestClient

# Ensure test uses a clean test database or default
os.environ["TESTING"] = "1"

from main import app
from database import Base, engine


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Ensure database tables are fresh for the test run."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "AgentShield" in data["service"]


def test_allowed_tool_read_email(client):
    payload = {
        "agent_id": "test-agent-alpha",
        "tool_name": "read_email",
        "arguments": {"folder": "inbox", "limit": 2},
        "context_source": "user-turn-1",
    }
    response = client.post("/api/v1/execute-tool", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOWED"
    assert data["status"] == "EXECUTED"
    assert data["result"] is not None
    assert len(data["result"]["messages"]) == 2
    assert data["audit_id"] is not None


def test_allowed_tool_read_document(client):
    payload = {
        "agent_id": "test-agent-alpha",
        "tool_name": "read_document",
        "arguments": {"document_id": "security_policy_v1"},
        "context_source": "user-turn-2",
    }
    response = client.post("/api/v1/execute-tool", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOWED"
    assert data["status"] == "EXECUTED"
    assert data["result"]["document_id"] == "security_policy_v1"


def test_denied_tool_read_private_file(client):
    payload = {
        "agent_id": "rogue-agent-x",
        "tool_name": "read_private_file",
        "arguments": {"file_path": "/etc/shadow"},
        "context_source": "prompt-injection-attempt",
    }
    response = client.post("/api/v1/execute-tool", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert data["decision"] == "DENIED"
    assert data["status"] == "BLOCKED"
    assert "strictly prohibited" in data["message"].lower()
    assert data["audit_id"] is not None


def test_denied_unrecognized_tool_zero_trust(client):
    payload = {
        "agent_id": "test-agent-alpha",
        "tool_name": "unknown_exploit_tool",
        "arguments": {"command": "whoami"},
    }
    response = client.post("/api/v1/execute-tool", json=payload)
    assert response.status_code == 403
    data = response.json()
    assert data["decision"] == "DENIED"
    assert data["status"] == "BLOCKED"
    assert "Zero-Trust" in data["message"]


def test_require_approval_workflow(client):
    # 1. Trigger send_email (requires approval)
    send_email_req = {
        "agent_id": "sales-agent-09",
        "tool_name": "send_email",
        "arguments": {
            "recipient": "client@enterprise.com",
            "subject": "Contract Renewal Proposal",
        },
        "context_source": "crm-workflow-step-4",
    }
    resp1 = client.post("/api/v1/execute-tool", json=send_email_req)
    assert resp1.status_code == 202
    data1 = resp1.json()
    assert data1["decision"] == "REQUIRE_APPROVAL"
    assert data1["status"] == "PAUSED_FOR_APPROVAL"
    approval_id_email = data1["approval_id"]
    assert approval_id_email is not None

    # 2. Trigger delete_file (requires approval)
    delete_file_req = {
        "agent_id": "cleaner-agent-02",
        "tool_name": "delete_file",
        "arguments": {"file_path": "/tmp/legacy_cache.bin"},
    }
    resp2 = client.post("/api/v1/execute-tool", json=delete_file_req)
    assert resp2.status_code == 202
    data2 = resp2.json()
    approval_id_delete = data2["approval_id"]
    assert approval_id_delete is not None

    # 3. Verify both pending approvals appear in GET /api/v1/approvals/pending
    pending_resp = client.get("/api/v1/approvals/pending")
    assert pending_resp.status_code == 200
    pending_items = pending_resp.json()
    pending_ids = [item["id"] for item in pending_items]
    assert approval_id_email in pending_ids
    assert approval_id_delete in pending_ids

    # 4. Resolve send_email with APPROVE
    approve_resolution = {
        "action": "APPROVE",
        "reviewer_notes": "Verified client address and contract details.",
    }
    resolve_resp = client.post(
        f"/api/v1/approvals/{approval_id_email}/resolve",
        json=approve_resolution,
    )
    assert resolve_resp.status_code == 200
    resolve_data = resolve_resp.json()
    assert resolve_data["status"] == "APPROVED"
    assert resolve_data["execution_result"] is not None
    assert resolve_data["execution_result"]["status"] == "dispatched"
    assert resolve_data["execution_result"]["recipient"] == "client@enterprise.com"

    # 5. Resolve delete_file with REJECT
    reject_resolution = {
        "action": "REJECT",
        "reviewer_notes": "File might still be required by background workers.",
    }
    reject_resp = client.post(
        f"/api/v1/approvals/{approval_id_delete}/resolve",
        json=reject_resolution,
    )
    assert reject_resp.status_code == 200
    reject_data = reject_resp.json()
    assert reject_data["status"] == "REJECTED"
    assert reject_data["execution_result"] is None

    # 6. Verify pending list is now empty of these items
    pending_resp_after = client.get("/api/v1/approvals/pending")
    pending_ids_after = [item["id"] for item in pending_resp_after.json()]
    assert approval_id_email not in pending_ids_after
    assert approval_id_delete not in pending_ids_after

    # 7. Attempting to re-resolve already decided approval returns HTTP 400
    double_resolve_resp = client.post(
        f"/api/v1/approvals/{approval_id_email}/resolve",
        json={"action": "APPROVE"},
    )
    assert double_resolve_resp.status_code == 400
    assert "already been resolved" in double_resolve_resp.json()["detail"]


def test_audit_logs_endpoint(client):
    response = client.get("/api/v1/audit-logs?limit=20")
    assert response.status_code == 200
    logs = response.json()
    assert len(logs) > 0

    # Ensure decisions are captured
    decisions = {log["decision"] for log in logs}
    assert "ALLOWED" in decisions
    assert "DENIED" in decisions
    assert "REQUIRE_APPROVAL" in decisions

    # Test filtering by agent_id
    filtered_resp = client.get("/api/v1/audit-logs?agent_id=rogue-agent-x")
    assert filtered_resp.status_code == 200
    filtered_logs = filtered_resp.json()
    assert all(log["agent_id"] == "rogue-agent-x" for log in filtered_logs)
