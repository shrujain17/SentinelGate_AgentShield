import React from 'react';

export default function AccessPolicies() {
  const policies = [
    {
      id: 'POL-01',
      title: 'Zero Direct Tool Execution Invariant',
      category: 'Agent Isolation',
      status: 'ACTIVE_ENFORCING',
      severity: 'CRITICAL',
      rule: 'Autonomous AI agents possess zero local execution privileges, zero direct OS shell access, and zero raw file descriptors. Every action must be converted into a structured ProposedToolCall and routed to SentinelGate.',
      enforcement: 'Hardcoded in AgentOrchestrator and AgentShieldAgent classes. Direct tool execution triggers immediate exception.',
    },
    {
      id: 'POL-02',
      title: 'Provenance-Based Access Control (PBAC)',
      category: 'Data Tainting & Provenance',
      status: 'ACTIVE_ENFORCING',
      severity: 'CRITICAL',
      rule: 'Instruction provenance is determined exclusively by application execution context (USER_DIRECT vs UNTRUSTED_DOCUMENT). AI models are strictly prohibited from assigning their own trusted provenance.',
      enforcement: 'Orchestrator unconditionally overrides any model-generated provenance attribute. Content from tools/documents is automatically tainted.',
    },
    {
      id: 'POL-03',
      title: 'Bounded Reasoning Cycles Limit (Max 2)',
      category: 'Loop Prevention',
      status: 'ACTIVE_ENFORCING',
      severity: 'HIGH',
      rule: 'Agent execution is strictly limited to MAX_REASONING_CYCLES=2. Prevents recursive prompt injection attacks from generating infinite malicious follow-up actions.',
      enforcement: 'Enforced by Stage-1 and Stage-2 counters in orchestrator. Loop termination triggers fail-closed return.',
    },
    {
      id: 'POL-04',
      title: 'Deterministic Absolute Deny Overrides',
      category: 'Access Control',
      status: 'ACTIVE_ENFORCING',
      severity: 'CRITICAL',
      rule: 'Confidential system resources (read_private_file, read_restricted_file, read_secret, access_confidential_db) are permanently blocked. Human supervisor approval CANNOT override an absolute denial.',
      enforcement: 'Checked at Step 1 of evaluate_permission(). is_absolute_deny=True halts authorization unconditionally.',
    },
    {
      id: 'POL-05',
      title: 'Cryptographic Nonce & Single-Use Approval Tokens',
      category: 'Human Oversight (HITL)',
      status: 'ACTIVE_ENFORCING',
      severity: 'HIGH',
      rule: 'Pending approval tickets are cryptographically unique, expire in 300 seconds (TTL), and enforce strict single-use. Replay attempts on already resolved tickets return HTTP 400 Bad Request.',
      enforcement: 'Database record status transition (PENDING -> APPROVED/REJECTED). Second submission is rejected.',
    },
    {
      id: 'POL-06',
      title: 'Exact Argument Binding Invariant',
      category: 'Integrity',
      status: 'ACTIVE_ENFORCING',
      severity: 'CRITICAL',
      rule: 'Supervisor approval authorizes ONLY the exact arguments recorded when the ticket was generated. Runtime argument drift or substitution is impossible.',
      enforcement: 'Execution utilizes the exact serialized payload from the ApprovalRequestModel table.',
    },
    {
      id: 'POL-07',
      title: 'Fail-Closed Contradiction Validation',
      category: 'Zero-Trust Verification',
      status: 'ACTIVE_ENFORCING',
      severity: 'CRITICAL',
      rule: 'If a gateway response exhibits internal contradictions (e.g., ALLOW but executed=False, or REQUIRE_APPROVAL with executed=True, or missing approval_id), the orchestrator immediately halts execution and fails closed.',
      enforcement: 'validate_gateway_response() validates all responses before any downstream processing.',
    },
    {
      id: 'POL-08',
      title: 'Tamper-Evident SHA-256 Hash Chain',
      category: 'Audit & Accountability',
      status: 'ACTIVE_ENFORCING',
      severity: 'HIGH',
      rule: 'Every gateway evaluation writes an append-only audit record linked to the previous block via SHA-256 hash. Any manual file modification or record deletion breaks chain integrity.',
      enforcement: 'AuditLogger generates H_i = SHA256(H_{i-1} + JSON(Record_i)). Verified by /api/v1/audit/verify.',
    },
  ];

  return (
    <div>
      {/* Overview Cards */}
      <div className="metric-grid-4">
        <div className="metric-card allow">
          <div className="metric-label">Active Governance Policies</div>
          <div className="metric-value" style={{ color: 'var(--emerald)' }}>{policies.length}</div>
          <div className="metric-desc">100% Enforcing Zero-Trust</div>
        </div>

        <div className="metric-card purple">
          <div className="metric-label">Enforcement Mode</div>
          <div className="metric-value" style={{ color: 'var(--purple)', fontSize: '1.4rem' }}>FAIL-CLOSED</div>
          <div className="metric-desc">Rejects on contradiction</div>
        </div>

        <div className="metric-card">
          <div className="metric-label">Policy Architecture</div>
          <div className="metric-value" style={{ color: 'var(--cyan)', fontSize: '1.4rem' }}>PBAC + HITL</div>
          <div className="metric-desc">Provenance + Human Review</div>
        </div>

        <div className="metric-card deny">
          <div className="metric-label">Bypass Vulnerability</div>
          <div className="metric-value" style={{ color: 'var(--crimson)' }}>0.0%</div>
          <div className="metric-desc">Interception is mandatory</div>
        </div>
      </div>

      {/* Policies List */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">📜 Enterprise Zero-Trust Policy Declarations</h3>
            <p className="panel-subtitle">Authoritative security mandates enforced by SentinelGate across all agent workflows</p>
          </div>
          <span className="badge allow">ALL POLICIES ACTIVE</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {policies.map((p) => (
            <div
              key={p.id}
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                padding: '1.15rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <span className="badge cyan">{p.id}</span>
                  <strong style={{ fontSize: '0.95rem', color: '#fff' }}>{p.title}</strong>
                  <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>• {p.category}</span>
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <span className="badge allow">{p.status}</span>
                  <span className="badge deny" style={{ fontSize: '0.68rem' }}>{p.severity}</span>
                </div>
              </div>

              <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.45, marginBottom: '0.6rem' }}>
                {p.rule}
              </p>

              <div style={{ background: 'rgba(8, 14, 27, 0.6)', padding: '0.6rem 0.85rem', borderRadius: 'var(--radius-xs)', borderLeft: '3px solid var(--cyan)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>TECHNICAL ENFORCEMENT:</span>
                <p style={{ fontSize: '0.78rem', color: 'var(--cyan)', marginTop: '2px' }}>{p.enforcement}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
