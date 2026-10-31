import React, { useState } from 'react';

export default function AgentMonitor({ auditLogs, stats, onNavigate }) {
  const [selectedAgent, setSelectedAgent] = useState('agent_01');

  // Agents registered in the Zero-Trust system
  const registeredAgents = [
    {
      id: 'agent_01',
      name: 'AgentShield Primary Reasoner',
      type: 'Autonomous LLM Agent',
      status: 'ACTIVE_MONITORED',
      permissionLevel: 'BOUNDED_ZERO_TRUST',
      reasoningLimit: 'MAX 2 CYCLES',
      directToolAccess: 'DENIED (Strict Zero-Trust)',
      connectedTools: ['read_public_document', 'summarize_public_document', 'read_email'],
      restrictedTools: ['read_private_file', 'read_secret', 'access_confidential_db'],
      approvalRequiredTools: ['send_email', 'delete_file', 'send_external_message', 'dispatch_external_alert', 'execute_system_command'],
    },
    {
      id: 'analyst_bot',
      name: 'Cyber Threat Intelligence Bot',
      type: 'Read-Only Document Analyst',
      status: 'SANDBOXED',
      permissionLevel: 'READ_ONLY_PUBLIC',
      reasoningLimit: 'MAX 1 CYCLE',
      directToolAccess: 'DENIED (Strict Zero-Trust)',
      connectedTools: ['read_public_document', 'summarize_public_document'],
      restrictedTools: ['read_private_file', 'read_secret', 'send_email', 'delete_file'],
      approvalRequiredTools: ['dispatch_external_alert'],
    },
    {
      id: 'external_agent_03',
      name: 'Third-Party Partner Ingestion Agent',
      type: 'External Integration Agent',
      status: 'UNTRUSTED_STAGING',
      permissionLevel: 'STRICT_CONTAINMENT',
      reasoningLimit: 'MAX 1 CYCLE',
      directToolAccess: 'DENIED (Strict Zero-Trust)',
      connectedTools: ['read_public_document'],
      restrictedTools: ['* (All other tools)'],
      approvalRequiredTools: ['send_external_message'],
    },
  ];

  const currentAgent = registeredAgents.find((a) => a.id === selectedAgent) || registeredAgents[0];

  // Filter logs for selected agent
  const agentLogs = auditLogs.filter((l) => l.agent_id === currentAgent.id || (!l.agent_id && currentAgent.id === 'agent_01'));
  const agentAllowed = agentLogs.filter((l) => l.decision === 'ALLOWED' || l.decision === 'ALLOW').length;
  const agentDenied = agentLogs.filter((l) => l.decision === 'DENIED' || l.decision === 'DENY').length;
  const agentApprovals = agentLogs.filter((l) => l.decision === 'REQUIRE_APPROVAL').length;

  return (
    <div>
      {/* Overview Cards */}
      <div className="metric-grid-4">
        <div className="metric-card">
          <div className="metric-label">Registered Agents</div>
          <div className="metric-value">{registeredAgents.length}</div>
          <div className="metric-desc">Monitored by Gateway</div>
        </div>

        <div className="metric-card allow">
          <div className="metric-label">Direct Execution Rights</div>
          <div className="metric-value" style={{ color: 'var(--emerald)' }}>0</div>
          <div className="metric-desc">All agents must route tools</div>
        </div>

        <div className="metric-card purple">
          <div className="metric-label">Reasoning Cycle Cap</div>
          <div className="metric-value" style={{ color: 'var(--purple)' }}>2</div>
          <div className="metric-desc">Prevents injection loops</div>
        </div>

        <div className="metric-card deny">
          <div className="metric-label">Untrusted Provenance Mode</div>
          <div className="metric-value" style={{ color: 'var(--cyan)' }}>ENFORCING</div>
          <div className="metric-desc">Doc content is untrusted</div>
        </div>
      </div>

      {/* Main Split: Agent List & Agent Detail Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.8fr', gap: '1.25rem', marginBottom: '1.5rem' }}>
        {/* Agent Registry Card */}
        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title">🤖 AI Agent Roster</h3>
              <p className="panel-subtitle">Select an agent to inspect its policy boundary</p>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {registeredAgents.map((agent) => {
              const isSelected = agent.id === selectedAgent;
              return (
                <div
                  key={agent.id}
                  onClick={() => setSelectedAgent(agent.id)}
                  style={{
                    padding: '1rem',
                    borderRadius: 'var(--radius-md)',
                    background: isSelected ? 'rgba(6, 182, 212, 0.08)' : 'var(--bg-surface)',
                    border: `1px solid ${isSelected ? 'var(--cyan)' : 'var(--border-subtle)'}`,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span className="pulse-dot" style={{ width: 8, height: 8 }}></span>
                      <strong style={{ color: '#fff', fontSize: '0.9rem' }}>{agent.name}</strong>
                    </div>
                    <span className="badge cyan">{agent.id}</span>
                  </div>

                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                    Type: {agent.type} · Boundary: {agent.permissionLevel}
                  </div>

                  <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                    <span className="badge allow" style={{ fontSize: '0.65rem' }}>
                      {agent.connectedTools.length} ALLOW TOOLS
                    </span>
                    <span className="badge deny" style={{ fontSize: '0.65rem' }}>
                      NO DIRECT SHELL
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Agent Inspector Panel */}
        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title">🔍 Agent Zero-Trust Profile: {currentAgent.name}</h3>
              <p className="panel-subtitle">Identity: <code>{currentAgent.id}</code> · Status: <span className="badge allow">{currentAgent.status}</span></p>
            </div>
            <button className="btn btn-sm btn-primary" onClick={() => onNavigate('agent_simulator')}>
              ⚡ Test in Simulator
            </button>
          </div>

          {/* Key Zero-Trust Guardrails */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.85rem', marginBottom: '1.25rem' }}>
            <div style={{ background: 'var(--bg-surface)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>DIRECT EXECUTION PRIVILEGE</div>
              <div style={{ fontSize: '0.88rem', fontWeight: 800, color: 'var(--crimson)', marginTop: '0.2rem' }}>ABSOLUTELY ZERO</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Model proposes, gateway mediates</div>
            </div>

            <div style={{ background: 'var(--bg-surface)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>PROVENANCE OVERRIDE</div>
              <div style={{ fontSize: '0.88rem', fontWeight: 800, color: 'var(--emerald)', marginTop: '0.2rem' }}>PROTECTED</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Model cannot assign trust level</div>
            </div>

            <div style={{ background: 'var(--bg-surface)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>REASONING LOOP BOUND</div>
              <div style={{ fontSize: '0.88rem', fontWeight: 800, color: 'var(--purple)', marginTop: '0.2rem' }}>2 CYCLES MAX</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Halts recursive prompt loops</div>
            </div>
          </div>

          {/* Permitted vs Restricted Tools */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.82rem' }}>
            <div>
              <strong style={{ color: 'var(--emerald)', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                🟢 Permitted Safe Tools (Direct Evaluation):
              </strong>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '0.35rem' }}>
                {currentAgent.connectedTools.map((t) => (
                  <code key={t} style={{ background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.3)', color: 'var(--emerald)' }}>
                    {t}
                  </code>
                ))}
              </div>
            </div>

            <div>
              <strong style={{ color: 'var(--amber)', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                🟡 High-Impact Tools (Require Human Supervisor Authorization):
              </strong>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '0.35rem' }}>
                {currentAgent.approvalRequiredTools.map((t) => (
                  <code key={t} style={{ background: 'rgba(245, 158, 11, 0.12)', border: '1px solid rgba(245, 158, 11, 0.3)', color: 'var(--amber)' }}>
                    {t}
                  </code>
                ))}
              </div>
            </div>

            <div>
              <strong style={{ color: 'var(--crimson)', fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                🔴 Absolute Deny Resources (Cannot Be Authorized):
              </strong>
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginTop: '0.35rem' }}>
                {currentAgent.restrictedTools.map((t) => (
                  <code key={t} style={{ background: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)', color: 'var(--crimson)' }}>
                    {t}
                  </code>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Selected Agent Interception History Table */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">📋 Interception Trail for {currentAgent.id}</h3>
            <p className="panel-subtitle">Recorded Gateway decisions for this specific agent</p>
          </div>
          <div style={{ display: 'flex', gap: '0.6rem' }}>
            <span className="badge allow">{agentAllowed} Allowed</span>
            <span className="badge deny">{agentDenied} Denied</span>
            <span className="badge approval">{agentApprovals} Approval Required</span>
          </div>
        </div>

        {agentLogs.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
            No requests recorded yet for {currentAgent.id}. Run a scenario or test simulation.
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Tool Requested</th>
                  <th>Verdict</th>
                  <th>Provenance</th>
                  <th>Risk Score</th>
                  <th>Gateway Policy Response</th>
                </tr>
              </thead>
              <tbody>
                {agentLogs.slice(0, 5).map((log) => (
                  <tr key={log.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td><code>{log.tool_name}</code></td>
                    <td>
                      <span className={`badge ${(log.decision || '').toLowerCase()}`}>
                        {log.decision}
                      </span>
                    </td>
                    <td style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)', fontSize: '0.74rem' }}>
                      {log.provenance || 'user_direct'}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>
                      {typeof log.risk_score === 'number' ? Math.round(log.risk_score * 100) : 10}/100
                    </td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      {log.reason}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
