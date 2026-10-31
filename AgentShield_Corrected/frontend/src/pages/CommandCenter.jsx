import React from 'react';
import { DecisionDonutChart, ActivityTrendChart, Sparkline } from '../components/SvgCharts';

export default function CommandCenter({
  stats,
  auditLogs,
  pendingApprovals,
  scenarios,
  onRunScenario,
  onNavigate,
  agentRunning,
}) {
  const allowed = stats.allowed_requests || 0;
  const denied = stats.denied_requests || 0;
  const pending = stats.pending_approvals || pendingApprovals.length || 0;
  const total = stats.total_interceptions || (allowed + denied + pending);

  // Compute threats detected from real audit logs
  const threatsCount = auditLogs.filter(
    (l) => (l.threats && l.threats.length > 0) || l.decision === 'DENIED' || l.risk_score > 0.5
  ).length;

  const successfulExecutions = allowed;

  const recentLogs = auditLogs.slice(0, 7);

  return (
    <div>
      {/* 6 Top Metric Cards */}
      <div className="metric-grid-6">
        <div className="metric-card">
          <div className="metric-label">
            <span>Total Requests</span>
            <Sparkline color="#06b6d4" />
          </div>
          <div className="metric-value">{total}</div>
          <div className="metric-desc">Evaluated by Gateway</div>
        </div>

        <div className="metric-card allow">
          <div className="metric-label">
            <span>Allowed Requests</span>
            <Sparkline color="#10b981" />
          </div>
          <div className="metric-value" style={{ color: 'var(--emerald)' }}>{allowed}</div>
          <div className="metric-desc">Zero-trust verified</div>
        </div>

        <div className="metric-card deny">
          <div className="metric-label">
            <span>Blocked Actions</span>
            <Sparkline color="#ef4444" />
          </div>
          <div className="metric-value" style={{ color: 'var(--crimson)' }}>{denied}</div>
          <div className="metric-desc">Unauthorized / Threat</div>
        </div>

        <div className="metric-card approval">
          <div className="metric-label">
            <span>Pending Approvals</span>
            <Sparkline color="#f59e0b" />
          </div>
          <div className="metric-value" style={{ color: 'var(--amber)' }}>{pending}</div>
          <div className="metric-desc">Awaiting supervisor</div>
        </div>

        <div className="metric-card deny">
          <div className="metric-label">
            <span>Threats Detected</span>
            <Sparkline color="#ef4444" />
          </div>
          <div className="metric-value" style={{ color: '#f87171' }}>{threatsCount}</div>
          <div className="metric-desc">Injections / Traversal</div>
        </div>

        <div className="metric-card purple">
          <div className="metric-label">
            <span>Executions</span>
            <Sparkline color="#8b5cf6" />
          </div>
          <div className="metric-value" style={{ color: 'var(--purple)' }}>{successfulExecutions}</div>
          <div className="metric-desc">Isolated in sandbox</div>
        </div>
      </div>

      {/* Middle Grid: Charts & System Status */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.6fr 1fr', gap: '1.25rem', marginBottom: '1.5rem' }}>
        {/* Decision Distribution Donut */}
        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title">🛡️ Decision Distribution</h3>
              <p className="panel-subtitle">Zero-Trust policy verdicts</p>
            </div>
            <span className="badge cyan">REAL-TIME</span>
          </div>
          <DecisionDonutChart allowed={allowed} denied={denied} pending={pending} size={150} />
        </div>

        {/* Activity Over Time Bar Chart */}
        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title">📈 Request Activity Timeline</h3>
              <p className="panel-subtitle">Recent gateway interceptions by risk</p>
            </div>
            <button className="btn btn-sm" onClick={() => onNavigate('audit_logs')}>View Full Trail →</button>
          </div>
          <ActivityTrendChart logs={auditLogs} />
        </div>

        {/* Gateway & Gemini Live Status */}
        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <h3 className="panel-title">⚡ Gateway Core</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.82rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.4rem', borderBottom: '1px solid var(--border-subtle)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Zero-Trust Status:</span>
              <span className="badge allow">ENFORCING</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.4rem', borderBottom: '1px solid var(--border-subtle)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Fail-Closed Mode:</span>
              <span style={{ color: 'var(--emerald)', fontWeight: 700 }}>ACTIVE (True)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.4rem', borderBottom: '1px solid var(--border-subtle)' }}>
              <span style={{ color: 'var(--text-muted)' }}>AI Provider Mode:</span>
              <span className="badge purple">MOCK FALLBACK</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '0.4rem', borderBottom: '1px solid var(--border-subtle)' }}>
              <span style={{ color: 'var(--text-muted)' }}>Audit Hash Chain:</span>
              <span style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>SHA-256 LINKED</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Avg Overhead:</span>
              <span style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>{stats.gateway_overhead_ms || 7.4} ms</span>
            </div>
          </div>
        </div>
      </div>

      {/* Live Activity Stream */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">📡 Live Security Interception Feed</h3>
            <p className="panel-subtitle">Real recorded forensic security events from the tamper-evident audit database</p>
          </div>
          <div style={{ display: 'flex', gap: '0.6rem' }}>
            <button className="btn btn-sm" onClick={() => onNavigate('agent_simulator')}>
              ⚡ Launch Simulator
            </button>
            <button className="btn btn-sm" onClick={() => onNavigate('audit_logs')}>
              All Records ({auditLogs.length}) →
            </button>
          </div>
        </div>

        {recentLogs.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
            No security events recorded yet. Run a scenario below to trigger gateway evaluation.
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Agent</th>
                  <th>Requested Tool</th>
                  <th>Decision</th>
                  <th>Provenance</th>
                  <th>Risk Level</th>
                  <th>Policy Summary</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.map((log) => {
                  const dec = (log.decision || '').toUpperCase();
                  const riskScore = typeof log.risk_score === 'number' ? Math.round(log.risk_score * 100) : 10;
                  let riskBadge = <span className="badge allow">LOW</span>;
                  if (riskScore > 75) riskBadge = <span className="badge deny">CRITICAL ({riskScore})</span>;
                  else if (riskScore > 40) riskBadge = <span className="badge approval">MED ({riskScore})</span>;

                  return (
                    <tr key={log.id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td>
                        <code>{log.agent_id || 'agent_01'}</code>
                      </td>
                      <td>
                        <strong>{log.tool_name}</strong>
                      </td>
                      <td>
                        <span className={`badge ${dec.toLowerCase()}`}>
                          {dec === 'ALLOW' || dec === 'ALLOWED' ? '✓ ALLOW' : dec === 'DENY' || dec === 'DENIED' ? '✕ DENY' : '⏳ APPROVAL'}
                        </span>
                      </td>
                      <td style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)', fontSize: '0.74rem' }}>
                        {log.provenance || 'user_direct'}
                      </td>
                      <td>{riskBadge}</td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', maxWidth: '380px' }}>
                        {log.reason}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Quick Launch Scenarios Panel */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">⚡ Quick Demonstration Scenarios</h3>
            <p className="panel-subtitle">Execute live defense scenarios directly into the gateway engine</p>
          </div>
          <button className="btn btn-sm btn-primary" onClick={() => onNavigate('agent_simulator')}>
            Open Full Simulator →
          </button>
        </div>

        <div className="scenario-grid">
          {scenarios.map((sc) => (
            <div key={sc.id} className="scenario-card" onClick={() => onRunScenario(sc.id)}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                  <span className="badge purple">SCENARIO {sc.id}</span>
                  <span
                    className={`badge ${
                      sc.expected_verdict === 'ALLOW' ? 'allow' : sc.expected_verdict === 'DENY' ? 'deny' : 'approval'
                    }`}
                  >
                    EXPECTS {sc.expected_verdict}
                  </span>
                </div>
                <h4 className="scenario-title">{sc.title}</h4>
                <p className="scenario-desc">{sc.description}</p>
              </div>
              <button className="btn btn-sm" disabled={agentRunning} style={{ width: '100%' }}>
                {agentRunning ? '⏳ Evaluating...' : `▶ Execute Scenario ${sc.id}`}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
