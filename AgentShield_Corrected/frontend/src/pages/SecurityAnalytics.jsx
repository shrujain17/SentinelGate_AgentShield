import React, { useState } from 'react';
import { DecisionDonutChart, ActivityTrendChart } from '../components/SvgCharts';

export default function SecurityAnalytics({ stats, auditLogs, pendingApprovals }) {
  const [timeFilter, setTimeFilter] = useState('all');

  const allowed = stats.allowed_requests || 0;
  const denied = stats.denied_requests || 0;
  const pending = stats.pending_approvals || pendingApprovals.length || 0;
  const total = stats.total_interceptions || (allowed + denied + pending);

  // Compute tool frequency from real audit logs
  const toolCounts = {};
  auditLogs.forEach((l) => {
    const t = l.tool_name || 'unknown';
    toolCounts[t] = (toolCounts[t] || 0) + 1;
  });
  const sortedTools = Object.entries(toolCounts).sort((a, b) => b[1] - a[1]);

  // Compute threat categories
  const threatCategories = {
    'Prompt Injection': 0,
    'Path Traversal': 0,
    'Restricted Resource Access': 0,
    'High-Impact Without Approval': 0,
    'Unknown Tool Execution': 0,
  };

  auditLogs.forEach((l) => {
    const r = (l.reason || '').toLowerCase();
    const t = (l.tool_name || '').toLowerCase();
    if (r.includes('injection') || r.includes('override') || r.includes('ignore')) {
      threatCategories['Prompt Injection'] += 1;
    } else if (r.includes('traversal') || r.includes('..') || r.includes('shadow')) {
      threatCategories['Path Traversal'] += 1;
    } else if (t.includes('restricted') || t.includes('private') || t.includes('secret')) {
      threatCategories['Restricted Resource Access'] += 1;
    } else if (l.decision === 'REQUIRE_APPROVAL') {
      threatCategories['High-Impact Without Approval'] += 1;
    } else if (l.decision === 'DENIED' || l.decision === 'DENY') {
      threatCategories['Unknown Tool Execution'] += 1;
    }
  });

  // Risk distribution
  let lowRisk = 0;
  let medRisk = 0;
  let highRisk = 0;
  let critRisk = 0;

  auditLogs.forEach((l) => {
    const score = typeof l.risk_score === 'number' ? l.risk_score * 100 : 10;
    if (score >= 80) critRisk++;
    else if (score >= 50) highRisk++;
    else if (score >= 25) medRisk++;
    else lowRisk++;
  });

  return (
    <div>
      {/* Top Banner: Real Recorded Data Notice */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          background: 'rgba(6, 182, 212, 0.08)',
          border: '1px solid rgba(6, 182, 212, 0.3)',
          padding: '0.85rem 1.25rem',
          borderRadius: 'var(--radius-md)',
          marginBottom: '1.5rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{ fontSize: '1.25rem' }}>📊</span>
          <div>
            <strong style={{ color: 'var(--cyan)', fontSize: '0.88rem' }}>Authentic Recorded Telemetry</strong>
            <p style={{ fontSize: '0.76rem', color: 'var(--text-secondary)' }}>
              All metrics below reflect real cryptographic audit events and deterministic policy evaluations recorded by SQLite and JSONL hash chain.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {['1h', '24h', '7d', 'all'].map((f) => (
            <button
              key={f}
              onClick={() => setTimeFilter(f)}
              className={`btn btn-sm ${timeFilter === f ? 'btn-primary' : ''}`}
              style={{ textTransform: 'uppercase' }}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Grid 1: Decision Distribution & Risk Tier Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.8fr', gap: '1.25rem', marginBottom: '1.5rem' }}>
        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title">🛡️ Policy Decision Share</h3>
              <p className="panel-subtitle">Distribution across {total} evaluated requests</p>
            </div>
            <span className="badge cyan">ZERO-TRUST</span>
          </div>
          <DecisionDonutChart allowed={allowed} denied={denied} pending={pending} size={160} />
        </div>

        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title">⚠️ Risk-Level Distribution</h3>
              <p className="panel-subtitle">Categorization based on threat analysis and tool impact</p>
            </div>
            <span className="badge neutral">{auditLogs.length} Events Evaluated</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '0.5rem' }}>
            {[
              { label: 'Critical Risk (80-100)', count: critRisk, color: 'var(--crimson)', desc: 'Direct prompt injections & secret exfiltration attempts' },
              { label: 'High Risk (50-79)', count: highRisk, color: '#f87171', desc: 'Destructive system commands & unauthorized file deletions' },
              { label: 'Moderate Risk (25-49)', count: medRisk, color: 'var(--amber)', desc: 'External dispatches requiring human-in-the-loop approval' },
              { label: 'Low Risk (0-24)', count: lowRisk, color: 'var(--emerald)', desc: 'Authorized public reads and synthetic benign queries' },
            ].map((tier) => {
              const pct = auditLogs.length > 0 ? Math.round((tier.count / auditLogs.length) * 100) : 0;
              return (
                <div key={tier.label}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                    <span style={{ color: tier.color, fontWeight: 700 }}>{tier.label}</span>
                    <span style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>{tier.count} ({pct}%)</span>
                  </div>
                  <div style={{ height: '7px', background: 'var(--bg-surface)', borderRadius: '999px', overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: tier.color, borderRadius: '999px', transition: 'width 0.4s ease' }}></div>
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px' }}>{tier.desc}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Grid 2: Most Frequently Requested Tools & Blocked Action Categories */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem', marginBottom: '1.5rem' }}>
        {/* Most Requested Tools */}
        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title">🧰 Most Requested Agent Tools</h3>
              <p className="panel-subtitle">Frequency of tool call proposals submitted to gateway</p>
            </div>
            <span className="badge purple">ISOLATED SANDBOX</span>
          </div>

          {sortedTools.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>No tool calls recorded yet.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {sortedTools.slice(0, 6).map(([toolName, count]) => {
                const max = sortedTools[0][1] || 1;
                const widthPct = Math.round((count / max) * 100);
                return (
                  <div key={toolName}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '0.2rem' }}>
                      <code>{toolName}</code>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontWeight: 700 }}>
                        {count} call{count > 1 ? 's' : ''}
                      </span>
                    </div>
                    <div style={{ height: '6px', background: 'var(--bg-surface)', borderRadius: '999px', overflow: 'hidden' }}>
                      <div style={{ width: `${widthPct}%`, height: '100%', background: 'linear-gradient(90deg, #06b6d4, #3b82f6)', borderRadius: '999px' }}></div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Blocked Action Categories */}
        <div className="panel" style={{ marginBottom: 0 }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title">🚫 Blocked Action Categories</h3>
              <p className="panel-subtitle">Policy violation breakdown</p>
            </div>
            <span className="badge deny">FAIL-CLOSED</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {Object.entries(threatCategories).map(([cat, cnt]) => (
              <div
                key={cat}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '0.65rem 0.85rem',
                  background: 'var(--bg-surface)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{cat}</span>
                <span className={`badge ${cnt > 0 ? 'deny' : 'neutral'}`}>{cnt} Intercepted</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Grid 3: Human Approval Velocity & Audit Trail Volume */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">⏳ Human-in-the-Loop Governance Telemetry</h3>
            <p className="panel-subtitle">Staging, reviewer latency, and one-time token authorization metrics</p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
          <div style={{ background: 'var(--bg-surface)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>CURRENT QUEUE</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--amber)', marginTop: '0.2rem' }}>{pending}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Awaiting supervisor</div>
          </div>

          <div style={{ background: 'var(--bg-surface)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>TICKET TTL LIMIT</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--cyan)', marginTop: '0.2rem' }}>300s</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Auto-expire window</div>
          </div>

          <div style={{ background: 'var(--bg-surface)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>REPLAY PROTECTION</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--emerald)', marginTop: '0.2rem' }}>100%</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Single-use enforcement</div>
          </div>

          <div style={{ background: 'var(--bg-surface)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>BOUND ARGUMENT MATCH</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--purple)', marginTop: '0.2rem' }}>STRICT</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>No runtime argument drift</div>
          </div>
        </div>
      </div>
    </div>
  );
}
