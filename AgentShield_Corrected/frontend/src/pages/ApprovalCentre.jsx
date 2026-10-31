import React, { useState } from 'react';

export default function ApprovalCentre({
  pendingApprovals,
  onResolveApproval,
  onRefresh,
  showToast,
  onNavigate,
}) {
  const [resolvingId, setResolvingId] = useState(null);
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [reviewerComment, setReviewerComment] = useState('Authorized by SOC Lead Analyst.');
  const [resolutionResult, setResolutionResult] = useState(null);

  const handleAction = async (approvalId, action) => {
    setResolvingId(approvalId);
    try {
      const res = await onResolveApproval(approvalId, action, reviewerComment);
      setResolutionResult(res);
      setSelectedTicket(null);
    } catch (e) {
      showToast('Error resolving approval: ' + e.message);
    } finally {
      setResolvingId(null);
    }
  };

  return (
    <div>
      {/* Overview Stats */}
      <div className="metric-grid-4">
        <div className="metric-card approval">
          <div className="metric-label">Queue Size</div>
          <div className="metric-value" style={{ color: 'var(--amber)' }}>{pendingApprovals.length}</div>
          <div className="metric-desc">Awaiting human supervisor</div>
        </div>

        <div className="metric-card">
          <div className="metric-label">Token Expiration Window</div>
          <div className="metric-value">300s</div>
          <div className="metric-desc">Auto-expires unreviewed items</div>
        </div>

        <div className="metric-card allow">
          <div className="metric-label">Execution Guardrail</div>
          <div className="metric-value" style={{ color: 'var(--emerald)', fontSize: '1.4rem' }}>EXACT BINDING</div>
          <div className="metric-desc">Executed only with original args</div>
        </div>

        <div className="metric-card purple">
          <div className="metric-label">Single-Use Guarantee</div>
          <div className="metric-value" style={{ color: 'var(--purple)', fontSize: '1.4rem' }}>NONCE ENFORCED</div>
          <div className="metric-desc">Cannot replay or reuse tickets</div>
        </div>
      </div>

      {/* Resolution Confirmation Notice (if an action was just resolved) */}
      {resolutionResult && (
        <div
          style={{
            background: resolutionResult.status === 'APPROVED' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
            border: `1px solid ${resolutionResult.status === 'APPROVED' ? 'var(--emerald)' : 'var(--crimson)'}`,
            borderRadius: 'var(--radius-md)',
            padding: '1.15rem 1.4rem',
            marginBottom: '1.5rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span style={{ fontSize: '1.3rem' }}>{resolutionResult.status === 'APPROVED' ? '✓' : '✕'}</span>
              <strong style={{ fontSize: '0.95rem', color: resolutionResult.status === 'APPROVED' ? 'var(--emerald)' : 'var(--crimson)' }}>
                Approval Request #{resolutionResult.approval_id} — {resolutionResult.status}
              </strong>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '0.3rem' }}>
              {resolutionResult.message}
            </p>
            {resolutionResult.execution_result && (
              <div style={{ marginTop: '0.5rem' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  SYNTHETIC EXECUTION RESULT:
                </span>
                <pre
                  style={{
                    background: 'var(--bg-input)',
                    padding: '0.5rem',
                    borderRadius: 'var(--radius-xs)',
                    fontSize: '0.74rem',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--cyan)',
                    marginTop: '2px',
                    maxHeight: '100px',
                    overflowY: 'auto',
                  }}
                >
                  {JSON.stringify(resolutionResult.execution_result, null, 2)}
                </pre>
              </div>
            )}
          </div>

          <button className="btn btn-sm" onClick={() => setResolutionResult(null)}>Dismiss ✕</button>
        </div>
      )}

      {/* Pending Tickets Table */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">⏳ Active Supervisor Review Queue</h3>
            <p className="panel-subtitle">Review proposed high-impact actions paused in memory & SQLite database</p>
          </div>
          <div style={{ display: 'flex', gap: '0.6rem' }}>
            <button className="btn btn-sm" onClick={onRefresh}>🔄 Refresh Queue</button>
            <button className="btn btn-sm btn-primary" onClick={() => onNavigate('agent_simulator')}>
              ⚡ Trigger Scenario D (Send Email)
            </button>
          </div>
        </div>

        {pendingApprovals.length === 0 ? (
          <div
            style={{
              textAlign: 'center',
              padding: '4rem 2rem',
              color: 'var(--text-muted)',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '0.75rem',
            }}
          >
            <span style={{ fontSize: '2.5rem' }}>✓</span>
            <strong style={{ fontSize: '1.1rem', color: '#fff' }}>No Pending Approvals in Queue</strong>
            <p style={{ fontSize: '0.84rem', maxWidth: '400px' }}>
              All high-impact actions have been reviewed, or none are currently queued. To test this workflow, trigger Scenario D or any high-impact tool in the Simulator.
            </p>
            <button className="btn btn-sm btn-primary" onClick={() => onNavigate('agent_simulator')} style={{ marginTop: '0.5rem' }}>
              Open Agent Simulator →
            </button>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {pendingApprovals.map((ticket) => {
              const ticketId = ticket.ticket_id || ticket.id;
              let payloadData = {};
              try {
                payloadData = typeof ticket.payload === 'string' ? JSON.parse(ticket.payload) : ticket.payload || {};
              } catch (e) {
                payloadData = { raw: ticket.payload };
              }

              return (
                <div
                  key={ticket.id}
                  style={{
                    background: 'var(--bg-surface)',
                    border: '1px solid rgba(245, 158, 11, 0.4)',
                    borderRadius: 'var(--radius-md)',
                    padding: '1.25rem',
                    boxShadow: '0 4px 18px rgba(0,0,0,0.3)',
                  }}
                >
                  {/* Ticket Header */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <span className="badge approval">TICKET #{ticket.id}</span>
                      <strong style={{ fontSize: '0.95rem', color: '#fff' }}>
                        Tool: <code>{ticket.tool_name}</code>
                      </strong>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--amber)' }}>
                        Created: {new Date(ticket.created_at).toLocaleTimeString()} · Expiring in &lt;300s
                      </span>
                      <span className="badge pending">AWAITING REVIEW</span>
                    </div>
                  </div>

                  {/* Metadata & Requester */}
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.6rem' }}>
                    Requesting Agent: <code>{ticket.agent_id || 'agent_01'}</code> · Target Resource:{' '}
                    <code>{payloadData.arguments ? JSON.stringify(payloadData.arguments) : 'External Resource'}</code>
                  </div>

                  {/* Exact Bound Arguments Payload */}
                  <div style={{ marginBottom: '1rem' }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      BOUND EXACT ARGUMENTS PAYLOAD (TAMPER-PROTECTED):
                    </span>
                    <pre
                      style={{
                        background: 'var(--bg-input)',
                        border: '1px solid var(--border-subtle)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '0.75rem',
                        fontSize: '0.78rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--cyan)',
                        maxHeight: '140px',
                        overflowY: 'auto',
                        marginTop: '0.25rem',
                      }}
                    >
                      {JSON.stringify(payloadData, null, 2)}
                    </pre>
                  </div>

                  {/* Supervisor Remarks Input & Action Buttons */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                    <div style={{ flex: 1, minWidth: '260px' }}>
                      <input
                        type="text"
                        className="form-input"
                        placeholder="Supervisor audit rationale..."
                        defaultValue="Supervisor verified intent via React SOC Console."
                        onChange={(e) => setReviewerComment(e.target.value)}
                        style={{ fontSize: '0.78rem', height: '34px' }}
                      />
                    </div>

                    <div style={{ display: 'flex', gap: '0.6rem' }}>
                      <button
                        className="btn btn-danger"
                        disabled={resolvingId === ticket.id}
                        onClick={() => handleAction(ticketId, 'REJECT')}
                      >
                        ✕ Reject & Block
                      </button>
                      <button
                        className="btn btn-success"
                        disabled={resolvingId === ticket.id}
                        onClick={() => handleAction(ticketId, 'APPROVE')}
                      >
                        ✓ Authorize & Execute
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
