import React, { useState } from 'react';

export default function AuditLogs({ auditLogs, onVerifyHashChain, onRefresh, showToast }) {
  const [filterDecision, setFilterDecision] = useState('all');
  const [filterAgent, setFilterAgent] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedId, setExpandedId] = useState(null);

  // Filter logs
  const filtered = auditLogs.filter((log) => {
    const matchDecision = filterDecision === 'all' || (log.decision || '').toLowerCase() === filterDecision.toLowerCase();
    const matchAgent = filterAgent === 'all' || (log.agent_id || 'agent_01') === filterAgent;
    const matchSearch =
      !searchTerm ||
      (log.tool_name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (log.reason || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (log.chain_hash || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      String(log.id).includes(searchTerm);

    return matchDecision && matchAgent && matchSearch;
  });

  // Export to CSV
  const handleExportCSV = () => {
    if (auditLogs.length === 0) {
      showToast('No records available to export.');
      return;
    }
    const headers = ['ID', 'Timestamp', 'Agent ID', 'Tool Name', 'Decision', 'Risk Score', 'Provenance', 'Reason', 'Chain Hash'];
    const rows = filtered.map((l) => [
      l.id,
      `"${l.timestamp}"`,
      `"${l.agent_id || 'agent_01'}"`,
      `"${l.tool_name}"`,
      `"${l.decision}"`,
      l.risk_score || 0,
      `"${l.provenance || 'user_direct'}"`,
      `"${(l.reason || '').replace(/"/g, '""')}"`,
      `"${l.chain_hash || ''}"`,
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `sentinelgate_audit_export_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast(`Exported ${filtered.length} audit records to CSV.`);
  };

  // Export to JSON
  const handleExportJSON = () => {
    if (auditLogs.length === 0) {
      showToast('No records available to export.');
      return;
    }
    const jsonString = `data:text/json;charset=utf-8,${encodeURIComponent(JSON.stringify(filtered, null, 2))}`;
    const link = document.createElement('a');
    link.setAttribute('href', jsonString);
    link.setAttribute('download', `sentinelgate_audit_export_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast(`Exported ${filtered.length} audit records to JSON.`);
  };

  return (
    <div>
      {/* Top Banner & Quick Controls */}
      <div className="panel" style={{ background: 'rgba(10, 15, 29, 0.6)' }}>
        <div className="panel-header">
          <div>
            <h3 className="panel-title">📑 Immutable Cryptographic Audit Trail</h3>
            <p className="panel-subtitle">
              Every gateway evaluation is cryptographically recorded in an append-only JSONL log linked with SHA-256 hashes
            </p>
          </div>
          <div style={{ display: 'flex', gap: '0.6rem' }}>
            <button className="btn btn-sm btn-primary" onClick={onVerifyHashChain}>
              🔗 Verify Hash Chain Integrity
            </button>
            <button className="btn btn-sm" onClick={onRefresh}>
              🔄 Refresh Logs
            </button>
            <button className="btn btn-sm" onClick={handleExportCSV}>
              📥 Export CSV
            </button>
            <button className="btn btn-sm" onClick={handleExportJSON}>
              📥 Export JSON
            </button>
          </div>
        </div>

        {/* Filters Bar */}
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: 1, minWidth: '220px' }}>
            <input
              type="text"
              className="form-input"
              placeholder="Search by tool, reason, ID, or SHA-256 hash..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>

          <div style={{ width: '170px' }}>
            <select className="form-select" value={filterDecision} onChange={(e) => setFilterDecision(e.target.value)}>
              <option value="all">All Decisions</option>
              <option value="allowed">ALLOWED (✓)</option>
              <option value="denied">DENIED (✕)</option>
              <option value="require_approval">REQUIRE_APPROVAL (⏳)</option>
            </select>
          </div>

          <div style={{ width: '170px' }}>
            <select className="form-select" value={filterAgent} onChange={(e) => setFilterAgent(e.target.value)}>
              <option value="all">All Agents</option>
              <option value="agent_01">agent_01</option>
              <option value="analyst_bot">analyst_bot</option>
              <option value="external_agent_03">external_agent_03</option>
            </select>
          </div>

          <span className="badge neutral" style={{ height: '36px', display: 'flex', alignItems: 'center' }}>
            Showing {filtered.length} of {auditLogs.length} Records
          </span>
        </div>
      </div>

      {/* Logs Table */}
      <div className="panel">
        {filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3.5rem', color: 'var(--text-muted)' }}>
            No audit records match the current filter criteria.
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="soc-table">
              <thead>
                <tr>
                  <th style={{ width: '50px' }}>ID</th>
                  <th>Timestamp</th>
                  <th>Agent</th>
                  <th>Tool Requested</th>
                  <th>Decision</th>
                  <th>Provenance</th>
                  <th>Risk</th>
                  <th>Policy Summary</th>
                  <th>Chain Hash</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((log) => {
                  const isExpanded = expandedId === log.id;
                  const dec = (log.decision || '').toLowerCase();
                  const riskScore = typeof log.risk_score === 'number' ? Math.round(log.risk_score * 100) : 10;

                  return (
                    <React.Fragment key={log.id}>
                      <tr style={{ background: isExpanded ? 'rgba(6, 182, 212, 0.06)' : undefined }}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-muted)' }}>
                          #{log.id}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                        <td>
                          <code>{log.agent_id || 'agent_01'}</code>
                        </td>
                        <td>
                          <strong style={{ color: '#fff' }}>{log.tool_name}</strong>
                        </td>
                        <td>
                          <span className={`badge ${dec}`}>
                            {dec.includes('allow') ? '✓ ALLOW' : dec.includes('deny') ? '✕ DENY' : '⏳ APPROVAL'}
                          </span>
                        </td>
                        <td style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                          {log.provenance || 'user_direct'}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.74rem' }}>
                          {riskScore}/100
                        </td>
                        <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {log.reason}
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                          {log.chain_hash ? log.chain_hash.slice(0, 10) + '...' : 'INITIAL'}
                        </td>
                        <td>
                          <button
                            className="btn btn-sm"
                            onClick={() => setExpandedId(isExpanded ? null : log.id)}
                            style={{ padding: '2px 8px', fontSize: '0.72rem' }}
                          >
                            {isExpanded ? 'Hide ▲' : 'View ▼'}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Forensic Details Drawer */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={10} style={{ background: 'rgba(8, 14, 27, 0.9)', padding: '1rem 1.5rem', borderBottom: '2px solid var(--cyan)' }}>
                            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.25rem', fontSize: '0.8rem' }}>
                              <div>
                                <strong style={{ color: 'var(--cyan)' }}>Bound Invocation Arguments & Context Payload:</strong>
                                <pre
                                  style={{
                                    background: 'var(--bg-base)',
                                    border: '1px solid var(--border-subtle)',
                                    borderRadius: 'var(--radius-xs)',
                                    padding: '0.65rem',
                                    fontFamily: 'var(--font-mono)',
                                    fontSize: '0.74rem',
                                    color: '#cbd5e1',
                                    marginTop: '0.35rem',
                                    maxHeight: '130px',
                                    overflowY: 'auto',
                                  }}
                                >
                                  {JSON.stringify(log.payload || {}, null, 2)}
                                </pre>
                              </div>

                              <div>
                                <strong style={{ color: 'var(--purple)' }}>Cryptographic SHA-256 Forensics Block:</strong>
                                <div style={{ marginTop: '0.35rem', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                                  <div style={{ background: 'var(--bg-base)', padding: '0.5rem', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-subtle)' }}>
                                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>RECORD SHA-256 CHAIN HASH:</span>
                                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--emerald)', wordBreak: 'break-all' }}>
                                      {log.chain_hash || 'SHA-256 Block Zero'}
                                    </div>
                                  </div>

                                  <div style={{ fontSize: '0.74rem', color: 'var(--text-secondary)' }}>
                                    <strong>Full Policy Reason:</strong> {log.reason}
                                  </div>

                                  {log.threats && log.threats.length > 0 && (
                                    <div style={{ fontSize: '0.74rem', color: 'var(--crimson)' }}>
                                      <strong>Threat Signatures:</strong> {log.threats.join(', ')}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
