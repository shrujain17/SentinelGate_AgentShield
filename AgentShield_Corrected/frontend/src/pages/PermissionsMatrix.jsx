import React, { useState } from 'react';

export default function PermissionsMatrix() {
  const [selectedToolDetail, setSelectedToolDetail] = useState(null);

  // Exact tools defined in security/permissions.py and backend/tools/synthetic_tools.py
  const permissionsList = [
    {
      tool: 'read_public_document',
      category: 'Document Operations',
      scope: 'Allowlisted Public Files Only (public_document.txt, malicious_document.txt)',
      verdict: 'ALLOW',
      supervisorOverride: 'N/A (Pre-approved)',
      reason: 'Safe read-only access to allowlisted public documents. Path traversal strictly sanitized.',
      riskTier: 'LOW',
    },
    {
      tool: 'summarize_public_document',
      category: 'Document Operations',
      scope: 'Allowlisted Public Files (Text Summarization)',
      verdict: 'ALLOW',
      supervisorOverride: 'N/A (Pre-approved)',
      reason: 'Isolated factual summarization with zero tool invocation rights during Stage 3.',
      riskTier: 'LOW',
    },
    {
      tool: 'read_email',
      category: 'Communications (Inbound)',
      scope: 'Synthetic Sandbox Inbox Messages',
      verdict: 'ALLOW',
      supervisorOverride: 'N/A (Pre-approved)',
      reason: 'Synthetic mock mailbox reading within memory simulation. No external IMAP/POP connection.',
      riskTier: 'LOW',
    },
    {
      tool: 'read_document',
      category: 'Document Operations',
      scope: 'Internal Documentation Sandbox',
      verdict: 'ALLOW',
      supervisorOverride: 'N/A (Pre-approved)',
      reason: 'Safe internal policy reader for synthetic training documents.',
      riskTier: 'LOW',
    },
    {
      tool: 'send_email',
      category: 'Communications (Outbound)',
      scope: 'Outbound Synthetic Dispatch',
      verdict: 'REQUIRE_APPROVAL',
      supervisorOverride: 'ALLOWED with Supervisor Signature',
      reason: 'High-impact outbound external dispatch. Staged in SQLite queue awaiting supervisor authorization.',
      riskTier: 'MODERATE',
    },
    {
      tool: 'delete_file',
      category: 'Storage Management',
      scope: 'File Deletion in Sandbox',
      verdict: 'REQUIRE_APPROVAL',
      supervisorOverride: 'ALLOWED with Supervisor Signature',
      reason: 'Destructive modification. Requires human confirmation to prevent accidental or malicious file loss.',
      riskTier: 'HIGH',
    },
    {
      tool: 'send_external_message',
      category: 'Communications (Outbound)',
      scope: 'External Webhook / Web API Dispatch',
      verdict: 'REQUIRE_APPROVAL',
      supervisorOverride: 'ALLOWED with Supervisor Signature',
      reason: 'External messaging could leak internal context. Bound to exact arguments and paused for review.',
      riskTier: 'HIGH',
    },
    {
      tool: 'dispatch_external_alert',
      category: 'Communications (Outbound)',
      scope: 'Emergency Incident Pager System',
      verdict: 'REQUIRE_APPROVAL',
      supervisorOverride: 'ALLOWED with Supervisor Signature',
      reason: 'High-visibility external alarm. Requires explicit supervisor sign-off before dispatching.',
      riskTier: 'HIGH',
    },
    {
      tool: 'execute_system_command',
      category: 'System Operations',
      scope: 'Isolated Synthetic Shell Simulation',
      verdict: 'REQUIRE_APPROVAL',
      supervisorOverride: 'ALLOWED with Supervisor Signature',
      reason: 'Command execution is strictly bounded to synthetic simulation. Real shell commands are prohibited.',
      riskTier: 'CRITICAL',
    },
    {
      tool: 'read_restricted_file',
      category: 'Confidential Access',
      scope: 'Restricted Files (payroll, passwords, /etc/shadow)',
      verdict: 'DENY',
      supervisorOverride: 'PROHIBITED (Cannot be overridden)',
      reason: 'Absolute Zero-Trust policy: Confidential system files can never be accessed by autonomous agents.',
      riskTier: 'CRITICAL (ABSOLUTE)',
    },
    {
      tool: 'read_private_file',
      category: 'Confidential Access',
      scope: 'Private User Data & Encryption Keys',
      verdict: 'DENY',
      supervisorOverride: 'PROHIBITED (Cannot be overridden)',
      reason: 'Absolute Deny policy rule: Protected resources are strictly unreachable.',
      riskTier: 'CRITICAL (ABSOLUTE)',
    },
    {
      tool: 'read_secret',
      category: 'Secret Management',
      scope: 'API Keys, Master Passwords & Credentials',
      verdict: 'DENY',
      supervisorOverride: 'PROHIBITED (Cannot be overridden)',
      reason: 'Direct access to raw secrets is completely blocked to eliminate credential exfiltration attacks.',
      riskTier: 'CRITICAL (ABSOLUTE)',
    },
    {
      tool: 'access_confidential_db',
      category: 'Database Access',
      scope: 'Production Database Tables',
      verdict: 'DENY',
      supervisorOverride: 'PROHIBITED (Cannot be overridden)',
      reason: 'Raw database read access is blocked. Only sanctioned synthetic tools may query data.',
      riskTier: 'CRITICAL (ABSOLUTE)',
    },
    {
      tool: '* (Any Unregistered Tool)',
      category: 'Unknown / Arbitrary',
      scope: 'Any tool not explicitly allowlisted in matrix',
      verdict: 'DENY',
      supervisorOverride: 'PROHIBITED (Fail-Closed Default)',
      reason: 'Zero-Trust Default Deny: Unknown tools are immediately blocked to prevent arbitrary code execution.',
      riskTier: 'CRITICAL (FAIL-CLOSED)',
    },
  ];

  return (
    <div>
      {/* Top Banner */}
      <div className="panel" style={{ background: 'rgba(10, 15, 29, 0.6)' }}>
        <div className="panel-header">
          <div>
            <h3 className="panel-title">🔐 Deterministic Zero-Trust Permissions Matrix</h3>
            <p className="panel-subtitle">
              Strict policy mapping governing all AI agent action proposals before reaching the synthetic sandbox
            </p>
          </div>
          <span className="badge allow">ENFORCED IN CODE (PERMISSIONS.PY)</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginTop: '0.5rem' }}>
          <div style={{ background: 'var(--bg-surface)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
            <span className="badge allow" style={{ marginBottom: '0.4rem' }}>ALLOW (4 TOOLS)</span>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
              Read-only operations on authorized documents & emails. Executed immediately with synthetic data.
            </div>
          </div>

          <div style={{ background: 'var(--bg-surface)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid rgba(245, 158, 11, 0.3)' }}>
            <span className="badge approval" style={{ marginBottom: '0.4rem' }}>REQUIRE_APPROVAL (5 TOOLS)</span>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
              High-impact external actions & deletions. Paused in memory/DB awaiting human supervisor token.
            </div>
          </div>

          <div style={{ background: 'var(--bg-surface)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
            <span className="badge deny" style={{ marginBottom: '0.4rem' }}>ABSOLUTE DENY (4 TOOLS)</span>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
              Confidential files, private keys, passwords. Strictly blocked; supervisor approval CANNOT override.
            </div>
          </div>

          <div style={{ background: 'var(--bg-surface)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-bright)' }}>
            <span className="badge neutral" style={{ marginBottom: '0.4rem' }}>FAIL-CLOSED DEFAULT</span>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
              Any unknown tool not in allowlist is denied immediately. No unvetted code can ever run.
            </div>
          </div>
        </div>
      </div>

      {/* Matrix Table */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">📋 Complete Tool Evaluation Policy Matrix</h3>
            <p className="panel-subtitle">Click any row to inspect policy rationale and security boundaries</p>
          </div>
        </div>

        <div className="table-wrapper">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Tool Name</th>
                <th>Category</th>
                <th>Policy Verdict</th>
                <th>Supervisor Authorization</th>
                <th>Risk Tier</th>
                <th>Policy Rationale</th>
              </tr>
            </thead>
            <tbody>
              {permissionsList.map((item) => {
                const isSelected = selectedToolDetail && selectedToolDetail.tool === item.tool;
                return (
                  <tr
                    key={item.tool}
                    onClick={() => setSelectedToolDetail(item)}
                    style={{
                      cursor: 'pointer',
                      background: isSelected ? 'rgba(6, 182, 212, 0.08)' : undefined,
                    }}
                  >
                    <td>
                      <code>{item.tool}</code>
                    </td>
                    <td style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>{item.category}</td>
                    <td>
                      <span className={`badge ${item.verdict.toLowerCase()}`}>
                        {item.verdict === 'ALLOW' ? '✓ ALLOW' : item.verdict === 'DENY' ? '✕ DENY' : '⏳ APPROVAL'}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.78rem', color: item.supervisorOverride.includes('PROHIBITED') ? 'var(--crimson)' : 'var(--text-secondary)' }}>
                      {item.supervisorOverride}
                    </td>
                    <td>
                      <span
                        style={{
                          fontSize: '0.72rem',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          color: item.riskTier.includes('CRITICAL') ? 'var(--crimson)' : item.riskTier.includes('HIGH') ? '#f87171' : item.riskTier.includes('MODERATE') ? 'var(--amber)' : 'var(--emerald)',
                        }}
                      >
                        {item.riskTier}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', maxWidth: '340px' }}>
                      {item.reason}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Policy Detail Drawer */}
      {selectedToolDetail && (
        <div className="panel" style={{ border: '1px solid var(--cyan)', background: 'rgba(6, 182, 212, 0.04)' }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title" style={{ color: 'var(--cyan)' }}>
                🔍 Tool Policy Inspector: <code>{selectedToolDetail.tool}</code>
              </h3>
              <p className="panel-subtitle">Category: {selectedToolDetail.category} · Scope: {selectedToolDetail.scope}</p>
            </div>
            <button className="btn btn-sm" onClick={() => setSelectedToolDetail(null)}>Close Inspector ✕</button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem', fontSize: '0.84rem' }}>
            <div>
              <strong>Enforced Policy Rule:</strong>
              <p style={{ color: 'var(--text-secondary)', marginTop: '0.25rem' }}>{selectedToolDetail.reason}</p>
            </div>
            <div>
              <strong>Human Supervisor Sign-Off Capability:</strong>
              <p style={{ color: selectedToolDetail.supervisorOverride.includes('PROHIBITED') ? 'var(--crimson)' : 'var(--amber)', marginTop: '0.25rem' }}>
                {selectedToolDetail.supervisorOverride}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
