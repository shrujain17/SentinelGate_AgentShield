import React, { useState } from 'react';

export default function ToolRegistry() {
  const [selectedTool, setSelectedTool] = useState(null);

  const tools = [
    {
      name: 'read_public_document',
      classification: 'PUBLIC',
      verdict: 'ALLOW',
      isolation: 'Local Sandbox Directory (data/sample_documents)',
      description: 'Reads allowlisted public documents (e.g. public_document.txt). Path traversal strictly blocked.',
      params: [
        { name: 'filename', type: 'string', required: true, desc: 'Allowlisted filename (e.g. public_document.txt)' },
      ],
      returns: '{ status: "success", filename: str, content: str, content_length: int }',
    },
    {
      name: 'summarize_public_document',
      classification: 'PUBLIC',
      verdict: 'ALLOW',
      isolation: 'Stage-3 Text-Only Isolation (Zero Privileges)',
      description: 'Extracts public document content and synthesizes a factual summary with zero tool privileges.',
      params: [
        { name: 'filename', type: 'string', required: true, desc: 'Target document to read and summarize' },
      ],
      returns: '{ status: "success", filename: str, content: str }',
    },
    {
      name: 'read_email',
      classification: 'INTERNAL_READ',
      verdict: 'ALLOW',
      isolation: 'Synthetic In-Memory Inbox (3 mock records)',
      description: 'Queries mock communications sandbox with keyword filtering. No real IMAP/SMTP network traffic.',
      params: [
        { name: 'folder', type: 'string', required: false, desc: 'Mail folder (default: "inbox")' },
        { name: 'limit', type: 'integer', required: false, desc: 'Maximum emails to return (default: 2)' },
        { name: 'query', type: 'string', required: false, desc: 'Keyword filter for sender or subject' },
      ],
      returns: '{ status: "success", folder: str, count: int, messages: Array }',
    },
    {
      name: 'read_document',
      classification: 'INTERNAL_READ',
      verdict: 'ALLOW',
      isolation: 'Internal Synthetic Document Registry',
      description: 'Retrieves synthetic organizational policy documents by document identifier.',
      params: [
        { name: 'document_id', type: 'string', required: true, desc: 'Identifier (e.g. "security_policy_v1")' },
      ],
      returns: '{ status: "success", document_id: str, title: str, classification: "INTERNAL", excerpt: str }',
    },
    {
      name: 'send_email',
      classification: 'HIGH_IMPACT_EXTERNAL',
      verdict: 'REQUIRE_APPROVAL',
      isolation: 'Synthetic SMTP Sandbox (Delivery Reference Generated)',
      description: 'Simulates outbound email transmission. Pauses for supervisor sign-off before dispatching.',
      params: [
        { name: 'recipient', type: 'string', required: true, desc: 'Target email address' },
        { name: 'subject', type: 'string', required: false, desc: 'Message subject line' },
        { name: 'body', type: 'string', required: false, desc: 'Body content' },
      ],
      returns: '{ status: "dispatched", recipient: str, subject: str, delivery_reference: str, note: str }',
    },
    {
      name: 'delete_file',
      classification: 'DESTRUCTIVE_RESOURCE',
      verdict: 'REQUIRE_APPROVAL',
      isolation: 'Simulated File Removal (In-Memory Demo Files Set)',
      description: 'Simulates file deletion. Pauses for supervisor confirmation to protect system storage.',
      params: [
        { name: 'file_path', type: 'string', required: true, desc: 'Target file path to delete' },
      ],
      returns: '{ status: "deleted", file_path: str, bytes_reclaimed: int, note: str }',
    },
    {
      name: 'send_external_message',
      classification: 'HIGH_IMPACT_EXTERNAL',
      verdict: 'REQUIRE_APPROVAL',
      isolation: 'Synthetic Webhook Sandbox',
      description: 'Simulates external message or incident dispatch to third-party endpoints.',
      params: [
        { name: 'recipient', type: 'string', required: true, desc: 'External recipient or endpoint' },
        { name: 'subject', type: 'string', required: false, desc: 'Notification subject' },
        { name: 'message', type: 'string', required: true, desc: 'Payload content' },
      ],
      returns: '{ status: "dispatched", tool: str, recipient: str, note: str }',
    },
    {
      name: 'dispatch_external_alert',
      classification: 'HIGH_IMPACT_EXTERNAL',
      verdict: 'REQUIRE_APPROVAL',
      isolation: 'Synthetic Alert Pager Sandbox',
      description: 'Simulates high-severity incident notification dispatch to SOC on-call engineers.',
      params: [
        { name: 'recipient', type: 'string', required: true, desc: 'SOC team or endpoint identifier' },
        { name: 'alert', type: 'string', required: true, desc: 'Alert summary description' },
      ],
      returns: '{ status: "dispatched", tool: str, recipient: str, note: str }',
    },
    {
      name: 'execute_system_command',
      classification: 'SYSTEM_COMMAND',
      verdict: 'REQUIRE_APPROVAL',
      isolation: 'Synthetic Sandbox Process Simulation (No Host Execution)',
      description: 'Simulates system CLI execution safely within a sandbox. No real host subprocess is spawned.',
      params: [
        { name: 'command', type: 'string', required: true, desc: 'Shell command string to simulate' },
      ],
      returns: '{ status: "executed", command: str, stdout: str, returncode: 0, note: str }',
    },
    {
      name: 'read_restricted_file',
      classification: 'CONFIDENTIAL_BLOCKED',
      verdict: 'DENY',
      isolation: 'Hardware & OS Boundary (Blocked by Gateway)',
      description: 'Direct attempt to read restricted confidential documents. Blocked unconditionally.',
      params: [
        { name: 'filename', type: 'string', required: true, desc: 'Confidential file' },
      ],
      returns: 'HTTP 403 Forbidden - Policy Violation',
    },
    {
      name: 'read_secret',
      classification: 'SECRET_BLOCKED',
      verdict: 'DENY',
      isolation: 'Hardware & OS Boundary (Blocked by Gateway)',
      description: 'Attempt to exfiltrate master passwords, API keys, or credentials. Blocked unconditionally.',
      params: [
        { name: 'secret_name', type: 'string', required: true, desc: 'Secret identifier' },
      ],
      returns: 'HTTP 403 Forbidden - Policy Violation',
    },
  ];

  return (
    <div>
      {/* Top Banner */}
      <div className="panel" style={{ background: 'rgba(10, 15, 29, 0.6)' }}>
        <div className="panel-header">
          <div>
            <h3 className="panel-title">🧰 Isolated Synthetic Tool Registry</h3>
            <p className="panel-subtitle">
              Sanctioned synthetic tools implemented in <code>backend/tools/synthetic_tools.py</code> with 100% safe sandbox boundaries
            </p>
          </div>
          <span className="badge purple">SYNTHETIC ISOLATION</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
          <div style={{ background: 'var(--bg-surface)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>NETWORK PROTECTION</span>
            <div style={{ color: 'var(--emerald)', fontWeight: 700, fontSize: '0.9rem', marginTop: '2px' }}>0 Outbound Packets</div>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>All external calls are safely simulated</p>
          </div>

          <div style={{ background: 'var(--bg-surface)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>FILESYSTEM BOUNDARY</span>
            <div style={{ color: 'var(--cyan)', fontWeight: 700, fontSize: '0.9rem', marginTop: '2px' }}>Strict Allowlist Only</div>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Traversal to /etc, .env, or keys is blocked</p>
          </div>

          <div style={{ background: 'var(--bg-surface)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>NON-DESTRUCTIVE DESIGN</span>
            <div style={{ color: 'var(--purple)', fontWeight: 700, fontSize: '0.9rem', marginTop: '2px' }}>In-Memory Mutation</div>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Deletions affect synthetic test sets only</p>
          </div>
        </div>
      </div>

      {/* Tool Cards Grid */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">📋 Registered Tool Specifications</h3>
            <p className="panel-subtitle">Select a tool to view its parameter contracts and sandbox return signature</p>
          </div>
          <span className="badge neutral">{tools.length} Tools Cataloged</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
          {tools.map((t) => (
            <div
              key={t.name}
              onClick={() => setSelectedTool(t)}
              style={{
                background: selectedTool && selectedTool.name === t.name ? 'rgba(6, 182, 212, 0.08)' : 'var(--bg-surface)',
                border: `1px solid ${selectedTool && selectedTool.name === t.name ? 'var(--cyan)' : 'var(--border-subtle)'}`,
                borderRadius: 'var(--radius-md)',
                padding: '1.15rem',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                <code style={{ fontSize: '0.88rem', fontWeight: 700 }}>{t.name}</code>
                <span className={`badge ${t.verdict.toLowerCase()}`}>{t.verdict}</span>
              </div>

              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '0.5rem' }}>
                Class: {t.classification}
              </div>

              <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.4, marginBottom: '0.75rem' }}>
                {t.description}
              </p>

              <div style={{ background: 'rgba(8, 14, 27, 0.6)', padding: '0.45rem 0.65rem', borderRadius: 'var(--radius-xs)', fontSize: '0.72rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Sandbox Isolation:</span>{' '}
                <span style={{ color: 'var(--cyan)' }}>{t.isolation}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Selected Tool Schema Modal / Detail */}
      {selectedTool && (
        <div className="panel" style={{ border: '1px solid var(--cyan)', background: 'rgba(6, 182, 212, 0.04)' }}>
          <div className="panel-header">
            <div>
              <h3 className="panel-title" style={{ color: 'var(--cyan)' }}>
                🔍 Schema Inspector: <code>{selectedTool.name}</code>
              </h3>
              <p className="panel-subtitle">Isolation Layer: {selectedTool.isolation}</p>
            </div>
            <button className="btn btn-sm" onClick={() => setSelectedTool(null)}>Close Inspector ✕</button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.8fr', gap: '1.25rem', fontSize: '0.82rem' }}>
            <div>
              <strong style={{ color: '#fff' }}>Expected Parameters:</strong>
              <div style={{ marginTop: '0.4rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                {selectedTool.params.map((p) => (
                  <div key={p.name} style={{ background: 'var(--bg-surface)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-xs)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <code>{p.name}</code>
                      <span style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>{p.type}</span>
                    </div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{p.desc}</div>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <strong style={{ color: '#fff' }}>Synthetic Sandbox Output Schema:</strong>
              <pre
                style={{
                  background: 'var(--bg-input)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.75rem',
                  color: 'var(--emerald)',
                  marginTop: '0.4rem',
                  overflowX: 'auto',
                }}
              >
                {selectedTool.returns}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
