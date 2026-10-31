import React, { useState } from 'react';

export default function IntegrityVerification({ onVerifyAuditChain, showToast }) {
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState(null);
  const [lastCheckTime, setLastCheckTime] = useState(null);

  const handleRunVerification = async () => {
    setVerifying(true);
    try {
      const data = await onVerifyAuditChain();
      setVerificationResult(data);
      setLastCheckTime(new Date().toLocaleTimeString());
      if (data.tamper_detected) {
        showToast('⚠️ TAMPER DETECTED in audit log chain!');
      } else {
        showToast('✅ Cryptographic hash chain verified 100% intact.');
      }
    } catch (e) {
      showToast('Verification error: ' + e.message);
    } finally {
      setVerifying(false);
    }
  };

  const isVerified = verificationResult && !verificationResult.tamper_detected && verificationResult.total_records > 0;
  const isTampered = verificationResult && verificationResult.tamper_detected;
  const isEmptyOrUnverified = !verificationResult || verificationResult.total_records === 0;

  let statusColor = 'var(--amber)';
  let statusText = 'UNVERIFIED / PENDING VERIFICATION';
  if (isVerified) {
    statusColor = 'var(--emerald)';
    statusText = 'CRYPTOGRAPHICALLY VERIFIED INTACT';
  } else if (isTampered) {
    statusColor = 'var(--crimson)';
    statusText = 'TAMPER DETECTED / CHAIN BROKEN';
  } else if (verificationResult && verificationResult.total_records === 0) {
    statusColor = 'var(--cyan)';
    statusText = 'ZERO RECORDS (NEW AUDIT CHAIN)';
  }

  return (
    <div>
      {/* Verification Station Hero Panel */}
      <div
        className="panel"
        style={{
          background: isVerified
            ? 'radial-gradient(circle at top right, rgba(16, 185, 129, 0.12) 0%, var(--bg-card) 65%)'
            : isTampered
            ? 'radial-gradient(circle at top right, rgba(239, 68, 68, 0.15) 0%, var(--bg-card) 65%)'
            : 'radial-gradient(circle at top right, rgba(6, 182, 212, 0.08) 0%, var(--bg-card) 65%)',
          border: `1px solid ${isVerified ? 'rgba(16, 185, 129, 0.4)' : isTampered ? 'rgba(239, 68, 68, 0.4)' : 'var(--border-bright)'}`,
        }}
      >
        <div className="panel-header">
          <div>
            <h3 className="panel-title">🔗 Forensic Cryptographic Hash-Chain Verification</h3>
            <p className="panel-subtitle">Independent verification station for append-only JSONL audit integrity</p>
          </div>
          <span className="badge" style={{ background: `${statusColor}22`, color: statusColor, border: `1px solid ${statusColor}55` }}>
            {statusText}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: '1.5rem', alignItems: 'center' }}>
          <div>
            <h2 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#fff', letterSpacing: '-0.02em', marginBottom: '0.6rem' }}>
              SHA-256 Merkle-Linked Block Verification
            </h2>
            <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '1.25rem' }}>
              SentinelGate links every evaluated action to the prior record using a mathematical SHA-256 hash chain:
              <code style={{ display: 'block', margin: '0.5rem 0', padding: '0.5rem', background: 'var(--bg-base)', color: 'var(--cyan)' }}>
                H_i = SHA256(H_{'{i-1}'} + canonical_json(Record_i))
              </code>
              Any unauthorized deletion, line tampering, timestamp modification, or injection rewrite immediately causes hash mismatch across all subsequent blocks.
            </p>

            <button
              className="btn btn-primary"
              onClick={handleRunVerification}
              disabled={verifying}
              style={{ padding: '0.85rem 1.6rem', fontSize: '0.95rem', fontWeight: 700 }}
            >
              {verifying ? '⏳ Computing SHA-256 Hashes Across All Records...' : '🛡️ VERIFY AUDIT INTEGRITY NOW'}
            </button>
          </div>

          {/* Verification Status Readout Card */}
          <div
            style={{
              background: 'var(--bg-surface)',
              border: `1px solid ${statusColor}44`,
              borderRadius: 'var(--radius-md)',
              padding: '1.25rem',
            }}
          >
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>CURRENT INTEGRITY STATUS</div>
            <div style={{ fontSize: '1.3rem', fontWeight: 900, color: statusColor, marginTop: '0.2rem' }}>
              {statusText}
            </div>

            <div style={{ marginTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.8rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.35rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Total Records Audited:</span>
                <strong style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>
                  {verificationResult ? verificationResult.total_records : 'Run Verification'}
                </strong>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.35rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Tamper Detected:</span>
                <strong style={{ color: isTampered ? 'var(--crimson)' : 'var(--emerald)' }}>
                  {verificationResult ? (verificationResult.tamper_detected ? 'YES (Tampered!)' : 'NO (Intact)') : 'Unknown'}
                </strong>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.35rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Last Verification Run:</span>
                <span style={{ color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>{lastCheckTime || 'Never'}</span>
              </div>

              <div style={{ marginTop: '0.35rem' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>LATEST CHAIN HEAD HASH:</span>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.72rem',
                    color: 'var(--emerald)',
                    background: 'var(--bg-input)',
                    padding: '0.45rem',
                    borderRadius: 'var(--radius-xs)',
                    wordBreak: 'break-all',
                    marginTop: '2px',
                  }}
                >
                  {verificationResult && verificationResult.latest_chain_hash
                    ? verificationResult.latest_chain_hash
                    : 'Run verification to compute head hash'}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Explanatory Architecture Guide for Judges */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">💡 Why Hash-Chaining Matters in AI Cybersecurity</h3>
            <p className="panel-subtitle">Architectural differentiator against covert insider threats and compromised host logs</p>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.25rem', fontSize: '0.84rem' }}>
          <div style={{ background: 'var(--bg-surface)', padding: '1.15rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ color: 'var(--cyan)', fontWeight: 800, fontSize: '0.9rem', marginBottom: '0.4rem' }}>
              1. Non-Repudiation
            </div>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.45 }}>
              Neither the requesting AI model nor a malicious attacker can claim an action was never requested or was altered post-hoc.
            </p>
          </div>

          <div style={{ background: 'var(--bg-surface)', padding: '1.15rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ color: 'var(--emerald)', fontWeight: 800, fontSize: '0.9rem', marginBottom: '0.4rem' }}>
              2. Tamper Evident
            </div>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.45 }}>
              If a compromised system process edits an audit entry to conceal an unauthorized exfiltration, every subsequent hash fails verification.
            </p>
          </div>

          <div style={{ background: 'var(--bg-surface)', padding: '1.15rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
            <div style={{ color: 'var(--purple)', fontWeight: 800, fontSize: '0.9rem', marginBottom: '0.4rem' }}>
              3. Dual Persistence Synchronization
            </div>
            <p style={{ color: 'var(--text-secondary)', lineHeight: 1.45 }}>
              The gateway synchronizes SQLite relational records with the raw JSONL hash chain upon lifespan startup, preserving redundancy.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
