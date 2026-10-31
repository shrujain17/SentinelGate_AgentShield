import React, { useState } from 'react';

export default function TopNav({
  activePage,
  setActivePage,
  stats,
  pendingApprovals,
  searchQuery,
  setSearchQuery,
  onRefresh,
}) {
  const [showNotifications, setShowNotifications] = useState(false);

  const pageMeta = {
    command_center: { group: 'OVERVIEW', title: 'Command Center', tagline: 'Real-Time Zero-Trust Gateway Operations' },
    security_analytics: { group: 'OVERVIEW', title: 'Security Analytics', tagline: 'Evaluations, Threats & Decision Metrics' },
    agent_monitor: { group: 'AI AGENT SECURITY', title: 'Agent Monitor', tagline: 'Agent Registry, Activity & Sandboxing' },
    agent_simulator: { group: 'AI AGENT SECURITY', title: 'Agent Simulator', tagline: 'Interactive Tool Call & Attack Defense Testing' },
    threat_center: { group: 'AI AGENT SECURITY', title: 'Threat Center', tagline: 'Heuristic Injection & Violation Detection' },
    permissions_matrix: { group: 'AI AGENT SECURITY', title: 'Permissions Matrix', tagline: 'Zero-Trust Tool & Resource Access Policy' },
    approval_centre: { group: 'ACCESS MANAGEMENT', title: 'Approval Centre', tagline: 'Human-in-the-Loop Supervisor Authorizations' },
    access_policies: { group: 'ACCESS MANAGEMENT', title: 'Access Policies', tagline: 'Enterprise Provenance & Fail-Closed Rules' },
    tool_registry: { group: 'ACCESS MANAGEMENT', title: 'Tool Registry', tagline: 'Isolated Synthetic Sandbox Tool Definitions' },
    audit_logs: { group: 'SECURITY INTELLIGENCE', title: 'Audit Logs', tagline: 'Immutable Cryptographic Forensics Trail' },
    integrity_verification: { group: 'SECURITY INTELLIGENCE', title: 'Integrity Verification', tagline: 'SHA-256 Hash Chain Tamper Proofing' },
    security_reports: { group: 'SECURITY INTELLIGENCE', title: 'Security Reports', tagline: 'Executive Posture & Compliance Summaries' },
    system_health: { group: 'SYSTEM', title: 'System Health', tagline: 'FastAPI, Engine Latency & Fail-Closed Status' },
    architecture_workflow: { group: 'SYSTEM', title: 'Architecture & Workflow', tagline: 'Zero-Trust AI Agent Mediation Architecture' },
    help_docs: { group: 'SYSTEM', title: 'Help & Documentation', tagline: 'Concept Explanations, Scenarios & SOC Glossary' },
  };

  const current = pageMeta[activePage] || {
    group: 'DASHBOARD',
    title: 'Security Gateway',
    tagline: 'Enterprise Zero-Trust AI Agent Protection',
  };

  return (
    <header className="saas-topbar">
      {/* Left: Breadcrumbs & Page Title */}
      <div className="topbar-left">
        <div>
          <div className="topbar-breadcrumbs">
            <span>{current.group}</span>
            <span className="breadcrumb-separator">/</span>
            <span className="breadcrumb-active">{current.title}</span>
          </div>
          <h2 className="topbar-page-title">{current.title}</h2>
        </div>
      </div>

      {/* Right: Telemetry & Controls */}
      <div className="topbar-right">
        {/* Search */}
        <div style={{ position: 'relative' }}>
          <input
            type="text"
            className="form-input"
            placeholder="Search records, tools, agents..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              paddingLeft: '2rem',
              width: '220px',
              height: '34px',
              fontSize: '0.78rem',
              background: 'rgba(8, 14, 27, 0.8)',
            }}
          />
          <span
            style={{
              position: 'absolute',
              left: '8px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--text-muted)',
              fontSize: '0.85rem',
            }}
          >
            🔍
          </span>
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              style={{
                position: 'absolute',
                right: '8px',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
              }}
            >
              ✕
            </button>
          )}
        </div>

        {/* Live Status Indicators */}
        <div className="status-pill">
          <span className="pulse-dot"></span>
          <span>GATEWAY ONLINE</span>
        </div>

        <div className="status-pill purple">
          <span className="pulse-dot" style={{ background: 'var(--purple)' }}></span>
          <span>AI REASONING: MOCK</span>
        </div>

        {/* Quick Simulation CTA */}
        {activePage !== 'agent_simulator' && (
          <button
            className="topbar-btn primary"
            onClick={() => setActivePage('agent_simulator')}
            title="Launch Interactive Simulation Testing"
          >
            ⚡ Test Simulator
          </button>
        )}

        {/* Manual Refresh */}
        <button
          className="topbar-btn"
          onClick={onRefresh}
          title="Refresh Backend Telemetry"
          style={{ width: '34px', height: '34px', padding: 0, justifyContent: 'center' }}
        >
          🔄
        </button>

        {/* Notification Bell with Dropdown */}
        <div style={{ position: 'relative' }}>
          <button
            className="topbar-btn"
            onClick={() => setShowNotifications(!showNotifications)}
            title="Supervisor Notification Feed"
            style={{ width: '34px', height: '34px', padding: 0, justifyContent: 'center', position: 'relative' }}
          >
            🔔
            {pendingApprovals.length > 0 && (
              <span
                style={{
                  position: 'absolute',
                  top: '-4px',
                  right: '-4px',
                  width: '18px',
                  height: '18px',
                  background: 'var(--amber)',
                  color: '#000',
                  borderRadius: '50%',
                  fontSize: '0.65rem',
                  fontWeight: 800,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  border: '2px solid var(--bg-base)',
                }}
              >
                {pendingApprovals.length}
              </span>
            )}
          </button>

          {showNotifications && (
            <div
              style={{
                position: 'absolute',
                top: '42px',
                right: 0,
                width: '320px',
                background: 'var(--bg-card-elevated)',
                border: '1px solid var(--border-bright)',
                borderRadius: 'var(--radius-md)',
                boxShadow: '0 8px 30px rgba(0,0,0,0.6)',
                zIndex: 100,
                padding: '1rem',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '0.75rem',
                  borderBottom: '1px solid var(--border-subtle)',
                  paddingBottom: '0.5rem',
                }}
              >
                <strong style={{ fontSize: '0.85rem' }}>Security Queue Notifications</strong>
                <button
                  onClick={() => setShowNotifications(false)}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                >
                  ✕
                </button>
              </div>

              {pendingApprovals.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '1rem 0', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                  No pending approval tickets currently queued.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                  {pendingApprovals.slice(0, 3).map((item) => (
                    <div
                      key={item.id}
                      onClick={() => {
                        setActivePage('approval_centre');
                        setShowNotifications(false);
                      }}
                      style={{
                        padding: '0.5rem 0.65rem',
                        background: 'var(--bg-surface)',
                        borderRadius: 'var(--radius-sm)',
                        cursor: 'pointer',
                        border: '1px solid rgba(245, 158, 11, 0.3)',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                        <span style={{ color: 'var(--amber)', fontWeight: 700 }}>Ticket #{item.id}</span>
                        <span style={{ color: 'var(--text-muted)' }}>Approval Required</span>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: '#fff', marginTop: '2px' }}>
                        Tool: <code>{item.tool_name}</code>
                      </div>
                    </div>
                  ))}
                  <button
                    className="btn btn-sm"
                    onClick={() => {
                      setActivePage('approval_centre');
                      setShowNotifications(false);
                    }}
                    style={{ width: '100%', marginTop: '0.25rem' }}
                  >
                    Open Approval Centre →
                  </button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* User profile */}
        <div className="user-profile-badge">
          <div className="user-avatar">SG</div>
          <div style={{ display: 'flex', flexDirection: 'column', fontSize: '0.72rem', lineHeight: 1.1 }}>
            <span style={{ fontWeight: 700, color: '#fff' }}>SecOps Analyst</span>
            <span style={{ color: 'var(--text-muted)' }}>Admin · Zero-Trust</span>
          </div>
        </div>
      </div>
    </header>
  );
}
