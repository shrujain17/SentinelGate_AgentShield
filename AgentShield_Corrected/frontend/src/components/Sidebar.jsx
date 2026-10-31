import React from 'react';

export default function Sidebar({
  activePage,
  setActivePage,
  collapsed,
  setCollapsed,
  pendingApprovalsCount = 0,
  auditCount = 0,
  zeroTrustStatus = 'ENFORCING',
}) {
  const menuGroups = [
    {
      group: 'OVERVIEW',
      items: [
        { id: 'command_center', label: 'Command Center', icon: '📊' },
        { id: 'security_analytics', label: 'Security Analytics', icon: '📈' },
      ],
    },
    {
      group: 'AI AGENT SECURITY',
      items: [
        { id: 'agent_monitor', label: 'Agent Monitor', icon: '🤖' },
        { id: 'agent_simulator', label: 'Agent Simulator', icon: '⚡' },
        { id: 'threat_center', label: 'Threat Center', icon: '🛡️' },
        { id: 'permissions_matrix', label: 'Permissions Matrix', icon: '🔐' },
      ],
    },
    {
      group: 'ACCESS MANAGEMENT',
      items: [
        {
          id: 'approval_centre',
          label: 'Approval Centre',
          icon: '⏳',
          badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : null,
        },
        { id: 'access_policies', label: 'Access Policies', icon: '📜' },
        { id: 'tool_registry', label: 'Tool Registry', icon: '🧰' },
      ],
    },
    {
      group: 'SECURITY INTELLIGENCE',
      items: [
        {
          id: 'audit_logs',
          label: 'Audit Logs',
          icon: '📑',
          badge: auditCount > 0 ? auditCount : null,
        },
        { id: 'integrity_verification', label: 'Integrity Verification', icon: '🔗' },
        { id: 'security_reports', label: 'Security Reports', icon: '📋' },
      ],
    },
    {
      group: 'SYSTEM',
      items: [
        { id: 'system_health', label: 'System Health', icon: '❤️' },
        { id: 'architecture_workflow', label: 'Architecture & Workflow', icon: '🧭' },
        { id: 'help_docs', label: 'Help & Documentation', icon: '💡' },
      ],
    },
  ];

  return (
    <aside className={`saas-sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Header / Brand */}
      <div className="sidebar-header">
        <a
          href="#command_center"
          onClick={(e) => {
            e.preventDefault();
            setActivePage('command_center');
          }}
          className="sidebar-brand"
        >
          <div className="brand-icon-box">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ffffff" strokeWidth="2.4">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" stroke="#ffffff" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          {!collapsed && (
            <div className="brand-text-box">
              <span className="brand-title">
                SENTINEL<span>GATE</span>
              </span>
              <span className="brand-subtitle">AGENTSHIELD SOC · V2.4</span>
            </div>
          )}
        </a>

        <button
          className="sidebar-toggle-btn"
          onClick={() => setCollapsed(!collapsed)}
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          aria-label="Toggle Sidebar"
        >
          {collapsed ? '▶' : '◀'}
        </button>
      </div>

      {/* Nav Menu */}
      <nav className="sidebar-nav">
        {menuGroups.map((grp) => (
          <div key={grp.group} style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem' }}>
            {!collapsed && <div className="nav-group-label">{grp.group}</div>}
            {grp.items.map((item) => {
              const isActive = activePage === item.id;
              return (
                <button
                  key={item.id}
                  className={`nav-item-btn ${isActive ? 'active' : ''}`}
                  onClick={() => setActivePage(item.id)}
                  title={collapsed ? item.label : undefined}
                >
                  <span className="nav-item-icon">{item.icon}</span>
                  {!collapsed && <span className="nav-item-text">{item.label}</span>}
                  {!collapsed && item.badge !== null && item.badge !== undefined && (
                    <span className="nav-badge-count">{item.badge}</span>
                  )}
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      {/* Footer / Telemetry Badge */}
      {!collapsed && (
        <div className="sidebar-footer">
          <div className="sidebar-status-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.68rem' }}>GATEWAY CORE</span>
              <span style={{ color: 'var(--emerald)', fontWeight: 700, fontSize: '0.68rem', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span className="pulse-dot" style={{ width: 6, height: 6 }}></span> ONLINE
              </span>
            </div>
            <div style={{ color: 'var(--cyan)', fontWeight: 600, fontSize: '0.74rem' }}>
              Zero-Trust: {zeroTrustStatus}
            </div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.68rem', marginTop: '3px' }}>
              Mode: Fail-Closed Enforcing
            </div>
          </div>
        </div>
      )}
    </aside>
  );
}
