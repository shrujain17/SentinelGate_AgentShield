import React, { useState, useEffect, useCallback } from 'react';
import Sidebar from './components/Sidebar';
import TopNav from './components/TopNav';

// Pages
import CommandCenter from './pages/CommandCenter';
import SecurityAnalytics from './pages/SecurityAnalytics';
import AgentMonitor from './pages/AgentMonitor';
import AgentSimulator from './pages/AgentSimulator';
import ThreatCenter from './pages/ThreatCenter';
import PermissionsMatrix from './pages/PermissionsMatrix';
import ApprovalCentre from './pages/ApprovalCentre';
import AccessPolicies from './pages/AccessPolicies';
import ToolRegistry from './pages/ToolRegistry';
import AuditLogs from './pages/AuditLogs';
import IntegrityVerification from './pages/IntegrityVerification';
import SecurityReports from './pages/SecurityReports';
import SystemHealth from './pages/SystemHealth';
import ArchitectureWorkflow from './pages/ArchitectureWorkflow';
import HelpDocs from './pages/HelpDocs';

export default function App() {
  const [activePage, setActivePage] = useState('command_center');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [toastMessage, setToastMessage] = useState(null);

  // Core telemetry state
  const [stats, setStats] = useState({
    total_interceptions: 0,
    allowed_requests: 0,
    denied_requests: 0,
    pending_approvals: 0,
    gateway_overhead_ms: 7.4,
    zero_trust_status: 'ENFORCING',
    fail_closed_mode: true,
  });
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [scenarios, setScenarios] = useState([]);
  const [lastSimulatorResult, setLastSimulatorResult] = useState(null);
  const [agentRunning, setAgentRunning] = useState(false);

  const showToast = useCallback((msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3800);
  }, []);

  // Fetch telemetry
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (e) {
      console.warn('Telemetry fetch error:', e);
    }
  }, []);

  const fetchPendingApprovals = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/approvals/pending');
      if (res.ok) {
        const data = await res.json();
        setPendingApprovals(data);
      }
    } catch (e) {
      console.warn('Approvals fetch error:', e);
    }
  }, []);

  const fetchAuditLogs = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/audit/logs?limit=50');
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data);
      }
    } catch (e) {
      console.warn('Audit logs fetch error:', e);
    }
  }, []);

  const fetchScenarios = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/scenarios');
      if (res.ok) {
        const data = await res.json();
        setScenarios(data);
      }
    } catch (e) {
      console.warn('Scenarios fetch error:', e);
    }
  }, []);

  const handleRefreshAll = useCallback(() => {
    fetchStats();
    fetchPendingApprovals();
    fetchAuditLogs();
    fetchScenarios();
    showToast('Telemetry refreshed from gateway.');
  }, [fetchStats, fetchPendingApprovals, fetchAuditLogs, fetchScenarios, showToast]);

  useEffect(() => {
    fetchStats();
    fetchPendingApprovals();
    fetchAuditLogs();
    fetchScenarios();

    const interval = setInterval(() => {
      fetchStats();
      fetchPendingApprovals();
    }, 4000);

    return () => clearInterval(interval);
  }, [fetchStats, fetchPendingApprovals, fetchAuditLogs, fetchScenarios]);

  // Execute Predefined Scenario
  const handleRunScenario = async (scenarioId) => {
    setAgentRunning(true);
    setLastSimulatorResult(null);
    try {
      const res = await fetch(`/api/v1/scenarios/${scenarioId}/run`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        const outcome = data.result || data;
        setLastSimulatorResult(outcome);
        fetchStats();
        fetchAuditLogs();
        fetchPendingApprovals();
        showToast(`Scenario ${scenarioId} executed: Status ${outcome.status || 'DONE'}`);
        if (activePage !== 'agent_simulator') {
          setActivePage('agent_simulator');
        }
      } else {
        const err = await res.json();
        showToast(`Scenario error: ${err.detail || 'Execution failed'}`);
      }
    } catch (e) {
      showToast(`Network error: ${e.message}`);
    } finally {
      setAgentRunning(false);
    }
  };

  // Run Custom Agent Prompt
  const handleRunAgentPrompt = async (payload) => {
    setAgentRunning(true);
    setLastSimulatorResult(null);
    try {
      const res = await fetch('/api/v1/agent/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        const data = await res.json();
        const outcome = data.result || data;
        setLastSimulatorResult(outcome);
        fetchStats();
        fetchAuditLogs();
        fetchPendingApprovals();
        showToast(`Agent task completed: ${outcome.status}`);
      } else {
        const err = await res.json();
        showToast(`Agent error: ${err.detail || 'Failed'}`);
      }
    } catch (e) {
      showToast(`Execution error: ${e.message}`);
    } finally {
      setAgentRunning(false);
    }
  };

  // Run Direct Tool Call Interception
  const handleRunDirectTool = async (payload) => {
    setAgentRunning(true);
    setLastSimulatorResult(null);
    try {
      const res = await fetch('/api/v1/execute-tool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      setLastSimulatorResult(data);
      fetchStats();
      fetchAuditLogs();
      fetchPendingApprovals();
      showToast(`Gateway verdict: ${data.decision} (HTTP ${res.status})`);
    } catch (e) {
      showToast(`Interception error: ${e.message}`);
    } finally {
      setAgentRunning(false);
    }
  };

  // Resolve Pending Supervisor Approval
  const handleResolveApproval = async (approvalId, action, reviewerNotes) => {
    try {
      const res = await fetch(`/api/v1/approvals/${approvalId}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          reviewer_notes: reviewerNotes || `Supervisor resolved via React SOC Console (${action}).`,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        showToast(`Approval #${approvalId} resolved: ${action}`);
        fetchPendingApprovals();
        fetchStats();
        fetchAuditLogs();
        return data;
      } else {
        const err = await res.json();
        showToast(`Error: ${err.detail || 'Failed to resolve'}`);
        throw new Error(err.detail || 'Resolution failed');
      }
    } catch (e) {
      showToast(`Failed to resolve approval: ${e.message}`);
      throw e;
    }
  };

  // Verify Hash Chain
  const handleVerifyAuditChain = async () => {
    try {
      const res = await fetch('/api/v1/audit/verify');
      if (res.ok) {
        const data = await res.json();
        fetchStats();
        return data;
      } else {
        const err = await res.json();
        throw new Error(err.detail || 'Verification request failed');
      }
    } catch (e) {
      throw e;
    }
  };

  // Interactive Threat Analysis
  const handleAnalyzeThreat = async (payloadString) => {
    try {
      const res = await fetch('/api/v1/threat/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payloads: [payloadString] }),
      });
      if (res.ok) {
        return await res.json();
      } else {
        throw new Error('Threat analyzer returned an error');
      }
    } catch (e) {
      throw e;
    }
  };

  return (
    <div className="saas-layout">
      {/* Toast Alert */}
      {toastMessage && (
        <div
          style={{
            position: 'fixed',
            bottom: '24px',
            right: '24px',
            background: 'var(--bg-card-elevated)',
            border: '1px solid var(--cyan)',
            color: '#fff',
            padding: '0.85rem 1.4rem',
            borderRadius: 'var(--radius-md)',
            boxShadow: '0 8px 30px rgba(0,0,0,0.6)',
            zIndex: 9999,
            fontSize: '0.84rem',
            fontFamily: 'var(--font-mono)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.6rem',
          }}
        >
          <span>🛡️</span>
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Reusable Sidebar Navigation */}
      <Sidebar
        activePage={activePage}
        setActivePage={setActivePage}
        collapsed={sidebarCollapsed}
        setCollapsed={setSidebarCollapsed}
        pendingApprovalsCount={pendingApprovals.length}
        auditCount={auditLogs.length}
        zeroTrustStatus={stats.zero_trust_status || 'ENFORCING'}
      />

      {/* Main SaaS App Shell */}
      <div className="saas-main">
        {/* Top Navigation Bar */}
        <TopNav
          activePage={activePage}
          setActivePage={setActivePage}
          stats={stats}
          pendingApprovals={pendingApprovals}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          onRefresh={handleRefreshAll}
        />

        {/* Dynamic Page Router */}
        <main className="saas-content">
          {activePage === 'command_center' && (
            <CommandCenter
              stats={stats}
              auditLogs={auditLogs}
              pendingApprovals={pendingApprovals}
              scenarios={scenarios}
              onRunScenario={handleRunScenario}
              onNavigate={setActivePage}
              agentRunning={agentRunning}
            />
          )}

          {activePage === 'security_analytics' && (
            <SecurityAnalytics
              stats={stats}
              auditLogs={auditLogs}
              pendingApprovals={pendingApprovals}
            />
          )}

          {activePage === 'agent_monitor' && (
            <AgentMonitor
              auditLogs={auditLogs}
              stats={stats}
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'agent_simulator' && (
            <AgentSimulator
              scenarios={scenarios}
              onRunAgentPrompt={handleRunAgentPrompt}
              onRunDirectTool={handleRunDirectTool}
              onRunScenario={handleRunScenario}
              onNavigate={setActivePage}
              agentRunning={agentRunning}
              lastResult={lastSimulatorResult}
              showToast={showToast}
            />
          )}

          {activePage === 'threat_center' && (
            <ThreatCenter
              auditLogs={auditLogs}
              onAnalyzeThreat={handleAnalyzeThreat}
              showToast={showToast}
            />
          )}

          {activePage === 'permissions_matrix' && <PermissionsMatrix />}

          {activePage === 'approval_centre' && (
            <ApprovalCentre
              pendingApprovals={pendingApprovals}
              onResolveApproval={handleResolveApproval}
              onRefresh={fetchPendingApprovals}
              showToast={showToast}
              onNavigate={setActivePage}
            />
          )}

          {activePage === 'access_policies' && <AccessPolicies />}

          {activePage === 'tool_registry' && <ToolRegistry />}

          {activePage === 'audit_logs' && (
            <AuditLogs
              auditLogs={auditLogs}
              onVerifyHashChain={handleVerifyAuditChain}
              onRefresh={fetchAuditLogs}
              showToast={showToast}
            />
          )}

          {activePage === 'integrity_verification' && (
            <IntegrityVerification
              onVerifyAuditChain={handleVerifyAuditChain}
              showToast={showToast}
            />
          )}

          {activePage === 'security_reports' && (
            <SecurityReports
              stats={stats}
              auditLogs={auditLogs}
              pendingApprovals={pendingApprovals}
              showToast={showToast}
            />
          )}

          {activePage === 'system_health' && <SystemHealth showToast={showToast} />}

          {activePage === 'architecture_workflow' && (
            <ArchitectureWorkflow onNavigate={setActivePage} />
          )}

          {activePage === 'help_docs' && <HelpDocs onNavigate={setActivePage} />}
        </main>
      </div>
    </div>
  );
}
