import React, { useState } from 'react';

export default function ArchitectureWorkflow({ onNavigate }) {
  const [activeStep, setActiveStep] = useState(4);

  const steps = [
    {
      num: 1,
      title: 'User Request Intake',
      role: 'User / External System',
      description: 'The operator or automated workflow submits a task or prompt to the AI agent.',
      securityInsight: 'Input is tagged with USER_DIRECT provenance. Sanitized and staged.',
    },
    {
      num: 2,
      title: 'AI Agent Intake & Contextualization',
      role: 'AgentShieldAgent Core',
      description: 'Coordinates task parsing, reasoning cycle tracking, and boundary containment.',
      securityInsight: 'Bounded by MAX_REASONING_CYCLES=2. Agent possesses NO local execution rights.',
    },
    {
      num: 3,
      title: 'Reasoning Engine (Gemini / Mock)',
      role: 'AI Reasoning Provider',
      description: 'Analyzes user prompt and formulates a structured ProposedToolCall.',
      securityInsight: 'CRITICAL MANDATE: Model outputs PROPOSALS ONLY. It cannot execute anything directly.',
    },
    {
      num: 4,
      title: 'Proposed Tool Action Interception',
      role: 'Zero-Trust Adapter Boundary',
      description: 'Tool calls are serialized into GatewayRequest with arguments and provenance.',
      securityInsight: 'Model is forbidden from declaring its own trust status. Provenance is set by caller.',
    },
    {
      num: 5,
      title: 'SentinelGate Security Gateway',
      role: 'Core Policy Interceptor (Person 4)',
      description: 'Evaluates every tool call through dual independent security engines.',
      securityInsight: 'Operates outside the AI process boundary. Fail-closed on missing response.',
      isGatewayCore: true,
    },
    {
      num: 6,
      title: 'Deterministic Policy Matrix',
      role: 'Permissions Matrix Engine',
      description: 'Applies deterministic rule matrix: ALLOW, REQUIRE_APPROVAL, or ABSOLUTE_DENY.',
      securityInsight: 'Confidential resources (passwords, shadow) trigger absolute permanent denial.',
    },
    {
      num: 7,
      title: 'Heuristic Threat & Injection Analysis',
      role: 'ThreatAnalyzer Engine',
      description: 'Scans parameters and context for prompt injection, path traversal, and payload overrides.',
      securityInsight: 'Detects "IGNORE ALL INSTRUCTIONS", directory traversal, and sensitive tokens.',
    },
    {
      num: 8,
      title: '3-Way Zero-Trust Decision',
      role: 'Gateway Verdict Dispatcher',
      description: 'Emits authoritative verdict: ALLOW (safe), DENY (blocked), or REQUIRE_APPROVAL (paused).',
      securityInsight: 'Shared response validation rejects contradictory responses (e.g. ALLOW with executed=False).',
    },
    {
      num: 9,
      title: 'Execution / Staging / Blocking',
      role: 'Isolated Sandbox / Supervisor Queue',
      description: 'ALLOW tools run in synthetic sandbox; REQUIRE_APPROVAL tools pause for supervisor sign-off.',
      securityInsight: 'Denied actions halt immediately with HTTP 403. Approval is bound to exact arguments.',
    },
    {
      num: 10,
      title: 'Cryptographic Audit Hash Chain',
      role: 'AuditLogger & SQLite Persistence',
      description: 'Records immutable SHA-256 linked block in append-only JSONL and relational database.',
      securityInsight: 'H_i = SHA256(H_{i-1} + JSON(Record_i)). Tamper-evident against covert log alteration.',
    },
  ];

  return (
    <div>
      {/* Top Banner */}
      <div className="panel" style={{ background: 'rgba(10, 15, 29, 0.6)' }}>
        <div className="panel-header">
          <div>
            <h3 className="panel-title">🧭 Complete Zero-Trust AI Agent Architecture</h3>
            <p className="panel-subtitle">
              Visual breakdown of why and how SentinelGate independently mediates every autonomous agent action
            </p>
          </div>
          <button className="btn btn-sm btn-primary" onClick={() => onNavigate('agent_simulator')}>
            ⚡ Test in Simulator
          </button>
        </div>

        {/* Core Principle Callout */}
        <div
          style={{
            background: 'linear-gradient(90deg, rgba(6, 182, 212, 0.12) 0%, rgba(139, 92, 246, 0.08) 100%)',
            border: '1px solid rgba(6, 182, 212, 0.35)',
            borderRadius: 'var(--radius-md)',
            padding: '1.15rem',
            marginTop: '0.5rem',
          }}
        >
          <div style={{ color: 'var(--cyan)', fontWeight: 800, fontSize: '0.95rem', marginBottom: '0.35rem' }}>
            THE SENTINELGATE ZERO-TRUST MANDATE
          </div>
          <p style={{ color: 'var(--text-primary)', fontSize: '0.86rem', lineHeight: 1.5 }}>
            <em>"Your AI agent can think. SENTINELGATE decides what it is allowed to do."</em> Autonomous agents must never have ambient tool execution privileges. All action proposals must pass through an independent, deterministic policy gateway that enforces access control, detects prompt injection, stages sensitive actions for human approval, and cryptographically audits every event.
          </p>
        </div>
      </div>

      {/* Interactive Step-by-Step Pipeline Flow */}
      <div className="panel">
        <div className="panel-header">
          <div>
            <h3 className="panel-title">⚡ End-to-End Mediation Workflow</h3>
            <p className="panel-subtitle">Click any stage to inspect its security role and technical enforcement</p>
          </div>
        </div>

        <div className="flow-diagram-container">
          {steps.map((st, idx) => {
            const isSelected = activeStep === st.num;
            return (
              <React.Fragment key={st.num}>
                <div
                  className={`flow-step-node ${st.isGatewayCore ? 'highlight-gateway' : ''}`}
                  onClick={() => setActiveStep(st.num)}
                  style={{
                    cursor: 'pointer',
                    borderColor: isSelected ? 'var(--cyan)' : undefined,
                    boxShadow: isSelected ? '0 0 16px rgba(6, 182, 212, 0.25)' : undefined,
                  }}
                >
                  <div className="flow-node-index">{st.num}</div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <strong style={{ fontSize: '0.95rem', color: '#fff' }}>{st.title}</strong>
                      <span className="badge cyan">{st.role}</span>
                    </div>
                    <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                      {st.description}
                    </p>
                    <div style={{ marginTop: '0.35rem', fontSize: '0.74rem', color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>
                      🔒 Guardrail: {st.securityInsight}
                    </div>
                  </div>
                </div>

                {idx < steps.length - 1 && (
                  <div className="flow-arrow-down">
                    <span>↓</span>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
}
