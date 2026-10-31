import React, { useState } from 'react';

/**
 * Interactive pure-SVG Donut Chart displaying ALLOW, DENY, REQUIRE_APPROVAL distributions.
 */
export function DecisionDonutChart({ allowed = 0, denied = 0, pending = 0, size = 180 }) {
  const [hoveredIndex, setHoveredIndex] = useState(null);

  const total = allowed + denied + pending;
  const data = [
    { label: 'ALLOW', count: allowed, color: '#10b981', glow: 'rgba(16, 185, 129, 0.4)' },
    { label: 'DENY', count: denied, color: '#ef4444', glow: 'rgba(239, 68, 68, 0.4)' },
    { label: 'APPROVAL', count: pending, color: '#f59e0b', glow: 'rgba(245, 158, 11, 0.4)' },
  ];

  if (total === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: size }}>
        <svg width={size} height={size} viewBox="0 0 100 100">
          <circle cx="50" cy="50" r="38" fill="none" stroke="var(--border-subtle)" strokeWidth="12" />
          <text x="50" y="54" textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontFamily="var(--font-mono)">
            NO DATA
          </text>
        </svg>
      </div>
    );
  }

  const radius = 38;
  const strokeWidth = 14;
  const circumference = 2 * Math.PI * radius;
  let accumulatedPercent = 0;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', flexWrap: 'wrap' }}>
      <div style={{ position: 'relative', width: size, height: size }}>
        <svg width={size} height={size} viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
          {/* Base Track */}
          <circle cx="50" cy="50" r={radius} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={strokeWidth} />

          {/* Slices */}
          {data.map((item, idx) => {
            if (item.count === 0) return null;
            const percent = item.count / total;
            const strokeDasharray = `${circumference * percent} ${circumference}`;
            const strokeDashoffset = -circumference * accumulatedPercent;
            accumulatedPercent += percent;

            const isHovered = hoveredIndex === idx;

            return (
              <circle
                key={item.label}
                cx="50"
                cy="50"
                r={radius}
                fill="none"
                stroke={item.color}
                strokeWidth={isHovered ? strokeWidth + 3 : strokeWidth}
                strokeDasharray={strokeDasharray}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                style={{
                  transition: 'all 0.25s ease',
                  cursor: 'pointer',
                  filter: isHovered ? `drop-shadow(0 0 8px ${item.glow})` : undefined,
                }}
                onMouseEnter={() => setHoveredIndex(idx)}
                onMouseLeave={() => setHoveredIndex(null)}
              />
            );
          })}
        </svg>

        {/* Center Text */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            pointerEvents: 'none',
          }}
        >
          <span style={{ fontSize: '1.4rem', fontWeight: 800, color: '#fff', lineHeight: 1 }}>{total}</span>
          <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
            {hoveredIndex !== null ? data[hoveredIndex].label : 'DECISIONS'}
          </span>
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', flex: 1, minWidth: '140px' }}>
        {data.map((item, idx) => {
          const pct = Math.round((item.count / total) * 100);
          return (
            <div
              key={item.label}
              onMouseEnter={() => setHoveredIndex(idx)}
              onMouseLeave={() => setHoveredIndex(null)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.35rem 0.6rem',
                borderRadius: 'var(--radius-sm)',
                background: hoveredIndex === idx ? 'rgba(255,255,255,0.05)' : 'transparent',
                cursor: 'pointer',
                transition: 'background 0.15s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ width: '9px', height: '9px', borderRadius: '50%', background: item.color, boxShadow: `0 0 6px ${item.color}` }}></span>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{item.label}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <strong style={{ fontSize: '0.84rem', color: '#fff' }}>{item.count}</strong>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>({pct}%)</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/**
 * Pure-SVG Activity Trend Bar Chart
 */
export function ActivityTrendChart({ logs = [] }) {
  // Aggregate decisions by most recent 8 buckets or logs
  const displayItems = logs.slice(0, 10).reverse();

  if (displayItems.length === 0) {
    return (
      <div style={{ height: '140px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
        No recent activity recorded yet. Run a scenario or test simulation.
      </div>
    );
  }

  const height = 130;
  const maxRisk = 100;

  return (
    <div style={{ width: '100%' }}>
      <svg width="100%" height={height} viewBox={`0 0 ${displayItems.length * 40} 100`} preserveAspectRatio="none">
        {/* Background Grid Lines */}
        <line x1="0" y1="25" x2={displayItems.length * 40} y2="25" stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />
        <line x1="0" y1="50" x2={displayItems.length * 40} y2="50" stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />
        <line x1="0" y1="75" x2={displayItems.length * 40} y2="75" stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />

        {displayItems.map((log, idx) => {
          const x = idx * 40 + 10;
          const risk = typeof log.risk_score === 'number' ? Math.min(100, log.risk_score * 100) : 20;
          const barHeight = Math.max(12, (risk / maxRisk) * 75);
          const y = 85 - barHeight;

          let color = '#10b981';
          if (log.decision === 'DENIED' || log.decision === 'DENY') color = '#ef4444';
          else if (log.decision === 'REQUIRE_APPROVAL') color = '#f59e0b';

          return (
            <g key={log.id || idx}>
              {/* Bar */}
              <rect
                x={x}
                y={y}
                width="20"
                height={barHeight}
                rx="3"
                fill={color}
                opacity="0.85"
                style={{ transition: 'all 0.2s ease', cursor: 'pointer' }}
              >
                <title>{`${log.tool_name} | Decision: ${log.decision} | Risk: ${Math.round(risk)}`}</title>
              </rect>
              {/* Tool Label */}
              <text
                x={x + 10}
                y="96"
                textAnchor="middle"
                fill="var(--text-muted)"
                fontSize="6"
                fontFamily="var(--font-mono)"
              >
                #{log.id || idx + 1}
              </text>
            </g>
          );
        })}
      </svg>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
        <span>Oldest recorded</span>
        <span>Latest gateway event</span>
      </div>
    </div>
  );
}

/**
 * Mini Sparkline SVG for stat cards
 */
export function Sparkline({ color = '#06b6d4' }) {
  return (
    <svg width="60" height="20" viewBox="0 0 60 20" style={{ overflow: 'visible' }}>
      <polyline
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        points="0,15 10,12 20,16 30,8 40,11 50,4 60,7"
      />
      <circle cx="60" cy="7" r="3" fill={color} />
    </svg>
  );
}

/**
 * Risk Meter Arc / Gauge (0 to 100)
 */
export function RiskMeterGauge({ score = 0, size = 120 }) {
  const clamped = Math.max(0, Math.min(100, score));
  let color = '#10b981';
  let level = 'LOW';
  if (clamped > 75) {
    color = '#ef4444';
    level = 'CRITICAL';
  } else if (clamped > 45) {
    color = '#f59e0b';
    level = 'ELEVATED';
  } else if (clamped > 20) {
    color = '#06b6d4';
    level = 'MODERATE';
  }

  // Semi-circle arc from 180 to 360 deg
  const radius = 45;
  const circumference = Math.PI * radius;
  const strokeDashoffset = circumference - (circumference * clamped) / 100;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <svg width={size} height={size * 0.65} viewBox="0 0 110 65">
        <path d="M 10 55 A 45 45 0 0 1 100 55" fill="none" stroke="var(--border-subtle)" strokeWidth="10" strokeLinecap="round" />
        <path
          d="M 10 55 A 45 45 0 0 1 100 55"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
        <text x="55" y="48" textAnchor="middle" fill="#fff" fontSize="16" fontWeight="800" fontFamily="var(--font-sans)">
          {Math.round(clamped)}
        </text>
      </svg>
      <span style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color, marginTop: '-2px' }}>
        {level} RISK
      </span>
    </div>
  );
}
