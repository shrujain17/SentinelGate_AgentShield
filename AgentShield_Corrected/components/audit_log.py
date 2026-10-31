"""
AgentShield - Live Security Audit Log Component
Displays the immutable chronological security audit trail with formatted badges.
"""

import streamlit as st
from config import COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_AMBER, COLOR_GRAY


def render_audit_log():
    """
    Renders the SOC Audit Log table.
    """
    logs = st.session_state.get("audit_logs", [])

    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 14px; margin-bottom: 6px;">
            <div style="font-size: 13px; font-weight: 700; color: #F8FAFC; letter-spacing: 0.8px; display: flex; align-items: center; gap: 8px;">
                <span style="color: {COLOR_CYAN}; font-family: 'JetBrains Mono', monospace;">📋</span> LIVE SECURITY AUDIT LOG
            </div>
            <div style="font-size: 10px; font-family: 'JetBrains Mono', monospace; color: {COLOR_GRAY};">
                PERSISTENT TAMPER-EVIDENT LEDGER ({len(logs)} TOTAL ENTRIES)
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    if not logs:
        st.markdown(
            f"""
            <div class="soc-card" style="text-align: center; padding: 14px; color: {COLOR_GRAY}; font-size: 11px;">
                No audit entries recorded yet.
            </div>
            """,
            unsafe_allow_html=True
        )
        return

    # Build HTML Table
    rows_html = []
    # Most recent entries first, limit to 8 to keep dashboard tight on 1080p
    displayed_logs = list(reversed(logs))[:8]

    for entry in displayed_logs:
        timestamp = entry.get("timestamp", "—")
        tool = entry.get("tool", "—")
        target = entry.get("target", "—")
        decision = entry.get("decision", "—")
        risk = entry.get("risk", "LOW")
        details = entry.get("details", "")

        # Format Decision Badge
        if decision == "ALLOWED" or decision == "ALLOW":
            dec_badge = '<span class="soc-badge badge-green">ALLOW</span>'
        elif "DENIED" in decision or "BLOCKED" in decision:
            dec_badge = '<span class="soc-badge badge-red">BLOCKED</span>'
        elif "REQUIRE" in decision:
            dec_badge = '<span class="soc-badge badge-amber">REQUIRE_APPROVAL</span>'
        elif "HUMAN_APPROVED" in decision or "OVERRIDE" in decision:
            dec_badge = '<span class="soc-badge badge-cyan">APPROVED BY HUMAN</span>'
        elif "BYPASS" in decision or "EXPLOIT" in decision:
            dec_badge = '<span class="soc-badge badge-red" style="animation: pulse-red 1.5s infinite;">BYPASS EXPLOIT</span>'
        else:
            dec_badge = f'<span class="soc-badge badge-gray">{decision}</span>'

        # Format Risk Badge
        if risk == "CRITICAL":
            risk_badge = '<span style="color: #ef4444; font-weight: 700;">CRITICAL</span>'
        elif risk == "HIGH":
            risk_badge = '<span style="color: #f87171; font-weight: 600;">HIGH</span>'
        elif risk == "MEDIUM":
            risk_badge = '<span style="color: #fbbf24; font-weight: 600;">MEDIUM</span>'
        else:
            risk_badge = '<span style="color: #34d399;">LOW</span>'

        rows_html.append(f"""
            <tr>
                <td style="color: #94a3b8; font-family: 'JetBrains Mono', monospace;">{timestamp}</td>
                <td style="color: #38bdf8; font-weight: 600;">{tool}</td>
                <td style="color: {'#fca5a5' if 'attacker' in target or 'payroll' in target else '#e2e8f0'};">{target}</td>
                <td>{dec_badge}</td>
                <td>{risk_badge}</td>
                <td style="color: #cbd5e1; font-size: 10px; max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="{details}">{details}</td>
            </tr>
        """)

    table_content = "".join(rows_html)

    st.markdown(
        f"""
        <div style="background: #111827; border: 1px solid #263449; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.4);">
            <table class="audit-table">
                <thead>
                    <tr>
                        <th style="width: 12%;">TIMESTAMP</th>
                        <th style="width: 16%;">TOOL</th>
                        <th style="width: 20%;">TARGET / DESTINATION</th>
                        <th style="width: 18%;">DECISION</th>
                        <th style="width: 12%;">RISK</th>
                        <th style="width: 22%;">FORENSIC DETAILS</th>
                    </tr>
                </thead>
                <tbody>
                    {table_content}
                </tbody>
            </table>
        </div>
        """,
        unsafe_allow_html=True
    )
