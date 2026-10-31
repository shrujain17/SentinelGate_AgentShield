"""
AgentShield - Real-Time Security Firewall & Policy Engine Component
Displays live risk evaluation, destination telemetry, and high-impact attack-vs-defense banners.
"""

import streamlit as st
from config import COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_AMBER, COLOR_GRAY


def render_firewall():
    """
    Renders the Real-Time Security Firewall card and Shield ON/OFF alert banners.
    """
    firewall_data = st.session_state.get("current_firewall", {})
    shield_enabled = st.session_state.get("shield_enabled", True)
    selected_scenario = st.session_state.get("selected_scenario", "clean")

    # -----------------------------------------------------------------------
    # 1. SHIELD ON VS BYPASS HIGH-IMPACT ALERT BANNERS
    # -----------------------------------------------------------------------
    is_exploit = firewall_data.get("is_exploit", False)
    decision = firewall_data.get("decision", "")

    if is_exploit or (selected_scenario == "injection" and not shield_enabled and decision):
        st.markdown(
            f"""
            <div class="alert-banner-exploit">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 24px;">⚠️</span>
                        <div>
                            <div style="font-size: 15px; font-weight: 800; color: #EF4444; letter-spacing: 1px;">
                                EXPLOIT SUCCEEDED — SECRETS EXFILTRATED
                            </div>
                            <div style="font-size: 11px; color: #fca5a5; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">
                                SECURITY STATUS: <strong style="color: #ffffff; background: #991b1b; padding: 1px 6px; border-radius: 4px;">UNPROTECTED (SHIELD BYPASSED)</strong>
                            </div>
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 10px; color: #fca5a5; font-family: 'JetBrains Mono', monospace;">DESTINATION</div>
                        <div style="font-size: 11px; color: #ffffff; font-weight: 700; font-family: 'JetBrains Mono', monospace;">attacker@webhook.site</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
    elif selected_scenario == "injection" and shield_enabled and decision:
        risk_score = firewall_data.get("risk_score", 0.94)
        st.markdown(
            f"""
            <div class="alert-banner-protected">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 24px;">🛡️</span>
                        <div>
                            <div style="font-size: 15px; font-weight: 800; color: #10B981; letter-spacing: 1px;">
                                THREAT NEUTRALIZED — MALICIOUS TOOL CALL INTERCEPTED
                            </div>
                            <div style="font-size: 11px; color: #a7f3d0; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">
                                SECURITY STATUS: <strong style="color: #ffffff; background: #065f46; padding: 1px 6px; border-radius: 4px;">PROTECTED (ZERO-TRUST ACTIVE)</strong>
                            </div>
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 10px; color: #a7f3d0; font-family: 'JetBrains Mono', monospace;">RISK SCORE</div>
                        <div style="font-size: 14px; color: #ffffff; font-weight: 800; font-family: 'JetBrains Mono', monospace;">{risk_score:.2f} (CRITICAL)</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # -----------------------------------------------------------------------
    # 2. REAL-TIME POLICY ENGINE CARD
    # -----------------------------------------------------------------------
    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <div style="font-size: 13px; font-weight: 700; color: #F8FAFC; letter-spacing: 0.8px; display: flex; align-items: center; gap: 8px;">
                <span style="color: {COLOR_CYAN};">⚙️</span> REAL-TIME POLICY ENGINE
            </div>
            <div style="font-size: 10px; font-family: 'JetBrains Mono', monospace; color: {COLOR_GRAY};">
                INSPECTION GATEWAY: PASS-THROUGH PROXY
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Default fallback data if empty
    tool = firewall_data.get("tool", "Waiting for agent invocation...")
    destination = firewall_data.get("destination", "—")
    risk_score = firewall_data.get("risk_score", 0.0)
    risk_class = firewall_data.get("risk_classification", "IDLE")
    decision_str = firewall_data.get("decision", "STANDBY")
    reason = firewall_data.get("reason", "Gateway listening for incoming tool execution requests from agent.")

    # Determine badge colors
    if risk_class == "CRITICAL":
        risk_badge = '<span class="soc-badge badge-red">CRITICAL RISK</span>'
        score_color = COLOR_RED
    elif risk_class == "HIGH":
        risk_badge = '<span class="soc-badge badge-red">HIGH RISK</span>'
        score_color = COLOR_RED
    elif risk_class == "MEDIUM":
        risk_badge = '<span class="soc-badge badge-amber">MEDIUM RISK</span>'
        score_color = COLOR_AMBER
    elif risk_class == "LOW":
        risk_badge = '<span class="soc-badge badge-green">LOW RISK</span>'
        score_color = COLOR_GREEN
    else:
        risk_badge = '<span class="soc-badge badge-gray">IDLE</span>'
        score_color = COLOR_GRAY

    # Decision Badge
    if "REQUIRE" in decision_str:
        dec_badge = '<span class="soc-badge badge-amber" style="font-size: 11px; padding: 4px 10px;">REQUIRE APPROVAL</span>'
        border_class = "soc-card-amber"
    elif "DENIED" in decision_str or "BLOCKED" in decision_str:
        dec_badge = '<span class="soc-badge badge-red" style="font-size: 11px; padding: 4px 10px;">DENIED</span>'
        border_class = "soc-card-red"
    elif "ALLOWED" in decision_str or "ALLOW" in decision_str:
        dec_badge = '<span class="soc-badge badge-green" style="font-size: 11px; padding: 4px 10px;">ALLOWED</span>'
        border_class = "soc-card-green"
    elif "BYPASS" in decision_str:
        dec_badge = '<span class="soc-badge badge-red" style="font-size: 11px; padding: 4px 10px;">BYPASS (UNPROTECTED)</span>'
        border_class = "soc-card-red"
    else:
        dec_badge = '<span class="soc-badge badge-gray">STANDBY</span>'
        border_class = "soc-card-cyan"

    # Risk Progress Bar Percentage
    bar_pct = min(max(int(risk_score * 100), 4), 100) if risk_score > 0 else 0

    st.markdown(
        f"""
        <div class="soc-card {border_class}" style="margin-bottom: 10px;">
            <div style="display: grid; grid-template-columns: 1.5fr 1fr; gap: 12px; margin-bottom: 10px;">
                <div>
                    <div style="font-size: 10px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace;">REQUESTED TOOL</div>
                    <div style="font-size: 14px; font-weight: 700; color: #F8FAFC; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">
                        {tool}
                    </div>
                    <div style="font-size: 10px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace; margin-top: 6px;">REQUESTED DESTINATION</div>
                    <div style="font-size: 12px; color: {'#f87171' if 'attacker' in destination else '#38bdf8'}; font-family: 'JetBrains Mono', monospace; margin-top: 1px;">
                        {destination}
                    </div>
                </div>

                <div style="text-align: right; display: flex; flex-direction: column; justify-content: space-between; align-items: flex-end;">
                    <div>
                        <div style="font-size: 10px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace; margin-bottom: 2px;">SECURITY DECISION</div>
                        {dec_badge}
                    </div>
                    <div style="margin-top: 6px;">
                        <div style="font-size: 10px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace; margin-bottom: 2px;">CLASSIFICATION</div>
                        {risk_badge}
                    </div>
                </div>
            </div>

            <!-- Risk Score Bar -->
            <div style="background: #080D18; border: 1px solid #1e293b; border-radius: 6px; padding: 8px 10px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; font-size: 10px; font-family: 'JetBrains Mono', monospace; margin-bottom: 4px;">
                    <span style="color: {COLOR_GRAY};">RISK TAINT SCORE</span>
                    <span style="color: {score_color}; font-weight: 700;">{risk_score:.2f} / 1.00</span>
                </div>
                <div style="width: 100%; height: 6px; background: #1e293b; border-radius: 999px; overflow: hidden;">
                    <div style="width: {bar_pct}%; height: 100%; background: {score_color}; transition: width 0.3s ease;"></div>
                </div>
            </div>

            <!-- Detection Reason -->
            <div style="border-top: 1px solid #1e293b; padding-top: 8px;">
                <div style="font-size: 10px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace; margin-bottom: 2px;">DETECTION RATIONALE:</div>
                <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4; font-style: italic;">
                    "{reason}"
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
