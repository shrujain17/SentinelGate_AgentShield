"""
AgentShield - Top Header Component
Renders the SOC brand identity, real-time telemetry counters, shield toggle, and demo controls.
"""

import streamlit as st
from config import COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_AMBER, COLOR_GRAY


def render_header(on_reset_callback=None):
    """
    Renders the unified top navigation and telemetry bar.
    """
    # 5-Column Header Layout
    col_brand, col_status, col_metrics, col_toggle, col_reset = st.columns([2.8, 1.6, 2.8, 2.0, 1.2])

    with col_brand:
        st.markdown(
            f"""
            <div style="display: flex; align-items: center; gap: 12px; padding: 4px 0;">
                <div style="
                    width: 38px; height: 38px; border-radius: 8px;
                    background: rgba(0, 242, 254, 0.12);
                    border: 1px solid rgba(0, 242, 254, 0.4);
                    display: flex; align-items: center; justify-content: center;
                    font-size: 20px; box-shadow: 0 0 12px rgba(0, 242, 254, 0.25);
                ">
                    🛡️
                </div>
                <div>
                    <div style="font-size: 18px; font-weight: 800; letter-spacing: 1.5px; color: #F8FAFC; line-height: 1.1;">
                        AGENT<span style="color: {COLOR_CYAN};">SHIELD</span>
                    </div>
                    <div style="font-size: 10px; font-weight: 600; letter-spacing: 0.8px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace;">
                        AI AGENT SECURITY COMMAND CENTER
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_status:
        shield_state = st.session_state.get("shield_enabled", True)
        status_text = "ACTIVE" if shield_state else "BYPASS"
        dot_class = "dot-green" if shield_state else "dot-red"
        badge_class = "badge-green" if shield_state else "badge-red"

        st.markdown(
            f"""
            <div style="background: #111827; border: 1px solid #263449; border-radius: 8px; padding: 6px 10px; display: flex; flex-direction: column; justify-content: center; height: 46px;">
                <div style="font-size: 9px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace; text-transform: uppercase;">
                    System Status
                </div>
                <div style="display: flex; align-items: center; gap: 6px; margin-top: 2px;">
                    <span class="pulse-dot {dot_class}"></span>
                    <span class="soc-badge {badge_class}" style="font-size: 10px;">{status_text}</span>
                    <span style="font-size: 9px; color: #64748B; font-family: 'JetBrains Mono', monospace;">SANDBOX</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_metrics:
        blocked = st.session_state.get("blocked_count", 14)
        pending = st.session_state.get("pending_count", 1)

        st.markdown(
            f"""
            <div style="display: flex; gap: 8px;">
                <div style="flex: 1; background: #111827; border: 1px solid #263449; border-radius: 8px; padding: 6px 10px; height: 46px;">
                    <div style="font-size: 9px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace;">BLOCKED THREATS</div>
                    <div style="font-size: 16px; font-weight: 800; color: {COLOR_RED}; font-family: 'JetBrains Mono', monospace; line-height: 1.2;">
                        {blocked} <span style="font-size: 10px; font-weight: 400; color: #f87171;">EVENTS</span>
                    </div>
                </div>
                <div style="flex: 1; background: #111827; border: 1px solid #263449; border-radius: 8px; padding: 6px 10px; height: 46px;">
                    <div style="font-size: 9px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace;">PENDING APPROVALS</div>
                    <div style="font-size: 16px; font-weight: 800; color: {COLOR_AMBER}; font-family: 'JetBrains Mono', monospace; line-height: 1.2;">
                        {pending} <span style="font-size: 10px; font-weight: 400; color: #fbbf24;">HOLD</span>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_toggle:
        # Shield Toggle Control with immediate session state sync
        current_shield = st.session_state.get("shield_enabled", True)
        st.markdown(
            f"""
            <div style="font-size: 9px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace; margin-bottom: 2px;">
                SHIELD PROTECTION TOGGLE
            </div>
            """,
            unsafe_allow_html=True
        )
        toggle_val = st.toggle(
            "ENABLED" if current_shield else "BYPASS",
            value=current_shield,
            key="shield_toggle_widget",
            help="Toggle between full Zero-Trust security gateway protection and bypassed unmediated execution."
        )

        if toggle_val != current_shield:
            st.session_state["shield_enabled"] = toggle_val
            # Log toggle change to terminal
            t_now = "just now"
            if toggle_val:
                st.session_state["activity_logs"].append(
                    {"time": t_now, "type": "green", "text": "[GATEWAY] Security Shield re-enabled. All policy checks active."}
                )
            else:
                st.session_state["activity_logs"].append(
                    {"time": t_now, "type": "red", "text": "[ALERT] Shield protection BYPASSED. Gateway interception disabled!"}
                )
            st.rerun()

    with col_reset:
        st.markdown(
            f"""
            <div style="font-size: 9px; color: {COLOR_GRAY}; font-family: 'JetBrains Mono', monospace; margin-bottom: 2px;">
                CONTROLS
            </div>
            """,
            unsafe_allow_html=True
        )
        if st.button("↺ RESET", use_container_width=True, help="Reset demo to initial pristine state"):
            if on_reset_callback:
                on_reset_callback()
            st.rerun()

    # Subtle divider
    st.markdown(
        f"""
        <div style="height: 1px; background: linear-gradient(90deg, {COLOR_CYAN} 0%, #263449 50%, rgba(38, 52, 73, 0) 100%); margin: 8px 0 14px 0; opacity: 0.7;"></div>
        """,
        unsafe_allow_html=True
    )
