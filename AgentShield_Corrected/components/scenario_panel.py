"""
AgentShield - Scenario Panel Component
Allows selecting and launching the 3 core cybersecurity demonstration scenarios.
"""

import streamlit as st
from config import COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_AMBER, COLOR_GRAY
from data.mock_data import SCENARIOS


def render_scenario_panel(on_execute_callback=None):
    """
    Renders the Agent Execution Lab scenario selector and trigger.
    """
    selected_id = st.session_state.get("selected_scenario", "clean")
    shield_enabled = st.session_state.get("shield_enabled", True)

    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <div style="font-size: 13px; font-weight: 700; color: #F8FAFC; letter-spacing: 0.8px; display: flex; align-items: center; gap: 8px;">
                <span style="color: {COLOR_CYAN};">⚡</span> AGENT EXECUTION LAB
            </div>
            <div style="font-size: 10px; font-family: 'JetBrains Mono', monospace; color: {COLOR_GRAY};">
                TARGET RUNTIME: GEMINI 2.0 FLASH
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 3 Scenario Selection Buttons
    btn_col1, btn_col2, btn_col3 = st.columns(3)

    with btn_col1:
        is_active = (selected_id == "clean")
        btn_label = "01 CLEAN" if not is_active else "▶ 01 CLEAN"
        if st.button(btn_label, key="btn_scen_clean", use_container_width=True):
            st.session_state["selected_scenario"] = "clean"
            st.session_state["approval_status_msg"] = None
            st.rerun()

    with btn_col2:
        is_active = (selected_id == "injection")
        btn_label = "02 INJECTION" if not is_active else "▶ 02 INJECTION"
        if st.button(btn_label, key="btn_scen_injection", use_container_width=True):
            st.session_state["selected_scenario"] = "injection"
            st.session_state["approval_status_msg"] = None
            st.rerun()

    with btn_col3:
        is_active = (selected_id == "rbac")
        btn_label = "03 RBAC" if not is_active else "▶ 03 RBAC"
        if st.button(btn_label, key="btn_scen_rbac", use_container_width=True):
            st.session_state["selected_scenario"] = "rbac"
            st.session_state["approval_status_msg"] = None
            st.rerun()

    # Active Scenario Information Card
    scenario = SCENARIOS.get(selected_id, SCENARIOS["clean"])

    # Dynamic badge based on shield status
    if selected_id == "clean":
        badge_html = f'<span class="soc-badge badge-green">EXPECTED: ALLOWED</span>'
        card_class = "soc-card-green"
    elif selected_id == "injection":
        if shield_enabled:
            badge_html = f'<span class="soc-badge badge-amber">SHIELD ON: INTERCEPT & HOLD</span>'
            card_class = "soc-card-amber"
        else:
            badge_html = f'<span class="soc-badge badge-red">SHIELD OFF: EXPLOIT SUCCEEDS</span>'
            card_class = "soc-card-red"
    else:  # rbac
        badge_html = f'<span class="soc-badge badge-red">EXPECTED: RBAC VIOLATION (403)</span>'
        card_class = "soc-card-red"

    st.markdown(
        f"""
        <div class="soc-card {card_class}" style="margin-top: 6px; margin-bottom: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                <div>
                    <div style="font-size: 13px; font-weight: 700; color: #F8FAFC;">
                        {scenario['title']}
                    </div>
                    <div style="font-size: 11px; color: {COLOR_CYAN}; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">
                        Task: "{scenario['task']}"
                    </div>
                </div>
                {badge_html}
            </div>

            <p style="font-size: 11px; color: {COLOR_GRAY}; line-height: 1.4; margin: 4px 0 8px 0;">
                {scenario['description']}
            </p>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; background: #080D18; border: 1px solid #1e293b; border-radius: 6px; padding: 6px 10px; font-size: 10px; font-family: 'JetBrains Mono', monospace;">
                <div>
                    <span style="color: #64748B;">TARGET:</span>
                    <span style="color: #F8FAFC; margin-left: 4px;">{scenario['target']}</span>
                </div>
                <div>
                    <span style="color: #64748B;">TOOL CALL:</span>
                    <span style="color: #F8FAFC; margin-left: 4px;">{scenario['tool']}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Big Execution Trigger Button
    st.markdown('<div class="execute-btn">', unsafe_allow_html=True)
    if st.button("⚡ EXECUTE SCENARIO", key="btn_execute_scenario", use_container_width=True):
        if on_execute_callback:
            on_execute_callback(selected_id)
    st.markdown('</div>', unsafe_allow_html=True)
