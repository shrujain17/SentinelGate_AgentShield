"""
AgentShield - Human-in-the-Loop Approval Panel Component
Provides supervisor review, payload inspection, and 1-click Approve/Deny triage.
"""

import streamlit as st
from config import COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_AMBER, COLOR_GRAY


def render_approval_panel(on_resolve_callback=None):
    """
    Renders the Human-in-the-Loop authorization card and triage buttons.
    """
    pending = st.session_state.get("pending_approval", None)
    status_msg = st.session_state.get("approval_status_msg", None)

    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 10px; margin-bottom: 6px;">
            <div style="font-size: 13px; font-weight: 700; color: #F8FAFC; letter-spacing: 0.8px; display: flex; align-items: center; gap: 8px;">
                <span style="color: {COLOR_AMBER};">👤</span> HUMAN-IN-THE-LOOP APPROVAL CENTRE
            </div>
            <div style="font-size: 10px; font-family: 'JetBrains Mono', monospace; color: {COLOR_GRAY};">
                SUPERVISOR TRIAGE QUEUE
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # CASE 1: AN ACTION JUST RESOLVED
    if status_msg:
        is_neutralized = "THREAT NEUTRALIZED" in status_msg or "BLOCKED" in status_msg
        banner_bg = "rgba(16, 185, 129, 0.15)" if is_neutralized else "rgba(59, 130, 246, 0.15)"
        border_col = COLOR_GREEN if is_neutralized else "#3b82f6"
        icon = "🛡️" if is_neutralized else "✓"
        title = "THREAT NEUTRALIZED" if is_neutralized else "APPROVED BY HUMAN"

        st.markdown(
            f"""
            <div style="background: {banner_bg}; border: 1px solid {border_col}; border-radius: 8px; padding: 12px 14px; margin-bottom: 10px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 18px;">{icon}</span>
                    <div>
                        <div style="font-size: 13px; font-weight: 800; color: #F8FAFC; letter-spacing: 0.8px;">
                            {title}
                        </div>
                        <div style="font-size: 11px; color: #cbd5e1; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">
                            {status_msg}
                        </div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # CASE 2: ACTIVE PENDING APPROVAL REQUIRING HUMAN ACTION
    if pending:
        tool = pending.get("tool", "send_email()")
        args = pending.get("args", {})
        risk_score = pending.get("risk_score", 0.94)
        reason = pending.get("reason", "Sensitive data taint detected in outbound payload.")
        staged_at = pending.get("staged_at", "")

        to_dest = args.get("to", args.get("recipient", "attacker@webhook.site"))
        subject = args.get("subject", "Confidential Data")

        st.markdown(
            f"""
            <div class="soc-card soc-card-amber" style="margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span class="soc-badge badge-amber" style="font-size: 11px; padding: 3px 8px;">
                            ACTION REQUIRED – HUMAN APPROVAL
                        </span>
                        <span style="font-size: 10px; color: #64748B; font-family: 'JetBrains Mono', monospace;">REQUEST #104</span>
                    </div>
                    <div style="font-size: 10px; color: {COLOR_AMBER}; font-family: 'JetBrains Mono', monospace; font-weight: 700;">
                        RISK: {risk_score:.2f} (CRITICAL)
                    </div>
                </div>

                <div style="background: #080D18; border: 1px solid #1e293b; border-radius: 6px; padding: 8px 10px; margin-bottom: 8px; font-family: 'JetBrains Mono', monospace; font-size: 11px;">
                    <div style="margin-bottom: 4px;">
                        <span style="color: #64748B;">TOOL:</span>
                        <span style="color: #38bdf8; font-weight: 600; margin-left: 6px;">{tool}</span>
                    </div>
                    <div style="margin-bottom: 4px;">
                        <span style="color: #64748B;">ARGUMENTS:</span>
                        <span style="color: #f87171; margin-left: 6px;">to = {to_dest}</span>,
                        <span style="color: #F8FAFC; margin-left: 4px;">subject = "{subject}"</span>
                    </div>
                    <div>
                        <span style="color: #64748B;">STAGED AT:</span>
                        <span style="color: #94A3B8; margin-left: 6px;">{staged_at}</span>
                    </div>
                </div>

                <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4; margin-bottom: 10px;">
                    <strong style="color: {COLOR_AMBER};">Detection Reason:</strong> {reason}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Action Buttons: APPROVE ONCE vs DENY ACTION
        col_btn_approve, col_btn_deny = st.columns(2)

        with col_btn_approve:
            st.markdown('<div class="btn-approve">', unsafe_allow_html=True)
            if st.button("✓ APPROVE ONCE", key="btn_hitl_approve", use_container_width=True, help="Authorize tool execution with supervisor sign-off"):
                if on_resolve_callback:
                    on_resolve_callback(pending["id"], "APPROVE")
            st.markdown('</div>', unsafe_allow_html=True)

        with col_btn_deny:
            st.markdown('<div class="btn-deny">', unsafe_allow_html=True)
            if st.button("🛑 DENY ACTION", key="btn_hitl_deny", use_container_width=True, help="Block tool execution and neutralize threat"):
                if on_resolve_callback:
                    on_resolve_callback(pending["id"], "DENY")
            st.markdown('</div>', unsafe_allow_html=True)

    # CASE 3: NO APPROVAL PENDING & NO RECENT RESOLUTION
    elif not status_msg:
        st.markdown(
            f"""
            <div class="soc-card" style="margin-bottom: 8px; text-align: center; padding: 22px 14px;">
                <div style="font-size: 18px; margin-bottom: 4px; opacity: 0.6;">✓</div>
                <div style="font-size: 12px; font-weight: 600; color: #94A3B8;">
                    Approval Queue Clear
                </div>
                <div style="font-size: 10px; color: #64748B; font-family: 'JetBrains Mono', monospace; margin-top: 2px;">
                    No sensitive agent actions currently paused for supervisor sign-off.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
