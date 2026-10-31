"""
AgentShield – AI Agent Security Command Center
A high-performance, dark-themed SOC dashboard built with Python and Streamlit.
"""

import streamlit as st
from config import SOC_CSS
from data.mock_data import INITIAL_ACTIVITY_LOGS, get_initial_audit_logs, SCENARIOS
from services.api import AgentShieldService
from components.header import render_header
from components.scenario_panel import render_scenario_panel
from components.activity_stream import render_activity_stream
from components.firewall import render_firewall
from components.approval_panel import render_approval_panel
from components.audit_log import render_audit_log

# ---------------------------------------------------------------------------
# 1. Page Configuration & Custom CSS Injection
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="AgentShield SOC | AI Agent Security Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Inject custom SOC CSS into the Streamlit DOM
st.markdown(SOC_CSS, unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# 2. Session State Initialization
# ---------------------------------------------------------------------------
if "initialized" not in st.session_state:
    st.session_state["initialized"] = True
    st.session_state["shield_enabled"] = True
    st.session_state["selected_scenario"] = "clean"
    st.session_state["blocked_count"] = 14
    st.session_state["pending_count"] = 1
    st.session_state["activity_logs"] = list(INITIAL_ACTIVITY_LOGS)
    st.session_state["audit_logs"] = get_initial_audit_logs()
    st.session_state["current_firewall"] = {
        "tool": "read_document()",
        "destination": "internal://knowledge-base/docs",
        "risk_score": 0.04,
        "risk_classification": "LOW",
        "decision": "ALLOWED",
        "reason": "Policy check passed: Read-only access to authorized public internal documents.",
        "status_badge": "ALLOWED",
        "badge_color": "green",
        "is_exploit": False
    }
    st.session_state["pending_approval"] = None
    st.session_state["approval_status_msg"] = None

# Service instance
service = AgentShieldService()


# ---------------------------------------------------------------------------
# 3. Action Callbacks
# ---------------------------------------------------------------------------
def handle_execute_scenario(scenario_id: str):
    """Executes the selected scenario through the security gateway service."""
    shield_on = st.session_state.get("shield_enabled", True)
    result = service.run_scenario(scenario_id, shield_on)

    if not result:
        return

    # 1. Update activity stream logs
    new_events = result.get("events", [])
    st.session_state["activity_logs"].extend(new_events)

    # 2. Update real-time policy engine data
    st.session_state["current_firewall"] = result.get("firewall", {})

    # 3. Handle pending approvals or exploit outcomes
    pending = result.get("pending_approval")
    outcome = result.get("outcome")

    if pending:
        st.session_state["pending_approval"] = pending
        st.session_state["pending_count"] = st.session_state.get("pending_count", 0) + 1
        st.session_state["approval_status_msg"] = None
    elif outcome == "EXPLOIT_SUCCEEDED":
        st.session_state["pending_approval"] = None
        st.session_state["approval_status_msg"] = None
    elif outcome == "PERMISSION_VIOLATION":
        st.session_state["pending_approval"] = None
        st.session_state["blocked_count"] = st.session_state.get("blocked_count", 14) + 1
        st.session_state["approval_status_msg"] = None
    else:  # Clean completed
        st.session_state["pending_approval"] = None
        st.session_state["approval_status_msg"] = None

    # 4. Append to persistent audit logs
    audit_entry = result.get("audit_entry")
    if audit_entry:
        st.session_state["audit_logs"].append(audit_entry)

    st.rerun()


def handle_resolve_approval(approval_id: int, action: str):
    """Resolves a pending human-in-the-loop approval request."""
    result = service.resolve_approval(approval_id, action)

    # Decrement pending count
    cur_pending = st.session_state.get("pending_count", 1)
    st.session_state["pending_count"] = max(0, cur_pending - 1)

    # Terminal log announcement
    t_now = result["audit_entry"]["timestamp"]
    if action == "APPROVE":
        st.session_state["activity_logs"].append({
            "time": t_now,
            "type": "cyan",
            "text": "[HUMAN-OVERRIDE] Action authorized by supervisor. Tool executed with override."
        })
        st.session_state["approval_status_msg"] = "APPROVED BY HUMAN — Tool executed with supervisor sign-off."
    else:
        st.session_state["activity_logs"].append({
            "time": t_now,
            "type": "green",
            "text": "[HUMAN-TRIAGE] Action rejected by supervisor. Threat neutralized. Outbound socket terminated."
        })
        st.session_state["blocked_count"] = st.session_state.get("blocked_count", 14) + 1
        st.session_state["approval_status_msg"] = "THREAT NEUTRALIZED — Outbound socket purged, no action executed."

    # Clear pending approval
    st.session_state["pending_approval"] = None

    # Append audit log
    st.session_state["audit_logs"].append(result["audit_entry"])

    st.rerun()


def handle_reset_demo():
    """Restores the SOC dashboard to its initial pristine baseline."""
    st.session_state["shield_enabled"] = True
    st.session_state["selected_scenario"] = "clean"
    st.session_state["blocked_count"] = 14
    st.session_state["pending_count"] = 1
    st.session_state["activity_logs"] = list(INITIAL_ACTIVITY_LOGS)
    st.session_state["audit_logs"] = get_initial_audit_logs()
    st.session_state["current_firewall"] = {
        "tool": "read_document()",
        "destination": "internal://knowledge-base/docs",
        "risk_score": 0.04,
        "risk_classification": "LOW",
        "decision": "ALLOWED",
        "reason": "Policy check passed: Read-only access to authorized public internal documents.",
        "status_badge": "ALLOWED",
        "badge_color": "green",
        "is_exploit": False
    }
    st.session_state["pending_approval"] = None
    st.session_state["approval_status_msg"] = None


# ---------------------------------------------------------------------------
# 4. Master SOC Layout (1920x1080 Desktop Viewport Optimized)
# ---------------------------------------------------------------------------

# Top Header & Navigation
render_header(on_reset_callback=handle_reset_demo)

# Main Two-Column Layout
left_column, right_column = st.columns([1, 1], gap="medium")

with left_column:
    render_scenario_panel(on_execute_callback=handle_execute_scenario)
    render_activity_stream()

with right_column:
    render_firewall()
    render_approval_panel(on_resolve_callback=handle_resolve_approval)

# Bottom Full-Width Section: Live Security Audit Log
render_audit_log()
