"""
AgentShield - Live Agent Activity Stream Component
Renders the terminal-style telemetry window with real-time color-coded events.
"""

import streamlit as st
from config import COLOR_CYAN, COLOR_GREEN, COLOR_RED, COLOR_AMBER, COLOR_GRAY


def render_activity_stream():
    """
    Renders the live terminal activity stream container.
    """
    logs = st.session_state.get("activity_logs", [])

    st.markdown(
        f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 10px; margin-bottom: 6px;">
            <div style="font-size: 12px; font-weight: 700; color: #F8FAFC; letter-spacing: 0.8px; display: flex; align-items: center; gap: 8px;">
                <span style="color: {COLOR_CYAN}; font-family: 'JetBrains Mono', monospace;">&gt;_</span> LIVE AGENT ACTIVITY STREAM
            </div>
            <div style="font-size: 9px; font-family: 'JetBrains Mono', monospace; color: #64748B; display: flex; align-items: center; gap: 6px;">
                <span class="pulse-dot dot-green" style="width: 6px; height: 6px;"></span> BUFFER: {len(logs)} EVENTS
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Build Terminal HTML
    lines_html = []
    # Display the most recent events (limit to last 25 for fast rendering)
    recent_logs = logs[-25:] if len(logs) > 25 else logs

    for item in recent_logs:
        t = item.get("time", "")
        text = item.get("text", "")
        log_type = item.get("type", "gray")

        # Color mapping
        if log_type == "red" or "CRITICAL" in text or "ALERT" in text or "EXPLOIT" in text or "VIOLATION" in text:
            color_class = "term-red"
        elif log_type == "green" or "COMPLETED" in text or "CLEAN" in text or "ALLOWED" in text or "passed" in text.lower():
            color_class = "term-green"
        elif log_type == "amber" or "WARNING" in text or "HOLD" in text or "REQUIRE" in text:
            color_class = "term-amber"
        elif log_type == "cyan" or "SYSTEM" in text or "GATEWAY" in text or "AGENT" in text:
            color_class = "term-cyan"
        else:
            color_class = "term-gray"

        time_str = f'<span class="term-time">[{t}]</span>' if t else ""
        lines_html.append(f'<div class="terminal-line">{time_str}<span class="{color_class}">{text}</span></div>')

    content = "".join(lines_html) if lines_html else '<div class="terminal-line term-gray">// Terminal idle. Select a scenario above and click EXECUTE SCENARIO.</div>'

    st.markdown(
        f"""
        <div class="terminal-window" id="soc-terminal">
            {content}
        </div>
        """,
        unsafe_allow_html=True
    )
