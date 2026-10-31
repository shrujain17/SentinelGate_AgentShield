"""
AgentShield - Configuration & Styling System
Provides color palettes, typography, layout constants, and custom SOC CSS.
"""

# Color Palette Constants
COLOR_BG = "#080D18"
COLOR_CARD = "#111827"
COLOR_BORDER = "#263449"
COLOR_CYAN = "#00F2FE"       # Primary Accent / Electric Cyan
COLOR_GREEN = "#10B981"      # Security Enabled / Normal
COLOR_RED = "#EF4444"        # Threat Detected / Exploit
COLOR_AMBER = "#F59E0B"      # Pending Approval / Warning
COLOR_GRAY = "#94A3B8"       # Secondary Text
COLOR_MUTED = "#64748B"      # Dark Muted Text

# Streamlit Custom CSS for SOC Experience
SOC_CSS = """
<style>
/* Import Clean Monospace & Tech Sans Fonts */
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700;800&display=swap');

/* Hide Default Streamlit Elements */
#MainMenu, header, footer {
    visibility: hidden !important;
    height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
}

[data-testid="stDecoration"] {
    display: none !important;
}

/* Base Body & Container Adjustments */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #080D18 !important;
    color: #F8FAFC !important;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    overflow-x: hidden !important;
}

.main .block-container {
    max-width: 98% !important;
    padding-top: 0.8rem !important;
    padding-bottom: 0.8rem !important;
    padding-left: 1.2rem !important;
    padding-right: 1.2rem !important;
}

/* Glassmorphism SOC Cards */
.soc-card {
    background: #111827;
    border: 1px solid #263449;
    border-radius: 10px;
    padding: 14px 16px;
    margin-bottom: 12px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.45);
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.soc-card:hover {
    border-color: #3b506f;
}

.soc-card-cyan {
    border-left: 3px solid #00F2FE !important;
}

.soc-card-green {
    border-left: 3px solid #10B981 !important;
    box-shadow: 0 0 15px rgba(16, 185, 129, 0.12) !important;
}

.soc-card-red {
    border-left: 3px solid #EF4444 !important;
    box-shadow: 0 0 20px rgba(239, 68, 68, 0.2) !important;
}

.soc-card-amber {
    border-left: 3px solid #F59E0B !important;
    box-shadow: 0 0 18px rgba(245, 158, 11, 0.18) !important;
}

/* Monospace Terminal Logs */
.terminal-window {
    background-color: #050811;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    line-height: 1.5;
    height: 235px;
    overflow-y: auto;
    box-shadow: inset 0 2px 8px rgba(0,0,0,0.8);
}

.terminal-line {
    margin-bottom: 3px;
    word-break: break-word;
}

.term-cyan { color: #00F2FE; }
.term-green { color: #10B981; }
.term-amber { color: #F59E0B; }
.term-red { color: #EF4444; font-weight: 600; }
.term-gray { color: #94A3B8; }
.term-time { color: #64748B; margin-right: 6px; }

/* Custom Scrollbar for Terminal */
.terminal-window::-webkit-scrollbar {
    width: 5px;
}
.terminal-window::-webkit-scrollbar-thumb {
    background: #263449;
    border-radius: 4px;
}
.terminal-window::-webkit-scrollbar-track {
    background: #080D18;
}

/* Badges & Pills */
.soc-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}

.badge-green {
    background: rgba(16, 185, 129, 0.15);
    color: #10B981;
    border: 1px solid rgba(16, 185, 129, 0.4);
}

.badge-red {
    background: rgba(239, 68, 68, 0.18);
    color: #EF4444;
    border: 1px solid rgba(239, 68, 68, 0.5);
    animation: pulse-red 2s infinite;
}

.badge-amber {
    background: rgba(245, 158, 11, 0.18);
    color: #F59E0B;
    border: 1px solid rgba(245, 158, 11, 0.5);
    animation: pulse-amber 2s infinite;
}

.badge-cyan {
    background: rgba(0, 242, 254, 0.12);
    color: #00F2FE;
    border: 1px solid rgba(0, 242, 254, 0.35);
}

.badge-gray {
    background: rgba(148, 163, 184, 0.1);
    color: #94A3B8;
    border: 1px solid #334155;
}

@keyframes pulse-red {
    0%, 100% { box-shadow: 0 0 5px rgba(239, 68, 68, 0.3); }
    50% { box-shadow: 0 0 15px rgba(239, 68, 68, 0.7); }
}

@keyframes pulse-amber {
    0%, 100% { box-shadow: 0 0 5px rgba(245, 158, 11, 0.3); }
    50% { box-shadow: 0 0 15px rgba(245, 158, 11, 0.7); }
}

/* Pulsing Status Dot */
.pulse-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
    margin-right: 6px;
}
.dot-green {
    background-color: #10B981;
    box-shadow: 0 0 8px #10B981;
}
.dot-red {
    background-color: #EF4444;
    box-shadow: 0 0 8px #EF4444;
}

/* Big Alert Callouts */
.alert-banner-exploit {
    background: linear-gradient(135deg, rgba(239, 68, 68, 0.22) 0%, rgba(17, 24, 39, 0.95) 100%);
    border: 1px solid #EF4444;
    border-radius: 8px;
    padding: 12px 16px;
    box-shadow: 0 0 25px rgba(239, 68, 68, 0.3);
    margin-bottom: 10px;
}

.alert-banner-protected {
    background: linear-gradient(135deg, rgba(16, 185, 129, 0.18) 0%, rgba(17, 24, 39, 0.95) 100%);
    border: 1px solid #10B981;
    border-radius: 8px;
    padding: 12px 16px;
    box-shadow: 0 0 20px rgba(16, 185, 129, 0.25);
    margin-bottom: 10px;
}

/* Custom Table / Audit Log Formatting */
.audit-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 11px;
    font-family: 'JetBrains Mono', monospace;
}

.audit-table th {
    background: #0b1120;
    color: #94A3B8;
    text-align: left;
    padding: 7px 10px;
    border-bottom: 1px solid #263449;
    font-weight: 600;
}

.audit-table td {
    padding: 6px 10px;
    border-bottom: 1px solid #1a2333;
    color: #e2e8f0;
}

.audit-table tr:hover {
    background: #162032;
}

/* Custom Streamlit Button Styling */
div.stButton > button {
    background-color: #1a2436 !important;
    color: #F8FAFC !important;
    border: 1px solid #263449 !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    font-size: 12px !important;
    padding: 0.4rem 0.8rem !important;
    transition: all 0.2s ease !important;
}

div.stButton > button:hover {
    border-color: #00F2FE !important;
    box-shadow: 0 0 10px rgba(0, 242, 254, 0.25) !important;
    color: #00F2FE !important;
}

div.stButton > button:active {
    transform: scale(0.98);
}

/* Primary Execution Button */
.execute-btn div.stButton > button {
    background: linear-gradient(90deg, #00B4D8 0%, #00F2FE 100%) !important;
    color: #080D18 !important;
    border: none !important;
    font-weight: 700 !important;
    letter-spacing: 0.5px !important;
    box-shadow: 0 0 15px rgba(0, 242, 254, 0.4) !important;
}

.execute-btn div.stButton > button:hover {
    background: linear-gradient(90deg, #00F2FE 0%, #00B4D8 100%) !important;
    box-shadow: 0 0 25px rgba(0, 242, 254, 0.6) !important;
    color: #050811 !important;
}

/* Approve Button */
.btn-approve div.stButton > button {
    background: #065f46 !important;
    border: 1px solid #10B981 !important;
    color: #34d399 !important;
}
.btn-approve div.stButton > button:hover {
    background: #047857 !important;
    box-shadow: 0 0 12px rgba(16, 185, 129, 0.4) !important;
    color: #ffffff !important;
}

/* Deny Button */
.btn-deny div.stButton > button {
    background: #7f1d1d !important;
    border: 1px solid #EF4444 !important;
    color: #f87171 !important;
}
.btn-deny div.stButton > button:hover {
    background: #991b1b !important;
    box-shadow: 0 0 12px rgba(239, 68, 68, 0.4) !important;
    color: #ffffff !important;
}
</style>
"""