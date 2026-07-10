"""
soc_dashboard.py — MY SOC  |  Main entry point & UI orchestrator
Run with:  streamlit run soc_dashboard.py
"""

# ── Bootstrap — MUST be first, before any local imports ───────────────────────
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import time
import threading
from datetime import datetime, timezone

import streamlit as st

import config
from db import database as db
from auth import authenticator as auth
from utils.logger import get_logger

log = get_logger(__name__)

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="MY SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global Design System ───────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=IBM+Plex+Mono:wght@300;400;500&display=swap');

:root {
  --bg-deep:      #0c0f1a;
  --bg-base:      #111827;
  --bg-surface:   #1a2235;
  --bg-raised:    #1f2a40;
  --bg-overlay:   #252f47;
  --teal:         #2dd4bf;
  --teal-dim:     #14b8a6;
  --teal-glow:    rgba(45,212,191,0.08);
  --teal-glow-md: rgba(45,212,191,0.15);
  --coral:        #fb7185;
  --amber:        #fbbf24;
  --emerald:      #34d399;
  --sky:          #38bdf8;
  --sev-critical: #f43f5e;
  --sev-high:     #fb923c;
  --sev-medium:   #fbbf24;
  --sev-low:      #4ade80;
  --sev-info:     #60a5fa;
  --text-primary:   #f1f5f9;
  --text-secondary: #94a3b8;
  --text-muted:     #475569;
  --text-accent:    #2dd4bf;
  --border:       #1e3a5a;
  --border-dim:   #162030;
  --border-glow:  rgba(45,212,191,0.30);
  --font-display: 'DM Serif Display', Georgia, serif;
  --font-body:    'DM Sans', system-ui, sans-serif;
  --font-mono:    'IBM Plex Mono', monospace;
  --radius-sm: 6px; --radius-md: 10px; --radius-lg: 16px;
  --shadow-card: 0 2px 12px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.03);
  --shadow-teal: 0 0 24px rgba(45,212,191,0.07);
  --transition: all 0.2s cubic-bezier(0.4,0,0.2,1);
  --transition-fast: all 0.12s ease;
}

html, body, [class*="css"], [class*="st-"] {
  font-family: var(--font-body) !important;
  background-color: var(--bg-base) !important;
  color: var(--text-primary) !important;
  -webkit-font-smoothing: antialiased;
}

.main .block-container {
  animation: pageIn 0.3s cubic-bezier(0.4,0,0.2,1) both;
  padding-top: 1.5rem !important;
  max-width: 1600px !important;
}
@keyframes pageIn {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* Sidebar */
section[data-testid="stSidebar"] {
  background: var(--bg-deep) !important;
  border-right: 1px solid var(--border-dim) !important;
  box-shadow: 4px 0 32px rgba(0,0,0,0.5) !important;
}
section[data-testid="stSidebar"] > div { padding: 0 !important; }
section[data-testid="stSidebar"] * { font-family: var(--font-body) !important; }

/* Typography */
h1,h2,h3 { font-family: var(--font-display) !important; letter-spacing:-0.02em; }

/* Nav buttons */
.stButton > button {
  width: 100% !important;
  background: transparent !important;
  border: 1px solid transparent !important;
  color: var(--text-secondary) !important;
  font-family: var(--font-body) !important;
  font-size: 0.83rem !important;
  font-weight: 500 !important;
  text-align: left !important;
  padding: 9px 14px !important;
  border-radius: var(--radius-sm) !important;
  transition: var(--transition) !important;
  margin-bottom: 1px !important;
}
.stButton > button:hover {
  background: var(--teal-glow) !important;
  border-color: var(--border-glow) !important;
  color: var(--teal) !important;
  transform: translateX(3px) !important;
}
.nav-active > div > button {
  background: var(--teal-glow-md) !important;
  border-color: rgba(45,212,191,0.4) !important;
  color: var(--teal) !important;
  font-weight: 600 !important;
}
.stButton > button[kind="primary"] {
  background: linear-gradient(135deg, var(--teal) 0%, #0d9488 100%) !important;
  border: none !important;
  color: #0c0f1a !important;
  font-weight: 700 !important;
  box-shadow: 0 2px 12px rgba(45,212,191,0.25) !important;
}
.stButton > button[kind="primary"]:hover {
  transform: translateY(-1px) !important;
  box-shadow: 0 4px 20px rgba(45,212,191,0.4) !important;
}

/* Metrics */
[data-testid="metric-container"] {
  background: var(--bg-surface) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius-md) !important;
  padding: 16px 20px !important;
  box-shadow: var(--shadow-card) !important;
  transition: var(--transition) !important;
}
[data-testid="metric-container"]:hover {
  border-color: var(--border-glow) !important;
  transform: translateY(-1px);
  box-shadow: var(--shadow-card), var(--shadow-teal) !important;
}
[data-testid="stMetricLabel"] {
  color: var(--text-muted) !important;
  font-size: 0.68rem !important;
  font-weight: 600 !important;
  text-transform: uppercase !important;
  letter-spacing: 0.1em !important;
}
[data-testid="stMetricValue"] {
  color: var(--text-primary) !important;
  font-family: var(--font-mono) !important;
}

/* DataFrames */
.stDataFrame {
  border-radius: var(--radius-md) !important;
  overflow: hidden !important;
  border: 1px solid var(--border) !important;
  box-shadow: 0 2px 12px rgba(0,0,0,0.4) !important;
}
.stDataFrame thead th {
  background: var(--bg-raised) !important;
  color: var(--text-muted) !important;
  font-size: 0.67rem !important;
  font-weight: 600 !important;
  text-transform: uppercase !important;
  letter-spacing: 0.1em !important;
  padding: 10px 14px !important;
  border-bottom: 1px solid var(--border) !important;
}
.stDataFrame tbody td {
  font-size: 0.82rem !important;
  font-family: var(--font-mono) !important;
  padding: 8px 14px !important;
  border-bottom: 1px solid var(--border-dim) !important;
}
.stDataFrame tbody tr { transition: var(--transition-fast) !important; }
.stDataFrame tbody tr:hover { background: var(--teal-glow) !important; }

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
  background: transparent !important;
  border-bottom: 1px solid var(--border) !important;
  gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
  font-size: 0.82rem !important;
  font-weight: 500 !important;
  color: var(--text-muted) !important;
  padding: 10px 18px !important;
  border-bottom: 2px solid transparent !important;
  transition: var(--transition) !important;
  font-family: var(--font-body) !important;
}
.stTabs [data-baseweb="tab"]:hover { color: var(--text-primary) !important; background: var(--teal-glow) !important; }
.stTabs [aria-selected="true"] {
  color: var(--teal) !important;
  border-bottom: 2px solid var(--teal) !important;
  background: transparent !important;
  font-weight: 600 !important;
}

/* Expander */
.streamlit-expanderHeader {
  background: var(--bg-surface) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius-sm) !important;
  font-size: 0.85rem !important;
  font-weight: 500 !important;
  color: var(--text-secondary) !important;
  transition: var(--transition) !important;
  font-family: var(--font-body) !important;
}
.streamlit-expanderHeader:hover { border-color: var(--border-glow) !important; color: var(--teal) !important; }
.streamlit-expanderContent {
  background: var(--bg-surface) !important;
  border: 1px solid var(--border) !important;
  border-top: none !important;
  border-radius: 0 0 var(--radius-sm) var(--radius-sm) !important;
}

/* Inputs */
.stTextInput > div > div > input,
.stTextArea > div > textarea,
.stNumberInput > div > div > input {
  background: var(--bg-surface) !important;
  border: 1px solid var(--border) !important;
  color: var(--text-primary) !important;
  font-family: var(--font-body) !important;
  font-size: 0.87rem !important;
  border-radius: var(--radius-sm) !important;
  transition: var(--transition) !important;
  padding: 9px 12px !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > textarea:focus {
  border-color: var(--teal) !important;
  box-shadow: 0 0 0 3px rgba(45,212,191,0.10) !important;
  background: var(--bg-raised) !important;
}
.stTextInput label, .stTextArea label, .stSelectbox label,
.stMultiSelect label, .stNumberInput label, .stSlider label,
.stRadio label, .stCheckbox label, .stDateInput label {
  font-size: 0.72rem !important;
  font-weight: 600 !important;
  color: var(--text-secondary) !important;
  text-transform: uppercase !important;
  letter-spacing: 0.07em !important;
  font-family: var(--font-body) !important;
}
.stSelectbox > div > div {
  background: var(--bg-surface) !important;
  border: 1px solid var(--border) !important;
  border-radius: var(--radius-sm) !important;
  color: var(--text-primary) !important;
  font-size: 0.87rem !important;
  transition: var(--transition) !important;
}

/* Alerts */
.stAlert { border-radius: var(--radius-sm) !important; border: none !important; font-family: var(--font-body) !important; }

/* Scrollbar */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg-deep); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
::-webkit-scrollbar-thumb:hover { background: var(--teal-dim); }

hr { border: none !important; border-top: 1px solid var(--border-dim) !important; margin: 18px 0 !important; }

/* Hide chrome */
#MainMenu, footer, header { visibility: hidden !important; }
.viewerBadge_container__1QSob, [data-testid="stDecoration"] { display: none !important; }

/* ── Custom components ─────── */
.kpi-card {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 20px;
  box-shadow: var(--shadow-card);
  transition: var(--transition);
  position: relative;
  overflow: hidden;
  cursor: default;
}
.kpi-card:hover {
  transform: translateY(-2px);
  border-color: rgba(255,255,255,0.09);
  box-shadow: var(--shadow-card), 0 8px 30px rgba(0,0,0,0.3);
}
.kpi-card .kpi-bg {
  position: absolute; top: -20px; right: -20px;
  width: 80px; height: 80px; border-radius: 50%;
  opacity: 0.06;
}
.kpi-value {
  font-family: var(--font-mono);
  font-size: 2.1rem;
  font-weight: 500;
  line-height: 1;
  margin-bottom: 6px;
  letter-spacing: -0.02em;
}
.kpi-label {
  font-size: 0.68rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--text-muted);
}
.kpi-top-bar {
  position: absolute; top: 0; left: 0; right: 0;
  height: 2px; border-radius: var(--radius-md) var(--radius-md) 0 0;
}

.alert-banner {
  padding: 10px 14px;
  border-radius: var(--radius-sm);
  margin: 4px 0;
  font-size: 0.79rem;
  font-weight: 500;
  display: flex;
  align-items: center;
  gap: 8px;
  animation: slideIn 0.2s ease;
}
@keyframes slideIn {
  from { opacity: 0; transform: translateX(-6px); }
  to   { opacity: 1; transform: translateX(0); }
}

.status-dot-live {
  display: inline-block;
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--emerald);
  animation: pulseLive 2s infinite;
  flex-shrink: 0;
}
.status-dot-dead {
  display: inline-block;
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--text-muted);
  flex-shrink: 0;
}
@keyframes pulseLive {
  0%  { box-shadow: 0 0 0 0 rgba(52,211,153,0.5); }
  70% { box-shadow: 0 0 0 7px rgba(52,211,153,0); }
  100%{ box-shadow: 0 0 0 0 rgba(52,211,153,0); }
}

.sev-pill {
  display: inline-flex;
  align-items: center;
  padding: 2px 9px;
  border-radius: 20px;
  font-size: 0.65rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.sev-CRITICAL { background: rgba(244,63,94,0.15);  color: #f43f5e; border: 1px solid rgba(244,63,94,0.3); }
.sev-HIGH     { background: rgba(251,146,60,0.15);  color: #fb923c; border: 1px solid rgba(251,146,60,0.3); }
.sev-MEDIUM   { background: rgba(251,191,36,0.12);  color: #fbbf24; border: 1px solid rgba(251,191,36,0.3); }
.sev-LOW      { background: rgba(74,222,128,0.10);  color: #4ade80; border: 1px solid rgba(74,222,128,0.25); }
.sev-INFO     { background: rgba(96,165,250,0.10);  color: #60a5fa; border: 1px solid rgba(96,165,250,0.25); }

.section-title {
  font-family: var(--font-display);
  font-size: 1.1rem;
  color: var(--text-primary);
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.section-title::after {
  content: '';
  flex: 1;
  height: 1px;
  background: linear-gradient(to right, var(--border), transparent);
}

.nav-section-label {
  font-size: 0.6rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.18em;
  color: var(--text-muted);
  padding: 0 16px;
  margin: 14px 0 4px;
}

.sla-ok     { color: var(--emerald); font-weight: 600; font-size: 0.72rem; }
.sla-warn   { color: var(--amber);   font-weight: 600; font-size: 0.72rem; }
.sla-breach { color: var(--coral);   font-weight: 700; font-size: 0.72rem; animation: blink 1.4s step-end infinite; }
@keyframes blink { 0%,100%{ opacity:1; } 50%{ opacity:0.3; } }

code, .mono {
  font-family: var(--font-mono) !important;
  font-size: 0.84em;
  background: var(--bg-raised);
  padding: 1px 6px;
  border-radius: 4px;
  color: var(--teal);
  border: 1px solid var(--border-dim);
}
</style>
""", unsafe_allow_html=True)


# ── Lucide-style SVG icon library ─────────────────────────────────────────────
ICONS = {
    "shield":      '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    "target":      '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
    "activity":    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    "globe":       '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
    "bar-chart":   '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/></svg>',
    "search":      '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    "monitor":     '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
    "alert-tri":   '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    "repeat":      '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>',
    "file-text":   '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
    "settings":    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    "network":     '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="6" height="6" rx="1"/><rect x="16" y="2" width="6" height="6" rx="1"/><rect x="9" y="16" width="6" height="6" rx="1"/><path d="M5 8v3a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8"/><line x1="12" y1="13" x2="12" y2="16"/></svg>',
    "terminal":    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>',
    "log":         '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/><line x1="8" y1="9" x2="10" y2="9"/></svg>',
    "wifi":        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 16 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>',
    "lock":        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    "user":        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
    "logout":      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
    "cpu":         '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>',
    "database":    '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
    "eye":         '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    "flame":       '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/></svg>',
}

def icon(name: str, color: str = "currentColor", size: int = 16) -> str:
    svg = ICONS.get(name, ICONS["shield"])
    return svg.replace('width="16"', f'width="{size}"').replace('height="16"', f'height="{size}"').replace('stroke="currentColor"', f'stroke="{color}"')


# ── Backend init ───────────────────────────────────────────────────────────────
@st.cache_resource
def _init_backend():
    db.init_db()
    auth.ensure_default_admin()
    log.info("MY SOC backend initialised")
    return True

_init_backend()

# ── Session defaults ───────────────────────────────────────────────────────────
_DEFAULTS = {
    "authenticated": False, "user": None, "page": "Threat Overview",
    "login_error": "", "sniffer_obj": None, "sniffer_running": False,
    "sniffer_stats": {}, "syslog_obj": None, "syslog_running": False,
    "syslog_stats": {}, "detection_obj": None, "ml_obj": None,
    "ml_stats": {}, "alert_mgr_obj": None,
}
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


def _refresh_engine_stats():
    s = st.session_state.get("sniffer_obj")
    if s and st.session_state.sniffer_running:
        st.session_state.sniffer_stats = s.get_stats()
    sy = st.session_state.get("syslog_obj")
    if sy and st.session_state.syslog_running:
        st.session_state.syslog_stats = sy.get_stats()
    ml = st.session_state.get("ml_obj")
    if ml:
        st.session_state.ml_stats = ml.get_stats()


def _auto_start_demo():
    if st.session_state.sniffer_running:
        return
    try:
        from engine.sniffer import DemoSniffer
        from engine.detection import DetectionEngine
        from engine.ml_anomaly import MLAnomalyDetector
        from alerts.alert_manager import AlertManager
        from utils.helpers import geolocate

        detection = DetectionEngine()
        ml = MLAnomalyDetector()
        alert_mgr = AlertManager()

        detection.add_alert_callback(lambda r: alert_mgr.dispatch({
            "severity": r.severity, "alert_type": r.rule_name,
            "src_ip": r.src_ip, "dst_ip": r.dst_ip,
            "src_port": r.src_port, "dst_port": r.dst_port,
            "protocol": r.protocol, "description": r.description,
            "raw_data": r.raw_data, "threat_score": r.threat_score,
        }))
        ml.add_callback(lambda a: alert_mgr.dispatch({
            "severity": "MEDIUM", "alert_type": "ML_ANOMALY",
            "src_ip": a.src_ip, "dst_ip": a.dst_ip,
            "src_port": a.src_port, "dst_port": a.dst_port,
            "protocol": a.protocol,
            "description": f"ML anomaly detected (score={a.score:.3f})",
            "raw_data": f"length={a.length}", "threat_score": 50,
        }) if a.is_anomaly else None)

        def _on_packet(pkt):
            detection.process(pkt)
            ml.process(pkt)
            try:
                from rules.custom_rules import evaluate as eval_custom
                eval_custom(pkt)
            except Exception:
                pass
            geo = geolocate(pkt.src_ip)
            try:
                db.insert_traffic({
                    "src_ip": pkt.src_ip, "dst_ip": pkt.dst_ip,
                    "src_port": pkt.src_port, "dst_port": pkt.dst_port,
                    "protocol": pkt.protocol, "length": pkt.length,
                    "flags": pkt.flags, "ttl": pkt.ttl,
                    "country": geo.get("country", ""),
                })
            except Exception:
                pass

        sniffer = DemoSniffer()
        sniffer.add_callback(_on_packet)
        sniffer.start()
        st.session_state.update({
            "sniffer_obj": sniffer, "detection_obj": detection,
            "ml_obj": ml, "alert_mgr_obj": alert_mgr,
            "sniffer_running": True,
        })
    except Exception as e:
        log.warning("Auto-start failed: %s", e)


# ── Login ──────────────────────────────────────────────────────────────────────
def _render_login():
    st.markdown("""
    <style>
    .login-wrap {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    </style>
    """, unsafe_allow_html=True)

    _, col, _ = st.columns([1.8, 3, 1.8])
    with col:
        st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)

        # Logo block
        st.markdown(f"""
        <div style="text-align:center; margin-bottom:36px; animation: pageIn 0.4s ease both;">
          <div style="display:inline-flex;align-items:center;justify-content:center;
                      width:56px;height:56px;border-radius:14px;
                      background:linear-gradient(135deg,#1a2235,#1f2a40);
                      border:1px solid #1e3a5a;margin-bottom:16px;
                      box-shadow:0 4px 20px rgba(45,212,191,0.15)">
            <span style="color:#2dd4bf">{icon("shield", "#2dd4bf", 26)}</span>
          </div>
          <div style="font-family:'DM Serif Display',serif;font-size:2.6rem;
                      color:#f1f5f9;letter-spacing:-0.03em;line-height:1">
            My<span style="color:#2dd4bf">SOC</span>
          </div>
          <div style="color:#475569;font-size:0.72rem;letter-spacing:0.25em;
                      text-transform:uppercase;margin-top:8px;font-weight:500">
            Security Operations Center
          </div>
          <div style="width:40px;height:1px;background:linear-gradient(to right,transparent,#1e3a5a,transparent);
                      margin:14px auto 0"></div>
        </div>
        """, unsafe_allow_html=True)

        # Login form card
        st.markdown("""
        <div style="background:#1a2235;border:1px solid #1e3a5a;border-radius:16px;
                    padding:32px;box-shadow:0 8px 40px rgba(0,0,0,0.6),
                    inset 0 1px 0 rgba(255,255,255,0.04)">
        """, unsafe_allow_html=True)

        with st.form("login_form"):
            st.markdown('<div style="margin-bottom:4px"></div>', unsafe_allow_html=True)
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="••••••••••")
            totp_code = st.text_input("Authenticator Code", placeholder="6-digit code (if enrolled)", max_chars=6)
            st.markdown('<div style="margin-top:4px"></div>', unsafe_allow_html=True)
            submitted = st.form_submit_button("Sign In", type="primary", use_container_width=True)

        st.markdown("</div>", unsafe_allow_html=True)

        if submitted:
            from auth.rate_limiter import check_login, record_failed_login
            allowed, rate_msg = check_login("ui")
            if not allowed:
                st.session_state.login_error = rate_msg
                st.rerun()

            ok, msg, user = auth.authenticate(username.strip(), password)
            if ok:
                from auth.totp import is_enrolled, check_totp_login
                if is_enrolled(username.strip()):
                    if not totp_code.strip():
                        st.session_state.login_error = "Two-factor code required."
                        record_failed_login("ui")
                        st.rerun()
                    if not check_totp_login(username.strip(), totp_code.strip()):
                        st.session_state.login_error = "Invalid authenticator code."
                        record_failed_login("ui")
                        st.rerun()
                st.session_state.update({"authenticated": True, "user": user, "login_error": ""})
                st.rerun()
            else:
                record_failed_login("ui")
                st.session_state.login_error = msg
                st.rerun()

        if st.session_state.login_error:
            st.error(st.session_state.login_error)

        st.markdown(f"""
        <div style="text-align:center;margin-top:20px;color:#334155;font-size:0.65rem;letter-spacing:0.06em">
          MySOC v{config.APP_VERSION} &nbsp;·&nbsp; All access is logged &nbsp;·&nbsp; Unauthorized use prohibited
        </div>
        """, unsafe_allow_html=True)


# ── Nav pages ──────────────────────────────────────────────────────────────────
NAV_PAGES = [
    ("shield",    "Threat Overview",  None),
    ("target",    "Alert Triage",     None),
    ("wifi",      "Live Traffic",     None),
    ("network",   "Network Topology", None),
    ("globe",     "Geo Map",          None),
    ("bar-chart", "Analytics",        None),
    ("terminal",  "Threat Hunt",      None),
    ("search",    "Threat Intel",     None),
    ("monitor",   "Endpoint Monitor", None),
    ("alert-tri", "Incidents",        None),
    ("repeat",    "Shift Handover",   None),
    ("log",       "Log Management",   None),
    ("file-text", "Reports",          None),
    ("settings",  "Settings",         "admin"),
]


def _render_sidebar(user: dict):
    SEV_COLORS = {"CRITICAL": "#f43f5e", "HIGH": "#fb923c", "MEDIUM": "#fbbf24", "LOW": "#4ade80", "INFO": "#60a5fa"}

    with st.sidebar:
        # ── Logo ──────────────────────────────────────────────────────────────
        st.markdown(f"""
        <div style="padding:20px 16px 12px">
          <div style="display:flex;align-items:center;gap:10px">
            <div style="width:34px;height:34px;border-radius:9px;
                        background:linear-gradient(135deg,#1f2a40,#252f47);
                        border:1px solid #1e3a5a;display:flex;align-items:center;
                        justify-content:center;flex-shrink:0">
              <span style="color:#2dd4bf">{icon("shield","#2dd4bf",16)}</span>
            </div>
            <div>
              <div style="font-family:'DM Serif Display',serif;font-size:1.15rem;
                          color:#f1f5f9;letter-spacing:-0.02em;line-height:1">
                My<span style="color:#2dd4bf">SOC</span>
              </div>
              <div style="font-size:0.58rem;color:#334155;letter-spacing:0.15em;
                          text-transform:uppercase;margin-top:1px">Operations</div>
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Active alerts banner ──────────────────────────────────────────────
        counts = db.get_alert_counts_by_severity()
        crit = counts.get("CRITICAL", 0)
        high = counts.get("HIGH", 0)

        if crit > 0:
            st.markdown(f"""
            <div style="margin:0 10px 6px;padding:8px 12px;
                        background:rgba(244,63,94,0.10);
                        border:1px solid rgba(244,63,94,0.25);
                        border-radius:8px;display:flex;align-items:center;gap:8px">
              <span style="width:6px;height:6px;border-radius:50%;background:#f43f5e;
                           flex-shrink:0;animation:pulseLive 1.5s infinite"></span>
              <span style="font-size:0.75rem;color:#f43f5e;font-weight:600">
                {crit} critical alert{"s" if crit != 1 else ""} active
              </span>
            </div>
            """, unsafe_allow_html=True)
        elif high > 0:
            st.markdown(f"""
            <div style="margin:0 10px 6px;padding:8px 12px;
                        background:rgba(251,146,60,0.10);
                        border:1px solid rgba(251,146,60,0.25);
                        border-radius:8px;display:flex;align-items:center;gap:8px">
              <span style="width:6px;height:6px;border-radius:50%;background:#fb923c;flex-shrink:0"></span>
              <span style="font-size:0.75rem;color:#fb923c;font-weight:600">
                {high} high alert{"s" if high != 1 else ""} active
              </span>
            </div>
            """, unsafe_allow_html=True)

        # ── Navigation ────────────────────────────────────────────────────────
        st.markdown('<div class="nav-section-label">Navigation</div>', unsafe_allow_html=True)

        for icon_name, name, min_role in NAV_PAGES:
            if min_role and not auth.has_permission(user, min_role):
                continue
            is_active = (st.session_state.page == name)
            if is_active:
                st.markdown('<div class="nav-active">', unsafe_allow_html=True)
            # Mapping SVG icon names to Emojis for Streamlit button labels (since buttons don't support HTML)
            icon_map = {
                "shield": "🛡️", "target": "🎯", "wifi": "📶", "network": "🌐", 
                "globe": "🌍", "bar-chart": "📊", "terminal": "💻", "search": "🔍", 
                "monitor": "🖥️", "alert-tri": "🚨", "repeat": "🔄", "log": "📋", "file-text": "📄"
            }
            emoji = icon_map.get(icon_name, "🔹")
            label = f"{emoji} {name}"
            if st.button(label, key=f"nav_{name}"):
                st.session_state.page = name
                st.rerun()
            if is_active:
                st.markdown('</div>', unsafe_allow_html=True)

        # ── System status ─────────────────────────────────────────────────────
        st.markdown('<div class="nav-section-label" style="margin-top:16px">System</div>', unsafe_allow_html=True)
        st.markdown('<div style="padding:0 10px">', unsafe_allow_html=True)

        sn_on  = st.session_state.sniffer_running
        sy_on  = st.session_state.syslog_running
        ml_ok  = st.session_state.ml_stats.get("trained", False)
        pps    = st.session_state.sniffer_stats.get("pps", 0)

        def _status_row(lbl, ok, detail=""):
            dot = '<span class="status-dot-live"></span>' if ok else '<span class="status-dot-dead"></span>'
            d = f'<span style="color:#334155;font-size:0.65rem">{detail}</span>' if detail else ""
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:8px;padding:5px 6px;
                        border-radius:6px;margin-bottom:1px;transition:all 0.2s">
              {dot}
              <span style="font-size:0.78rem;color:{'#94a3b8' if ok else '#475569'};flex:1">{lbl}</span>
              {d}
            </div>""", unsafe_allow_html=True)

        _status_row("Capture", sn_on, f"{pps} pps" if sn_on else "stopped")
        _status_row("Syslog", sy_on, f":{config.SYSLOG_PORT}" if sy_on else "stopped")
        _status_row("ML Engine", ml_ok, f"{st.session_state.ml_stats.get('anomalies',0)} found" if ml_ok else "training")
        _status_row("Database", True, "connected")
        st.markdown('</div>', unsafe_allow_html=True)

        # ── Alert mini summary ────────────────────────────────────────────────
        total = sum(counts.values())
        if total > 0:
            st.markdown('<div class="nav-section-label" style="margin-top:12px">Alerts</div>', unsafe_allow_html=True)
            st.markdown('<div style="padding:0 10px 4px">', unsafe_allow_html=True)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                cnt = counts.get(sev, 0)
                if cnt == 0:
                    continue
                c = SEV_COLORS[sev]
                w = int(cnt / max(total, 1) * 60)
                st.markdown(f"""
                <div style="display:flex;align-items:center;gap:8px;padding:3px 6px;margin-bottom:1px">
                  <span style="font-size:0.65rem;color:#475569;width:56px;flex-shrink:0">{sev[:3]}</span>
                  <div style="background:{c};height:3px;width:{w}px;border-radius:2px;opacity:0.7"></div>
                  <span style="font-size:0.72rem;color:{c};font-weight:600;font-family:'IBM Plex Mono',monospace">{cnt}</span>
                </div>""", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)

        # ── User / logout ─────────────────────────────────────────────────────
        st.markdown('<div style="margin-top:auto;padding:12px 10px 8px;border-top:1px solid #162030">', unsafe_allow_html=True)
        rc = {"admin": "#fb923c", "analyst": "#2dd4bf", "viewer": "#4ade80"}.get(user.get("role", ""), "#475569")
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:10px;padding:8px 6px;
                    background:#1a2235;border-radius:8px;border:1px solid #1e3a5a;
                    margin-bottom:8px">
          <div style="width:30px;height:30px;border-radius:8px;background:#252f47;
                      display:flex;align-items:center;justify-content:center;flex-shrink:0">
            <span style="color:#94a3b8">{icon("user","#94a3b8",13)}</span>
          </div>
          <div style="min-width:0">
            <div style="font-size:0.82rem;font-weight:600;color:#f1f5f9;
                        overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
              {user.get("username","")}</div>
            <div style="font-size:0.62rem;color:{rc};text-transform:uppercase;
                        letter-spacing:0.08em;font-weight:600">{user.get("role","")}</div>
          </div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

        if st.button("🚪 Sign Out", key="logout"):
            auth.logout(user.get("username", ""))
            for svc in ["sniffer_obj", "syslog_obj"]:
                obj = st.session_state.get(svc)
                if obj:
                    try: obj.stop()
                    except: pass
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()

        st.markdown(f"""
        <div style="text-align:center;padding:4px 0 8px;color:#1e3a5a;font-size:0.58rem">
          {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")} UTC
        </div>""", unsafe_allow_html=True)


def _page_header(title: str, subtitle: str = "", icon_name: str = "shield"):
    st.markdown(f"""
    <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #162030;
                animation:pageIn 0.3s ease both">
      <div style="display:flex;align-items:center;gap:12px">
        <div style="width:40px;height:40px;border-radius:10px;
                    background:linear-gradient(135deg,#1f2a40,#252f47);
                    border:1px solid #1e3a5a;display:flex;align-items:center;
                    justify-content:center;flex-shrink:0;
                    box-shadow:0 2px 12px rgba(45,212,191,0.08)">
          <span style="color:#2dd4bf">{icon(icon_name,"#2dd4bf",18)}</span>
        </div>
        <div>
          <div style="font-family:'DM Serif Display',serif;font-size:1.6rem;
                      color:#f1f5f9;letter-spacing:-0.03em;line-height:1.1">{title}</div>
          {"" if not subtitle else f'<div style="font-size:0.78rem;color:#475569;margin-top:3px;font-weight:400">{subtitle}</div>'}
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)


def _route(page: str):
    if page == "Threat Overview":
        from views import threat_overview;   threat_overview.render()
    elif page == "Alert Triage":
        from views import alert_triage;      alert_triage.render()
    elif page == "Live Traffic":
        from views import live_traffic;      live_traffic.render()
    elif page == "Network Topology":
        from views import network_topology;  network_topology.render()
    elif page == "Geo Map":
        from views import geo_map;           geo_map.render()
    elif page == "Analytics":
        from views import analytics;         analytics.render()
    elif page == "Threat Hunt":
        from views import threat_hunt;       threat_hunt.render()
    elif page == "Threat Intel":
        from views import threat_intel;      threat_intel.render()
    elif page == "Endpoint Monitor":
        from views import endpoint_monitor;  endpoint_monitor.render()
    elif page == "Incidents":
        from views import incidents;         incidents.render()
    elif page == "Shift Handover":
        from views import shift_handover;    shift_handover.render()
    elif page == "Log Management":
        from views import log_management;    log_management.render()
    elif page == "Reports":
        from views import reports;           reports.render()
    elif page == "Settings":
        from views import settings;          settings.render()
    else:
        st.error(f"Unknown page: '{page}'")


def main():
    if not st.session_state.authenticated:
        _render_login()
        return

    user = st.session_state.user
    if not st.session_state.sniffer_running:
        _auto_start_demo()
    _refresh_engine_stats()
    _render_sidebar(user)
    _route(st.session_state.page)


if __name__ == "__main__":
    main()
