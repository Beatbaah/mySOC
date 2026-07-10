"""
utils/ui.py — Shared UI components for the MY SOC design system.
Import these in every view for consistent cards, badges, headers, charts.
"""
import sys as _sys
from pathlib import Path as _Path
_PROJECT_ROOT = str(_Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, _PROJECT_ROOT)

import streamlit as st
import plotly.graph_objects as go

# ── Design tokens (mirrors CSS vars) ──────────────────────────────────────────
BG_DEEP    = "#0c0f1a"
BG_BASE    = "#111827"
BG_SURFACE = "#1a2235"
BG_RAISED  = "#1f2a40"
TEAL       = "#2dd4bf"
TEAL_DIM   = "#14b8a6"
CORAL      = "#fb7185"
AMBER      = "#fbbf24"
EMERALD    = "#34d399"
SKY        = "#38bdf8"
TEXT_PRI   = "#f1f5f9"
TEXT_SEC   = "#94a3b8"
TEXT_MUTED = "#475569"
BORDER     = "#1e3a5a"

SEV_COLORS = {
    "CRITICAL": "#f43f5e",
    "HIGH":     "#fb923c",
    "MEDIUM":   "#fbbf24",
    "LOW":      "#4ade80",
    "INFO":     "#60a5fa",
}


# ── Plotly base layout ────────────────────────────────────────────────────────
def chart_layout(height: int = 300, show_legend: bool = True, margin=None) -> dict:
    m = margin or dict(l=0, r=0, t=10, b=30)
    return dict(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(26,34,53,0.5)",
        font=dict(family="DM Sans, system-ui", color=TEXT_SEC, size=11),
        xaxis=dict(
            gridcolor="rgba(30,58,90,0.5)", gridwidth=1,
            linecolor=BORDER, tickfont=dict(size=10),
            showgrid=True, zeroline=False,
        ),
        yaxis=dict(
            gridcolor="rgba(30,58,90,0.5)", gridwidth=1,
            linecolor=BORDER, tickfont=dict(size=10),
            showgrid=True, zeroline=False,
        ),
        showlegend=show_legend,
        legend=dict(
            bgcolor="rgba(26,34,53,0.8)",
            bordercolor=BORDER, borderwidth=1,
            font=dict(size=10), orientation="h",
            yanchor="bottom", y=1.02, xanchor="left", x=0,
        ),
        margin=m,
        hoverlabel=dict(
            bgcolor=BG_RAISED,
            bordercolor=BORDER,
            font=dict(family="IBM Plex Mono", size=11, color=TEXT_PRI),
        ),
    )


# ── KPI card ──────────────────────────────────────────────────────────────────
def kpi_card(col, label: str, value, color: str = TEAL,
             icon_svg: str = "", trend: str = "", trend_good: bool = True):
    trend_color = EMERALD if trend_good else CORAL
    trend_html = f'<div style="font-size:0.7rem;color:{trend_color};margin-top:6px">{trend}</div>' if trend else ""
    icon_html = f'<div style="position:absolute;top:14px;right:14px;opacity:0.15;color:{color}">{icon_svg}</div>' if icon_svg else ""

    col.markdown(f"""
    <div class="kpi-card" style="animation:pageIn 0.3s ease both">
      {icon_html}
      <div class="kpi-top-bar" style="background:{color}"></div>
      <div class="kpi-value" style="color:{color}">{value}</div>
      <div class="kpi-label">{label}</div>
      {trend_html}
    </div>
    """, unsafe_allow_html=True)


# ── Section title ─────────────────────────────────────────────────────────────
def section_title(title: str, subtitle: str = ""):
    sub = f'<div style="font-size:0.75rem;color:{TEXT_MUTED};margin-top:3px">{subtitle}</div>' if subtitle else ""
    st.markdown(f"""
    <div style="margin-bottom:14px">
      <div class="section-title">{title}</div>
      {sub}
    </div>
    """, unsafe_allow_html=True)


# ── Severity pill ─────────────────────────────────────────────────────────────
def sev_pill(severity: str) -> str:
    c = SEV_COLORS.get(severity.upper(), TEXT_MUTED)
    return (f'<span class="sev-pill sev-{severity.upper()}">'
            f'{severity.upper()}</span>')


# ── Alert card ────────────────────────────────────────────────────────────────
def alert_card(alert: dict, show_actions: bool = False, idx: int = 0):
    sev   = alert.get("severity", "INFO")
    c     = SEV_COLORS.get(sev, TEXT_MUTED)
    acked = bool(alert.get("acknowledged", 0))
    op    = "0.5" if acked else "1"
    delay = f"animation-delay:{idx * 0.04}s"

    st.markdown(f"""
    <div class="alert-card" style="border-left:3px solid {c};opacity:{op};{delay}">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">
            {sev_pill(sev)}
            <span style="font-size:0.83rem;font-weight:600;color:{TEXT_PRI}">{alert.get("alert_type","?")}</span>
            <span style="font-size:0.7rem;color:{TEXT_MUTED}">#{alert.get("id","")}</span>
          </div>
          <div style="font-size:0.79rem;color:{TEXT_SEC};margin-bottom:6px;
                      white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
            {alert.get("description","")[:120]}
          </div>
          <div style="display:flex;gap:14px;flex-wrap:wrap">
            <span style="font-size:0.7rem;color:{TEXT_MUTED}">
              Src &nbsp;<code style="background:{BG_RAISED};color:{TEAL};padding:1px 6px;
              border-radius:4px;font-family:'IBM Plex Mono',monospace;font-size:0.78rem;
              border:1px solid #162030">{alert.get("src_ip","—")}</code>
            </span>
            <span style="font-size:0.7rem;color:{TEXT_MUTED}">
              Dst &nbsp;<code style="background:{BG_RAISED};color:{SKY};padding:1px 6px;
              border-radius:4px;font-family:'IBM Plex Mono',monospace;font-size:0.78rem;
              border:1px solid #162030">{alert.get("dst_ip","—")}</code>
            </span>
            <span style="font-size:0.7rem;color:{TEXT_MUTED}">{alert.get("timestamp","")[:16]}</span>
            {"<span style='font-size:0.7rem;color:" + EMERALD + "'>✓ Acked by " + str(alert.get('ack_by','')) + "</span>" if acked else ""}
          </div>
        </div>
        <div style="text-align:right;flex-shrink:0">
          <div style="font-family:'IBM Plex Mono',monospace;font-size:1.1rem;
                      font-weight:500;color:{c}">{alert.get("threat_score",0)}</div>
          <div style="font-size:0.6rem;color:{TEXT_MUTED};text-transform:uppercase;letter-spacing:0.08em">score</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)


# ── Empty state ───────────────────────────────────────────────────────────────
def empty_state(message: str = "No data available", icon: str = "—"):
    st.markdown(f"""
    <div style="text-align:center;padding:48px 20px;color:{TEXT_MUTED}">
      <div style="font-size:2.5rem;margin-bottom:12px;opacity:0.3">{icon}</div>
      <div style="font-size:0.85rem;font-weight:500">{message}</div>
    </div>
    """, unsafe_allow_html=True)


# ── Info row ──────────────────────────────────────────────────────────────────
def info_row(label: str, value, mono: bool = False):
    val_style = (f"font-family:'IBM Plex Mono',monospace;color:{TEAL}" if mono
                 else f"color:{TEXT_PRI}")
    st.markdown(f"""
    <div style="display:flex;justify-content:space-between;align-items:center;
                padding:6px 0;border-bottom:1px solid #162030">
      <span style="font-size:0.75rem;color:{TEXT_MUTED};text-transform:uppercase;
                   letter-spacing:0.06em;font-weight:500">{label}</span>
      <span style="font-size:0.82rem;{val_style}">{value}</span>
    </div>
    """, unsafe_allow_html=True)


# ── Panel container ───────────────────────────────────────────────────────────
def panel(content_fn, title: str = "", padding: int = 18):
    hdr = f'<div style="font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:{TEXT_MUTED};margin-bottom:12px">{title}</div>' if title else ""
    st.markdown(f"""
    <div style="background:{BG_SURFACE};border:1px solid {BORDER};
                border-radius:10px;padding:{padding}px;
                box-shadow:0 2px 12px rgba(0,0,0,0.4),inset 0 1px 0 rgba(255,255,255,0.03)">
      {hdr}
    """, unsafe_allow_html=True)
    content_fn()
    st.markdown("</div>", unsafe_allow_html=True)


# ── Page header (used by all views) ───────────────────────────────────────────
def page_header(title: str, subtitle: str = "", icon_svg: str = ""):
    icon_block = f"""
    <div style="width:40px;height:40px;border-radius:10px;
                background:linear-gradient(135deg,#1f2a40,#252f47);
                border:1px solid #1e3a5a;display:flex;align-items:center;
                justify-content:center;flex-shrink:0;
                box-shadow:0 2px 12px rgba(45,212,191,0.08)">
      <span style="color:#2dd4bf">{icon_svg}</span>
    </div>""" if icon_svg else ""

    sub_block = f'<div style="font-size:0.78rem;color:{TEXT_MUTED};margin-top:3px">{subtitle}</div>' if subtitle else ""

    st.markdown(f"""
    <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #162030;
                animation:pageIn 0.3s ease both">
      <div style="display:flex;align-items:center;gap:12px">
        {icon_block}
        <div>
          <div style="font-family:'DM Serif Display',serif;font-size:1.65rem;
                      color:#f1f5f9;letter-spacing:-0.03em;line-height:1.1">{title}</div>
          {sub_block}
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)
