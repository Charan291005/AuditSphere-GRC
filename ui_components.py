"""
UI Components and Design System for AuditSphere.

Enterprise Design Specs:
- Light theme
- Primary accent: #751C35 (Burgundy / Claret)
- Background: #F7F8FA
- Card background: #FFFFFF
- Primary text: #1F2937
- Secondary text: #6B7280
- Success: #15803D
- Warning: #D97706
- Critical: #DC2626
- Clean borders: 1px solid #E5E7EB
- Typography: System sans-serif / Inter
- Accessible contrast and minimal border-radius
"""

import streamlit as st
from typing import Optional, Dict, Any


def inject_custom_styles():
    """Inject custom CSS to establish the enterprise GRC design system."""
    st.markdown(
        """
        <style>
        /* Base typography and background */
        html, body, [class*="css"] {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            color: #1F2937;
        }

        /* Top header bar clean up */
        header[data-testid="stHeader"] {
            background-color: #FFFFFF;
            border-bottom: 1px solid #E5E7EB;
        }

        /* Sidebar Styling */
        section[data-testid="stSidebar"] {
            background-color: #FFFFFF;
            border-right: 1px solid #E5E7EB;
            padding-top: 1rem;
        }

        /* Sidebar brand logo & title */
        .sidebar-brand {
            padding: 0.5rem 0.25rem 1rem 0.25rem;
            border-bottom: 1px solid #E5E7EB;
            margin-bottom: 1.25rem;
        }
        .sidebar-brand-title {
            color: #751C35;
            font-size: 1.35rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            margin: 0;
            line-height: 1.2;
        }
        .sidebar-brand-sub {
            color: #6B7280;
            font-size: 0.75rem;
            font-weight: 500;
            margin-top: 0.2rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Metric cards */
        .grc-kpi-card {
            background-color: #FFFFFF;
            border: 1px solid #E5E7EB;
            border-radius: 4px;
            padding: 1.25rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
        }
        .grc-kpi-label {
            font-size: 0.8rem;
            font-weight: 600;
            color: #6B7280;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.35rem;
        }
        .grc-kpi-value {
            font-size: 1.85rem;
            font-weight: 700;
            color: #1F2937;
            line-height: 1.1;
        }
        .grc-kpi-desc {
            font-size: 0.75rem;
            color: #9CA3AF;
            margin-top: 0.35rem;
        }

        /* Standard Content Cards */
        .grc-card {
            background-color: #FFFFFF;
            border: 1px solid #E5E7EB;
            border-radius: 4px;
            padding: 1.5rem;
            margin-bottom: 1.25rem;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
        }
        .grc-card-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: #1F2937;
            margin-bottom: 0.75rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        /* Status badges */
        .badge {
            display: inline-block;
            padding: 0.2rem 0.55rem;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 3px;
            letter-spacing: 0.02em;
        }
        .badge-draft {
            background-color: #F3F4F6;
            color: #4B5563;
            border: 1px solid #D1D5DB;
        }
        .badge-in-progress {
            background-color: #EFF6FF;
            color: #1E40AF;
            border: 1px solid #BFDBFE;
        }
        .badge-in-review {
            background-color: #FFFBEB;
            color: #B45309;
            border: 1px solid #FDE68A;
        }
        .badge-completed {
            background-color: #F0FDF4;
            color: #15803D;
            border: 1px solid #BBF7D0;
        }
        .badge-archived {
            background-color: #F9FAFB;
            color: #6B7280;
            border: 1px solid #E5E7EB;
        }

        /* Action pill / event tag */
        .event-tag {
            font-size: 0.7rem;
            font-weight: 700;
            padding: 0.15rem 0.4rem;
            border-radius: 2px;
            text-transform: uppercase;
        }
        .event-created {
            background-color: #ECFDF5;
            color: #065F46;
            border: 1px solid #A7F3D0;
        }
        .event-edited {
            background-color: #EFF6FF;
            color: #1E40AF;
            border: 1px solid #BFDBFE;
        }
        .event-archived {
            background-color: #FEF2F2;
            color: #991B1B;
            border: 1px solid #FECACA;
        }

        /* Educational disclaimer banner */
        .grc-disclaimer {
            background-color: #FFFFFF;
            border-left: 3px solid #751C35;
            border-top: 1px solid #E5E7EB;
            border-right: 1px solid #E5E7EB;
            border-bottom: 1px solid #E5E7EB;
            border-radius: 3px;
            padding: 0.75rem 1rem;
            margin-bottom: 1.25rem;
            font-size: 0.8rem;
            color: #4B5563;
        }
        .grc-disclaimer strong {
            color: #751C35;
        }

        /* Primary Button */
        div.stButton > button {
            border-radius: 3px !important;
            font-weight: 500 !important;
            font-size: 0.875rem !important;
            border: 1px solid #E5E7EB !important;
        }
        div.stButton > button[kind="primary"] {
            background-color: #751C35 !important;
            color: #FFFFFF !important;
            border: 1px solid #751C35 !important;
        }
        div.stButton > button[kind="primary"]:hover {
            background-color: #5C152A !important;
            border-color: #5C152A !important;
        }

        /* Tables & Dataframes */
        div[data-testid="stTable"], div[data-testid="stDataFrame"] {
            border: 1px solid #E5E7EB;
            border-radius: 3px;
            background-color: #FFFFFF;
        }

        /* Section divider */
        hr {
            margin-top: 1rem;
            margin-bottom: 1.5rem;
            border: 0;
            border-top: 1px solid #E5E7EB;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_status_badge(status: str) -> str:
    """Return HTML for an assessment or control status badge."""
    css_class = {
        "Draft": "badge-draft",
        "In Progress": "badge-in-progress",
        "In Review": "badge-in-review",
        "Completed": "badge-completed",
        "Archived": "badge-archived",
        "Implemented": "badge-completed",
        "Partially Implemented": "badge-in-review",
        "Not Implemented": "event-archived",
        "Not Assessed": "badge-draft",
        "Not Applicable": "badge-archived",
    }.get(status, "badge-draft")

    return f'<span class="badge {css_class}">{status}</span>'


def render_review_badge(status: str) -> str:
    """Return HTML for an evidence review status badge."""
    colors = {
        "Accepted": ("#15803D", "#F0FDF4", "#BBF7D0"),
        "Pending Review": ("#B45309", "#FFFBEB", "#FDE68A"),
        "Needs Clarification": ("#1E40AF", "#EFF6FF", "#BFDBFE"),
        "Rejected": ("#B91C1C", "#FEF2F2", "#FECACA"),
    }.get(status, ("#4B5563", "#F3F4F6", "#D1D5DB"))

    return f'<span style="background-color: {colors[1]}; color: {colors[0]}; border: 1px solid {colors[2]}; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: 600;">{status}</span>'


def render_integrity_badge(status: str) -> str:
    """Return HTML for an evidence SHA-256 integrity status badge."""
    colors = {
        "Verified": ("#15803D", "#F0FDF4", "#BBF7D0"),
        "Hash mismatch": ("#B91C1C", "#FEF2F2", "#FECACA"),
        "File missing": ("#991B1B", "#FEF2F2", "#FECACA"),
        "Not yet verified": ("#6B7280", "#F3F4F6", "#D1D5DB"),
    }.get(status, ("#6B7280", "#F3F4F6", "#D1D5DB"))

    return f'<span style="background-color: {colors[1]}; color: {colors[0]}; border: 1px solid {colors[2]}; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: 600;">{status}</span>'


def render_severity_badge(severity: str) -> str:
    """Return HTML for an audit finding severity badge."""
    colors = {
        "Critical": ("#991B1B", "#FEF2F2", "#FECACA"),
        "High": ("#C2410C", "#FFF7ED", "#FED7AA"),
        "Medium": ("#B45309", "#FFFBEB", "#FDE68A"),
        "Low": ("#1D4ED8", "#EFF6FF", "#BFDBFE"),
        "Informational": ("#4B5563", "#F3F4F6", "#D1D5DB"),
    }.get(severity, ("#4B5563", "#F3F4F6", "#D1D5DB"))

    return f'<span style="background-color: {colors[1]}; color: {colors[0]}; border: 1px solid {colors[2]}; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase;">{severity}</span>'


def render_conclusion_badge(conclusion: str) -> str:
    """Return HTML for a control test conclusion badge."""
    colors = {
        "Pass": ("#15803D", "#F0FDF4", "#BBF7D0"),
        "Fail": ("#B91C1C", "#FEF2F2", "#FECACA"),
        "Inconclusive": ("#B45309", "#FFFBEB", "#FDE68A"),
        "Not tested": ("#4B5563", "#F3F4F6", "#D1D5DB"),
    }.get(conclusion, ("#4B5563", "#F3F4F6", "#D1D5DB"))

    return f'<span style="background-color: {colors[1]}; color: {colors[0]}; border: 1px solid {colors[2]}; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; font-weight: 700;">{conclusion}</span>'


def render_event_badge(event_type: str) -> str:
    """Return HTML for an activity log event type."""
    if "CREATED" in event_type:
        css = "event-created"
    elif "EDITED" in event_type or "UPDATED" in event_type:
        css = "event-edited"
    elif "ARCHIVED" in event_type or "DELETED" in event_type:
        css = "event-archived"
    else:
        css = "event-edited"
    return f'<span class="event-tag {css}">{event_type.replace("_", " ")}</span>'


def render_educational_disclaimer():
    """Render the mandatory educational simulation disclaimer."""
    st.markdown(
        """
        <div class="grc-disclaimer">
            <strong>Educational Assessment Simulator:</strong> AuditSphere is an educational simulation and portfolio GRC application.
            Records, controls, and assessments conducted herein are simulations for evaluation, training, and demonstrative risk management.
            Conducting assessments in this software does not constitute formal certification or accredited audit conformity under ISO/IEC 27001.
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_kpi_card(label: str, value: Any, description: str = ""):
    """Render a clean enterprise KPI metric box."""
    st.markdown(
        f"""
        <div class="grc-kpi-card">
            <div class="grc-kpi-label">{label}</div>
            <div class="grc-kpi-value">{value}</div>
            <div class="grc-kpi-desc">{description}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_empty_state(title: str, message: str, action_text: Optional[str] = None):
    """Render a clean empty state card without cheesy graphics."""
    st.markdown(
        f"""
        <div class="grc-card" style="text-align: center; padding: 2.5rem 1.5rem;">
            <div style="color: #6B7280; font-size: 1.1rem; font-weight: 600; margin-bottom: 0.5rem;">{title}</div>
            <div style="color: #9CA3AF; font-size: 0.875rem; max-width: 480px; margin: 0 auto;">{message}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
