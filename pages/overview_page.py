"""
Overview Dashboard page view for AuditSphere.

Displays genuine metrics derived strictly from the SQLite database.
Does not fabricate compliance percentages or mock results.
"""

import streamlit as st
import pandas as pd
from services.dashboard_service import get_dashboard_summary
from ui_components import (
    render_kpi_card,
    render_status_badge,
    render_event_badge,
    render_empty_state,
    render_educational_disclaimer,
)


def render_overview_page():
    """Render the primary dashboard overview."""
    st.markdown("## Overview Dashboard")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.95rem; margin-top: -0.5rem;'>"
        "High-level ISMS assessment posture, active assessment workspace context, and recent lifecycle events."
        "</p>",
        unsafe_allow_html=True,
    )

    render_educational_disclaimer()

    active_id = st.session_state.get("active_assessment_id")
    summary = get_dashboard_summary(active_assessment_id=active_id)

    # Top KPI Metrics Row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        render_kpi_card(
            label="Total Assessments",
            value=summary["total_assessments"],
            description="All recorded assessments in database",
        )
    with col2:
        render_kpi_card(
            label="Active Assessments",
            value=summary["active_assessments"],
            description="Assessments currently in flight",
        )
    with col3:
        render_kpi_card(
            label="Archived Assessments",
            value=summary["archived_assessments"],
            description="Historical or retired assessment records",
        )
    with col4:
        active_title = (
            summary["active_assessment"]["title"]
            if summary["active_assessment"]
            else "None Selected"
        )
        if len(active_title) > 22:
            active_title = active_title[:20] + "..."
        render_kpi_card(
            label="Active Context",
            value=active_title,
            description="Currently selected workspace target",
        )

    # Active Assessment Details & Pipeline Status
    c_left, c_right = st.columns([3, 2])

    with c_left:
        st.markdown(
            '<div class="grc-card-title">Active Assessment Details</div>',
            unsafe_allow_html=True,
        )

        active = summary["active_assessment"]
        if active:
            st.markdown(
                f"""
                <div class="grc-card" style="margin-bottom: 0;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem;">
                        <div>
                            <span style="font-size: 1.15rem; font-weight: 700; color: #1F2937;">{active['title']}</span>
                            <div style="font-size: 0.85rem; color: #6B7280;">{active['organization']} &bull; {active['industry']}</div>
                        </div>
                        <div>
                            {render_status_badge(active['status'])}
                        </div>
                    </div>
                    <div style="font-size: 0.825rem; color: #4B5563; margin-bottom: 0.5rem;">
                        <strong>Standard:</strong> {active['standard']} &nbsp;|&nbsp;
                        <strong>Lead Assessor:</strong> {active['lead_assessor']} &nbsp;|&nbsp;
                        <strong>Date:</strong> {active['assessment_date']}
                    </div>
                    <div style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid #E5E7EB;">
                        <div style="font-size: 0.8rem; font-weight: 600; color: #374151; margin-bottom: 0.25rem;">Defined Scope:</div>
                        <div style="font-size: 0.85rem; color: #4B5563; background-color: #F9FAFB; padding: 0.5rem 0.75rem; border-radius: 3px; border: 1px solid #F3F4F6;">
                            {active['scope']}
                        </div>
                    </div>
                    {f'''
                    <div style="margin-top: 0.5rem;">
                        <div style="font-size: 0.8rem; font-weight: 600; color: #374151; margin-bottom: 0.25rem;">Objectives:</div>
                        <div style="font-size: 0.85rem; color: #4B5563; background-color: #F9FAFB; padding: 0.5rem 0.75rem; border-radius: 3px; border: 1px solid #F3F4F6;">
                            {active['objectives']}
                        </div>
                    </div>
                    ''' if active.get('objectives') else ''}
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            render_empty_state(
                title="No Active Assessment Selected",
                message="Select an active assessment from the left sidebar or the Assessment Management module to load its contextual workspace.",
            )

    with c_right:
        st.markdown(
            '<div class="grc-card-title">Assessment Pipeline Status</div>',
            unsafe_allow_html=True,
        )

        status_dist = summary["status_distribution"]
        all_statuses = ["Draft", "In Progress", "In Review", "Completed", "Archived"]

        st.markdown(
            """
            <div class="grc-card" style="margin-bottom: 0;">
            """,
            unsafe_allow_html=True,
        )

        for status_name in all_statuses:
            count = status_dist.get(status_name, 0)
            st.markdown(
                f"""
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0; border-bottom: 1px solid #F3F4F6;">
                    <span style="font-size: 0.875rem; color: #374151;">{render_status_badge(status_name)}</span>
                    <span style="font-size: 0.95rem; font-weight: 700; color: #1F2937;">{count}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown(
            """
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<hr/>", unsafe_allow_html=True)

    # Activity Stream Row
    st.markdown(
        '<div class="grc-card-title">Recent Assessment Activity</div>',
        unsafe_allow_html=True,
    )

    activities = summary["recent_activities"]
    if activities:
        rows = []
        for act in activities:
            # Parse readable timestamp
            time_str = act["timestamp"].replace("T", " ").replace("Z", " UTC")
            rows.append(
                {
                    "Timestamp": time_str,
                    "Assessment": act.get("assessment_title") or f"ID #{act.get('assessment_id')}",
                    "Event": act["event_type"].replace("ASSESSMENT_", "").title(),
                    "Description": act["description"],
                    "Actor": act["actor"],
                }
            )

        df_activity = pd.DataFrame(rows)
        st.dataframe(
            df_activity,
            use_container_width=True,
            hide_index=True,
        )
    else:
        render_empty_state(
            title="No Activity Logged Yet",
            message="Assessment lifecycle events (creation, edits, archival) will automatically appear in this feed.",
        )

    # Future Modules Notice
    st.markdown(
        """
        <div style="margin-top: 1.5rem; padding: 0.85rem 1rem; background-color: #FFFFFF; border: 1px dashed #D1D5DB; border-radius: 4px; font-size: 0.825rem; color: #6B7280;">
            <strong>Subsequent Phase Modules:</strong> ISO 27001 Control Compliance metrics, Gap Severity Distribution, and Risk Heatmaps will be activated in Phases 2 and 3. In compliance with strict GRC integrity standards, no artificial or mock percentages are displayed.
        </div>
        """,
        unsafe_allow_html=True,
    )
