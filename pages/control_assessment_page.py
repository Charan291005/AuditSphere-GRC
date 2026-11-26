"""
ISO/IEC 27001:2022 Control Assessment Page for AuditSphere.

Enables assessors to review, filter, and evaluate the 20 selected Annex A controls,
document observations and testing notes, provide remediation recommendations,
and compute real-time readiness and gap metrics.
"""

import streamlit as st
import pandas as pd
from datetime import datetime, date
from typing import Optional, Dict, Any, List

from services.assessment_service import get_assessment
from services.control_service import (
    get_assessment_controls,
    get_single_control_assessment,
    update_control_assessment,
    create_fincore_demo_assessment,
)
from services.assessment_engine import (
    VALID_CONTROL_STATUSES,
    calculate_overall_metrics,
)
from ui_components import (
    render_kpi_card,
    render_status_badge,
    render_empty_state,
    render_educational_disclaimer,
)


def render_control_assessment_page():
    """Render the primary ISO 27001 selected-control assessment engine."""
    st.markdown("## ISO 27001 Control Assessment")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.95rem; margin-top: -0.5rem;'>"
        "Evaluate security controls across the 4 Annex A themes (Organizational, People, Physical, Technological), "
        "document testing notes and observations, and track readiness posture."
        "</p>",
        unsafe_allow_html=True,
    )

    render_educational_disclaimer()

    active_id = st.session_state.get("active_assessment_id")
    if not active_id:
        render_empty_state(
            title="No Active Assessment Selected",
            message="Please select or create an assessment in the left sidebar or Assessment Management to evaluate controls.",
        )
        # Option to load demo assessment directly
        if st.button("Load FinCore Technologies Demo Assessment", type="primary"):
            demo = create_fincore_demo_assessment()
            st.session_state["active_assessment_id"] = demo["assessment"]["id"]
            st.success("Loaded FinCore Technologies demonstration assessment.")
            st.rerun()
        return

    assessment = get_assessment(active_id)
    if not assessment:
        st.error("Active assessment could not be loaded from database.")
        return

    is_archived = assessment["status"] == "Archived"

    # Display active assessment summary strip
    c_hdr1, c_hdr2 = st.columns([3, 1])
    with c_hdr1:
        st.markdown(
            f"""
            <div style="background-color: #FFFFFF; border: 1px solid #E5E7EB; border-left: 4px solid #751C35; border-radius: 4px; padding: 0.85rem 1.15rem; margin-bottom: 1.25rem;">
                <div style="font-size: 1.1rem; font-weight: 700; color: #1F2937;">{assessment['title']}</div>
                <div style="font-size: 0.85rem; color: #4B5563; margin-top: 0.2rem;">
                    <strong>Organization:</strong> {assessment['organization']} &nbsp;|&nbsp;
                    <strong>Framework:</strong> {assessment['standard']} &nbsp;|&nbsp;
                    <strong>Lead Assessor:</strong> {assessment['lead_assessor']} &nbsp;|&nbsp;
                    <strong>Status:</strong> {render_status_badge(assessment['status'])}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with c_hdr2:
        if st.button("Load Demo Data (FinCore)", use_container_width=True, help="Load the official 20-control demonstration dataset for FinCore Technologies."):
            demo = create_fincore_demo_assessment()
            st.session_state["active_assessment_id"] = demo["assessment"]["id"]
            st.success("Loaded FinCore demonstration assessment.")
            st.rerun()

    if is_archived:
        st.warning(
            "This assessment is Archived. All control records are in read-only mode and cannot be modified."
        )

    # Fetch all controls for this assessment
    all_controls = get_assessment_controls(assessment_id=active_id)
    metrics = calculate_overall_metrics(all_controls)
    status_counts = metrics["status_counts"]

    # Readiness & Coverage Metrics Row
    m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
    with m_col1:
        render_kpi_card(
            label="Selected Controls",
            value=f"{metrics['total_controls']} / 20",
            description="Educational Annex A subset",
        )
    with m_col2:
        cov_val = f"{metrics['coverage_pct']:.1f}%" if metrics["coverage_pct"] is not None else "N/A"
        render_kpi_card(
            label="Assessment Coverage",
            value=cov_val,
            description=f"{metrics['assessed_controls']} of {metrics['applicable_controls']} applicable assessed",
        )
    with m_col3:
        read_val = f"{metrics['weighted_readiness_pct']:.1f}%" if metrics["weighted_readiness_pct"] is not None else "N/A"
        render_kpi_card(
            label="Weighted Readiness",
            value=read_val,
            description="Score across assessed controls",
        )
    with m_col4:
        render_kpi_card(
            label="Potential Gaps",
            value=metrics["potential_gaps"],
            description="Partial (0.5) + Not Implemented (1.0)",
        )
    with m_col5:
        render_kpi_card(
            label="Pending Controls",
            value=metrics["pending_controls"],
            description="Controls in 'Not Assessed' status",
        )

    # Detailed status badge count bar
    st.markdown(
        f"""
        <div style="background-color: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 4px; padding: 0.65rem 1rem; margin-bottom: 1.5rem; display: flex; gap: 1.5rem; flex-wrap: wrap; font-size: 0.825rem; align-items: center;">
            <span style="font-weight: 600; color: #374151;">Implementation Breakdown:</span>
            <span>{render_status_badge('Implemented')}: <strong>{status_counts.get('Implemented', 0)}</strong></span>
            <span>{render_status_badge('Partially Implemented')}: <strong>{status_counts.get('Partially Implemented', 0)}</strong></span>
            <span>{render_status_badge('Not Implemented')}: <strong>{status_counts.get('Not Implemented', 0)}</strong></span>
            <span>{render_status_badge('Not Assessed')}: <strong>{status_counts.get('Not Assessed', 0)}</strong></span>
            <span>{render_status_badge('Not Applicable')}: <strong>{status_counts.get('Not Applicable', 0)}</strong></span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Filter controls
    f_col1, f_col2, f_col3 = st.columns([2, 1.5, 1.5])
    with f_col1:
        search_query = st.text_input(
            "Search Controls",
            placeholder="Search by reference (e.g. A.5.1), title, or owner...",
            label_visibility="collapsed",
            key="ctrl_search",
        )
    with f_col2:
        category_filter = st.selectbox(
            "Category Filter",
            options=["All Categories", "Organizational", "People", "Physical", "Technological"],
            label_visibility="collapsed",
            key="ctrl_cat_filter",
        )
    with f_col3:
        status_filter = st.selectbox(
            "Status Filter",
            options=["All Statuses"] + list(VALID_CONTROL_STATUSES),
            label_visibility="collapsed",
            key="ctrl_stat_filter",
        )

    filtered_controls = get_assessment_controls(
        assessment_id=active_id,
        status_filter=status_filter,
        category_filter=category_filter,
        search_query=search_query,
    )

    # Main split layout: Catalogue Table on left (or top), Evaluation Form on right (or bottom)
    left_col, right_col = st.columns([7, 5])

    # Manage selected control in session state
    if "selected_control_id" not in st.session_state:
        st.session_state["selected_control_id"] = (
            filtered_controls[0]["control_id"] if filtered_controls else 1
        )

    with left_col:
        st.markdown(f"**Selected Annex A Controls Catalogue ({len(filtered_controls)} matching)**")

        if not filtered_controls:
            render_empty_state(
                title="No Controls Found",
                message="No controls match your filter criteria. Reset the search or status filters to view the catalogue.",
            )
        else:
            # Render interactive table of controls
            for c in filtered_controls:
                is_selected = c["control_id"] == st.session_state.get("selected_control_id")
                card_border = "#751C35" if is_selected else "#E5E7EB"
                card_bg = "#FDF8F9" if is_selected else "#FFFFFF"

                st.markdown(
                    f"""
                    <div style="background-color: {card_bg}; border: 1px solid {card_border}; border-left: { '4px solid #751C35;' if is_selected else '1px solid #E5E7EB;' } border-radius: 4px; padding: 0.85rem 1rem; margin-bottom: 0.65rem;">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div>
                                <span style="font-weight: 700; color: #751C35; font-size: 0.95rem; margin-right: 0.5rem;">{c['control_identifier']}</span>
                                <span style="font-weight: 600; color: #1F2937; font-size: 0.95rem;">{c['control_title']}</span>
                                <div style="font-size: 0.8rem; color: #6B7280; margin-top: 0.2rem;">
                                    Category: <strong>{c['category']}</strong> &bull; Owner: <strong>{c.get('control_owner') or 'Unassigned'}</strong>
                                </div>
                            </div>
                            <div>
                                {render_status_badge(c['status'])}
                            </div>
                        </div>
                        <div style="font-size: 0.775rem; color: #6B7280; margin-top: 0.35rem; display: flex; justify-content: space-between;">
                            <span>Last Assessed: {c.get('assessed_at') or 'Never'}</span>
                            <span>Assessor: {c.get('assessed_by') or 'None'}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                # Select button
                if st.button(
                    f"Assess {c['control_identifier']}" if not is_selected else f"Currently Inspecting {c['control_identifier']}",
                    key=f"btn_select_ctrl_{c['control_id']}",
                    use_container_width=True,
                    disabled=is_selected,
                ):
                    st.session_state["selected_control_id"] = c["control_id"]
                    st.rerun()

                st.markdown("<div style='margin-bottom: 0.35rem;'></div>", unsafe_allow_html=True)

    with right_col:
        # Load currently selected control details
        selected_cid = st.session_state.get("selected_control_id", 1)
        selected_ctrl = get_single_control_assessment(
            assessment_id=active_id, control_id=selected_cid
        )

        if not selected_ctrl:
            render_empty_state(
                title="Select a Control",
                message="Click 'Assess' on any control in the directory to inspect guidance and record an evaluation.",
            )
            return

        _render_control_evaluation_form(
            assessment=assessment,
            control=selected_ctrl,
            is_archived=is_archived,
        )


def _render_control_evaluation_form(
    assessment: Dict[str, Any],
    control: Dict[str, Any],
    is_archived: bool,
):
    """Render the evaluation and observation entry form for the selected control."""
    st.markdown(
        f"""
        <div style="background-color: #FFFFFF; border: 1px solid #751C35; border-radius: 4px; padding: 1.15rem; margin-bottom: 1rem;">
            <div style="font-size: 0.75rem; font-weight: 700; color: #751C35; text-transform: uppercase; letter-spacing: 0.05em;">
                Control Evaluation Workspace
            </div>
            <div style="font-size: 1.25rem; font-weight: 700; color: #1F2937; margin-top: 0.2rem;">
                {control['control_identifier']} – {control['control_title']}
            </div>
            <div style="font-size: 0.8rem; color: #6B7280; margin-top: 0.2rem; margin-bottom: 0.75rem;">
                {control['clause']} &bull; Theme: <strong>{control['category']}</strong>
            </div>
            <div style="font-size: 0.85rem; color: #374151; background: #F9FAFB; padding: 0.65rem; border-radius: 3px; border: 1px solid #F3F4F6; margin-bottom: 0.75rem;">
                <strong>Objective:</strong> {control.get('objective', '')}
            </div>
            <div style="font-size: 0.825rem; color: #4B5563; line-height: 1.5;">
                {control['control_description']}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Collapsible Auditor Guidance
    with st.expander("Audit Guidance & Suggested Evidence", expanded=False):
        st.markdown("**Suggested Assessment Questions:**")
        for q in control.get("assessment_questions", []):
            st.markdown(f"- {q}")

        st.markdown("**Suggested Evidence Types:**")
        for ev in control.get("suggested_evidence", []):
            st.markdown(f"- {ev}")

        st.markdown("**Example Gaps & Deficiencies:**")
        for gap in control.get("example_gaps", []):
            st.markdown(f"- {gap}")

        st.markdown("**Example Remediation Guidance:**")
        for rec in control.get("example_recommendations", []):
            st.markdown(f"- {rec}")

    # Evaluation Form
    form_key = f"eval_form_{assessment['id']}_{control['control_id']}"
    with st.form(key=form_key):
        st.markdown("#### Record Assessor Evaluation")

        status_idx = (
            VALID_CONTROL_STATUSES.index(control["status"])
            if control["status"] in VALID_CONTROL_STATUSES
            else 0
        )
        new_status = st.selectbox(
            "Implementation Status *",
            options=VALID_CONTROL_STATUSES,
            index=status_idx,
            help="Select the current evaluated implementation status according to audit evidence.",
        )

        owner = st.text_input(
            "Control Owner",
            value=control.get("control_owner") or "",
            placeholder="e.g. IT Security Lead, VP of Operations...",
        )

        obs = st.text_area(
            "Assessment Observation *",
            value=control.get("assessment_observation") or "",
            placeholder="Document detailed observations on how the control is implemented or what deficiencies were identified...",
            height=100,
            help="Mandatory for Implemented, Partially Implemented, and Not Implemented controls.",
        )

        notes = st.text_area(
            "Testing Notes & Sampling Details (Optional)",
            value=control.get("testing_notes") or "",
            placeholder="Record testing procedures, sample sizes, interviewed personnel, or system logs reviewed...",
            height=70,
        )

        ev_notes = st.text_area(
            "Evidence References (Optional)",
            value=control.get("evidence_notes") or "",
            placeholder="List reviewed policy IDs, ticket references, or audit screenshots...",
            height=60,
        )

        rec = st.text_area(
            "Remediation Recommendation *",
            value=control.get("recommendation") or "",
            placeholder="Specify corrective actions needed to reach full implementation...",
            height=80,
            help="Mandatory for Partially Implemented and Not Implemented controls.",
        )

        just = st.text_area(
            "Applicability Justification *",
            value=control.get("applicability_justification") or "",
            placeholder="Explain why this control is not applicable to the defined ISMS scope...",
            height=70,
            help="Mandatory when status is set to Not Applicable.",
        )

        # Assessor & Date fields
        c_ass1, c_ass2 = st.columns(2)
        with c_ass1:
            default_assessor = control.get("assessed_by") or assessment.get("lead_assessor") or ""
            assessor_name = st.text_input("Assessor Name *", value=default_assessor)
        with c_ass2:
            default_date = date.today()
            if control.get("assessed_at"):
                try:
                    default_date = datetime.strptime(control["assessed_at"], "%Y-%m-%d").date()
                except Exception:
                    default_date = date.today()
            ass_date = st.date_input("Assessment Date *", value=default_date)

        save_btn = st.form_submit_button(
            "Save Assessment",
            type="primary",
            use_container_width=True,
            disabled=is_archived,
        )

        if save_btn:
            if is_archived:
                st.error("Cannot modify an Archived assessment.")
                return

            date_str = ass_date.strftime("%Y-%m-%d") if ass_date else ""
            try:
                updated = update_control_assessment(
                    assessment_id=assessment["id"],
                    control_id=control["control_id"],
                    status=new_status,
                    control_owner=owner,
                    assessment_observation=obs,
                    testing_notes=notes,
                    evidence_notes=ev_notes,
                    recommendation=rec,
                    applicability_justification=just,
                    assessor_name=assessor_name,
                    assessment_date=date_str,
                )
                st.success(
                    f"Saved evaluation for control {control['control_identifier']} ({new_status})!"
                )
                st.rerun()
            except (ValueError, PermissionError) as ex:
                st.error(f"Validation Error: {str(ex)}")
            except Exception as ex:
                st.error(f"Persistence Error: {str(ex)}")
