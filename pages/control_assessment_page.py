"""
ISO/IEC 27001:2022 Control Assessment Page for AuditSphere.

Enables assessors to review, filter, and evaluate the 20 selected Annex A controls,
document observations and testing notes, provide remediation recommendations,
map evidence artifacts, execute control testing, track findings, and compute
real-time readiness and gap metrics.
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
from services.evidence_manager import (
    get_assessment_evidence,
    map_evidence_to_control,
    unmap_evidence_from_control,
    upload_evidence,
    get_evidence_file_bytes,
)
from services.gap_engine import (
    create_control_test,
    get_control_tests,
    create_finding,
    get_assessment_findings,
    TEST_TYPES,
    TEST_CONCLUSIONS,
    FINDING_SEVERITIES,
    FINDING_TYPES,
)
from ui_components import (
    render_kpi_card,
    render_status_badge,
    render_review_badge,
    render_integrity_badge,
    render_conclusion_badge,
    render_severity_badge,
    render_empty_state,
    render_educational_disclaimer,
)


def render_control_assessment_page():
    """Render the primary ISO 27001 selected-control assessment engine."""
    st.markdown("## ISO 27001 Control Assessment")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.95rem; margin-top: -0.5rem;'>"
        "Evaluate security controls across the 4 Annex A themes (Organizational, People, Physical, Technological), "
        "document testing notes and observations, map evidence, record testing, and track readiness posture."
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
        if st.button("Load Demo Data (FinCore)", use_container_width=True, help="Load the official demonstration dataset for FinCore Technologies."):
            demo = create_fincore_demo_assessment()
            st.session_state["active_assessment_id"] = demo["assessment"]["id"]
            st.success("Loaded FinCore demonstration assessment.")
            st.rerun()

    if is_archived:
        st.warning("This assessment is Archived. All control records are in read-only mode and cannot be modified.")

    # Fetch all controls for this assessment
    all_controls = get_assessment_controls(assessment_id=active_id)
    metrics = calculate_overall_metrics(all_controls)
    status_counts = metrics["status_counts"]

    # Readiness & Coverage Metrics Row
    m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
    with m_col1:
        render_kpi_card("Selected Controls", f"{metrics['total_controls']} / 20", "Educational Annex A subset")
    with m_col2:
        cov_val = f"{metrics['coverage_pct']:.1f}%" if metrics["coverage_pct"] is not None else "N/A"
        render_kpi_card("Assessment Coverage", cov_val, f"{metrics['assessed_controls']} of {metrics['applicable_controls']} applicable assessed")
    with m_col3:
        read_val = f"{metrics['weighted_readiness_pct']:.1f}%" if metrics["weighted_readiness_pct"] is not None else "N/A"
        render_kpi_card("Weighted Readiness", read_val, "Score across assessed controls")
    with m_col4:
        render_kpi_card("Potential Gaps", metrics["potential_gaps"], "Partial + Not Implemented")
    with m_col5:
        render_kpi_card("Pending Controls", metrics["pending_controls"], "Controls in 'Not Assessed'")

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

    # Split layout: Directory on left, Evaluation / Evidence / Testing workspace on right
    left_col, right_col = st.columns([6, 6])

    if "selected_control_id" not in st.session_state:
        st.session_state["selected_control_id"] = (
            filtered_controls[0]["control_id"] if filtered_controls else 1
        )

    with left_col:
        st.markdown(f"**Selected Annex A Controls Catalogue ({len(filtered_controls)} matching)**")

        if not filtered_controls:
            render_empty_state(
                title="No Controls Found",
                message="No controls match your filter criteria.",
            )
        else:
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

                if st.button(
                    f"Select {c['control_identifier']}" if not is_selected else f"Viewing {c['control_identifier']}",
                    key=f"btn_select_ctrl_{c['control_id']}",
                    use_container_width=True,
                    disabled=is_selected,
                ):
                    st.session_state["selected_control_id"] = c["control_id"]
                    st.rerun()

                st.markdown("<div style='margin-bottom: 0.35rem;'></div>", unsafe_allow_html=True)

    with right_col:
        selected_cid = st.session_state.get("selected_control_id", 1)
        selected_ctrl = get_single_control_assessment(assessment_id=active_id, control_id=selected_cid)

        if not selected_ctrl:
            render_empty_state("Select a Control", "Click 'Select' on any control to evaluate or view testing records.")
            return

        _render_control_detail_tabs(assessment, selected_ctrl, is_archived)


def _render_control_detail_tabs(assessment: Dict[str, Any], control: Dict[str, Any], is_archived: bool):
    """Render the tabbed workspace for a selected control: Evaluation, Mapped Evidence, Testing, Findings."""
    st.markdown(
        f"""
        <div style="background-color: #FFFFFF; border: 1px solid #751C35; border-radius: 4px; padding: 1.15rem; margin-bottom: 1rem;">
            <div style="font-size: 0.75rem; font-weight: 700; color: #751C35; text-transform: uppercase; letter-spacing: 0.05em;">
                Control Workspace
            </div>
            <div style="font-size: 1.25rem; font-weight: 700; color: #1F2937; margin-top: 0.2rem;">
                {control['control_identifier']} – {control['control_title']}
            </div>
            <div style="font-size: 0.8rem; color: #6B7280; margin-top: 0.2rem; margin-bottom: 0.65rem;">
                {control['clause']} &bull; Theme: <strong>{control['category']}</strong> &bull; Current Status: {render_status_badge(control['status'])}
            </div>
            <div style="font-size: 0.85rem; color: #374151; background: #F9FAFB; padding: 0.65rem; border-radius: 3px; border: 1px solid #F3F4F6; margin-bottom: 0.65rem;">
                <strong>Objective:</strong> {control.get('objective', '')}
            </div>
            <div style="font-size: 0.825rem; color: #4B5563; line-height: 1.5;">
                {control['control_description']}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    t_eval, t_evidence, t_testing, t_findings, t_remediation = st.tabs(
        ["Control Evaluation", "Mapped Evidence", "Control Testing", "Findings & Gaps", "Corrective Actions & Reassessment"]
    )

    with t_eval:
        _render_evaluation_form(assessment, control, is_archived)

    with t_evidence:
        _render_mapped_evidence_subtab(assessment, control, is_archived)

    with t_testing:
        _render_testing_subtab(assessment, control, is_archived)

    with t_findings:
        _render_findings_subtab(assessment, control, is_archived)

    with t_remediation:
        _render_remediation_subtab(assessment, control, is_archived)


def _render_evaluation_form(assessment: Dict[str, Any], control: Dict[str, Any], is_archived: bool):
    """Render the evaluation and observation entry form."""
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

    form_key = f"eval_form_{assessment['id']}_{control['control_id']}"
    with st.form(key=form_key):
        st.markdown("##### Record Assessor Evaluation")

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

        save_btn = st.form_submit_button("Save Assessment", type="primary", use_container_width=True, disabled=is_archived)

        if save_btn:
            if is_archived:
                st.error("Cannot modify an Archived assessment.")
                return

            date_str = ass_date.strftime("%Y-%m-%d") if ass_date else ""
            try:
                update_control_assessment(
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
                st.success(f"Saved evaluation for control {control['control_identifier']} ({new_status})!")
                st.rerun()
            except (ValueError, PermissionError) as ex:
                st.error(f"Validation Error: {str(ex)}")
            except Exception as ex:
                st.error(f"Persistence Error: {str(ex)}")


def _render_mapped_evidence_subtab(assessment: Dict[str, Any], control: Dict[str, Any], is_archived: bool):
    """Render mapped evidence artifacts and mapping controls for the selected control."""
    st.markdown("##### Supporting Audit Evidence")

    ca_id = control["assessment_control_id"]
    all_ev = get_assessment_evidence(assessment["id"])

    # Find evidence mapped to this control
    mapped_ev = [
        e for e in all_ev
        if any(c["control_identifier"] == control["control_identifier"] for c in e.get("mapped_controls", []))
    ]

    accepted_count = sum(1 for e in mapped_ev if e["review_status"] == "Accepted")
    st.markdown(
        f"<div style='font-size: 0.85rem; color: #4B5563; margin-bottom: 0.75rem;'>"
        f"<strong>Mapped Artifacts:</strong> {len(mapped_ev)} &nbsp;|&nbsp; "
        f"<strong>Accepted Evidence:</strong> {accepted_count} &nbsp;|&nbsp; "
        f"<strong>Pending/Rejected:</strong> {len(mapped_ev) - accepted_count}"
        f"</div>",
        unsafe_allow_html=True,
    )

    if not mapped_ev:
        st.info("No evidence files are currently mapped to this control.")
    else:
        for ev in mapped_ev:
            st.markdown(
                f"""
                <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 3px; padding: 0.75rem 0.9rem; margin-bottom: 0.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="font-weight: 700; color: #1F2937;">{ev['evidence_identifier']} – {ev['title']}</span>
                            <div style="font-size: 0.775rem; color: #6B7280;">Type: {ev['evidence_type']} &bull; File: <code>{ev.get('original_file_name') or ev['file_name']}</code></div>
                        </div>
                        <div style="display: flex; gap: 0.4rem;">
                            {render_review_badge(ev['review_status'])}
                            {render_integrity_badge(ev.get('integrity_status', 'Not yet verified'))}
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Unmap action
            if not is_archived:
                if st.button(f"Unlink {ev['evidence_identifier']}", key=f"btn_unmap_{ev['id']}_{ca_id}"):
                    unmap_evidence_from_control(ev["id"], ca_id)
                    st.success(f"Unmapped {ev['evidence_identifier']}.")
                    st.rerun()

    st.markdown("<hr style='margin: 1rem 0;' />", unsafe_allow_html=True)

    # Link existing evidence
    if not is_archived:
        st.markdown("###### Map Existing Evidence File")
        unmapped_ev = [
            e for e in all_ev
            if not any(c["control_identifier"] == control["control_identifier"] for c in e.get("mapped_controls", []))
        ]
        if unmapped_ev:
            ev_map_options = {
                f"{e['evidence_identifier']} – {e['title']} ({e['review_status']})": e["id"]
                for e in unmapped_ev
            }
            selected_to_map = st.selectbox("Select Evidence Artifact to Link", options=list(ev_map_options.keys()))
            if st.button("Link Evidence to Control", key="btn_link_ev"):
                target_ev_id = ev_map_options[selected_to_map]
                map_evidence_to_control(target_ev_id, ca_id, notes=f"Mapped to {control['control_identifier']}")
                st.success(f"Successfully linked evidence to {control['control_identifier']}!")
                st.rerun()
        else:
            st.caption("All existing evidence files in this assessment are already linked to this control.")


def _render_testing_subtab(assessment: Dict[str, Any], control: Dict[str, Any], is_archived: bool):
    """Render control testing records and new test execution form."""
    st.markdown("##### Control Testing Records")

    ca_id = control["assessment_control_id"]
    tests = get_control_tests(assessment["id"], control_assessment_id=ca_id)

    if not tests:
        st.info("No testing records have been documented for this control yet.")
    else:
        for t in tests:
            st.markdown(
                f"""
                <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 3px solid #751C35; border-radius: 3px; padding: 0.85rem; margin-bottom: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <span style="font-weight: 700; color: #1F2937;">{t['test_reference']} – {t['test_type']}</span>
                            <div style="font-size: 0.8rem; color: #6B7280;">Date: {t['testing_date']} &bull; Assessor: {t['assessor_name']}</div>
                        </div>
                        <div>
                            {render_conclusion_badge(t['conclusion'])}
                        </div>
                    </div>
                    <div style="font-size: 0.825rem; color: #374151; margin-top: 0.4rem;">
                        <strong>Objective:</strong> {t['testing_objective']}<br/>
                        <strong>Procedure:</strong> {t['testing_procedure']}<br/>
                        <strong>Observed:</strong> {t['observed_result']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<hr style='margin: 1rem 0;' />", unsafe_allow_html=True)

    # Record new test form
    if not is_archived:
        with st.expander("Record New Control Test", expanded=False):
            with st.form(f"new_test_form_{ca_id}"):
                c1, c2 = st.columns(2)
                with c1:
                    test_type = st.selectbox("Test Type *", options=TEST_TYPES)
                    conclusion = st.selectbox("Conclusion *", options=TEST_CONCLUSIONS)
                with c2:
                    t_date = st.date_input("Testing Date *", value=date.today())
                    assessor = st.text_input("Assessor *", value=assessment.get("lead_assessor") or "Lead Assessor")

                obj = st.text_input("Testing Objective *", placeholder="e.g. Verify that MFA is enforced across all privileged access endpoints.")
                proc = st.text_area("Testing Procedure *", placeholder="Document testing steps, inspected configs, or staff interviewed...")
                exp = st.text_input("Expected Result *", placeholder="e.g. 100% of sampled administrative logins require hardware token MFA.")
                obs = st.text_area("Observed Result *", placeholder="e.g. 2 out of 10 sampled accounts allowed single-factor password bypass.")
                ev_refs = st.text_input("Supporting Evidence References", placeholder="e.g. EVD-002, EVD-005")

                save_test_btn = st.form_submit_button("Record Test Result", type="primary")

                if save_test_btn:
                    date_str = t_date.strftime("%Y-%m-%d") if t_date else ""
                    try:
                        create_control_test(
                            assessment_id=assessment["id"],
                            control_assessment_id=ca_id,
                            test_type=test_type,
                            testing_objective=obj,
                            testing_procedure=proc,
                            expected_result=exp,
                            observed_result=obs,
                            conclusion=conclusion,
                            supporting_evidence_references=ev_refs,
                            assessor_name=assessor,
                            testing_date=date_str,
                        )
                        st.success(f"Control test recorded ({conclusion})!")
                        st.rerun()
                    except ValueError as ve:
                        st.error(f"Validation Error: {str(ve)}")
                    except Exception as ex:
                        st.error(f"Error: {str(ex)}")


def _render_remediation_subtab(assessment: Dict[str, Any], control: Dict[str, Any], is_archived: bool):
    """Render linked corrective actions and explicit control reassessment workflow."""
    from services.remediation_service import (
        get_control_remediations,
        get_remediation_verifications,
        get_remediation_evidence,
    )

    ca_id = control["assessment_control_id"]
    linked_actions = get_control_remediations(ca_id)

    st.markdown("##### Linked Corrective Actions & Remediation Status")
    st.caption("Review implemented corrective actions and verified evidence before updating control posture.")

    if not linked_actions:
        st.info("No corrective actions currently linked to this control.")
    else:
        for act in linked_actions:
            v_list = get_remediation_verifications(act["id"])
            v_res = v_list[0]["verification_result"] if v_list else "Unverified"
            ev_list = get_remediation_evidence(act["id"])

            st.markdown(
                f"""
                <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 3px solid #751C35; padding: 0.85rem 1rem; border-radius: 3px; margin-bottom: 0.65rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong>{act['remediation_identifier']} – {act['action_title']} ({act['action_priority']})</strong>
                        <span style="font-size: 0.8rem; padding: 0.2rem 0.5rem; background: #EFF6FF; border-radius: 2px;">
                            Status: <strong>{act['status']}</strong> &bull; Progress: <strong>{act['progress_percentage']}%</strong>
                        </span>
                    </div>
                    <div style="font-size: 0.825rem; color: #4B5563; margin-top: 0.35rem;">
                        <strong>Owner:</strong> {act['action_owner']} &bull;
                        <strong>Target Date:</strong> {act['target_date']} &bull;
                        <strong>Latest Verification:</strong> <strong>{v_res}</strong>
                    </div>
                    <div style="font-size: 0.8rem; color: #6B7280; margin-top: 0.25rem;">
                        <strong>Remediation Evidence:</strong> {', '.join([e['title'] for e in ev_list]) if ev_list else 'None linked'}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<hr style='margin: 1.25rem 0;' />", unsafe_allow_html=True)
    st.markdown("##### 🔄 Explicit Control Reassessment")
    st.caption(
        "Closing corrective actions does not automatically mark controls as Implemented. "
        "The assessor must review evidence and record updated assessment observations."
    )

    if is_archived:
        st.warning("Cannot reassess control in an Archived assessment.")
        return

    with st.form(f"reassess_ctrl_form_{ca_id}"):
        curr_status_idx = (
            VALID_CONTROL_STATUSES.index(control["status"])
            if control["status"] in VALID_CONTROL_STATUSES
            else 0
        )
        reass_status = st.selectbox(
            "Reassessed Implementation Status *",
            options=VALID_CONTROL_STATUSES,
            index=curr_status_idx,
        )

        reass_obs = st.text_area(
            "Updated Assessment Observation *",
            value=control.get("assessment_observation") or "",
            placeholder="Document how remediation evidence confirms control implementation...",
            height=90,
        )

        reass_rec = st.text_area(
            "Outstanding Recommendations (if not fully implemented)",
            value=control.get("recommendation") or "",
            placeholder="Remaining gaps or ongoing monitoring requirements...",
            height=60,
        )

        reass_btn = st.form_submit_button("Save Reassessed Control Status", type="primary")

        if reass_btn:
            try:
                update_control_assessment(
                    control_assessment_id=ca_id,
                    status=reass_status,
                    assessment_observation=reass_obs,
                    recommendation=reass_rec,
                    assessor_name=assessment.get("lead_assessor") or "Lead Assessor",
                    assessment_date=date.today().isoformat(),
                )
                st.success(f"Control {control['control_identifier']} reassessed successfully to '{reass_status}'!")
                st.rerun()
            except Exception as ex:
                st.error(f"Error reassessing control: {ex}")


def _render_findings_subtab(assessment: Dict[str, Any], control: Dict[str, Any], is_archived: bool):
    """Render audit findings linked to the selected control and form to create a finding."""
    st.markdown("##### Linked Audit Findings")

    ca_id = control["assessment_control_id"]
    findings = [
        f for f in get_assessment_findings(assessment["id"])
        if f.get("control_assessment_id") == ca_id
    ]

    if not findings:
        st.info("No formal findings are linked to this control.")
    else:
        for fnd in findings:
            st.markdown(
                f"""
                <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 3px solid #DC2626; border-radius: 3px; padding: 0.85rem; margin-bottom: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <span style="font-weight: 700; color: #1F2937;">{fnd['finding_identifier']} – {fnd['title']}</span>
                            <div style="font-size: 0.8rem; color: #6B7280;">Type: {fnd['finding_type']} &bull; Status: {fnd['status']}</div>
                        </div>
                        <div>
                            {render_severity_badge(fnd['severity'])}
                        </div>
                    </div>
                    <div style="font-size: 0.825rem; color: #374151; margin-top: 0.4rem;">
                        <strong>Condition:</strong> {fnd.get('condition') or fnd.get('description')}<br/>
                        <strong>Impact:</strong> {fnd.get('effect') or 'Unspecified'}<br/>
                        <strong>Recommendation:</strong> {fnd.get('recommendation')}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<hr style='margin: 1rem 0;' />", unsafe_allow_html=True)

    if not is_archived:
        with st.expander("Raise Formal Audit Finding for This Control", expanded=False):
            with st.form(f"create_fnd_ctrl_{ca_id}"):
                title = st.text_input("Finding Title *", placeholder="e.g. Single-Factor Password Access Permitted on Administrative Endpoints")
                f1, f2 = st.columns(2)
                with f1:
                    sev = st.selectbox("Severity *", options=FINDING_SEVERITIES, index=1)
                    f_type = st.selectbox("Finding Classification *", options=FINDING_TYPES, index=1)
                with f2:
                    dept = st.text_input("Responsible Department", placeholder="e.g. Cloud Infrastructure, IT")
                    f_status = st.selectbox("Initial Finding Status", options=["Open", "Draft"])

                crit = st.text_area(
                    "Assessment Criteria *",
                    value=f"ISO/IEC 27001:2022 {control['clause']} {control['control_identifier']} ({control['control_title']})",
                    height=60,
                )
                cond = st.text_area(
                    "Observed Condition *",
                    value=control.get("assessment_observation") or "",
                    placeholder="Describe the factual condition observed during the assessment...",
                    height=70,
                )
                eff = st.text_area(
                    "Potential Impact / Effect *",
                    placeholder="Explain business, security, or compliance risk resulting from this condition...",
                    height=60,
                )
                rec = st.text_area(
                    "Remediation Recommendation *",
                    value=control.get("recommendation") or "",
                    placeholder="Document required corrective actions...",
                    height=60,
                )
                ev_ref = st.text_input("Supporting Evidence References *", value=control.get("evidence_notes") or "", placeholder="e.g. EVD-001, EVD-003")
                ev_lim = st.text_input("Documented Evidence Limitations (if no evidence available)", placeholder="e.g. Assessor denied access to live production logs")

                submit_fnd = st.form_submit_button("Confirm Audit Finding", type="primary")

                if submit_fnd:
                    try:
                        create_finding(
                            assessment_id=assessment["id"],
                            control_assessment_id=ca_id,
                            title=title,
                            criteria=crit,
                            condition=cond,
                            effect=eff,
                            recommendation=rec,
                            severity=sev,
                            finding_type=f_type,
                            responsible_department=dept,
                            supporting_evidence_references=ev_ref,
                            evidence_limitations=ev_lim,
                            status=f_status,
                            assessor_name=assessment.get("lead_assessor") or "Lead Assessor",
                        )
                        st.success("Formal audit finding created and linked!")
                        st.rerun()
                    except ValueError as ve:
                        st.error(f"Validation Error: {str(ve)}")
                    except Exception as ex:
                        st.error(f"Error: {str(ex)}")


def _render_remediation_subtab(assessment: Dict[str, Any], control: Dict[str, Any], is_archived: bool):
    """Render linked corrective actions and explicit control reassessment workflow."""
    from services.remediation_service import (
        get_control_remediations,
        get_remediation_verifications,
        get_remediation_evidence,
    )

    ca_id = control["assessment_control_id"]
    linked_actions = get_control_remediations(ca_id)

    st.markdown("##### Linked Corrective Actions & Remediation Status")
    st.caption("Review implemented corrective actions and verified evidence before updating control posture.")

    if not linked_actions:
        st.info("No corrective actions currently linked to this control.")
    else:
        for act in linked_actions:
            v_list = get_remediation_verifications(act["id"])
            v_res = v_list[0]["verification_result"] if v_list else "Unverified"
            ev_list = get_remediation_evidence(act["id"])

            st.markdown(
                f"""
                <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 3px solid #751C35; padding: 0.85rem 1rem; border-radius: 3px; margin-bottom: 0.65rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong>{act['remediation_identifier']} – {act['action_title']} ({act['action_priority']})</strong>
                        <span style="font-size: 0.8rem; padding: 0.2rem 0.5rem; background: #EFF6FF; border-radius: 2px;">
                            Status: <strong>{act['status']}</strong> &bull; Progress: <strong>{act['progress_percentage']}%</strong>
                        </span>
                    </div>
                    <div style="font-size: 0.825rem; color: #4B5563; margin-top: 0.35rem;">
                        <strong>Owner:</strong> {act['action_owner']} &bull;
                        <strong>Target Date:</strong> {act['target_date']} &bull;
                        <strong>Latest Verification:</strong> <strong>{v_res}</strong>
                    </div>
                    <div style="font-size: 0.8rem; color: #6B7280; margin-top: 0.25rem;">
                        <strong>Remediation Evidence:</strong> {', '.join([e['title'] for e in ev_list]) if ev_list else 'None linked'}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<hr style='margin: 1.25rem 0;' />", unsafe_allow_html=True)
    st.markdown("##### 🔄 Explicit Control Reassessment")
    st.caption(
        "Closing corrective actions does not automatically mark controls as Implemented. "
        "The assessor must review evidence and record updated assessment observations."
    )

    if is_archived:
        st.warning("Cannot reassess control in an Archived assessment.")
        return

    with st.form(f"reassess_ctrl_form_{ca_id}"):
        curr_status_idx = (
            VALID_CONTROL_STATUSES.index(control["status"])
            if control["status"] in VALID_CONTROL_STATUSES
            else 0
        )
        reass_status = st.selectbox(
            "Reassessed Implementation Status *",
            options=VALID_CONTROL_STATUSES,
            index=curr_status_idx,
        )

        reass_obs = st.text_area(
            "Updated Assessment Observation *",
            value=control.get("assessment_observation") or "",
            placeholder="Document how remediation evidence confirms control implementation...",
            height=90,
        )

        reass_rec = st.text_area(
            "Outstanding Recommendations (if not fully implemented)",
            value=control.get("recommendation") or "",
            placeholder="Remaining gaps or ongoing monitoring requirements...",
            height=60,
        )

        reass_btn = st.form_submit_button("Save Reassessed Control Status", type="primary")

        if reass_btn:
            try:
                update_control_assessment(
                    control_assessment_id=ca_id,
                    status=reass_status,
                    assessment_observation=reass_obs,
                    recommendation=reass_rec,
                    assessor_name=assessment.get("lead_assessor") or "Lead Assessor",
                    assessment_date=date.today().isoformat(),
                )
                st.success(f"Control {control['control_identifier']} reassessed successfully to '{reass_status}'!")
                st.rerun()
            except Exception as ex:
                st.error(f"Error reassessing control: {ex}")
