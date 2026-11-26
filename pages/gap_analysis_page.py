"""
Gap Analysis and Audit Findings module for AuditSphere.

Enables assessors to review automatically identified implementation gaps,
failed control tests, evidence deficiencies, and formal audit findings (CCCER).
Provides full traceability from Control -> Evidence -> Testing -> Finding.
"""

import streamlit as st
import pandas as pd
from typing import Optional, Dict, Any, List

from services.assessment_service import get_assessment
from services.control_service import get_assessment_controls
from services.gap_engine import (
    identify_potential_gaps,
    get_assessment_findings,
    get_single_finding,
    create_finding,
    update_finding,
    FINDING_SEVERITIES,
    FINDING_STATUSES,
    FINDING_TYPES,
)
from ui_components import (
    render_kpi_card,
    render_severity_badge,
    render_status_badge,
    render_empty_state,
    render_educational_disclaimer,
)


def render_gap_analysis_page():
    """Render the primary Gap Analysis and Formal Findings workspace."""
    st.markdown("## Gap Analysis & Audit Findings")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.95rem; margin-top: -0.5rem;'>"
        "Identify control implementation gaps, analyze testing failures and evidence deficiencies, "
        "and manage formal non-conformity audit findings with full traceability."
        "</p>",
        unsafe_allow_html=True,
    )

    render_educational_disclaimer()

    active_id = st.session_state.get("active_assessment_id")
    if not active_id:
        render_empty_state(
            title="No Active Assessment Selected",
            message="Please select or create an assessment in the left sidebar or Assessment Management to view gaps and findings.",
        )
        return

    assessment = get_assessment(active_id)
    if not assessment:
        st.error("Active assessment could not be loaded from database.")
        return

    is_archived = assessment["status"] == "Archived"
    if is_archived:
        st.warning("This assessment is Archived. Gap analysis and findings are in read-only mode.")

    # Run automated gap identification engine
    gap_data = identify_potential_gaps(active_id)
    confirmed_findings = get_assessment_findings(active_id)

    # Top KPI metrics
    open_findings_count = sum(1 for f in confirmed_findings if f["status"] in ("Open", "Under Review", "Draft"))
    critical_high_count = sum(1 for f in confirmed_findings if f["severity"] in ("Critical", "High"))

    k1, k2, k3, k4, k5, k6 = st.columns(6)
    with k1:
        render_kpi_card("Implementation Gaps", len(gap_data["implementation_gaps"]), "Partial + Not Implemented")
    with k2:
        render_kpi_card("Failed Tests", len(gap_data["failed_tests"]), "Failed test records")
    with k3:
        render_kpi_card("Evidence Alerts", len(gap_data["evidence_deficiencies"]), "Missing / Unaccepted evidence")
    with k4:
        render_kpi_card("Pending Controls", len(gap_data["pending_controls"]), "Awaiting initial audit")
    with k5:
        render_kpi_card("Confirmed Findings", len(confirmed_findings), "Documented non-conformities")
    with k6:
        render_kpi_card("Critical / High", critical_high_count, "Elevated risk findings")

    st.markdown("<hr style='margin: 1rem 0 1.25rem 0;' />", unsafe_allow_html=True)

    tab_gaps, tab_findings, tab_create, tab_working_paper = st.tabs(
        ["Potential Gaps & Deficiencies", "Confirmed Audit Findings", "Raise New Finding", "Working-Paper Detail"]
    )

    with tab_gaps:
        _render_potential_gaps_tab(assessment, gap_data, is_archived)

    with tab_findings:
        _render_confirmed_findings_tab(assessment, confirmed_findings, is_archived)

    with tab_create:
        _render_create_finding_tab(assessment, is_archived)

    with tab_working_paper:
        _render_working_paper_tab(assessment, confirmed_findings, is_archived)


def _render_potential_gaps_tab(assessment: Dict[str, Any], gap_data: Dict[str, Any], is_archived: bool):
    """Render automated potential gaps, failed tests, and evidence deficiencies."""
    st.markdown("#### Automated Gap Analysis Diagnostics")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.85rem; margin-top: -0.5rem;'>"
        "AuditSphere automatically scans control evaluations, testing records, and evidence mappings to identify potential gaps. "
        "These items highlight audit concerns and can be promoted to formal findings when verified."
        "</p>",
        unsafe_allow_html=True,
    )

    c_gaps, c_def = st.columns([1, 1])

    with c_gaps:
        st.markdown(f"**Identified Implementation Gaps ({len(gap_data['implementation_gaps'])})**")
        if not gap_data["implementation_gaps"]:
            st.success("No implementation gaps detected. All assessed controls are evaluated as Implemented or Not Applicable.")
        else:
            for g in gap_data["implementation_gaps"]:
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 3px solid #D97706; border-radius: 3px; padding: 0.85rem; margin-bottom: 0.75rem;">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div>
                                <span style="font-weight: 700; color: #1F2937;">{g['control_identifier']} – {g['control_title']}</span>
                                <div style="font-size: 0.8rem; color: #6B7280;">Owner: <strong>{g['owner']}</strong> &bull; Status: {render_status_badge(g['status'])}</div>
                            </div>
                        </div>
                        <div style="font-size: 0.8rem; color: #991B1B; margin-top: 0.35rem; background: #FEF2F2; padding: 0.3rem 0.5rem; border-radius: 2px;">
                            <strong>Flagged:</strong> {g['flagged_reason']}
                        </div>
                        <div style="font-size: 0.825rem; color: #4B5563; margin-top: 0.35rem;">
                            <strong>Observation:</strong> {g['observation']}<br/>
                            <strong>Remediation:</strong> {g['recommendation']}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if not is_archived:
                    if st.button(f"Promote {g['control_identifier']} to Formal Finding", key=f"btn_promote_{g['control_assessment_id']}"):
                        st.session_state["prefill_gap_control_id"] = g["control_assessment_id"]
                        st.session_state["prefill_gap_title"] = f"Deficiency in {g['control_identifier']} ({g['control_title']})"
                        st.session_state["prefill_gap_cond"] = g["observation"]
                        st.session_state["prefill_gap_rec"] = g["recommendation"]
                        st.info(f"Loaded {g['control_identifier']} into 'Raise New Finding' tab above.")

    with c_def:
        st.markdown(f"**Failed Tests & Evidence Deficiencies ({len(gap_data['failed_tests']) + len(gap_data['evidence_deficiencies'])})**")

        # Failed tests
        for t in gap_data["failed_tests"]:
            st.markdown(
                f"""
                <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 3px solid #DC2626; border-radius: 3px; padding: 0.85rem; margin-bottom: 0.75rem;">
                    <div style="display: flex; justify-content: space-between;">
                        <span style="font-weight: 700; color: #DC2626;">TEST FAILURE: {t['test_reference']}</span>
                        <span style="font-size: 0.775rem; color: #6B7280;">{t['control_identifier']}</span>
                    </div>
                    <div style="font-size: 0.825rem; color: #374151; margin-top: 0.25rem;">
                        <strong>Procedure:</strong> {t['testing_procedure']}<br/>
                        <strong>Observed:</strong> {t['observed_result']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Evidence deficiencies
        if not gap_data["evidence_deficiencies"] and not gap_data["failed_tests"]:
            st.success("No evidence deficiencies or failed tests detected.")
        else:
            for d in gap_data["evidence_deficiencies"]:
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 3px solid #6B7280; border-radius: 3px; padding: 0.75rem; margin-bottom: 0.5rem; font-size: 0.825rem;">
                        <span style="font-weight: 700; color: #374151;">{d['deficiency_type']}</span>:
                        <span style="color: #4B5563;">{d['flagged_reason']}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )


def _render_confirmed_findings_tab(assessment: Dict[str, Any], findings: List[Dict[str, Any]], is_archived: bool):
    """Render table and directory of confirmed audit findings."""
    st.markdown("#### Confirmed Non-Conformities & Findings")

    f1, f2, f3 = st.columns([2.5, 1.8, 1.8])
    with f1:
        s_query = st.text_input("Search Findings", placeholder="Search by title, ID, or control...", key="fnd_search", label_visibility="collapsed")
    with f2:
        sev_filter = st.selectbox("Filter Severity", options=["All Severities"] + FINDING_SEVERITIES, key="fnd_sev_filter", label_visibility="collapsed")
    with f3:
        stat_filter = st.selectbox("Filter Status", options=["All Statuses"] + FINDING_STATUSES, key="fnd_stat_filter", label_visibility="collapsed")

    filtered_findings = get_assessment_findings(
        assessment_id=assessment["id"],
        status_filter=stat_filter,
        severity_filter=sev_filter,
        search_query=s_query,
    )

    st.markdown(f"**Found {len(filtered_findings)} finding(s)**")

    if not filtered_findings:
        render_empty_state(
            title="No Formal Findings Recorded",
            message="No findings match your current filters. Document findings using the 'Raise New Finding' tab or promote a gap.",
        )
        return

    for fnd in filtered_findings:
        f_id = fnd["id"]
        ctrl_ref = fnd.get("control_identifier") or "General"
        ctrl_title = fnd.get("control_title") or "Scope wide"

        st.markdown(
            f"""
            <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 4px solid #751C35; border-radius: 4px; padding: 1.15rem; margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <span style="font-size: 1.05rem; font-weight: 700; color: #1F2937;">{fnd['finding_identifier']} – {fnd['title']}</span>
                        <div style="font-size: 0.8rem; color: #6B7280; margin-top: 0.2rem;">
                            Control: <strong>{ctrl_ref} ({ctrl_title})</strong> &bull;
                            Classification: <strong>{fnd['finding_type']}</strong> &bull;
                            Department: <strong>{fnd.get('responsible_department') or 'Unassigned'}</strong>
                        </div>
                    </div>
                    <div style="display: flex; gap: 0.5rem; align-items: center;">
                        {render_severity_badge(fnd['severity'])}
                        {render_status_badge(fnd['status'])}
                    </div>
                </div>
                <div style="font-size: 0.85rem; color: #374151; margin-top: 0.6rem; background: #F9FAFB; padding: 0.6rem; border-radius: 3px; border: 1px solid #F3F4F6;">
                    <strong>Condition:</strong> {fnd['condition']}<br/>
                    <strong>Impact:</strong> {fnd.get('effect') or 'Unspecified'}<br/>
                    <strong>Recommendation:</strong> {fnd['recommendation']}
                </div>
                <div style="margin-top: 0.5rem; display: flex; justify-content: space-between; font-size: 0.775rem; color: #6B7280;">
                    <span>Supporting Evidence: <strong>{fnd.get('supporting_evidence_references') or 'Documented limitation'}</strong></span>
                    <span>Identified: <strong>{fnd['identified_at']}</strong> by {fnd['assessor_name']}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        b1, b2 = st.columns([1.5, 4])
        with b1:
            if st.button("View Working Paper", key=f"btn_wp_{f_id}", use_container_width=True):
                st.session_state["working_paper_finding_id"] = f_id
                st.info(f"Loaded {fnd['finding_identifier']} into 'Working-Paper Detail' tab.")


def _render_create_finding_tab(assessment: Dict[str, Any], is_archived: bool):
    """Render form to raise a formal audit finding with CCCER structure."""
    st.markdown("#### Raise Formal Audit Finding (CCCER)")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.85rem; margin-top: -0.5rem;'>"
        "Every confirmed finding must be traceable to assessment criteria, factual conditions, potential impact, "
        "and supporting evidence or a documented evidence limitation."
        "</p>",
        unsafe_allow_html=True,
    )

    if is_archived:
        st.warning("Cannot create findings for an Archived assessment.")
        return

    # Check for pre-filled data from promoted gap
    pre_ca_id = st.session_state.get("prefill_gap_control_id")
    pre_title = st.session_state.get("prefill_gap_title", "")
    pre_cond = st.session_state.get("prefill_gap_cond", "")
    pre_rec = st.session_state.get("prefill_gap_rec", "")

    # Controls mapping dropdown
    controls = get_assessment_controls(assessment["id"])
    ctrl_options = {
        f"{c['control_identifier']} – {c['control_title']}": c["assessment_control_id"]
        for c in controls
    }

    def_ctrl_idx = 0
    if pre_ca_id:
        for idx, (_, caid) in enumerate(ctrl_options.items()):
            if caid == pre_ca_id:
                def_ctrl_idx = idx
                break

    with st.form("create_formal_finding_form"):
        selected_ctrl_label = st.selectbox("Associated Security Control *", options=list(ctrl_options.keys()), index=def_ctrl_idx)
        chosen_ca_id = ctrl_options[selected_ctrl_label]

        title = st.text_input("Finding Title *", value=pre_title, placeholder="e.g. Incomplete Multi-Factor Authentication Enforcement on Cloud Console")

        c1, c2, c3 = st.columns(3)
        with c1:
            severity = st.selectbox("Severity Level *", options=FINDING_SEVERITIES, index=1)
        with c2:
            f_type = st.selectbox("Finding Classification *", options=FINDING_TYPES, index=1)
        with c3:
            dept = st.text_input("Responsible Department", placeholder="e.g. Infrastructure, IT Operations")

        criteria = st.text_area(
            "Audit Criteria (Requirement) *",
            value=f"ISO/IEC 27001:2022 requirement for {selected_ctrl_label}",
            placeholder="Document standard requirement, regulatory clause, or organizational policy clause...",
            height=65,
        )

        condition = st.text_area(
            "Observed Condition (Factual Audit Finding) *",
            value=pre_cond,
            placeholder="State the factual, verified condition observed during the assessment...",
            height=85,
        )

        cause = st.text_area(
            "Root Cause (Optional)",
            placeholder="Explain why this condition exists (e.g. legacy systems, lack of automated provisioning)...",
            height=65,
        )

        effect = st.text_area(
            "Potential Impact / Effect *",
            placeholder="Describe business, operational, or security risks resulting from this gap...",
            height=70,
        )

        recommendation = st.text_area(
            "Remediation Recommendation *",
            value=pre_rec,
            placeholder="Specific actionable corrective actions required to close this finding...",
            height=75,
        )

        r_ev1, r_ev2 = st.columns(2)
        with r_ev1:
            ev_refs = st.text_input("Supporting Evidence References *", placeholder="e.g. EVD-001, EVD-004")
        with r_ev2:
            ev_limits = st.text_input("Evidence Limitations (if no evidence available)", placeholder="e.g. Limited to sample of 10 users due to access constraints")

        test_refs = st.text_input("Supporting Control Test References (Optional)", placeholder="e.g. TST-001")
        assessor = st.text_input("Lead Assessor", value=assessment.get("lead_assessor") or "Lead Assessor")

        submit_btn = st.form_submit_button("Confirm & Register Finding", type="primary")

        if submit_btn:
            try:
                created = create_finding(
                    assessment_id=assessment["id"],
                    control_assessment_id=chosen_ca_id,
                    title=title,
                    criteria=criteria,
                    condition=condition,
                    cause=cause,
                    effect=effect,
                    recommendation=recommendation,
                    severity=severity,
                    finding_type=f_type,
                    supporting_evidence_references=ev_refs,
                    evidence_limitations=ev_limits,
                    supporting_test_references=test_refs,
                    responsible_department=dept,
                    assessor_name=assessor,
                    status="Open",
                )
                st.success(f"Formal Finding '{created['finding_identifier']} – {created['title']}' registered successfully!")
                # Clean prefill
                st.session_state.pop("prefill_gap_control_id", None)
                st.session_state.pop("prefill_gap_title", None)
                st.session_state.pop("prefill_gap_cond", None)
                st.session_state.pop("prefill_gap_rec", None)
                st.rerun()
            except ValueError as ve:
                st.error(f"Validation Error: {str(ve)}")
            except Exception as ex:
                st.error(f"Error: {str(ex)}")


def _render_working_paper_tab(assessment: Dict[str, Any], findings: List[Dict[str, Any]], is_archived: bool):
    """Render structured auditor working-paper detail showing Control -> Evidence -> Test -> Finding traceability."""
    st.markdown("#### Audit Working-Paper & Traceability View")

    if not findings:
        render_empty_state("No Findings Available", "Raise formal findings to view their structured audit working papers.")
        return

    fnd_options = {
        f"{f['finding_identifier']} – {f['title']} ({f['severity']})": f["id"]
        for f in findings
    }

    pre_id = st.session_state.get("working_paper_finding_id")
    def_idx = 0
    if pre_id:
        for idx, (_, fid) in enumerate(fnd_options.items()):
            if fid == pre_id:
                def_idx = idx
                break

    sel_label = st.selectbox("Select Finding Working Paper", options=list(fnd_options.keys()), index=def_idx)
    target_fid = fnd_options[sel_label]
    fnd = get_single_finding(target_fid)
    if not fnd:
        st.error("Finding record could not be loaded.")
        return

    # Structured Working Paper Card
    st.markdown(
        f"""
        <div style="background: #FFFFFF; border: 1px solid #751C35; border-radius: 4px; padding: 1.5rem; margin-bottom: 1.25rem;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 1px solid #E5E7EB; padding-bottom: 0.75rem;">
                <div>
                    <div style="font-size: 0.8rem; font-weight: 700; color: #751C35; text-transform: uppercase;">
                        ISMS Audit Working Paper &bull; {fnd['finding_identifier']}
                    </div>
                    <div style="font-size: 1.35rem; font-weight: 700; color: #1F2937; margin-top: 0.2rem;">
                        {fnd['title']}
                    </div>
                    <div style="font-size: 0.825rem; color: #6B7280; margin-top: 0.25rem;">
                        Classification: <strong>{fnd['finding_type']}</strong> &bull;
                        Assessor: <strong>{fnd['assessor_name']}</strong> &bull;
                        Identified Date: <strong>{fnd['identified_at']}</strong>
                    </div>
                </div>
                <div style="display: flex; gap: 0.5rem; align-items: center;">
                    {render_severity_badge(fnd['severity'])}
                    {render_status_badge(fnd['status'])}
                </div>
            </div>

            <!-- Traceability Hierarchy -->
            <div style="background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 3px; padding: 0.85rem; margin: 1rem 0; font-size: 0.85rem;">
                <div style="font-weight: 700; color: #374151; margin-bottom: 0.4rem;">Audit Traceability Chain:</div>
                <div><strong>1. Security Control:</strong> {fnd.get('control_identifier') or 'General'} – {fnd.get('control_title') or 'ISMS Boundary'}</div>
                <div><strong>2. Supporting Evidence:</strong> {fnd.get('supporting_evidence_references') or 'Explicitly documented evidence limitation'}</div>
                <div><strong>3. Testing Procedures:</strong> {fnd.get('supporting_test_references') or 'Design walkthrough / inspection review'}</div>
                <div><strong>4. Resulting Finding:</strong> {fnd['finding_identifier']} ({fnd['severity']})</div>
            </div>

            <!-- CCCER Sections -->
            <div style="font-size: 0.875rem; color: #1F2937; line-height: 1.6;">
                <p><strong>Criteria (The Standard):</strong><br/><span style="color: #4B5563;">{fnd['criteria']}</span></p>
                <p><strong>Condition (What was Found):</strong><br/><span style="color: #4B5563;">{fnd['condition']}</span></p>
                {f'''<p><strong>Root Cause:</strong><br/><span style="color: #4B5563;">{fnd['cause']}</span></p>''' if fnd.get('cause') else ''}
                <p><strong>Effect / Potential Impact (The Risk):</strong><br/><span style="color: #4B5563;">{fnd['effect']}</span></p>
                <p><strong>Remediation Recommendation (Corrective Action):</strong><br/><span style="color: #4B5563;">{fnd['recommendation']}</span></p>
                {f'''<p style="background: #FFFBEB; border: 1px solid #FDE68A; padding: 0.5rem; border-radius: 3px;"><strong>Evidence Limitations:</strong><br/>{fnd['evidence_limitations']}</p>''' if fnd.get('evidence_limitations') else ''}
                {f'''<p style="background: #F0FDF4; border: 1px solid #BBF7D0; padding: 0.5rem; border-radius: 3px;"><strong>Closure Verification Notes:</strong><br/>{fnd['verification_notes']}</p>''' if fnd.get('verification_notes') else ''}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Edit & Status Management Form
    if not is_archived:
        with st.expander(f"Manage Finding Status & Update Details ({fnd['finding_identifier']})"):
            with st.form(f"edit_finding_{fnd['id']}"):
                title_edit = st.text_input("Title *", value=fnd["title"])
                e_col1, e_col2, e_col3 = st.columns(3)
                with e_col1:
                    sev_edit = st.selectbox("Severity", options=FINDING_SEVERITIES, index=FINDING_SEVERITIES.index(fnd["severity"]))
                with e_col2:
                    type_edit = st.selectbox("Type", options=FINDING_TYPES, index=FINDING_TYPES.index(fnd["finding_type"]))
                with e_col3:
                    stat_edit = st.selectbox("Status", options=FINDING_STATUSES, index=FINDING_STATUSES.index(fnd["status"]))

                crit_edit = st.text_area("Criteria *", value=fnd["criteria"], height=60)
                cond_edit = st.text_area("Condition *", value=fnd["condition"], height=70)
                cause_edit = st.text_area("Cause", value=fnd.get("cause") or "", height=60)
                eff_edit = st.text_area("Effect / Impact *", value=fnd.get("effect") or "", height=60)
                rec_edit = st.text_area("Recommendation *", value=fnd["recommendation"], height=65)

                ver_notes = st.text_area(
                    "Verification Notes (Required if setting Status to 'Closed') *",
                    value=fnd.get("verification_notes") or "",
                    placeholder="Document audit verification proving this finding has been validated and remediated...",
                    height=70,
                )

                update_btn = st.form_submit_button("Update Finding Record", type="primary")

                if update_btn:
                    try:
                        update_finding(
                            finding_id=fnd["id"],
                            title=title_edit,
                            criteria=crit_edit,
                            condition=cond_edit,
                            effect=eff_edit,
                            recommendation=rec_edit,
                            severity=sev_edit,
                            finding_type=type_edit,
                            status=stat_edit,
                            cause=cause_edit,
                            supporting_evidence_references=fnd.get("supporting_evidence_references"),
                            evidence_limitations=fnd.get("evidence_limitations"),
                            verification_notes=ver_notes,
                        )
                        st.success(f"Finding {fnd['finding_identifier']} updated successfully!")
                        st.rerun()
                    except ValueError as ve:
                        st.error(f"Validation Error: {str(ve)}")
                    except Exception as ex:
                        st.error(f"Error: {str(ex)}")
