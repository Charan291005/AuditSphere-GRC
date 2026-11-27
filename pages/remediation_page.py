"""
AuditSphere – Remediation Tracker Page
Comprehensive Corrective Action Management, Root Cause Analysis (5 Whys),
Progress Tracking, Deadline Management, Effectiveness Verification, and Audit Working Papers.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any, Dict, List, Optional

import pandas as pd
import streamlit as st

from database import db_session
from services.assessment_service import get_assessment
from services.evidence_manager import get_assessment_evidence
from services.gap_engine import get_assessment_findings
from services.remediation_engine import (
    VALID_PRIORITIES,
    VALID_RCA_METHODS,
    VALID_STATUSES,
    VALID_VERIFICATION_RESULTS,
    calculate_remediation_metrics,
    export_remediations_to_csv,
    suggest_priority_from_source,
    validate_status_transition,
)
from services.remediation_service import (
    cancel_remediation,
    close_remediation,
    create_remediation,
    extend_deadline,
    get_assessment_remediations,
    get_remediation_controls,
    get_remediation_deadline_extensions,
    get_remediation_evidence,
    get_remediation_findings,
    get_remediation_progress_history,
    get_remediation_risks,
    get_remediation_verifications,
    get_single_remediation,
    link_control_to_remediation,
    link_evidence_to_remediation,
    link_finding_to_remediation,
    link_risk_to_remediation,
    record_progress_update,
    record_verification,
    reopen_remediation,
    unlink_control_from_remediation,
    unlink_evidence_from_remediation,
    unlink_finding_from_remediation,
    unlink_risk_from_remediation,
    update_remediation,
)
from services.risk_service import get_assessment_risks
from ui_components import render_educational_disclaimer, render_section_header


def render_remediation_page() -> None:
    """Render the Remediation & Corrective Action Management workspace."""
    st.markdown(
        """
        <div style="margin-bottom: 1rem;">
            <h1 style="color: #751C35; margin-bottom: 0.25rem;">Remediation & Corrective Action Tracker</h1>
            <p style="color: #6B7280; font-size: 0.95rem;">
                Manage security corrective actions, investigate root causes (5 Whys), track implementation progress,
                verify audit effectiveness, and maintain complete lifecycle traceability.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    render_educational_disclaimer()

    active_id = st.session_state.get("active_assessment_id")
    if not active_id:
        st.warning("⚠️ No assessment workspace currently selected. Please select or create an assessment.")
        return

    assessment = get_assessment(active_id)
    if not assessment:
        st.error(f"Assessment #{active_id} could not be retrieved.")
        return

    is_archived = bool(assessment.get("is_archived") or assessment.get("status") == "Archived")
    if is_archived:
        st.warning(
            "🔒 **Assessment Archived**: This assessment workspace is archived. "
            "Remediation records and verifications are preserved in read-only mode."
        )

    # Load records & calculate metrics
    remediations = get_assessment_remediations(active_id)
    metrics = calculate_remediation_metrics(remediations)

    # -------------------------------------------------------------
    # Top KPI Metrics Cards
    # -------------------------------------------------------------
    c1, c2, c3, c4, c5, c6, c7 = st.columns(7)

    with c1:
        st.markdown(
            f"""
            <div class="grc-kpi-card">
                <div class="grc-kpi-label">Total Actions</div>
                <div class="grc-kpi-value">{metrics['total_actions']}</div>
                <div class="grc-kpi-desc">Registered actions</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            f"""
            <div class="grc-kpi-card">
                <div class="grc-kpi-label">Open</div>
                <div class="grc-kpi-value">{metrics['open']}</div>
                <div class="grc-kpi-desc">Awaiting start</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c3:
        st.markdown(
            f"""
            <div class="grc-kpi-card">
                <div class="grc-kpi-label">In Progress</div>
                <div class="grc-kpi-value">{metrics['in_progress']}</div>
                <div class="grc-kpi-desc">Under treatment</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c4:
        st.markdown(
            f"""
            <div class="grc-kpi-card">
                <div class="grc-kpi-label">Awaiting Verif</div>
                <div class="grc-kpi-value" style="color: #B45309;">{metrics['awaiting_verification']}</div>
                <div class="grc-kpi-desc">Completed 100%</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c5:
        st.markdown(
            f"""
            <div class="grc-kpi-card">
                <div class="grc-kpi-label">Closed</div>
                <div class="grc-kpi-value" style="color: #15803D;">{metrics['closed']}</div>
                <div class="grc-kpi-desc">Verified effective</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c6:
        overdue_style = "color: #DC2626;" if metrics["overdue"] > 0 else "color: #1F2937;"
        st.markdown(
            f"""
            <div class="grc-kpi-card">
                <div class="grc-kpi-label">Overdue</div>
                <div class="grc-kpi-value" style="{overdue_style}">{metrics['overdue']}</div>
                <div class="grc-kpi-desc">Past target date</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c7:
        closure_rate_str = (
            f"{metrics['verified_closure_rate']}%"
            if metrics["verified_closure_rate"] is not None
            else "N/A"
        )
        st.markdown(
            f"""
            <div class="grc-kpi-card">
                <div class="grc-kpi-label">Closure Rate</div>
                <div class="grc-kpi-value" style="color: #751C35;">{closure_rate_str}</div>
                <div class="grc-kpi-desc">Verified / Active</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Deadline Alerts Bar
    if metrics["overdue"] > 0:
        overdue_items = [
            f"**{r['remediation_identifier']}** ('{r['action_title']}' – Due: {r['target_date']})"
            for r in remediations
            if r.get("status") not in ("Closed", "Cancelled")
            and r.get("target_date")
            and r.get("target_date") < metrics["reference_date"]
        ]
        st.error(f"🚨 **Overdue Corrective Actions ({metrics['overdue']}):** " + ", ".join(overdue_items))

    if metrics["due_today"] > 0 or metrics["due_in_7_days"] > 0:
        st.info(
            f"📅 **Upcoming Deadlines:** {metrics['due_today']} action(s) due today, "
            f"{metrics['due_in_7_days']} action(s) due within the next 7 days."
        )

    # -------------------------------------------------------------
    # Workspace Tabs
    # -------------------------------------------------------------
    tab_reg, tab_form, tab_detail, tab_actions = st.tabs(
        [
            "📋 Action Register",
            "✏️ Corrective Action Form",
            "📑 Working Paper Detail",
            "⚡ Verification & Closure Actions",
        ]
    )

    # -------------------------------------------------------------
    # TAB 1: Action Register
    # -------------------------------------------------------------
    with tab_reg:
        st.subheader("Corrective Action Register")

        # Filters row
        f_col1, f_col2, f_col3, f_col4 = st.columns(4)
        with f_col1:
            search_term = st.text_input("🔍 Search Actions", placeholder="Ref, title, owner, cause...")
        with f_col2:
            status_filter = st.selectbox("Filter Status", ["All"] + VALID_STATUSES)
        with f_col3:
            prio_filter = st.selectbox("Filter Priority", ["All"] + VALID_PRIORITIES)
        with f_col4:
            all_owners = sorted(list({r["action_owner"] for r in remediations if r.get("action_owner")}))
            owner_filter = st.selectbox("Filter Owner", ["All"] + all_owners)

        # Relational filters expander
        with st.expander("🔗 Relational Filters (Findings / Risks / Controls)", expanded=False):
            rf_col1, rf_col2 = st.columns(2)
            findings_list = get_assessment_findings(active_id)
            findings_opts = {"All": None}
            for f in findings_list:
                findings_opts[f"{f['finding_identifier']} - {f['title'][:35]}"] = f["id"]

            risks_list = get_assessment_risks(active_id)
            risks_opts = {"All": None}
            for rk in risks_list:
                risks_opts[f"{rk['risk_identifier']} - {rk['title'][:35]}"] = rk["id"]

            with rf_col1:
                selected_finding_label = st.selectbox("Filter by Finding", list(findings_opts.keys()))
                filter_finding_id = findings_opts[selected_finding_label]

            with rf_col2:
                selected_risk_label = st.selectbox("Filter by Risk", list(risks_opts.keys()))
                filter_risk_id = risks_opts[selected_risk_label]

        # Fetch filtered list
        filtered_remediations = get_assessment_remediations(
            assessment_id=active_id,
            search=search_term,
            status_filter=status_filter,
            priority_filter=prio_filter,
            owner_filter=owner_filter,
            finding_id=filter_finding_id,
            risk_id=filter_risk_id,
        )

        if not filtered_remediations:
            st.info("No corrective actions match the specified criteria.")
        else:
            # Build display DataFrame
            table_rows = []
            for item in filtered_remediations:
                # Latest verification
                verifs = get_remediation_verifications(item["id"])
                latest_verif_res = verifs[0]["verification_result"] if verifs else "Unverified"

                table_rows.append(
                    {
                        "ID": item["id"],
                        "Ref": item["remediation_identifier"],
                        "Title": item["action_title"],
                        "Priority": item["action_priority"],
                        "Owner": item["action_owner"],
                        "Department": item["responsible_department"] or "—",
                        "Target Date": item["target_date"],
                        "Progress": f"{item['progress_percentage']}%",
                        "Status": item["status"],
                        "Verification": latest_verif_res,
                    }
                )

            df = pd.DataFrame(table_rows)
            st.dataframe(
                df[["Ref", "Title", "Priority", "Owner", "Department", "Target Date", "Progress", "Status", "Verification"]],
                use_container_width=True,
                hide_index=True,
            )

        # CSV Export
        st.markdown("<hr style='margin: 1rem 0;' />", unsafe_allow_html=True)
        findings_map: Dict[int, str] = {}
        risks_map: Dict[int, str] = {}
        controls_map: Dict[int, str] = {}
        verifs_map: Dict[int, str] = {}

        for r in remediations:
            rid = r["id"]
            rf = get_remediation_findings(rid)
            findings_map[rid] = ", ".join([f["finding_identifier"] for f in rf])
            rr = get_remediation_risks(rid)
            risks_map[rid] = ", ".join([rk["risk_identifier"] for rk in rr])
            rc = get_remediation_controls(rid)
            controls_map[rid] = ", ".join([c["control_identifier"] for c in rc])
            rv = get_remediation_verifications(rid)
            verifs_map[rid] = rv[0]["verification_result"] if rv else "Unverified"

        csv_content = export_remediations_to_csv(
            remediations=remediations,
            findings_map=findings_map,
            risks_map=risks_map,
            controls_map=controls_map,
            verifications_map=verifs_map,
        )

        st.download_button(
            label="📥 Export Corrective Action Register (CSV)",
            data=csv_content,
            file_name=f"corrective_actions_assessment_{active_id}_{date.today().isoformat()}.csv",
            mime="text/csv",
            help="Download sanitized CSV register with formula injection defense (CWE-1236).",
        )

    # -------------------------------------------------------------
    # TAB 2: Corrective Action Form (5 Sections)
    # -------------------------------------------------------------
    with tab_form:
        st.subheader("Corrective Action Working Form")

        form_mode = st.radio(
            "Form Mode",
            ["Create New Corrective Action", "Edit Existing Corrective Action"],
            horizontal=True,
        )

        selected_action: Optional[Dict[str, Any]] = None
        if form_mode == "Edit Existing Corrective Action":
            if not remediations:
                st.warning("No existing corrective actions to edit.")
            else:
                edit_opts = {
                    f"{r['remediation_identifier']} – {r['action_title']} ({r['status']})": r["id"]
                    for r in remediations
                }
                chosen_edit_label = st.selectbox("Select Action to Edit", list(edit_opts.keys()))
                selected_action = get_single_remediation(edit_opts[chosen_edit_label])

        # Pre-fills
        act_title = selected_action["action_title"] if selected_action else ""
        act_desc = selected_action.get("action_description") or "" if selected_action else ""
        act_owner = selected_action["action_owner"] if selected_action else "IT Operations"
        act_dept = selected_action.get("responsible_department") or "" if selected_action else "IT & Security"
        act_prio = selected_action["action_priority"] if selected_action else "Medium"
        act_prio_just = selected_action.get("priority_justification") or "" if selected_action else ""
        act_imm_corr = selected_action.get("immediate_correction") or "" if selected_action else ""
        act_rc_method = selected_action.get("root_cause_analysis_method") or "Direct Analysis" if selected_action else "Direct Analysis"
        act_root_cause = selected_action.get("root_cause") or "" if selected_action else ""
        act_contrib = selected_action.get("contributing_factors") or "" if selected_action else ""
        act_long_term = selected_action.get("long_term_corrective_action") or "" if selected_action else ""
        act_expected = selected_action.get("expected_outcome") or "" if selected_action else ""
        act_verif_req = selected_action.get("verification_requirements") or "" if selected_action else ""
        act_target_date = selected_action["target_date"] if selected_action else (date.today().isoformat())
        act_progress = int(selected_action.get("progress_percentage", 0)) if selected_action else 0
        act_impl_summary = selected_action.get("implementation_summary") or "" if selected_action else ""

        # Section A: Source and Identification
        st.markdown("#### Section A – Source and Identification")
        sa_c1, sa_c2 = st.columns([3, 1])
        with sa_c1:
            form_title = st.text_input("Corrective Action Title *", value=act_title)
        with sa_c2:
            form_prio = st.selectbox(
                "Priority *",
                VALID_PRIORITIES,
                index=VALID_PRIORITIES.index(act_prio) if act_prio in VALID_PRIORITIES else 1,
            )

        form_desc = st.text_area(
            "Action Description",
            value=act_desc,
            placeholder="Describe the issue, context, and what needs to be addressed...",
        )

        # Multi-select relationships
        all_findings = get_assessment_findings(active_id)
        f_choices = {f"{f['finding_identifier']} – {f['title'][:40]}": f["id"] for f in all_findings}

        current_linked_fids = (
            [f["id"] for f in get_remediation_findings(selected_action["id"])] if selected_action else []
        )
        selected_f_labels = [label for label, fid in f_choices.items() if fid in current_linked_fids]
        form_linked_findings = st.multiselect("Linked Confirmed Findings", list(f_choices.keys()), default=selected_f_labels)

        all_risks = get_assessment_risks(active_id)
        r_choices = {
            f"{rk['risk_identifier']} – {rk['title'][:40]} (Res: {rk.get('residual_risk_level', 'Unassessed')})": rk["id"]
            for rk in all_risks
        }
        current_linked_rids = (
            [rk["id"] for rk in get_remediation_risks(selected_action["id"])] if selected_action else []
        )
        selected_r_labels = [label for label, rid in r_choices.items() if rid in current_linked_rids]
        form_linked_risks = st.multiselect("Linked Risks", list(r_choices.keys()), default=selected_r_labels)

        # Check if linked to critical risk and priority is Medium or Low
        has_critical_risk = False
        for lbl in form_linked_risks:
            if "Res: Critical" in lbl:
                has_critical_risk = True
                break

        form_prio_just = ""
        if has_critical_risk and form_prio in ("Medium", "Low"):
            st.warning(
                "⚠️ This corrective action is linked to a **Critical Risk** but assigned a lower priority. "
                "Documented justification is required."
            )
            form_prio_just = st.text_area(
                "Priority Alignment Justification *",
                value=act_prio_just,
                placeholder="Explain why this corrective action has a lower priority despite being linked to a Critical risk...",
            )

        # Section B: Root Cause and Action Plan
        st.markdown("<hr style='margin: 1.5rem 0;' />", unsafe_allow_html=True)
        st.markdown("#### Section B – Root Cause and Action Plan")
        st.caption(
            "Distinguish immediate correction (containment) from long-term corrective action (preventing recurrence)."
        )

        form_imm_corr = st.text_area(
            "Immediate Correction (Short-Term Containment)",
            value=act_imm_corr,
            placeholder="Action taken immediately to contain or isolate the detected non-conformity...",
        )

        sb_c1, sb_c2 = st.columns([1, 2])
        with sb_c1:
            form_rc_method = st.selectbox(
                "Root Cause Analysis Method",
                VALID_RCA_METHODS,
                index=VALID_RCA_METHODS.index(act_rc_method) if act_rc_method in VALID_RCA_METHODS else 0,
            )

        # 5 Whys Interactive Builder
        rc_details_obj = {}
        if form_rc_method == "5 Whys":
            st.markdown("##### 🔍 5 Whys Analysis Workflow")
            # Parse existing details if present
            raw_details = selected_action.get("root_cause_details") if selected_action else None
            existing_whys = {}
            if raw_details:
                try:
                    existing_whys = json.loads(raw_details) if isinstance(raw_details, str) else raw_details
                except Exception:
                    existing_whys = {}

            problem_stmt = st.text_input(
                "Problem Statement",
                value=existing_whys.get("problem_statement", act_title),
            )
            why1 = st.text_input("1. Why did the issue occur?", value=existing_whys.get("why1", ""))
            why2 = st.text_input("2. Why did that happen?", value=existing_whys.get("why2", ""))
            why3 = st.text_input("3. Why was that not detected or prevented?", value=existing_whys.get("why3", ""))
            why4 = st.text_input("4. Why did that failure occur?", value=existing_whys.get("why4", ""))
            why5 = st.text_input("5. Why (Root Cause)?", value=existing_whys.get("why5", ""))

            rc_details_obj = {
                "problem_statement": problem_stmt,
                "why1": why1,
                "why2": why2,
                "why3": why3,
                "why4": why4,
                "why5": why5,
            }

        with sb_c2:
            form_root_cause = st.text_area(
                "Root Cause Description *",
                value=act_root_cause,
                placeholder="Document the underlying systemic root cause that allowed this defect to occur...",
            )

        form_contrib = st.text_input(
            "Contributing Factors",
            value=act_contrib,
            placeholder="e.g. Personnel turnover, lack of automated tooling, budget constraints...",
        )

        form_long_term = st.text_area(
            "Long-Term Corrective Action Plan *",
            value=act_long_term,
            placeholder="Describe the permanent systemic action plan to prevent recurrence...",
        )

        sb_c3, sb_c4 = st.columns(2)
        with sb_c3:
            form_expected = st.text_input(
                "Expected Outcome",
                value=act_expected,
                placeholder="e.g. 100% MFA coverage, zero residual unmanaged accounts...",
            )
        with sb_c4:
            form_verif_req = st.text_input(
                "Verification Requirements",
                value=act_verif_req,
                placeholder="e.g. Inspect Azure AD sign-in logs, verify policy enforcement...",
            )

        # Section C: Ownership and Timeline
        st.markdown("<hr style='margin: 1.5rem 0;' />", unsafe_allow_html=True)
        st.markdown("#### Section C – Ownership and Timeline")
        sc_c1, sc_c2, sc_c3 = st.columns(3)
        with sc_c1:
            form_owner = st.text_input("Responsible Action Owner *", value=act_owner)
        with sc_c2:
            form_dept = st.text_input("Responsible Department", value=act_dept)
        with sc_c3:
            form_target_date = st.text_input("Target Completion Date (YYYY-MM-DD) *", value=act_target_date)

        # Section D: Implementation Details
        st.markdown("<hr style='margin: 1.5rem 0;' />", unsafe_allow_html=True)
        st.markdown("#### Section D – Implementation")
        sd_c1, sd_c2 = st.columns([1, 2])
        with sd_c1:
            form_progress = st.slider("Implementation Progress (%)", 0, 100, value=act_progress, step=5)
        with sd_c2:
            form_impl_summary = st.text_area(
                "Implementation Summary",
                value=act_impl_summary,
                placeholder="Document technical or procedural steps taken during implementation...",
            )

        # Remediation evidence linking
        all_evidence = get_assessment_evidence(active_id)
        ev_choices = {f"{e['title']} ({e.get('original_file_name', 'file')})": e["id"] for e in all_evidence}
        current_linked_eids = (
            [e["id"] for e in get_remediation_evidence(selected_action["id"])] if selected_action else []
        )
        selected_ev_labels = [label for label, eid in ev_choices.items() if eid in current_linked_eids]
        form_linked_evidence = st.multiselect("Supporting Remediation Evidence", list(ev_choices.keys()), default=selected_ev_labels)

        # Save Button
        st.markdown("<hr style='margin: 1.5rem 0;' />", unsafe_allow_html=True)
        save_btn = st.button("💾 Save Corrective Action Record", type="primary", disabled=is_archived)

        if save_btn:
            try:
                selected_f_ids = [f_choices[lbl] for lbl in form_linked_findings]
                selected_r_ids = [r_choices[lbl] for lbl in form_linked_risks]
                selected_e_ids = [ev_choices[lbl] for lbl in form_linked_evidence]

                action_payload = {
                    "action_title": form_title,
                    "action_description": form_desc,
                    "action_owner": form_owner,
                    "responsible_department": form_dept,
                    "action_priority": form_prio,
                    "priority_justification": form_prio_just,
                    "immediate_correction": form_imm_corr,
                    "root_cause_analysis_method": form_rc_method,
                    "root_cause": form_root_cause,
                    "root_cause_details": rc_details_obj if form_rc_method == "5 Whys" else None,
                    "contributing_factors": form_contrib,
                    "long_term_corrective_action": form_long_term,
                    "expected_outcome": form_expected,
                    "verification_requirements": form_verif_req,
                    "target_date": form_target_date,
                    "progress_percentage": form_progress,
                    "implementation_summary": form_impl_summary,
                    "finding_id": selected_f_ids[0] if selected_f_ids else None,
                    "risk_id": selected_r_ids[0] if selected_r_ids else None,
                    "linked_finding_ids": selected_f_ids,
                    "linked_risk_ids": selected_r_ids,
                    "linked_evidence_ids": selected_e_ids,
                }

                if form_mode == "Create New Corrective Action":
                    new_id = create_remediation(active_id, action_payload)
                    st.success(f"✅ Corrective action created successfully with ID #{new_id}!")
                    st.rerun()
                else:
                    assert selected_action is not None
                    update_remediation(selected_action["id"], action_payload)
                    st.success(f"✅ Corrective action '{selected_action['remediation_identifier']}' updated successfully!")
                    st.rerun()

            except Exception as e:
                st.error(f"❌ Error saving corrective action: {e}")

    # -------------------------------------------------------------
    # TAB 3: Working Paper Detail
    # -------------------------------------------------------------
    with tab_detail:
        st.subheader("Remediation Working Paper Assurance View")

        if not remediations:
            st.info("No corrective actions available in this assessment.")
        else:
            detail_opts = {
                f"{r['remediation_identifier']} – {r['action_title']} [{r['status']}]": r["id"]
                for r in remediations
            }
            chosen_det_label = st.selectbox("Select Action Working Paper", list(detail_opts.keys()))
            det_id = detail_opts[chosen_det_label]
            action_item = get_single_remediation(det_id)

            if action_item:
                # Header card
                prio_color = {
                    "Critical": "#751C35",
                    "High": "#D9534F",
                    "Medium": "#F0AD4E",
                    "Low": "#5CB85C",
                }.get(action_item["action_priority"], "#6B7280")

                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 4px solid {prio_color}; padding: 1.25rem; border-radius: 4px; margin-bottom: 1rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div>
                                <span style="font-size: 0.8rem; font-weight: 700; color: #6B7280; text-transform: uppercase;">
                                    {action_item['remediation_identifier']} &bull; Priority: {action_item['action_priority']}
                                </span>
                                <h3 style="margin: 0.25rem 0; color: #1F2937;">{action_item['action_title']}</h3>
                            </div>
                            <div style="text-align: right;">
                                <span style="padding: 0.35rem 0.75rem; font-size: 0.85rem; font-weight: 700; border-radius: 3px; background: #EFF6FF; color: #1E40AF; border: 1px solid #BFDBFE;">
                                    {action_item['status']}
                                </span>
                            </div>
                        </div>
                        <div style="margin-top: 0.75rem; font-size: 0.85rem; color: #4B5563;">
                            <strong>Owner:</strong> {action_item['action_owner']} ({action_item.get('responsible_department') or 'General'}) &bull;
                            <strong>Target Date:</strong> {action_item['target_date']} &bull;
                            <strong>Progress:</strong> {action_item['progress_percentage']}%
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.progress(action_item["progress_percentage"] / 100.0)

                # Root Cause & Action Plan Details
                st.markdown("#### Root Cause & Action Plan Analysis")
                rc_c1, rc_c2 = st.columns(2)
                with rc_c1:
                    st.markdown("**Immediate Correction (Containment):**")
                    st.info(action_item.get("immediate_correction") or "No immediate correction documented.")
                    st.markdown(f"**Root Cause Analysis Method:** `{action_item.get('root_cause_analysis_method')}`")
                    st.markdown("**Root Cause:**")
                    st.markdown(action_item.get("root_cause") or "*Under investigation*")

                with rc_c2:
                    st.markdown("**Long-Term Corrective Action:**")
                    st.success(action_item.get("long_term_corrective_action") or "Plan not yet specified.")
                    st.markdown(f"**Expected Outcome:** {action_item.get('expected_outcome') or '—'}")
                    st.markdown(f"**Verification Requirements:** {action_item.get('verification_requirements') or '—'}")

                # If 5 Whys recorded, display table
                if action_item.get("root_cause_details"):
                    try:
                        whys = json.loads(action_item["root_cause_details"])
                        if isinstance(whys, dict) and whys.get("why1"):
                            st.markdown("##### 5 Whys Diagnostic Sequence")
                            why_rows = [
                                {"Level": "Problem Statement", "Description": whys.get("problem_statement", "")},
                                {"Level": "Why 1", "Description": whys.get("why1", "")},
                                {"Level": "Why 2", "Description": whys.get("why2", "")},
                                {"Level": "Why 3", "Description": whys.get("why3", "")},
                                {"Level": "Why 4", "Description": whys.get("why4", "")},
                                {"Level": "Why 5 (Root Cause)", "Description": whys.get("why5", "")},
                            ]
                            st.table(pd.DataFrame(why_rows))
                    except Exception:
                        pass

                # Traceability Matrix Grid
                st.markdown("#### End-to-End Traceability Links")
                tr_c1, tr_c2, tr_c3, tr_c4 = st.columns(4)

                with tr_c1:
                    linked_f = get_remediation_findings(det_id)
                    st.markdown(f"**Linked Findings ({len(linked_f)}):**")
                    for f in linked_f:
                        st.markdown(f"- **{f['finding_identifier']}**: {f['title'][:25]}...")
                    if not linked_f:
                        st.caption("No linked findings.")

                with tr_c2:
                    linked_r = get_remediation_risks(det_id)
                    st.markdown(f"**Linked Risks ({len(linked_r)}):**")
                    for rk in linked_r:
                        st.markdown(f"- **{rk['risk_identifier']}** ({rk.get('residual_risk_level', 'Unassessed')})")
                    if not linked_r:
                        st.caption("No linked risks.")

                with tr_c3:
                    linked_c = get_remediation_controls(det_id)
                    st.markdown(f"**Linked Controls ({len(linked_c)}):**")
                    for c in linked_c:
                        st.markdown(f"- **{c['control_identifier']}**: {c['control_title'][:25]}...")
                    if not linked_c:
                        st.caption("No linked controls.")

                with tr_c4:
                    linked_e = get_remediation_evidence(det_id)
                    st.markdown(f"**Linked Evidence ({len(linked_e)}):**")
                    for e in linked_e:
                        st.markdown(f"- **{e['title']}** ({e.get('integrity_status', 'Verified')})")
                    if not linked_e:
                        st.caption("No linked evidence.")

                # Three Historical Ledgers
                st.markdown("<hr style='margin: 1.5rem 0;' />", unsafe_allow_html=True)
                st.markdown("#### Audit Trail & Historical Ledgers")

                with st.expander("📈 Progress Update History", expanded=False):
                    prog_hist = get_remediation_progress_history(det_id)
                    if not prog_hist:
                        st.caption("No progress updates logged yet.")
                    else:
                        st.table(
                            pd.DataFrame(
                                [
                                    {
                                        "Progress": f"{p['progress_percentage']}%",
                                        "Description": p["description"],
                                        "Blockers": p.get("blockers") or "None",
                                        "Updated By": p["updated_by"],
                                        "Timestamp": p["timestamp"],
                                    }
                                    for p in prog_hist
                                ]
                            )
                        )

                with st.expander("📅 Deadline Extension History", expanded=False):
                    deadlines = get_remediation_deadline_extensions(det_id)
                    if not deadlines:
                        st.caption("No deadline extensions recorded.")
                    else:
                        st.table(
                            pd.DataFrame(
                                [
                                    {
                                        "Previous Deadline": d["previous_deadline"],
                                        "New Deadline": d["new_deadline"],
                                        "Extension Reason": d["extension_reason"],
                                        "Approving Authority": d["approving_authority"],
                                        "Recorded At": d["timestamp"],
                                    }
                                    for d in deadlines
                                ]
                            )
                        )

                with st.expander("🛡️ Effectiveness Verification Ledger", expanded=True):
                    verifs = get_remediation_verifications(det_id)
                    if not verifs:
                        st.caption("No formal verifications recorded yet.")
                    else:
                        for v in verifs:
                            res_color = {
                                "Effective": "#15803D",
                                "Ineffective": "#DC2626",
                                "Inconclusive": "#D97706",
                            }.get(v["verification_result"], "#4B5563")

                            st.markdown(
                                f"""
                                <div style="border: 1px solid #E5E7EB; border-left: 3px solid {res_color}; padding: 0.75rem 1rem; margin-bottom: 0.5rem; background: #FFFFFF; border-radius: 3px;">
                                    <div style="display: flex; justify-content: space-between;">
                                        <strong>{v['verification_reference']} &bull; Result: <span style="color: {res_color};">{v['verification_result']}</span></strong>
                                        <span style="font-size: 0.8rem; color: #6B7280;">{v['verification_date']} by {v['verifier_name']}</span>
                                    </div>
                                    <div style="font-size: 0.85rem; color: #374151; margin-top: 0.35rem;">
                                        <strong>Objective:</strong> {v['verification_objective']}<br/>
                                        <strong>Procedure:</strong> {v['verification_procedure']}<br/>
                                        <strong>Observed Outcome:</strong> {v['observed_outcome']}<br/>
                                        <strong>Notes:</strong> {v.get('verification_notes') or '—'}
                                    </div>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )

    # -------------------------------------------------------------
    # TAB 4: Lifecycle & Verification Actions
    # -------------------------------------------------------------
    with tab_actions:
        st.subheader("Lifecycle & Governance Actions")

        if not remediations:
            st.info("No corrective actions available in this assessment.")
        else:
            action_opts = {
                f"{r['remediation_identifier']} – {r['action_title']} ({r['status']}, {r['progress_percentage']}%)": r["id"]
                for r in remediations
            }
            chosen_act_label = st.selectbox("Select Action to Manage", list(action_opts.keys()))
            act_id = action_opts[chosen_act_label]
            target_act = get_single_remediation(act_id)

            if target_act:
                act_tabs = st.tabs(
                    [
                        "1. Progress Update",
                        "2. Extend Deadline",
                        "3. Record Verification",
                        "4. Formally Close",
                        "5. Reopen Action",
                        "6. Cancel Action",
                    ]
                )

                # Sub-action 1: Progress Update
                with act_tabs[0]:
                    st.markdown("##### Record Implementation Progress Update")
                    pu_progress = st.slider(
                        "Progress Percentage (%)",
                        0,
                        100,
                        value=int(target_act.get("progress_percentage", 0)),
                        step=5,
                    )
                    pu_desc = st.text_area("Progress Description *", placeholder="Describe progress completed since last update...")
                    pu_blockers = st.text_input("Current Blockers / Impediments", placeholder="Leave empty if on schedule...")
                    pu_updater = st.text_input("Updated By", value=target_act["action_owner"])

                    if st.button("Submit Progress Update", disabled=is_archived):
                        try:
                            record_progress_update(
                                remediation_id=act_id,
                                progress_percentage=pu_progress,
                                description=pu_desc,
                                blockers=pu_blockers,
                                updated_by=pu_updater,
                            )
                            st.success("✅ Progress update recorded successfully!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error: {e}")

                # Sub-action 2: Extend Deadline
                with act_tabs[1]:
                    st.markdown("##### Request & Approve Deadline Extension")
                    st.info(f"Current Target Deadline: **{target_act['target_date']}**")
                    de_new_date = st.text_input("New Target Deadline (YYYY-MM-DD) *", value=target_act["target_date"])
                    de_reason = st.text_area("Extension Reason *", placeholder="Document the operational or vendor dependency reason...")
                    de_authority = st.text_input("Approving Authority *", value="CISO / Lead Auditor")

                    if st.button("Approve Deadline Extension", disabled=is_archived):
                        try:
                            extend_deadline(
                                remediation_id=act_id,
                                new_deadline=de_new_date,
                                extension_reason=de_reason,
                                approving_authority=de_authority,
                            )
                            st.success("✅ Deadline extension recorded successfully!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error: {e}")

                # Sub-action 3: Record Verification
                with act_tabs[2]:
                    st.markdown("##### Document Effectiveness Verification Review")
                    st.caption("Verifies whether the corrective action has effectively remediated the cause.")
                    vr_c1, vr_c2 = st.columns(2)
                    with vr_c1:
                        vr_obj = st.text_input("Verification Objective *", value=f"Verify implementation and effectiveness of {target_act['remediation_identifier']}")
                        vr_proc = st.text_area("Verification Procedure *", placeholder="e.g. Examined Azure AD Conditional Access policies and sign-in logs...")
                        vr_expected = st.text_input("Expected Outcome *", value=target_act.get("expected_outcome") or "Control operating effectively")
                    with vr_c2:
                        vr_observed = st.text_area("Observed Outcome *", placeholder="Document factual findings from testing or examination...")
                        vr_sample = st.text_input("Sample / Records Examined", placeholder="e.g. 50 privileged user sign-ins across 14 days")
                        vr_result = st.selectbox("Verification Result *", VALID_VERIFICATION_RESULTS)

                    vr_c3, vr_c4 = st.columns(2)
                    with vr_c3:
                        vr_notes = st.text_area("Verification Notes", placeholder="Additional auditor notes or observations...")
                        vr_next_action = st.text_input("Recommended Next Action", placeholder="e.g. Close corrective action, or return for remediation")
                    with vr_c4:
                        vr_verifier = st.text_input("Verifier Name *", value="Information Security Auditor")
                        vr_date = st.text_input("Verification Date *", value=date.today().isoformat())

                    if vr_verifier == target_act["action_owner"]:
                        st.warning("⚠️ **Segregation of Duties:** The designated verifier is identical to the action owner. Simulated roles should maintain independent review.")

                    if st.button("Record Effectiveness Verification", disabled=is_archived):
                        try:
                            record_verification(
                                remediation_id=act_id,
                                verification_data={
                                    "verification_objective": vr_obj,
                                    "verification_procedure": vr_proc,
                                    "expected_outcome": vr_expected,
                                    "observed_outcome": vr_observed,
                                    "sample_examined": vr_sample,
                                    "verification_result": vr_result,
                                    "verifier_name": vr_verifier,
                                    "verification_date": vr_date,
                                    "verification_notes": vr_notes,
                                    "recommended_next_action": vr_next_action,
                                },
                            )
                            st.success("✅ Effectiveness verification recorded!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error: {e}")

                # Sub-action 4: Formally Close Action
                with act_tabs[3]:
                    st.markdown("##### Formally Close Verified Corrective Action")
                    st.caption("Requires 100% progress, implementation summary, supporting evidence, and 'Effective' verification.")

                    cl_rationale = st.text_area(
                        "Closure Rationale *",
                        placeholder="Document verified auditor rationale confirming the defect has been remediated...",
                    )
                    cl_date = st.text_input("Closure Date", value=date.today().isoformat())

                    if st.button("Formally Close Action", type="primary", disabled=is_archived):
                        try:
                            close_remediation(act_id, closure_rationale=cl_rationale)
                            st.success(f"✅ Corrective action '{target_act['remediation_identifier']}' formally closed!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Closure Blocked: {e}")

                # Sub-action 5: Reopen Action
                with act_tabs[4]:
                    st.markdown("##### Reopen Corrective Action")
                    st.caption("Used if verification is Ineffective or if an issue recurred post-closure.")
                    ro_justification = st.text_area("Reopen Justification *", placeholder="Explain why this action is being reopened...")

                    if st.button("Reopen Corrective Action", disabled=is_archived):
                        try:
                            reopen_remediation(act_id, reopen_justification=ro_justification)
                            st.success(f"✅ Corrective action '{target_act['remediation_identifier']}' reopened!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error: {e}")

                # Sub-action 6: Cancel Action
                with act_tabs[5]:
                    st.markdown("##### Cancel Corrective Action")
                    st.caption("Cancelled actions do not count as successfully remediated.")
                    ca_reason = st.text_area("Cancellation Reason *", placeholder="Explain why this action is no longer required or deemed invalid...")

                    if st.button("Cancel Corrective Action", disabled=is_archived):
                        try:
                            cancel_remediation(act_id, cancellation_reason=ca_reason)
                            st.success(f"✅ Corrective action '{target_act['remediation_identifier']}' cancelled!")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error: {e}")
