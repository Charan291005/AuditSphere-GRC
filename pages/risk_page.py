"""
Risk Register and Risk Management Module for AuditSphere.

Enables assessors, risk owners, and security leaders to:
- Identify, evaluate, and prioritize information security risks
- Differentiate Inherent, Current Residual, and Target Residual risk
- Explore risks via an interactive 5×5 Plotly likelihood-impact heatmap
- Link risks to Annex A controls, confirmed audit findings, and evidence artifacts
- Manage risk treatment plans (Mitigate, Accept, Transfer, Avoid) and governance decisions
- Track risk reassessment history and export audit-ready CSV records
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from services.assessment_service import get_assessment
from services.control_service import get_assessment_controls
from services.gap_engine import get_assessment_findings
from services.evidence_manager import get_assessment_evidence
from services.risk_engine import (
    RISK_CATEGORIES,
    TREATMENT_STRATEGIES,
    RISK_STATUSES,
    APPROVAL_STATUSES,
    RISK_SEVERITY_COLORS,
    calculate_risk_score,
    classify_risk_score,
    evaluate_risk_record,
    calculate_risk_register_metrics,
    aggregate_risk_heatmap_data,
    compare_risk_evaluations,
    is_review_overdue,
    export_risks_to_csv,
)
from services.risk_service import (
    create_risk,
    update_risk,
    archive_risk,
    get_single_risk,
    get_assessment_risks,
    link_finding_to_risk,
    unlink_finding_from_risk,
    link_control_to_risk,
    unlink_control_from_risk,
    link_evidence_to_risk,
    unlink_evidence_from_risk,
)
from ui_components import (
    render_kpi_card,
    render_severity_badge,
    render_status_badge,
    render_empty_state,
    render_educational_disclaimer,
)


def render_risk_page():
    """Render the primary Risk Register workspace."""
    st.markdown("## Information Security Risk Register")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.95rem; margin-top: -0.5rem;'>"
        "Identify, evaluate, prioritize, and treat information security risks with traceable links "
        "to Annex A controls, audit findings, and supporting evidence."
        "</p>",
        unsafe_allow_html=True,
    )

    render_educational_disclaimer()

    active_id = st.session_state.get("active_assessment_id")
    if not active_id:
        render_empty_state(
            title="No Active Assessment Selected",
            message="Please select or create an assessment in the left sidebar or Assessment Management to access the risk register.",
        )
        return

    assessment = get_assessment(active_id)
    if not assessment:
        st.error("Active assessment could not be loaded from database.")
        return

    is_archived = assessment["status"] == "Archived"
    if is_archived:
        st.warning("This assessment is Archived. Risk register is in read-only mode.")

    # Retrieve all risks for this assessment
    all_risks = get_assessment_risks(active_id, include_archived=False)
    metrics = calculate_risk_register_metrics(all_risks)

    # Top KPI Metrics Row
    k1, k2, k3, k4, k5, k6, k7, k8 = st.columns(8)
    with k1:
        render_kpi_card("Total Risks", metrics["total_risks"], "Identified risks")
    with k2:
        render_kpi_card("Critical", metrics["critical_risks"], "Score 20-25")
    with k3:
        render_kpi_card("High", metrics["high_risks"], "Score 12-19")
    with k4:
        render_kpi_card("Medium", metrics["medium_risks"], "Score 6-11")
    with k5:
        render_kpi_card("Low", metrics["low_risks"], "Score 1-5")
    with k6:
        render_kpi_card("Unassessed", metrics["unassessed_risks"], "Awaiting scoring")
    with k7:
        render_kpi_card("Accepted", metrics["accepted_risks"], "Formal acceptance")
    with k8:
        render_kpi_card("Overdue", metrics["overdue_reviews"], "Reviews overdue")

    st.markdown("<hr style='margin: 1rem 0 1.25rem 0;' />", unsafe_allow_html=True)

    # Tabbed views
    tab_list, tab_heatmap, tab_form, tab_detail = st.tabs(
        ["Risk Register Table", "Interactive Risk Heatmap", "Assess / Create Risk", "Risk Detail & Reassessment"]
    )

    with tab_list:
        _render_risk_table_tab(assessment, all_risks, is_archived)

    with tab_heatmap:
        _render_heatmap_tab(assessment, all_risks)

    with tab_form:
        _render_risk_form_tab(assessment, is_archived)

    with tab_detail:
        _render_risk_detail_tab(assessment, is_archived)


# =========================================================================
# 1. RISK REGISTER DIRECTORY TABLE TAB
# =========================================================================


def _render_risk_table_tab(assessment: Dict[str, Any], risks: List[Dict[str, Any]], is_archived: bool):
    """Render filtered table and card view of risk records with CSV export."""
    st.markdown("#### Risk Register Directory")

    c1, c2, c3, c4 = st.columns([2.5, 1.5, 1.5, 1.5])
    with c1:
        search_q = st.text_input("Search Risks", placeholder="Search by title, RSK ID, asset, threat...", key="rsk_search", label_visibility="collapsed")
    with c2:
        cat_filter = st.selectbox("Category", options=["All Categories"] + RISK_CATEGORIES, key="rsk_cat_filter", label_visibility="collapsed")
    with c3:
        sev_filter = st.selectbox("Residual Severity", options=["All Severities", "Critical", "High", "Medium", "Low", "Not Assessed"], key="rsk_sev_filter", label_visibility="collapsed")
    with c4:
        stat_filter = st.selectbox("Status", options=["All Statuses"] + RISK_STATUSES, key="rsk_stat_filter", label_visibility="collapsed")

    c5, c6 = st.columns([2, 2])
    with c5:
        strat_filter = st.selectbox("Treatment Strategy", options=["All Strategies"] + TREATMENT_STRATEGIES, key="rsk_strat_filter")
    with c6:
        owners = sorted(list({r.get("risk_owner") for r in risks if r.get("risk_owner")}))
        owner_filter = st.selectbox("Risk Owner", options=["All Owners"] + owners, key="rsk_owner_filter")

    # Fetch filtered risks
    filtered = get_assessment_risks(
        assessment_id=assessment["id"],
        status_filter=stat_filter,
        severity_filter=sev_filter,
        category_filter=cat_filter,
        treatment_filter=strat_filter,
        owner_filter=owner_filter,
        search_query=search_q,
    )

    h_col1, h_col2 = st.columns([4, 1.5])
    with h_col1:
        st.markdown(f"**Displaying {len(filtered)} risk record(s)**")
    with h_col2:
        if filtered:
            csv_str = export_risks_to_csv(filtered)
            st.download_button(
                label="📥 Export Risk Register (CSV)",
                data=csv_str.encode("utf-8"),
                file_name=f"Risk_Register_{assessment['organization'].replace(' ', '_')}_{date.today().isoformat()}.csv",
                mime="text/csv",
                use_container_width=True,
            )

    if not filtered:
        render_empty_state(
            title="No Risk Records Found",
            message="No risks match your filter criteria. Create a risk using 'Assess / Create Risk' or link one from an audit finding.",
        )
        return

    # Render structured table rows
    for r in filtered:
        r_id = r["id"]
        res_lvl = r.get("residual_risk_level") or "Not Assessed"
        res_score_str = str(r.get("residual_risk_score")) if r.get("residual_risk_score") is not None else "N/A"
        inh_lvl = r.get("inherent_risk_level") or "Not Assessed"
        inh_score_str = str(r.get("inherent_risk_score")) if r.get("inherent_risk_score") is not None else "N/A"
        tgt_score_str = str(r.get("target_risk_score")) if r.get("target_risk_score") is not None else "N/A"

        # Check if review is overdue
        is_overdue = is_review_overdue(r.get("review_date")) and r.get("status") != "Closed"

        st.markdown(
            f"""
            <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 4px solid #751C35; border-radius: 4px; padding: 1rem 1.15rem; margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <span style="font-size: 1.05rem; font-weight: 700; color: #1F2937;">{r['risk_identifier']} – {r['title']}</span>
                        <div style="font-size: 0.8rem; color: #6B7280; margin-top: 0.2rem;">
                            Category: <strong>{r.get('risk_category', 'Other')}</strong> &bull;
                            Asset/Process: <strong>{r.get('asset_or_process') or 'Unspecified'}</strong> &bull;
                            Owner: <strong>{r.get('risk_owner') or 'Unassigned'}</strong>
                        </div>
                    </div>
                    <div style="display: flex; gap: 0.5rem; align-items: center;">
                        {render_severity_badge(res_lvl)}
                        {render_status_badge(r['status'])}
                        {f'<span style="background-color: #FEE2E2; color: #991B1B; font-size: 0.7rem; font-weight: 600; padding: 0.15rem 0.4rem; border-radius: 3px; border: 1px solid #FCA5A5;">OVERDUE REVIEW</span>' if is_overdue else ''}
                    </div>
                </div>
                <div style="display: flex; gap: 1.5rem; margin-top: 0.6rem; padding: 0.5rem 0.75rem; background: #F9FAFB; border-radius: 3px; border: 1px solid #F3F4F6; font-size: 0.825rem;">
                    <div>Inherent Score: <strong>{inh_score_str}</strong> ({inh_lvl})</div>
                    <div style="color: #751C35; font-weight: 700;">Current Residual: {res_score_str} ({res_lvl})</div>
                    <div>Target Residual: <strong>{tgt_score_str}</strong> ({r.get('target_risk_level') or 'N/A'})</div>
                    <div>Treatment: <strong>{r.get('treatment_strategy', 'Mitigate')}</strong></div>
                    <div>Review Date: <strong>{r.get('review_date') or 'Unset'}</strong></div>
                </div>
                {f'''
                <div style="font-size: 0.8rem; color: #4B5563; margin-top: 0.5rem;">
                    <strong>Threat:</strong> {r['threat']} &nbsp;|&nbsp; <strong>Vulnerability:</strong> {r['vulnerability']}
                </div>
                ''' if r.get('threat') or r.get('vulnerability') else ''}
            </div>
            """,
            unsafe_allow_html=True,
        )

        b1, b2, b3 = st.columns([1.5, 1.5, 3])
        with b1:
            if st.button("Inspect Details", key=f"btn_det_{r_id}", use_container_width=True):
                st.session_state["selected_risk_id"] = r_id
                st.info(f"Loaded {r['risk_identifier']} into 'Risk Detail & Reassessment' tab.")
        with b2:
            if not is_archived:
                if st.button("Edit Assessment", key=f"btn_edit_{r_id}", use_container_width=True):
                    st.session_state["editing_risk_id"] = r_id
                    st.info(f"Loaded {r['risk_identifier']} into 'Assess / Create Risk' tab.")


# =========================================================================
# 2. INTERACTIVE RISK HEATMAP TAB
# =========================================================================


def _render_heatmap_tab(assessment: Dict[str, Any], risks: List[Dict[str, Any]]):
    """Render 5×5 Likelihood × Impact interactive Plotly risk matrix."""
    st.markdown("#### Interactive 5×5 Risk Matrix Heatmap")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.85rem; margin-top: -0.5rem;'>"
        "Visualize organizational risk posture across Inherent, Current Residual, and Estimated Target exposure. "
        "Cells represent Likelihood (vertical) × Impact (horizontal)."
        "</p>",
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns([2, 3])
    with c1:
        eval_mode = st.radio(
            "Evaluation Perspective",
            options=["current_residual", "inherent", "target_residual"],
            format_func=lambda x: {
                "current_residual": "Current Residual Risk (Post-Control)",
                "inherent": "Inherent Risk (Pre-Control)",
                "target_residual": "Target Residual Risk (Estimated Future Post-Treatment)",
            }[x],
            horizontal=False,
            key="hm_eval_mode",
        )

    # Aggregate heatmap data
    heatmap_data = aggregate_risk_heatmap_data(risks, evaluation_type=eval_mode)

    if eval_mode == "target_residual":
        st.info("ℹ️ **Target Residual Risk** represents estimated future risk exposure upon completion of treatment plans. It does not replace current residual risk.")

    # Build 5x5 Plotly Heatmap
    # X: Impact (1 to 5), Y: Likelihood (1 to 5)
    z_counts = [[0 for _ in range(5)] for _ in range(5)]
    hover_texts = [[ "" for _ in range(5)] for _ in range(5)]

    for cell in heatmap_data["cells"]:
        l_idx = cell["likelihood"] - 1  # 0 to 4
        i_idx = cell["impact"] - 1      # 0 to 4
        cnt = cell["count"]
        z_counts[l_idx][i_idx] = cnt
        risk_list_str = "<br>".join([f"• {r['risk_identifier']}: {r['title'][:35]}" for r in cell["risks"][:5]])
        if len(cell["risks"]) > 5:
            risk_list_str += f"<br>...and {len(cell['risks']) - 5} more"
        hover_texts[l_idx][i_idx] = (
            f"<b>Likelihood:</b> {cell['likelihood']} &bull; <b>Impact:</b> {cell['impact']}<br>"
            f"<b>Score:</b> {cell['score']} ({cell['severity']})<br>"
            f"<b>Total Risks:</b> {cnt}<br>"
            f"{risk_list_str if cnt > 0 else '<i>No risks in this cell</i>'}"
        )

    # Custom annotations on cells showing risk counts
    annotations = []
    for l_val in range(1, 6):
        for i_val in range(1, 6):
            cnt = z_counts[l_val - 1][i_val - 1]
            score = l_val * i_val
            sev = classify_risk_score(score)
            color = "#FFFFFF" if sev in ("Critical", "High") else "#1F2937"
            annotations.append(
                dict(
                    x=i_val,
                    y=l_val,
                    text=f"<b>{cnt}</b>" if cnt > 0 else "0",
                    showarrow=False,
                    font=dict(size=14, color=color),
                )
            )

    # Base severity score matrix for background color
    base_scores = [[l * i for i in range(1, 6)] for l in range(1, 6)]

    # Accessible severity colorscale mapping:
    # 1-5 Low (Green), 6-11 Med (Amber), 12-19 High (Orange), 20-25 Critical (Red)
    colorscale = [
        [0.0, "#DCFCE7"],   # Light Green
        [0.2, "#86EFAC"],   # Green
        [0.24, "#FEF3C7"],  # Light Amber
        [0.44, "#FCD34D"],  # Amber
        [0.48, "#FFEDD5"],  # Light Orange
        [0.76, "#FB923C"],  # Orange
        [0.8, "#FEE2E2"],   # Light Red
        [1.0, "#EF4444"],   # Red
    ]

    fig = go.Figure(
        data=go.Heatmap(
            z=base_scores,
            x=[1, 2, 3, 4, 5],
            y=[1, 2, 3, 4, 5],
            hoverongaps=False,
            colorscale=colorscale,
            showscale=False,
            text=hover_texts,
            hoverinfo="text",
        )
    )

    fig.update_layout(
        annotations=annotations,
        xaxis=dict(
            title="Impact (Consequence Severity)",
            tickmode="array",
            tickvals=[1, 2, 3, 4, 5],
            ticktext=["1 - Insignificant", "2 - Minor", "3 - Moderate", "4 - Major", "5 - Catastrophic"],
            side="bottom",
        ),
        yaxis=dict(
            title="Likelihood (Probability)",
            tickmode="array",
            tickvals=[1, 2, 3, 4, 5],
            ticktext=["1 - Rare", "2 - Unlikely", "3 - Possible", "4 - Likely", "5 - Almost Certain"],
        ),
        margin=dict(t=20, b=20, l=40, r=20),
        height=380,
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
    )

    g1, g2 = st.columns([3, 2])
    with g1:
        st.plotly_chart(fig, use_container_width=True)

    with g2:
        st.markdown("**Heatmap Summary & Cell Inspector**")
        st.markdown(
            f"""
            <div style="background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 4px; padding: 0.75rem; font-size: 0.85rem; margin-bottom: 0.75rem;">
                <div>Total Assessed Risks in Grid: <strong>{heatmap_data['total_assessed']}</strong></div>
                <div>Unassessed Risks (Excluded from Grid): <strong>{heatmap_data['unassessed_count']}</strong></div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("**Inspect Specific Matrix Cell:**")
        f_col1, f_col2 = st.columns(2)
        with f_col1:
            inspect_l = st.selectbox("Likelihood", [5, 4, 3, 2, 1], key="hm_sel_l")
        with f_col2:
            inspect_i = st.selectbox("Impact", [1, 2, 3, 4, 5], key="hm_sel_i")

        matching_cell = next(
            (c for c in heatmap_data["cells"] if c["likelihood"] == inspect_l and c["impact"] == inspect_i),
            None,
        )

        if matching_cell and matching_cell["risks"]:
            st.markdown(f"Found **{len(matching_cell['risks'])}** risk(s) with Likelihood {inspect_l} & Impact {inspect_i}:")
            for cr in matching_cell["risks"]:
                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E5E7EB; padding: 0.4rem 0.6rem; border-radius: 3px; font-size: 0.8rem; margin-bottom: 0.35rem;">
                        <strong>{cr['risk_identifier']}</strong>: {cr['title']}<br/>
                        <span style="color: #6B7280;">Owner: {cr['owner']} &bull; Status: {cr['status']}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.caption(f"No risks currently evaluated at Likelihood {inspect_l} and Impact {inspect_i}.")


# =========================================================================
# 3. INDIVIDUAL RISK ASSESSMENT FORM TAB
# =========================================================================


def _render_risk_form_tab(assessment: Dict[str, Any], is_archived: bool):
    """Render structured 5-section risk creation and editing form."""
    edit_id = st.session_state.get("editing_risk_id")
    is_editing = edit_id is not None

    st.markdown(f"#### {'Edit Risk Assessment' if is_editing else 'Create New Risk Record'}")

    if is_archived:
        st.warning("Cannot create or modify risk records in an Archived assessment.")
        return

    # Load existing risk data if in edit mode
    existing_risk = get_single_risk(edit_id) if is_editing else None

    # Handle pre-fill from confirmed finding (Phase 4 integration)
    pre_title = st.session_state.get("prefill_risk_title", "")
    pre_threat = st.session_state.get("prefill_risk_threat", "")
    pre_conseq = st.session_state.get("prefill_risk_consequence", "")
    pre_treatment = st.session_state.get("prefill_risk_treatment", "")
    pre_fid = st.session_state.get("prefill_risk_finding_id")
    pre_ca_id = st.session_state.get("prefill_risk_ca_id")

    if is_editing and existing_risk:
        st.info(f"Currently editing **{existing_risk['risk_identifier']} – {existing_risk['title']}**")
        if st.button("Cancel Edit / Create New Risk"):
            st.session_state.pop("editing_risk_id", None)
            st.rerun()

    # Form options
    findings = get_assessment_findings(assessment["id"])
    finding_options = {f"{f['finding_identifier']} – {f['title']}": f["id"] for f in findings}

    controls = get_assessment_controls(assessment["id"])
    control_options = {f"{c['control_identifier']} – {c['control_title']}": c["assessment_control_id"] for c in controls}

    evidence_items = get_assessment_evidence(assessment["id"])
    evidence_options = {f"{e['evidence_identifier']} – {e['title']}": e["id"] for e in evidence_items}

    with st.form("risk_assessment_form"):
        # SECTION A: RISK IDENTIFICATION
        st.markdown("**Section A: Risk Identification**")
        title_val = existing_risk["title"] if existing_risk else pre_title
        title = st.text_input("Risk Title *", value=title_val, placeholder="e.g. Unauthorized Ingress via Deprecated Remote Gateway")

        a1, a2 = st.columns(2)
        with a1:
            cat_idx = RISK_CATEGORIES.index(existing_risk["risk_category"]) if existing_risk and existing_risk.get("risk_category") in RISK_CATEGORIES else 0
            category = st.selectbox("Risk Category *", options=RISK_CATEGORIES, index=cat_idx)
            asset = st.text_input("Asset or Business Process", value=existing_risk.get("asset_or_process", "") if existing_risk else "", placeholder="e.g. AWS Payment VPC, Core Banking Gateway")
        with a2:
            owner = st.text_input("Risk Owner", value=existing_risk.get("risk_owner", "") if existing_risk else "", placeholder="e.g. Chief Information Security Officer, IT Ops Lead")
            dept = st.text_input("Responsible Department", value=existing_risk.get("responsible_department", "") if existing_risk else "", placeholder="e.g. Infrastructure Engineering")

        description = st.text_area("Detailed Risk Description", value=existing_risk.get("description", "") if existing_risk else "", placeholder="Describe the risk scenario, affected business systems, and stakeholder impact...", height=70)

        t1, t2, t3 = st.columns(3)
        with t1:
            threat = st.text_input("Threat Agent / Event", value=existing_risk.get("threat", "") if existing_risk else pre_threat, placeholder="e.g. External credential stuffing attacker")
        with t2:
            vulnerability = st.text_input("Vulnerability / Weakness", value=existing_risk.get("vulnerability", "") if existing_risk else "", placeholder="e.g. Password-only legacy VPN bypass")
        with t3:
            consequence = st.text_input("Potential Consequence", value=existing_risk.get("consequence", "") if existing_risk else pre_conseq, placeholder="e.g. Unauthorized lateral movement into payment systems")

        # Entity Linkages
        st.markdown("<div style='margin-top: 0.5rem;'><strong>Linked Compliance Entities:</strong></div>", unsafe_allow_html=True)
        l1, l2 = st.columns(2)
        with l1:
            def_f_indices = []
            if existing_risk:
                existing_fids = {f["id"] for f in existing_risk.get("linked_findings", [])}
                def_f_indices = [k for k, v in finding_options.items() if v in existing_fids]
            elif pre_fid:
                def_f_indices = [k for k, v in finding_options.items() if v == pre_fid]
            sel_findings = st.multiselect("Link Audit Findings", options=list(finding_options.keys()), default=def_f_indices)

        with l2:
            def_c_indices = []
            if existing_risk:
                existing_cids = {c["control_assessment_id"] for c in existing_risk.get("linked_controls", [])}
                def_c_indices = [k for k, v in control_options.items() if v in existing_cids]
            elif pre_ca_id:
                def_c_indices = [k for k, v in control_options.items() if v == pre_ca_id]
            sel_controls = st.multiselect("Link Annex A Controls", options=list(control_options.keys()), default=def_c_indices)

        st.markdown("<hr style='margin: 0.75rem 0;'/>", unsafe_allow_html=True)

        # SECTION B: INHERENT RISK
        st.markdown("**Section B: Inherent Risk Evaluation (Pre-Control Baseline)**")
        st.markdown("<span style='font-size: 0.8rem; color: #6B7280;'>Assess raw exposure before accounting for any mitigating security controls.</span>", unsafe_allow_html=True)
        b1, b2 = st.columns(2)
        with b1:
            inh_l_val = existing_risk.get("inherent_likelihood") or existing_risk.get("likelihood") if existing_risk else None
            inh_l = st.selectbox(
                "Inherent Likelihood (1-5)",
                options=[None, 1, 2, 3, 4, 5],
                index=([None, 1, 2, 3, 4, 5].index(inh_l_val) if inh_l_val in [1, 2, 3, 4, 5] else 0),
                format_func=lambda x: f"{x} - {['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'][x-1]}" if x else "Unassessed",
            )
        with b2:
            inh_i_val = existing_risk.get("inherent_impact") or existing_risk.get("impact") if existing_risk else None
            inh_i = st.selectbox(
                "Inherent Impact (1-5)",
                options=[None, 1, 2, 3, 4, 5],
                index=([None, 1, 2, 3, 4, 5].index(inh_i_val) if inh_i_val in [1, 2, 3, 4, 5] else 0),
                format_func=lambda x: f"{x} - {['Insignificant', 'Minor', 'Moderate', 'Major', 'Catastrophic'][x-1]}" if x else "Unassessed",
            )

        inh_rationale = st.text_area("Inherent Assessment Rationale", value=existing_risk.get("inherent_rationale", "") if existing_risk else "", placeholder="Document the justification for baseline inherent likelihood and impact scores...", height=60)

        st.markdown("<hr style='margin: 0.75rem 0;'/>", unsafe_allow_html=True)

        # SECTION C: EXISTING CONTROLS & CURRENT RESIDUAL RISK
        st.markdown("**Section C: Existing Controls & Current Residual Risk**")
        st.markdown("<span style='font-size: 0.8rem; color: #6B7280;'>Risk remaining after considering existing implemented security controls and audit evidence.</span>", unsafe_allow_html=True)

        existing_ctrls = st.text_area("Existing Security Controls in Place", value=existing_risk.get("existing_controls", "") if existing_risk else "", placeholder="e.g. Okta SSO deployed for corporate employees; legacy gateway access monitored via weekly log review...", height=60)

        c1, c2 = st.columns(2)
        with c1:
            res_l_val = existing_risk.get("residual_likelihood") if existing_risk else None
            res_l = st.selectbox(
                "Current Residual Likelihood (1-5)",
                options=[None, 1, 2, 3, 4, 5],
                index=([None, 1, 2, 3, 4, 5].index(res_l_val) if res_l_val in [1, 2, 3, 4, 5] else 0),
                format_func=lambda x: f"{x} - {['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'][x-1]}" if x else "Unassessed",
            )
        with c2:
            res_i_val = existing_risk.get("residual_impact") if existing_risk else None
            res_i = st.selectbox(
                "Current Residual Impact (1-5)",
                options=[None, 1, 2, 3, 4, 5],
                index=([None, 1, 2, 3, 4, 5].index(res_i_val) if res_i_val in [1, 2, 3, 4, 5] else 0),
                format_func=lambda x: f"{x} - {['Insignificant', 'Minor', 'Moderate', 'Major', 'Catastrophic'][x-1]}" if x else "Unassessed",
            )

        res_rationale = st.text_area("Residual Risk Assessment Rationale", value=existing_risk.get("residual_rationale", "") if existing_risk else "", placeholder="Explain how existing controls mitigate likelihood or impact...", height=60)

        st.markdown("<hr style='margin: 0.75rem 0;'/>", unsafe_allow_html=True)

        # SECTION D: RISK TREATMENT & TARGET RESIDUAL RISK
        st.markdown("**Section D: Risk Treatment & Target Residual Risk**")
        st.markdown("<span style='font-size: 0.8rem; color: #6B7280;'>Define treatment strategy and estimated post-treatment target risk.</span>", unsafe_allow_html=True)

        d1, d2 = st.columns(2)
        with d1:
            strat_idx = TREATMENT_STRATEGIES.index(existing_risk["treatment_strategy"]) if existing_risk and existing_risk.get("treatment_strategy") in TREATMENT_STRATEGIES else 0
            treatment_strat = st.selectbox("Treatment Strategy *", options=TREATMENT_STRATEGIES, index=strat_idx)
            proposed_treatment = st.text_area("Proposed Treatment Plan", value=existing_risk.get("proposed_treatment", "") if existing_risk else pre_treatment, placeholder="e.g. Decommission legacy gateway; migrate contractor authentication to Okta SAML proxy with FIDO2...", height=60)
        with d2:
            treatment_owner = st.text_input("Treatment Action Owner", value=existing_risk.get("treatment_owner", "") if existing_risk else "", placeholder="e.g. Head of Infrastructure")
            target_date_val = existing_risk.get("target_treatment_date", "") if existing_risk else ""
            target_treatment_date = st.text_input("Target Completion Date (YYYY-MM-DD)", value=target_date_val, placeholder="2026-08-30")
            treatment_justification = st.text_area("Treatment Justification", value=existing_risk.get("treatment_justification", "") if existing_risk else "", placeholder="Justify the selected treatment approach and resource allocation...", height=60)

        # Target Risk (Estimate)
        st.markdown("<span style='font-size: 0.8rem; font-weight: 600; color: #374151;'>Estimated Target Residual Risk (Upon Treatment Completion):</span>", unsafe_allow_html=True)
        tgt1, tgt2 = st.columns(2)
        with tgt1:
            tgt_l_val = existing_risk.get("target_likelihood") if existing_risk else None
            tgt_l = st.selectbox(
                "Target Likelihood (1-5)",
                options=[None, 1, 2, 3, 4, 5],
                index=([None, 1, 2, 3, 4, 5].index(tgt_l_val) if tgt_l_val in [1, 2, 3, 4, 5] else 0),
                format_func=lambda x: f"{x} - {['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'][x-1]}" if x else "Unassessed",
            )
        with tgt2:
            tgt_i_val = existing_risk.get("target_impact") if existing_risk else None
            tgt_i = st.selectbox(
                "Target Impact (1-5)",
                options=[None, 1, 2, 3, 4, 5],
                index=([None, 1, 2, 3, 4, 5].index(tgt_i_val) if tgt_i_val in [1, 2, 3, 4, 5] else 0),
                format_func=lambda x: f"{x} - {['Insignificant', 'Minor', 'Moderate', 'Major', 'Catastrophic'][x-1]}" if x else "Unassessed",
            )

        target_rationale = st.text_input("Target Assessment Rationale", value=existing_risk.get("target_rationale", "") if existing_risk else "", placeholder="e.g. Multi-factor authentication reduces likelihood of credential stuffing to rare.")

        st.markdown("<hr style='margin: 0.75rem 0;'/>", unsafe_allow_html=True)

        # SECTION E: ACCOUNTABILITY, STATUS & GOVERNANCE
        st.markdown("**Section E: Accountability, Acceptance & Lifecycle Status**")
        e1, e2, e3 = st.columns(3)
        with e1:
            st_idx = RISK_STATUSES.index(existing_risk["status"]) if existing_risk and existing_risk.get("status") in RISK_STATUSES else 0
            risk_status = st.selectbox("Risk Status *", options=RISK_STATUSES, index=st_idx)
        with e2:
            rev_date_val = existing_risk.get("review_date", "") if existing_risk else ""
            review_date = st.text_input("Next Review Date (YYYY-MM-DD)", value=rev_date_val, placeholder="2026-11-30")
        with e3:
            assessor = st.text_input("Assessor Name", value=existing_risk.get("assessor_name", "Lead Assessor") if existing_risk else "Lead Assessor")

        # Acceptance Governance
        st.markdown("<span style='font-size: 0.8rem; font-weight: 600; color: #374151;'>Simulated Risk Acceptance Decision:</span>", unsafe_allow_html=True)
        acc1, acc2, acc3 = st.columns(3)
        with acc1:
            appr_idx = APPROVAL_STATUSES.index(existing_risk["approval_status"]) if existing_risk and existing_risk.get("approval_status") in APPROVAL_STATUSES else 0
            approval_status = st.selectbox("Approval Decision Status", options=APPROVAL_STATUSES, index=appr_idx)
        with acc2:
            approver = st.text_input("Approving Authority (Simulated)", value=existing_risk.get("approving_authority", "") if existing_risk else "", placeholder="e.g. Risk Committee, Board of Directors")
        with acc3:
            appr_date = st.text_input("Decision Date (YYYY-MM-DD)", value=existing_risk.get("approval_date", "") if existing_risk else "", placeholder="2026-05-15")

        acceptance_just = st.text_area("Risk Acceptance Justification", value=existing_risk.get("acceptance_justification", "") if existing_risk else "", placeholder="Document commercial, operational, or legal justification for accepting risk exposure...", height=50)

        # Closure rationale if closing
        closure_note = ""
        if risk_status == "Closed":
            closure_note = st.text_area("Closure Rationale & Verification Note *", value=existing_risk.get("closure_rationale", "") if existing_risk else "", placeholder="Mandatory: Document how risk remediation was verified or reason for closure...", height=50)

        # Reassessment reason if editing
        reassessment_reason = ""
        if is_editing:
            reassessment_reason = st.text_input("Reason for Reassessment (Logged in Audit History)", placeholder="e.g. Quarterly review; implementation of Okta MFA.")

        submitted = st.form_submit_button("Save Risk Record", use_container_width=True)

        if submitted:
            try:
                chosen_fids = [finding_options[k] for k in sel_findings]
                chosen_cids = [control_options[k] for k in sel_controls]

                if is_editing and existing_risk:
                    updated = update_risk(
                        risk_id=existing_risk["id"],
                        title=title,
                        description=description,
                        asset_or_process=asset,
                        threat=threat,
                        vulnerability=vulnerability,
                        consequence=consequence,
                        risk_category=category,
                        existing_controls=existing_ctrls,
                        risk_owner=owner,
                        responsible_department=dept,
                        inherent_likelihood=inh_l,
                        inherent_impact=inh_i,
                        inherent_rationale=inh_rationale,
                        residual_likelihood=res_l,
                        residual_impact=res_i,
                        residual_rationale=res_rationale,
                        target_likelihood=tgt_l,
                        target_impact=tgt_i,
                        target_rationale=target_rationale,
                        treatment_strategy=treatment_strat,
                        treatment_justification=treatment_justification,
                        proposed_treatment=proposed_treatment,
                        treatment_owner=treatment_owner,
                        target_treatment_date=target_treatment_date,
                        acceptance_justification=acceptance_just,
                        approving_authority=approver,
                        approval_status=approval_status,
                        approval_date=appr_date,
                        review_date=review_date,
                        status=risk_status,
                        closure_rationale=closure_note,
                        assessor_name=assessor,
                        reassessment_reason=reassessment_reason,
                    )
                    # Update links
                    for fid in chosen_fids:
                        link_finding_to_risk(updated["id"], fid)
                    for caid in chosen_cids:
                        link_control_to_risk(updated["id"], caid)

                    st.success(f"Updated risk {updated['risk_identifier']}.")
                    st.session_state.pop("editing_risk_id", None)
                    st.rerun()

                else:
                    new_risk = create_risk(
                        assessment_id=assessment["id"],
                        title=title,
                        description=description,
                        asset_or_process=asset,
                        threat=threat,
                        vulnerability=vulnerability,
                        consequence=consequence,
                        risk_category=category,
                        existing_controls=existing_ctrls,
                        risk_owner=owner,
                        responsible_department=dept,
                        inherent_likelihood=inh_l,
                        inherent_impact=inh_i,
                        inherent_rationale=inh_rationale,
                        residual_likelihood=res_l,
                        residual_impact=res_i,
                        residual_rationale=res_rationale,
                        target_likelihood=tgt_l,
                        target_impact=tgt_i,
                        target_rationale=target_rationale,
                        treatment_strategy=treatment_strat,
                        treatment_justification=treatment_justification,
                        proposed_treatment=proposed_treatment,
                        treatment_owner=treatment_owner,
                        target_treatment_date=target_treatment_date,
                        acceptance_justification=acceptance_just,
                        approving_authority=approver,
                        approval_status=approval_status,
                        approval_date=appr_date,
                        review_date=review_date,
                        status=risk_status,
                        assessor_name=assessor,
                        linked_finding_ids=chosen_fids,
                        linked_control_ids=chosen_cids,
                    )
                    st.success(f"Created risk record {new_risk['risk_identifier']} successfully.")
                    # Clear pre-filled state
                    st.session_state.pop("prefill_risk_finding_id", None)
                    st.session_state.pop("prefill_risk_title", None)
                    st.session_state.pop("prefill_risk_threat", None)
                    st.session_state.pop("prefill_risk_consequence", None)
                    st.session_state.pop("prefill_risk_treatment", None)
                    st.session_state.pop("prefill_risk_ca_id", None)
                    st.rerun()

            except Exception as e:
                st.error(f"Error saving risk: {str(e)}")


# =========================================================================
# 4. RISK DETAIL & REASSESSMENT TAB
# =========================================================================


def _render_risk_detail_tab(assessment: Dict[str, Any], is_archived: bool):
    """Render comprehensive risk working-paper detail, three-tier score comparison, and review history."""
    sel_id = st.session_state.get("selected_risk_id")
    if not sel_id:
        render_empty_state(
            title="No Risk Selected for Inspection",
            message="Select 'Inspect Details' on any record in the Risk Register Table to view its working paper.",
        )
        return

    risk = get_single_risk(sel_id)
    if not risk or risk["assessment_id"] != assessment["id"]:
        st.error("Selected risk could not be found in active assessment.")
        return

    r_ref = risk["risk_identifier"]
    st.markdown(f"#### Risk Working Paper: {r_ref} – {risk['title']}")

    # Three-tier Comparison Cards
    c1, c2, c3 = st.columns(3)
    inh_score = risk.get("inherent_risk_score")
    res_score = risk.get("residual_risk_score")
    tgt_score = risk.get("target_risk_score")

    with c1:
        inh_lvl = risk.get("inherent_risk_level") or "Not Assessed"
        st.markdown(
            f"""
            <div style="background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 4px; padding: 0.85rem; text-align: center;">
                <div style="font-size: 0.775rem; color: #6B7280; font-weight: 600;">INHERENT RISK (PRE-CONTROL)</div>
                <div style="font-size: 1.75rem; font-weight: 800; color: #1F2937;">{inh_score if inh_score is not None else 'N/A'}</div>
                <div>{render_severity_badge(inh_lvl)}</div>
                <div style="font-size: 0.75rem; color: #6B7280; margin-top: 0.35rem;">
                    Likelihood: <strong>{risk.get('inherent_likelihood') or 'N/A'}</strong> &bull; Impact: <strong>{risk.get('inherent_impact') or 'N/A'}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c2:
        res_lvl = risk.get("residual_risk_level") or "Not Assessed"
        st.markdown(
            f"""
            <div style="background: #FFFFFF; border: 2px solid #751C35; border-radius: 4px; padding: 0.85rem; text-align: center;">
                <div style="font-size: 0.775rem; color: #751C35; font-weight: 700;">CURRENT RESIDUAL RISK (LIVE)</div>
                <div style="font-size: 1.75rem; font-weight: 800; color: #751C35;">{res_score if res_score is not None else 'N/A'}</div>
                <div>{render_severity_badge(res_lvl)}</div>
                <div style="font-size: 0.75rem; color: #6B7280; margin-top: 0.35rem;">
                    Likelihood: <strong>{risk.get('residual_likelihood') or 'N/A'}</strong> &bull; Impact: <strong>{risk.get('residual_impact') or 'N/A'}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with c3:
        tgt_lvl = risk.get("target_risk_level") or "Not Assessed"
        st.markdown(
            f"""
            <div style="background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 4px; padding: 0.85rem; text-align: center;">
                <div style="font-size: 0.775rem; color: #6B7280; font-weight: 600;">TARGET RESIDUAL (ESTIMATED)</div>
                <div style="font-size: 1.75rem; font-weight: 800; color: #1F2937;">{tgt_score if tgt_score is not None else 'N/A'}</div>
                <div>{render_severity_badge(tgt_lvl)}</div>
                <div style="font-size: 0.75rem; color: #6B7280; margin-top: 0.35rem;">
                    Likelihood: <strong>{risk.get('target_likelihood') or 'N/A'}</strong> &bull; Impact: <strong>{risk.get('target_impact') or 'N/A'}</strong>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Anomaly and Trajectory Check
    comparison = compare_risk_evaluations(inh_score, res_score, tgt_score)
    if comparison["has_anomalies"]:
        for anom in comparison["anomalies"]:
            st.warning(f"⚠️ **Assessment Note:** {anom}")
    elif comparison["risk_reduction_pct"] is not None:
        st.success(f"✓ Control measures achieve an estimated **{comparison['risk_reduction_pct']}%** reduction from inherent exposure.")

    # Core metadata breakdown
    st.markdown(
        f"""
        <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 4px; padding: 1rem; margin-top: 1rem; font-size: 0.85rem;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
                <span><strong>Category:</strong> {risk.get('risk_category', 'Other')}</span>
                <span><strong>Status:</strong> {render_status_badge(risk['status'])}</span>
                <span><strong>Owner:</strong> {risk.get('risk_owner') or 'Unassigned'}</span>
                <span><strong>Department:</strong> {risk.get('responsible_department') or 'Unassigned'}</span>
            </div>
            <div style="margin-top: 0.5rem;">
                <strong>Threat:</strong> {risk.get('threat') or 'None specified'}<br/>
                <strong>Vulnerability:</strong> {risk.get('vulnerability') or 'None specified'}<br/>
                <strong>Consequence:</strong> {risk.get('consequence') or 'None specified'}
            </div>
            <div style="margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid #F3F4F6;">
                <strong>Existing Security Controls:</strong> {risk.get('existing_controls') or 'No documented controls'}<br/>
                <strong>Proposed Treatment Plan ({risk.get('treatment_strategy', 'Mitigate')}):</strong> {risk.get('proposed_treatment') or 'No proposed treatment plan'}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Linked Entities Tabs
    st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
    l_tab1, l_tab2, l_tab3, l_tab4, l_tab5 = st.tabs([
        "Linked Audit Findings",
        "Linked Controls",
        "Linked Evidence",
        "Reassessment History",
        "Linked Corrective Actions & Reassessment",
    ])

    with l_tab1:
        f_list = risk.get("linked_findings", [])
        if f_list:
            for f in f_list:
                st.markdown(f"• **{f['finding_identifier']} – {f['title']}** (Severity: {f['severity']}, Status: {f['status']})")
        else:
            st.caption("No audit findings currently linked to this risk.")

    with l_tab2:
        c_list = risk.get("linked_controls", [])
        if c_list:
            for c in c_list:
                st.markdown(f"• **{c['control_identifier']} – {c['control_title']}** (Domain: {c['domain']}, Status: {c['control_status']})")
        else:
            st.caption("No Annex A controls currently linked to this risk.")

    with l_tab3:
        e_list = risk.get("linked_evidence", [])
        if e_list:
            for e in e_list:
                st.markdown(f"• **{e['evidence_identifier']} – {e['title']}** (Type: {e['evidence_type']}, Status: {e['review_status']})")
        else:
            st.caption("No evidence artifacts currently linked to this risk.")

    with l_tab4:
        h_list = risk.get("review_history", [])
        if h_list:
            st.markdown(
                """
                <p style="font-size: 0.8rem; color: #6B7280;">
                    Note: Review history records previous reassessments and rationale. It is an operational log, not a cryptographic blockchain.
                </p>
                """,
                unsafe_allow_html=True,
            )
            for h in h_list:
                st.markdown(
                    f"""
                    <div style="background: #F9FAFB; border: 1px solid #E5E7EB; border-left: 3px solid #751C35; border-radius: 3px; padding: 0.6rem; margin-bottom: 0.5rem; font-size: 0.8rem;">
                        <strong>Reassessment Timestamp:</strong> {h['review_timestamp'].replace('T', ' ')} by {h['reviewer_name']}<br/>
                        Score Change: {h.get('previous_score') or 'N/A'} ({h.get('previous_level') or 'N/A'}) &rarr; <strong>{h.get('new_score') or 'N/A'} ({h.get('new_level') or 'N/A'})</strong><br/>
                        <strong>Reason:</strong> {h['reason_for_change']}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.caption("No historical reassessments logged for this risk.")

    with l_tab5:
        from services.remediation_service import (
            get_risk_remediations,
            get_remediation_verifications,
            get_remediation_evidence,
        )

        risk_rems = get_risk_remediations(risk["id"])
        st.markdown("##### Linked Corrective Actions & Treatment Progress")
        st.caption(
            "Track operational remediation tasks addressing this risk. "
            "Residual risk scores are not automatically lowered; an explicit reassessment is required."
        )

        if not risk_rems:
            st.info("No corrective actions currently linked to this risk.")
        else:
            for act in risk_rems:
                verifs = get_remediation_verifications(act["id"])
                v_res = verifs[0]["verification_result"] if verifs else "Unverified"
                ev_list = get_remediation_evidence(act["id"])

                st.markdown(
                    f"""
                    <div style="background: #FFFFFF; border: 1px solid #E5E7EB; border-left: 3px solid #751C35; padding: 0.75rem 1rem; border-radius: 3px; margin-bottom: 0.5rem;">
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

        st.markdown("<hr style='margin: 1rem 0;' />", unsafe_allow_html=True)
        st.markdown("##### 🔄 Explicit Risk Reassessment")
        st.caption(
            "Assess current residual risk based on verified control testing and remediation evidence. "
            "Target residual risk remains an aspirational estimate."
        )

        if is_archived:
            st.warning("Cannot reassess risk in an Archived assessment.")
        else:
            with st.form(f"reassess_risk_form_{risk['id']}"):
                col_l, col_i = st.columns(2)
                curr_l = risk.get("residual_likelihood") or 3
                curr_i = risk.get("residual_impact") or 3

                with col_l:
                    reass_l = st.selectbox(
                        "Reassessed Residual Likelihood *",
                        options=[1, 2, 3, 4, 5],
                        index=[1, 2, 3, 4, 5].index(curr_l) if curr_l in [1, 2, 3, 4, 5] else 2,
                    )
                with col_i:
                    reass_i = st.selectbox(
                        "Reassessed Residual Impact *",
                        options=[1, 2, 3, 4, 5],
                        index=[1, 2, 3, 4, 5].index(curr_i) if curr_i in [1, 2, 3, 4, 5] else 2,
                    )

                reass_rationale = st.text_area(
                    "Reassessment Rationale *",
                    placeholder="Document specific verified changes justifying the updated likelihood and impact ratings...",
                    height=75,
                )

                reass_ctrls = st.text_input(
                    "Updated Existing Controls Description",
                    value=risk.get("existing_controls") or "",
                )

                reass_reviewer = st.text_input("Reviewer Name *", value=assessment.get("lead_assessor") or "Lead Risk Assessor")
                reass_date = st.text_input("Review Date", value=date.today().isoformat())

                reass_submit = st.form_submit_button("Save Reassessed Residual Risk", type="primary")

                if reass_submit:
                    if not reass_rationale.strip():
                        st.error("Reassessment rationale is required.")
                    else:
                        try:
                            update_risk(
                                risk_id=risk["id"],
                                residual_likelihood=reass_l,
                                residual_impact=reass_i,
                                residual_rationale=reass_rationale,
                                existing_controls=reass_ctrls,
                                review_date=reass_date,
                                assessor_name=reass_reviewer,
                            )
                            st.success(f"Risk {r_ref} reassessed successfully! New residual score: {reass_l * reass_i}.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error reassessing risk: {e}")

    # Archival Action
    if not is_archived:
        st.markdown("<hr style='margin: 1rem 0;' />", unsafe_allow_html=True)
        if st.button("Archive This Risk Record", key=f"btn_arch_{risk['id']}"):
            archive_risk(risk["id"], actor=assessment.get("lead_assessor", "Lead Assessor"))
            st.success(f"Archived risk {r_ref}.")
            st.session_state.pop("selected_risk_id", None)
            st.rerun()
