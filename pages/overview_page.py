"""
Overview Dashboard page view for AuditSphere.

Displays genuine metrics and visualizations derived strictly from SQLite database records.
Integrates live Phase 2 control assessment posture, coverage, weighted readiness scores,
and category breakdowns using Plotly. Does not display synthetic or fake percentages.
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from services.dashboard_service import get_dashboard_summary
from services.control_service import create_fincore_demo_assessment
from ui_components import (
    render_kpi_card,
    render_status_badge,
    render_event_badge,
    render_empty_state,
    render_educational_disclaimer,
)

# Professional GRC accessible color palette
STATUS_COLORS = {
    "Implemented": "#15803D",
    "Partially Implemented": "#D97706",
    "Not Implemented": "#DC2626",
    "Not Assessed": "#9CA3AF",
    "Not Applicable": "#4B5563",
}


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
                message="Select an active assessment from the left sidebar or Assessment Management to load its contextual workspace.",
            )
            if st.button("Load FinCore Technologies Demo Assessment"):
                demo = create_fincore_demo_assessment()
                st.session_state["active_assessment_id"] = demo["assessment"]["id"]
                st.success("Loaded FinCore Technologies demonstration assessment.")
                st.rerun()

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

    # PHASE 2: CONTROL READINESS & COMPLIANCE TELEMETRY
    st.markdown(
        '<div class="grc-card-title">ISO/IEC 27001:2022 Control Implementation Posture (Selected 20 Controls)</div>',
        unsafe_allow_html=True,
    )

    ctrl_metrics = summary.get("control_metrics")
    if ctrl_metrics and active:
        # Control KPI row
        k1, k2, k3, k4, k5, k6, k7 = st.columns(7)
        with k1:
            render_kpi_card(
                label="Selected Controls",
                value=f"{ctrl_metrics['total_controls']}",
                description="Annex A subset",
            )
        with k2:
            cov_str = (
                f"{ctrl_metrics['coverage_pct']:.1f}%"
                if ctrl_metrics["coverage_pct"] is not None
                else "N/A"
            )
            render_kpi_card(
                label="Coverage",
                value=cov_str,
                description=f"{ctrl_metrics['assessed_controls']} / {ctrl_metrics['applicable_controls']} assessed",
            )
        with k3:
            read_str = (
                f"{ctrl_metrics['weighted_readiness_pct']:.1f}%"
                if ctrl_metrics["weighted_readiness_pct"] is not None
                else "N/A"
            )
            render_kpi_card(
                label="Weighted Readiness",
                value=read_str,
                description="Assessed controls score",
            )
        with k4:
            render_kpi_card(
                label="Implemented",
                value=ctrl_metrics["status_counts"].get("Implemented", 0),
                description="Full conformity",
            )
        with k5:
            render_kpi_card(
                label="Potential Gaps",
                value=ctrl_metrics["potential_gaps"],
                description="Partial + Not Impl.",
            )
        with k6:
            render_kpi_card(
                label="Pending",
                value=ctrl_metrics["pending_controls"],
                description="Not assessed yet",
            )
        with k7:
            render_kpi_card(
                label="Not Applicable",
                value=ctrl_metrics["status_counts"].get("Not Applicable", 0),
                description="Out of scope",
            )

        # Plotly Visualizations Row
        st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
        g1, g2 = st.columns([1, 1])

        with g1:
            _render_status_donut_chart(ctrl_metrics["status_counts"])

        with g2:
            _render_category_progress_chart(ctrl_metrics["category_summary"])

        # Category Readiness Score Bar Chart
        st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
        _render_category_readiness_bar(ctrl_metrics["category_summary"])

    else:
        render_empty_state(
            title="No Control Evaluations Available",
            message="Select an active assessment to view control implementation posture, or navigate to ISO 27001 Control Assessment to evaluate controls.",
        )

    st.markdown("<hr/>", unsafe_allow_html=True)

    # PHASE 3: AUDIT EVIDENCE, TESTING & FINDINGS ASSURANCE
    ev_metrics = summary.get("evidence_metrics")
    fnd_metrics = summary.get("findings_metrics")
    tst_metrics = summary.get("test_metrics")

    if active and (ev_metrics or fnd_metrics or tst_metrics):
        st.markdown(
            '<div class="grc-card-title">Audit Evidence, Control Testing & Formal Findings</div>',
            unsafe_allow_html=True,
        )

        p3_col1, p3_col2, p3_col3, p3_col4, p3_col5 = st.columns(5)
        with p3_col1:
            tot_ev = ev_metrics["total_evidence"] if ev_metrics else 0
            acc_ev = ev_metrics["review_counts"].get("Accepted", 0) if ev_metrics else 0
            render_kpi_card(
                label="Evidence Records",
                value=f"{tot_ev}",
                description=f"{acc_ev} accepted by auditor",
            )
        with p3_col2:
            integ_errs = ev_metrics["integrity_issues"] if ev_metrics else 0
            render_kpi_card(
                label="Integrity Alerts",
                value=f"{integ_errs}",
                description="SHA-256 mismatch or missing" if integ_errs > 0 else "All local files intact",
            )
        with p3_col3:
            tot_tests = tst_metrics["total_tests"] if tst_metrics else 0
            pass_tests = tst_metrics["pass_count"] if tst_metrics else 0
            fail_tests = tst_metrics["fail_count"] if tst_metrics else 0
            render_kpi_card(
                label="Control Tests",
                value=f"{tot_tests}",
                description=f"{pass_tests} Pass &bull; {fail_tests} Fail",
            )
        with p3_col4:
            tot_fnd = fnd_metrics["total_findings"] if fnd_metrics else 0
            open_fnd = fnd_metrics["open_findings"] if fnd_metrics else 0
            render_kpi_card(
                label="Formal Findings",
                value=f"{tot_fnd}",
                description=f"{open_fnd} open / actionable",
            )
        with p3_col5:
            crit_high = (
                (fnd_metrics["severity_counts"].get("Critical", 0) + fnd_metrics["severity_counts"].get("High", 0))
                if fnd_metrics
                else 0
            )
            render_kpi_card(
                label="Critical & High",
                value=f"{crit_high}",
                description="Elevated risk non-conformities",
            )

        st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
        ef1, ef2 = st.columns([1, 1])

        with ef1:
            _render_findings_severity_chart(fnd_metrics["severity_counts"] if fnd_metrics else {})

        with ef2:
            _render_evidence_status_chart(ev_metrics["review_counts"] if ev_metrics else {})

        st.markdown("<hr/>", unsafe_allow_html=True)

    # PHASE 4: RISK MANAGEMENT & RESIDUAL EXPOSURE TELEMETRY
    rsk_metrics = summary.get("risk_metrics")
    if active and rsk_metrics and rsk_metrics["total_risks"] > 0:
        st.markdown(
            '<div class="grc-card-title">Information Security Risk Posture (Residual Exposure)</div>',
            unsafe_allow_html=True,
        )

        p4_c1, p4_c2, p4_c3, p4_c4, p4_c5, p4_c6 = st.columns(6)
        with p4_c1:
            render_kpi_card(
                label="Total Risks",
                value=f"{rsk_metrics['total_risks']}",
                description="Identified risk scenarios",
            )
        with p4_c2:
            render_kpi_card(
                label="Critical Residual",
                value=f"{rsk_metrics['critical_risks']}",
                description="Score 20-25 (Urgent)",
            )
        with p4_c3:
            render_kpi_card(
                label="High Residual",
                value=f"{rsk_metrics['high_risks']}",
                description="Score 12-19 (Elevated)",
            )
        with p4_c4:
            render_kpi_card(
                label="Medium / Low",
                value=f"{rsk_metrics['medium_risks'] + rsk_metrics['low_risks']}",
                description="Managed exposure",
            )
        with p4_c5:
            render_kpi_card(
                label="Accepted Risks",
                value=f"{rsk_metrics['accepted_risks']}",
                description="Approved decisions",
            )
        with p4_c6:
            render_kpi_card(
                label="Overdue Reviews",
                value=f"{rsk_metrics['overdue_reviews']}",
                description="Review date expired" if rsk_metrics['overdue_reviews'] > 0 else "All reviews current",
            )

        st.markdown("<div style='margin-top: 1rem;'></div>", unsafe_allow_html=True)
        rf1, rf2 = st.columns([1, 1])

        with rf1:
            _render_risk_severity_bar(rsk_metrics)

        with rf2:
            _render_treatment_donut_chart(rsk_metrics["treatment_counts"])

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
            time_str = act["timestamp"].replace("T", " ").replace("Z", " UTC")
            ctrl_ref = act.get("control_reference") or "-"
            rows.append(
                {
                    "Timestamp": time_str,
                    "Assessment": act.get("assessment_title")
                    or f"ID #{act.get('assessment_id')}",
                    "Control Ref": ctrl_ref,
                    "Event": act["event_type"].replace("ASSESSMENT_", "").replace("CONTROL_", "").title(),
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
            message="Assessment lifecycle and control evaluation events will automatically appear in this feed.",
        )

    # Subsequent Modules Notice
    st.markdown(
        """
        <div style="margin-top: 1.5rem; padding: 0.85rem 1rem; background-color: #FFFFFF; border: 1px dashed #D1D5DB; border-radius: 4px; font-size: 0.825rem; color: #6B7280;">
            <strong>Phase 5 Scope Notice:</strong> Corrective and Preventive Actions (CAPA) tracking, remediation milestone SLA management, and automated verification workflows will be activated in Phase 5. All Phase 1 through 4 workflows (Assessment Management, Control Assessment, Evidence Repository, Control Testing, Gap Analysis/Findings, and Risk Register) are fully operational. In compliance with strict GRC integrity standards, no artificial or mock percentages are displayed.
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_status_donut_chart(status_counts: Dict[str, int]):
    """Render Plotly donut chart showing implementation status breakdown."""
    st.markdown("**Control Implementation Status Distribution**")

    labels = ["Implemented", "Partially Implemented", "Not Implemented", "Not Assessed", "Not Applicable"]
    values = [status_counts.get(l, 0) for l in labels]
    colors = [STATUS_COLORS[l] for l in labels]

    if sum(values) == 0:
        st.info("No controls to display.")
        return

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.48,
                marker=dict(colors=colors, line=dict(color="#FFFFFF", width=1.5)),
                textinfo="value+percent",
                hoverinfo="label+value+percent",
                sort=False,
            )
        ]
    )

    fig.update_layout(
        margin=dict(t=10, b=10, l=10, r=10),
        height=260,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5, font=dict(size=10)),
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
    )

    st.plotly_chart(fig, use_container_width=True)


def _render_category_progress_chart(cat_summary: Dict[str, Dict[str, Any]]):
    """Render stacked horizontal bar chart showing control statuses per domain."""
    st.markdown("**Assessment Progress by Control Theme**")

    categories = ["Organizational", "People", "Physical", "Technological"]
    statuses = ["Implemented", "Partially Implemented", "Not Implemented", "Not Assessed", "Not Applicable"]

    data = []
    for s in statuses:
        s_key = s.lower().replace(" ", "_")
        vals = [cat_summary.get(c, {}).get(s_key, 0) for c in categories]
        data.append(
            go.Bar(
                name=s,
                y=categories,
                x=vals,
                orientation="h",
                marker=dict(color=STATUS_COLORS[s]),
            )
        )

    fig = go.Figure(data=data)
    fig.update_layout(
        barmode="stack",
        margin=dict(t=10, b=10, l=10, r=10),
        height=260,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5, font=dict(size=10)),
        xaxis=dict(title="Number of Controls", dtick=2),
        yaxis=dict(autorange="reversed"),
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
    )

    st.plotly_chart(fig, use_container_width=True)


def _render_category_readiness_bar(cat_summary: Dict[str, Dict[str, Any]]):
    """Render bar chart showing Weighted Readiness Score (%) across the 4 themes."""
    st.markdown("**Domain Weighted Readiness Scores (%)**")

    categories = ["Organizational", "People", "Physical", "Technological"]
    readiness_vals = []
    coverage_vals = []

    for c in categories:
        data = cat_summary.get(c, {})
        r = data.get("weighted_readiness_pct")
        readiness_vals.append(r if r is not None else 0.0)
        cov = data.get("coverage_pct")
        coverage_vals.append(cov if cov is not None else 0.0)

    fig = go.Figure()
    fig.add_trace(
        go.Bar(
            name="Weighted Readiness (%)",
            x=categories,
            y=readiness_vals,
            marker_color="#751C35",
            text=[f"{v:.1f}%" if v > 0 else "N/A" for v in readiness_vals],
            textposition="auto",
        )
    )
    fig.add_trace(
        go.Bar(
            name="Assessment Coverage (%)",
            x=categories,
            y=coverage_vals,
            marker_color="#D1D5DB",
            text=[f"{v:.1f}%" if v > 0 else "0%" for v in coverage_vals],
            textposition="auto",
        )
    )

    fig.update_layout(
        barmode="group",
        yaxis=dict(title="Percentage (%)", range=[0, 105]),
        margin=dict(t=20, b=10, l=10, r=10),
        height=260,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5, font=dict(size=11)),
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
    )

    st.plotly_chart(fig, use_container_width=True)


def _render_findings_severity_chart(severity_counts: Dict[str, int]):
    """Render horizontal bar chart for findings by severity."""
    st.markdown("**Findings by Severity**")
    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    colors = {
        "Critical": "#DC2626",
        "High": "#EA580C",
        "Medium": "#D97706",
        "Low": "#2563EB",
        "Informational": "#6B7280",
    }
    vals = [severity_counts.get(s, 0) for s in severities]

    if sum(vals) == 0:
        st.info("No formal findings recorded for this assessment.")
        return

    fig = go.Figure(
        data=[
            go.Bar(
                x=vals,
                y=severities,
                orientation="h",
                marker=dict(color=[colors[s] for s in severities]),
                text=[str(v) if v > 0 else "" for v in vals],
                textposition="auto",
            )
        ]
    )
    fig.update_layout(
        margin=dict(t=10, b=10, l=10, r=10),
        height=240,
        xaxis=dict(title="Findings Count", dtick=1),
        yaxis=dict(autorange="reversed"),
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
    )
    st.plotly_chart(fig, use_container_width=True)


def _render_evidence_status_chart(review_counts: Dict[str, int]):
    """Render donut chart for evidence review status distribution."""
    st.markdown("**Evidence Review Status**")
    statuses = ["Accepted", "Pending Review", "Needs Clarification", "Rejected"]
    colors = {
        "Accepted": "#15803D",
        "Pending Review": "#D97706",
        "Needs Clarification": "#2563EB",
        "Rejected": "#DC2626",
    }
    vals = [review_counts.get(s, 0) for s in statuses]

    if sum(vals) == 0:
        st.info("No audit evidence files uploaded for this assessment.")
        return

    fig = go.Figure(
        data=[
            go.Pie(
                labels=statuses,
                values=vals,
                hole=0.48,
                marker=dict(colors=[colors[s] for s in statuses], line=dict(color="#FFFFFF", width=1.5)),
                textinfo="value+percent",
                hoverinfo="label+value+percent",
                sort=False,
            )
        ]
    )
    fig.update_layout(
        margin=dict(t=10, b=10, l=10, r=10),
        height=240,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5, font=dict(size=10)),
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
    )
    st.plotly_chart(fig, use_container_width=True)


def _render_risk_severity_bar(rsk_metrics: Dict[str, Any]):
    """Render horizontal bar chart for current residual risk distribution."""
    st.markdown("**Current Residual Risk Distribution**")
    levels = ["Critical", "High", "Medium", "Low", "Unassessed"]
    counts = [
        rsk_metrics["critical_risks"],
        rsk_metrics["high_risks"],
        rsk_metrics["medium_risks"],
        rsk_metrics["low_risks"],
        rsk_metrics["unassessed_risks"],
    ]
    colors = ["#DC2626", "#EA580C", "#D97706", "#15803D", "#6B7280"]

    fig = go.Figure(
        data=[
            go.Bar(
                x=counts,
                y=levels,
                orientation="h",
                marker=dict(color=colors),
                text=[str(c) if c > 0 else "" for c in counts],
                textposition="auto",
            )
        ]
    )
    fig.update_layout(
        margin=dict(t=10, b=10, l=10, r=10),
        height=240,
        xaxis=dict(title="Number of Risks", dtick=1),
        yaxis=dict(autorange="reversed"),
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
    )
    st.plotly_chart(fig, use_container_width=True)


def _render_treatment_donut_chart(treatment_counts: Dict[str, int]):
    """Render donut chart for risk treatment strategies."""
    st.markdown("**Risk Treatment Strategies**")
    strategies = ["Mitigate", "Accept", "Transfer", "Avoid"]
    colors = {
        "Mitigate": "#751C35",
        "Accept": "#15803D",
        "Transfer": "#2563EB",
        "Avoid": "#D97706",
    }
    vals = [treatment_counts.get(s, 0) for s in strategies]

    if sum(vals) == 0:
        st.info("No treatment strategies recorded.")
        return

    fig = go.Figure(
        data=[
            go.Pie(
                labels=strategies,
                values=vals,
                hole=0.48,
                marker=dict(colors=[colors[s] for s in strategies], line=dict(color="#FFFFFF", width=1.5)),
                textinfo="value+percent",
                hoverinfo="label+value+percent",
                sort=False,
            )
        ]
    )
    fig.update_layout(
        margin=dict(t=10, b=10, l=10, r=10),
        height=240,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5, font=dict(size=10)),
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
    )
    st.plotly_chart(fig, use_container_width=True)
