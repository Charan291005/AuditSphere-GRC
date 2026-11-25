"""
Placeholder page view for modules planned for subsequent phases.

Explicitly clarifies implementation phase, active assessment context,
and database schema readiness without displaying fake metrics or decorative dummy buttons.
"""

import streamlit as st
from typing import Optional
from services.assessment_service import get_assessment
from ui_components import render_educational_disclaimer

MODULE_SPECS = {
    "iso27001_controls": {
        "title": "ISO 27001 Control Assessment",
        "phase": "Phase 2",
        "description": "Evaluation of ISO/IEC 27001:2022 security controls across the 4 Annex A themes (Organizational, People, Physical, Technological).",
        "db_tables": ["controls", "control_assessments"],
        "purpose": "Record implementation statuses, effectiveness ratings, and assessor observations against specific security controls.",
    },
    "evidence": {
        "title": "Evidence Management",
        "phase": "Phase 2",
        "description": "Upload, catalog, and trace audit artifacts and evidentiary files linked to assessed controls.",
        "db_tables": ["evidence", "control_evidence"],
        "purpose": "Provide verifiable audit evidence with SHA-256 integrity hashing and cross-assessment isolation.",
    },
    "gap_analysis": {
        "title": "Gap Analysis",
        "phase": "Phase 2",
        "description": "Identification and tracking of audit findings, non-conformities, and opportunities for improvement.",
        "db_tables": ["findings", "control_assessments"],
        "purpose": "Structure findings using Condition, Criteria, Cause, Effect, and Recommendation (CCCER) methodology.",
    },
    "risk_register": {
        "title": "Risk Register",
        "phase": "Phase 3",
        "description": "Risk identification, qualitative 5x5 scoring matrix, treatment planning, and residual risk calculation.",
        "db_tables": ["risks", "findings"],
        "purpose": "Evaluate inherent vs residual risks mapped directly to identified audit gaps and non-conformities.",
    },
    "remediation": {
        "title": "Remediation Tracker",
        "phase": "Phase 3",
        "description": "Corrective Action Plans (CAP), remediation ownership, due dates, and closure verification.",
        "db_tables": ["remediation", "findings", "risks"],
        "purpose": "Track accountability and completion of corrective actions with verification notes.",
    },
    "reports": {
        "title": "Assessment Reports",
        "phase": "Phase 3",
        "description": "Generation of executive summaries, Statement of Applicability (SoA) previews, and downloadable PDF/CSV audit reports.",
        "db_tables": ["assessments", "control_assessments", "findings", "risks", "remediation"],
        "purpose": "Export comprehensive, publication-grade ISMS assessment deliverables using ReportLab.",
    },
    "settings": {
        "title": "Settings & Framework Configuration",
        "phase": "Phase 3",
        "description": "Application settings, standard frameworks catalog, database backups, and environment diagnostics.",
        "db_tables": ["activity_log"],
        "purpose": "Manage platform configuration, theme preferences, and assessment framework definitions.",
    },
}


def render_placeholder_page(module_key: str):
    """Render a structured enterprise placeholder for an unimplemented module."""
    spec = MODULE_SPECS.get(
        module_key,
        {
            "title": "Planned Module",
            "phase": "Future Phase",
            "description": "Module scheduled for future development.",
            "db_tables": [],
            "purpose": "Planned functionality.",
        },
    )

    st.markdown(f"## {spec['title']}")
    st.markdown(
        f"<p style='color: #6B7280; font-size: 0.95rem; margin-top: -0.5rem;'>"
        f"{spec['description']}"
        f"</p>",
        unsafe_allow_html=True,
    )

    render_educational_disclaimer()

    active_id = st.session_state.get("active_assessment_id")
    active_assessment = get_assessment(active_id) if active_id else None

    # Context and Module Status Card
    st.markdown(
        f"""
        <div class="grc-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <span style="font-size: 1.15rem; font-weight: 700; color: #1F2937;">Implementation Status</span>
                <span style="background-color: #FFFBEB; color: #B45309; border: 1px solid #FDE68A; padding: 0.25rem 0.65rem; border-radius: 3px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase;">
                    Scheduled for {spec['phase']}
                </span>
            </div>
            <p style="color: #4B5563; font-size: 0.875rem; line-height: 1.6;">
                {spec['purpose']}
            </p>
            <div style="margin-top: 1.25rem; padding-top: 1rem; border-top: 1px solid #E5E7EB;">
                <div style="font-size: 0.8rem; font-weight: 600; color: #374151; margin-bottom: 0.35rem;">
                    Active Assessment Context:
                </div>
                <div style="font-size: 0.85rem; color: #6B7280; background-color: #F9FAFB; padding: 0.65rem 0.85rem; border-radius: 3px; border: 1px solid #F3F4F6;">
                    {f"<strong>{active_assessment['title']}</strong> ({active_assessment['organization']}) &bull; Status: {active_assessment['status']}" if active_assessment else "<em>No assessment currently selected. Once an assessment is activated, this module will operate within its scope.</em>"}
                </div>
            </div>
            <div style="margin-top: 1rem;">
                <div style="font-size: 0.8rem; font-weight: 600; color: #374151; margin-bottom: 0.35rem;">
                    Database Schema Readiness:
                </div>
                <div style="font-size: 0.85rem; color: #4B5563;">
                    The relational tables supporting this module are already initialized in SQLite:
                    <ul style="margin-top: 0.35rem; margin-bottom: 0; padding-left: 1.25rem;">
                        {"".join(f"<li style='margin-bottom: 0.2rem;'><code>{t}</code></li>" for t in spec['db_tables'])}
                    </ul>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Architectural Integrity Notice
    st.info(
        "**Strict GRC Development Principle:** In accordance with enterprise audit integrity requirements, "
        "no mock data, simulated percentages, or non-functional decorative buttons are shown. "
        f"This module will be connected directly to the database in {spec['phase']}."
    )
