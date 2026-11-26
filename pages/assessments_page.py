"""
Assessment Management module for AuditSphere.

Enables creation, filtering, editing, archival, and active-context selection
of ISMS assessments against ISO/IEC 27001:2022.
"""

import streamlit as st
from datetime import datetime, date
from typing import Optional
from services.assessment_service import (
    create_assessment,
    update_assessment,
    archive_assessment,
    list_assessments,
    get_assessment,
    VALID_STATUSES,
)
from ui_components import (
    render_status_badge,
    render_empty_state,
    render_educational_disclaimer,
)

INDUSTRY_PRESETS = [
    "Technology & SaaS",
    "Financial Services & Banking",
    "Healthcare & Life Sciences",
    "E-Commerce & Retail",
    "Telecommunications",
    "Manufacturing & Supply Chain",
    "Energy & Utilities",
    "Government & Public Sector",
    "Professional Services",
    "Other",
]


def render_assessments_page():
    """Render the assessment management workspace."""
    st.markdown("## Assessment Management")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.95rem; margin-top: -0.5rem;'>"
        "Create, view, edit, archive, and set the active ISO/IEC 27001:2022 assessment workspace."
        "</p>",
        unsafe_allow_html=True,
    )

    render_educational_disclaimer()

    # Sub-tabs for management workflows
    tab_list, tab_create, tab_edit = st.tabs(
        ["Assessments Directory", "Create New Assessment", "Edit Assessment"]
    )

    with tab_list:
        _render_directory_tab()

    with tab_create:
        _render_create_tab()

    with tab_edit:
        _render_edit_tab()


def _render_directory_tab():
    """Render the list and management controls of existing assessments."""
    # Filter bar
    f_col1, f_col2, f_col3, f_col4 = st.columns([2.5, 1.8, 1.2, 1.8])

    with f_col1:
        search_query = st.text_input(
            "Search Assessments",
            placeholder="Search by title, organization, or lead assessor...",
            label_visibility="collapsed",
        )
    with f_col2:
        status_filter = st.selectbox(
            "Filter by Status",
            options=["All Statuses"] + list(VALID_STATUSES),
            label_visibility="collapsed",
        )
    with f_col3:
        include_archived = st.checkbox("Show Archived", value=True)
    with f_col4:
        if st.button("Load FinCore Demo", use_container_width=True, help="Load the FinCore Technologies demonstration assessment."):
            from services.control_service import create_fincore_demo_assessment
            demo = create_fincore_demo_assessment()
            st.session_state["active_assessment_id"] = demo["assessment"]["id"]
            st.success("Loaded FinCore demonstration assessment.")
            st.rerun()

    # Fetch data
    db_status = None if status_filter == "All Statuses" else status_filter
    all_assessments = list_assessments(
        include_archived=include_archived, status_filter=db_status
    )

    # Apply search filter
    if search_query and search_query.strip():
        q = search_query.strip().lower()
        all_assessments = [
            a
            for a in all_assessments
            if q in a["title"].lower()
            or q in a["organization"].lower()
            or q in a["lead_assessor"].lower()
        ]

    active_id = st.session_state.get("active_assessment_id")

    st.markdown(f"**Found {len(all_assessments)} assessment(s)**")

    if not all_assessments:
        render_empty_state(
            title="No Assessments Found",
            message="No assessments match your current filters. Create an assessment using the 'Create New Assessment' tab above.",
        )
        return

    # Render each assessment card
    for asm in all_assessments:
        is_active = asm["id"] == active_id
        card_border = "#751C35" if is_active else "#E5E7EB"
        active_badge_html = (
            '<span style="background-color: #751C35; color: #FFFFFF; font-size: 0.7rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 2px; margin-left: 0.5rem; text-transform: uppercase;">ACTIVE CONTEXT</span>'
            if is_active
            else ""
        )

        st.markdown(
            f"""
            <div style="background-color: #FFFFFF; border: 1px solid {card_border}; border-left: { '4px solid #751C35;' if is_active else '1px solid #E5E7EB;' } border-radius: 4px; padding: 1.25rem; margin-bottom: 0.75rem; box-shadow: 0 1px 2px rgba(0,0,0,0.03);">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #1F2937;">
                            {asm['title']} {active_badge_html}
                        </div>
                        <div style="font-size: 0.85rem; color: #6B7280; margin-top: 0.15rem;">
                            <strong>{asm['organization']}</strong> &bull; {asm['industry']} &bull; Standard: {asm['standard']}
                        </div>
                    </div>
                    <div>
                        {render_status_badge(asm['status'])}
                    </div>
                </div>
                <div style="margin-top: 0.65rem; font-size: 0.825rem; color: #4B5563;">
                    <strong>Scope:</strong> {asm['scope']}
                </div>
                <div style="margin-top: 0.5rem; display: flex; gap: 1.5rem; font-size: 0.785rem; color: #6B7280;">
                    <span>Assessor: <strong>{asm['lead_assessor']}</strong></span>
                    <span>Assessment Date: <strong>{asm['assessment_date']}</strong></span>
                    <span>Last Updated: <strong>{asm['updated_at'][:10]}</strong></span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Card action buttons
        btn_col1, btn_col2, btn_col3, _ = st.columns([1.6, 1.2, 1.2, 3])

        with btn_col1:
            if not is_active:
                if st.button(
                    "Set as Active Context",
                    key=f"btn_activate_{asm['id']}",
                    use_container_width=True,
                ):
                    st.session_state["active_assessment_id"] = asm["id"]
                    st.rerun()
            else:
                st.button(
                    "Active Workspace",
                    key=f"btn_is_active_{asm['id']}",
                    disabled=True,
                    use_container_width=True,
                )

        with btn_col2:
            if st.button(
                "Edit Details",
                key=f"btn_edit_{asm['id']}",
                use_container_width=True,
            ):
                st.session_state["edit_assessment_id"] = asm["id"]
                st.info(f"Loaded '{asm['title']}' into Edit tab above. Please switch to the Edit Assessment tab.")

        with btn_col3:
            if asm["status"] != "Archived":
                if st.button(
                    "Archive",
                    key=f"btn_archive_{asm['id']}",
                    use_container_width=True,
                ):
                    archive_assessment(asm["id"])
                    st.success(f"Assessment '{asm['title']}' archived.")
                    st.rerun()
            else:
                st.button(
                    "Archived",
                    key=f"btn_archived_label_{asm['id']}",
                    disabled=True,
                    use_container_width=True,
                )

        st.markdown("<div style='margin-bottom: 0.5rem;'></div>", unsafe_allow_html=True)


def _render_create_tab():
    """Render the form to create a new assessment."""
    st.markdown("#### Define New ISMS Assessment")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.85rem; margin-top: -0.5rem;'>"
        "All fields marked with an asterisk (*) are mandatory. The assessment will be persisted in the local SQLite database."
        "</p>",
        unsafe_allow_html=True,
    )

    with st.form("create_assessment_form", clear_on_submit=False):
        c1, c2 = st.columns(2)
        with c1:
            title = st.text_input(
                "Assessment Title *",
                placeholder="e.g. FY2026 Core Infrastructure ISO 27001 Audit",
            )
            organization = st.text_input(
                "Organization Name *",
                placeholder="e.g. Acme Financial Technologies Ltd",
            )
            industry = st.selectbox("Industry Sector *", options=INDUSTRY_PRESETS)
            if industry == "Other":
                industry = st.text_input("Specify Industry *", placeholder="e.g. Biotechnology")

        with c2:
            lead_assessor = st.text_input(
                "Lead Assessor Name & Credentials *",
                placeholder="e.g. Jane Doe, Lead Auditor ISO 27001",
            )
            assessment_date = st.date_input(
                "Assessment Target Date *",
                value=date.today(),
            )
            status = st.selectbox(
                "Initial Status",
                options=["Draft", "In Progress"],
                index=0,
            )
            standard = st.text_input(
                "Standard Framework",
                value="ISO/IEC 27001:2022",
                disabled=True,
                help="ISO/IEC 27001:2022 is the standard framework supported in Phase 1.",
            )

        scope = st.text_area(
            "Assessment Scope *",
            placeholder="Define organizational boundaries, technical infrastructure, facilities, applications, and legal entities included in the ISMS scope...",
            height=100,
            help="Mandatory: Explicitly define what is inside the audit boundary.",
        )

        objectives = st.text_area(
            "Assessment Objectives (Optional)",
            placeholder="e.g. Internal audit verification prior to external recertification; evaluate compliance against Annex A controls...",
            height=80,
        )

        submit_btn = st.form_submit_button("Create Assessment", type="primary")

        if submit_btn:
            date_str = assessment_date.strftime("%Y-%m-%d") if assessment_date else ""
            try:
                created = create_assessment(
                    title=title,
                    organization=organization,
                    industry=industry,
                    scope=scope,
                    lead_assessor=lead_assessor,
                    assessment_date=date_str,
                    objectives=objectives,
                    status=status,
                )
                # Automatically set as active context
                st.session_state["active_assessment_id"] = created["id"]
                st.success(
                    f"Assessment '{created['title']}' created successfully (ID #{created['id']}) and set as the active context!"
                )
                st.rerun()
            except ValueError as ve:
                st.error(f"Validation Error: {str(ve)}")
            except Exception as ex:
                st.error(f"Database Error: {str(ex)}")


def _render_edit_tab():
    """Render the editing interface for existing assessments."""
    st.markdown("#### Edit Existing Assessment")

    all_assessments = list_assessments(include_archived=True)
    if not all_assessments:
        render_empty_state(
            title="No Assessments Available to Edit",
            message="Create an assessment first before attempting to edit.",
        )
        return

    # Determine default selection
    assessment_map = {
        f"#{a['id']} - {a['title']} ({a['organization']})": a["id"]
        for a in all_assessments
    }

    preselected_id = st.session_state.get(
        "edit_assessment_id"
    ) or st.session_state.get("active_assessment_id")

    default_index = 0
    if preselected_id:
        for idx, (lbl, aid) in enumerate(assessment_map.items()):
            if aid == preselected_id:
                default_index = idx
                break

    selected_label = st.selectbox(
        "Select Assessment to Edit",
        options=list(assessment_map.keys()),
        index=default_index,
    )

    selected_id = assessment_map[selected_label]
    assessment = get_assessment(selected_id)

    if not assessment:
        st.error("Selected assessment could not be loaded from database.")
        return

    # Parse date
    try:
        current_date = datetime.strptime(assessment["assessment_date"], "%Y-%m-%d").date()
    except Exception:
        current_date = date.today()

    with st.form(f"edit_assessment_form_{selected_id}"):
        c1, c2 = st.columns(2)
        with c1:
            title = st.text_input("Assessment Title *", value=assessment["title"])
            organization = st.text_input(
                "Organization Name *", value=assessment["organization"]
            )
            # Find industry preset
            curr_ind = assessment["industry"]
            ind_options = (
                INDUSTRY_PRESETS
                if curr_ind in INDUSTRY_PRESETS
                else [curr_ind] + INDUSTRY_PRESETS
            )
            industry = st.selectbox(
                "Industry Sector *",
                options=ind_options,
                index=ind_options.index(curr_ind) if curr_ind in ind_options else 0,
            )

        with c2:
            lead_assessor = st.text_input(
                "Lead Assessor *", value=assessment["lead_assessor"]
            )
            assessment_date = st.date_input(
                "Assessment Target Date *",
                value=current_date,
            )
            status_index = (
                VALID_STATUSES.index(assessment["status"])
                if assessment["status"] in VALID_STATUSES
                else 0
            )
            status = st.selectbox(
                "Assessment Status",
                options=VALID_STATUSES,
                index=status_index,
            )

        scope = st.text_area(
            "Assessment Scope *",
            value=assessment["scope"],
            height=100,
        )

        objectives = st.text_area(
            "Assessment Objectives",
            value=assessment["objectives"] or "",
            height=80,
        )

        save_btn = st.form_submit_button("Save Changes", type="primary")

        if save_btn:
            date_str = assessment_date.strftime("%Y-%m-%d") if assessment_date else ""
            try:
                updated = update_assessment(
                    assessment_id=selected_id,
                    title=title,
                    organization=organization,
                    industry=industry,
                    scope=scope,
                    lead_assessor=lead_assessor,
                    assessment_date=date_str,
                    status=status,
                    objectives=objectives,
                )
                st.success(f"Assessment '{updated['title']}' updated successfully!")
                st.rerun()
            except ValueError as ve:
                st.error(f"Validation Error: {str(ve)}")
            except Exception as ex:
                st.error(f"Database Error: {str(ex)}")
