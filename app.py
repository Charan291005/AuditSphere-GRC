"""
AuditSphere – ISMS Audit & Compliance Assessment Platform
Phase 1 Application Shell & Navigation Router.

Design Requirements:
- Professional enterprise GRC interface
- Light theme with primary accent #751C35
- Persistent sidebar navigation and active assessment context
- Parameterized SQLite backend with WAL mode and foreign key enforcement
- Genuine telemetry derived from database records without mock metrics
"""

import streamlit as st
from database import init_db
from services.assessment_service import list_assessments, get_assessment
from ui_components import inject_custom_styles
from pages.overview_page import render_overview_page
from pages.assessments_page import render_assessments_page
from pages.placeholder_page import render_placeholder_page

# Set top-level page configuration
st.set_page_config(
    page_title="AuditSphere | ISMS Audit & Compliance Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize database idempotently
init_db()

# Inject enterprise CSS styling
inject_custom_styles()


def initialize_session_state():
    """Ensure session state variables are properly initialized."""
    if "active_assessment_id" not in st.session_state:
        # Load the latest non-archived assessment as default if available
        active_list = list_assessments(include_archived=False)
        if active_list:
            st.session_state["active_assessment_id"] = active_list[0]["id"]
        else:
            # Check if any assessment exists
            all_list = list_assessments(include_archived=True)
            if all_list:
                st.session_state["active_assessment_id"] = all_list[0]["id"]
            else:
                st.session_state["active_assessment_id"] = None

    if "navigation_page" not in st.session_state:
        st.session_state["navigation_page"] = "Overview Dashboard"


initialize_session_state()

# MODULE DEFINITIONS
MODULES = [
    "Overview Dashboard",
    "Assessment Management",
    "ISO 27001 Control Assessment",
    "Evidence Management",
    "Gap Analysis",
    "Risk Register",
    "Remediation Tracker",
    "Assessment Reports",
    "Settings",
]

# SIDEBAR: PERSISTENT BRANDING & CONTROLS
with st.sidebar:
    # Branding header
    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="sidebar-brand-title">🛡️ AuditSphere</div>
            <div class="sidebar-brand-sub">ISMS GRC Platform &bull; ISO 27001:2022</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Active Assessment Workspace Context Selector
    st.markdown(
        "<div style='font-size: 0.75rem; font-weight: 700; color: #6B7280; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.35rem;'>Active Assessment Workspace</div>",
        unsafe_allow_html=True,
    )

    available_assessments = list_assessments(include_archived=True)
    if available_assessments:
        assessment_options = {
            f"#{a['id']}: {a['title'][:24]}..." if len(a['title']) > 24 else f"#{a['id']}: {a['title']}": a["id"]
            for a in available_assessments
        }

        # Resolve index
        current_active_id = st.session_state.get("active_assessment_id")
        current_index = 0
        for idx, (label, aid) in enumerate(assessment_options.items()):
            if aid == current_active_id:
                current_index = idx
                break

        selected_label = st.selectbox(
            "Select Workspace Assessment",
            options=list(assessment_options.keys()),
            index=current_index,
            label_visibility="collapsed",
            key="sidebar_assessment_selector",
        )

        chosen_id = assessment_options[selected_label]
        if chosen_id != current_active_id:
            st.session_state["active_assessment_id"] = chosen_id
            st.rerun()

        # Display brief active status pill
        active_rec = get_assessment(chosen_id)
        if active_rec:
            st.markdown(
                f"""
                <div style="font-size: 0.775rem; color: #4B5563; background: #F9FAFB; padding: 0.35rem 0.5rem; border-radius: 3px; border: 1px solid #E5E7EB; margin-bottom: 1rem;">
                    <strong>Org:</strong> {active_rec['organization']}<br/>
                    <strong>Status:</strong> {active_rec['status']}
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            """
            <div style="font-size: 0.775rem; color: #9CA3AF; background: #F9FAFB; padding: 0.5rem; border-radius: 3px; border: 1px solid #E5E7EB; margin-bottom: 1rem;">
                No assessments found in database. Create your first assessment in Assessment Management.
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<hr style='margin: 0.5rem 0 1rem 0;' />", unsafe_allow_html=True)

    # Navigation Menu
    st.markdown(
        "<div style='font-size: 0.75rem; font-weight: 700; color: #6B7280; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.35rem;'>Modules</div>",
        unsafe_allow_html=True,
    )

    # Format module names to show phase status for clarity
    nav_labels = [
        "1. Overview Dashboard",
        "2. Assessment Management",
        "3. ISO 27001 Controls (Phase 2)",
        "4. Evidence Management (Phase 2)",
        "5. Gap Analysis (Phase 2)",
        "6. Risk Register (Phase 3)",
        "7. Remediation Tracker (Phase 3)",
        "8. Assessment Reports (Phase 3)",
        "9. Settings (Phase 3)",
    ]

    # Map current selection
    current_nav_idx = 0
    for idx, mod in enumerate(MODULES):
        if mod == st.session_state["navigation_page"]:
            current_nav_idx = idx
            break

    selected_nav = st.radio(
        "Navigation",
        options=nav_labels,
        index=current_nav_idx,
        label_visibility="collapsed",
    )

    # Extract clean module name
    clean_module_name = MODULES[nav_labels.index(selected_nav)]
    if clean_module_name != st.session_state["navigation_page"]:
        st.session_state["navigation_page"] = clean_module_name
        st.rerun()

    st.markdown("<hr style='margin: 1.5rem 0 0.75rem 0;' />", unsafe_allow_html=True)

    # Sidebar footer
    st.markdown(
        """
        <div style="font-size: 0.72rem; color: #9CA3AF; line-height: 1.4;">
            <strong>AuditSphere v0.1.0 (Phase 1)</strong><br/>
            Engine: SQLite 3 (WAL / FKs ON)<br/>
            Framework: ISO/IEC 27001:2022<br/>
            Simulated GRC Portfolio Tool
        </div>
        """,
        unsafe_allow_html=True,
    )


# ROUTE TO SELECTED PAGE
page = st.session_state["navigation_page"]

if page == "Overview Dashboard":
    render_overview_page()
elif page == "Assessment Management":
    render_assessments_page()
elif page == "ISO 27001 Control Assessment":
    render_placeholder_page("iso27001_controls")
elif page == "Evidence Management":
    render_placeholder_page("evidence")
elif page == "Gap Analysis":
    render_placeholder_page("gap_analysis")
elif page == "Risk Register":
    render_placeholder_page("risk_register")
elif page == "Remediation Tracker":
    render_placeholder_page("remediation")
elif page == "Assessment Reports":
    render_placeholder_page("reports")
elif page == "Settings":
    render_placeholder_page("settings")
else:
    render_overview_page()
