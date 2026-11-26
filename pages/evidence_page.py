"""
Evidence Management module for AuditSphere.

Enables uploading, metadata cataloging, SHA-256 integrity verification,
multi-control mapping, downloading, and auditor review workflows.
"""

import streamlit as st
import pandas as pd
from datetime import date
from typing import Optional, Dict, Any, List

from services.assessment_service import get_assessment
from services.control_service import get_assessment_controls
from services.evidence_manager import (
    EVIDENCE_TYPES,
    REVIEW_STATUSES,
    upload_evidence,
    get_assessment_evidence,
    get_single_evidence,
    review_evidence,
    verify_evidence_integrity,
    archive_evidence,
    get_evidence_file_bytes,
)
from ui_components import (
    render_kpi_card,
    render_review_badge,
    render_integrity_badge,
    render_status_badge,
    render_empty_state,
    render_educational_disclaimer,
)


def render_evidence_page():
    """Render the primary evidence management workspace."""
    st.markdown("## Evidence Management")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.95rem; margin-top: -0.5rem;'>"
        "Upload audit artifacts, map evidence to Annex A controls, review sufficiency and reliability, "
        "and verify cryptographic SHA-256 integrity."
        "</p>",
        unsafe_allow_html=True,
    )

    render_educational_disclaimer()

    active_id = st.session_state.get("active_assessment_id")
    if not active_id:
        render_empty_state(
            title="No Active Assessment Selected",
            message="Please select or create an assessment in the left sidebar or Assessment Management to manage evidence.",
        )
        return

    assessment = get_assessment(active_id)
    if not assessment:
        st.error("Active assessment could not be loaded from database.")
        return

    is_archived = assessment["status"] == "Archived"
    if is_archived:
        st.warning("This assessment is Archived. Evidence repository is in read-only mode.")

    # Fetch evidence for active assessment
    all_evidence = get_assessment_evidence(active_id, include_archived=False)

    # Calculate summary metrics
    total_ev = len(all_evidence)
    accepted_ev = sum(1 for e in all_evidence if e["review_status"] == "Accepted")
    pending_ev = sum(1 for e in all_evidence if e["review_status"] == "Pending Review")
    needs_clar_ev = sum(1 for e in all_evidence if e["review_status"] == "Needs Clarification")
    rejected_ev = sum(1 for e in all_evidence if e["review_status"] == "Rejected")
    integrity_warnings = sum(
        1 for e in all_evidence if e.get("integrity_status") in ("Hash mismatch", "File missing")
    )

    # Top KPI row
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    with k1:
        render_kpi_card("Total Evidence", total_ev, "Active files in repo")
    with k2:
        render_kpi_card("Accepted", accepted_ev, "Suitable for audit")
    with k3:
        render_kpi_card("Pending Review", pending_ev, "Awaiting evaluation")
    with k4:
        render_kpi_card("Clarification", needs_clar_ev, "Needs more info")
    with k5:
        render_kpi_card("Rejected", rejected_ev, "Insufficient / invalid")
    with k6:
        render_kpi_card("Integrity Alerts", integrity_warnings, "Hash mismatch / missing")

    st.markdown("<hr style='margin: 1rem 0 1.25rem 0;' />", unsafe_allow_html=True)

    tab_repo, tab_upload, tab_review = st.tabs(
        ["Evidence Repository", "Upload New Evidence", "Review Evidence"]
    )

    with tab_repo:
        _render_repository_tab(assessment, all_evidence, is_archived)

    with tab_upload:
        _render_upload_tab(assessment, is_archived)

    with tab_review:
        _render_review_tab(assessment, all_evidence, is_archived)


def _render_repository_tab(assessment: Dict[str, Any], all_evidence: List[Dict[str, Any]], is_archived: bool):
    """Render the filterable evidence repository directory."""
    f1, f2, f3, f4 = st.columns([2.5, 1.8, 1.8, 1.8])
    with f1:
        search_query = st.text_input(
            "Search Evidence",
            placeholder="Search by title, reference (e.g. EVD-001), or description...",
            label_visibility="collapsed",
            key="ev_search",
        )
    with f2:
        type_filter = st.selectbox(
            "Evidence Type",
            options=["All Types"] + EVIDENCE_TYPES,
            label_visibility="collapsed",
            key="ev_type_filter",
        )
    with f3:
        status_filter = st.selectbox(
            "Review Status",
            options=["All Statuses"] + REVIEW_STATUSES,
            label_visibility="collapsed",
            key="ev_status_filter",
        )
    with f4:
        include_archived = st.checkbox("Show Archived", value=False, key="ev_show_archived")

    # Fetch filtered evidence
    filtered = get_assessment_evidence(
        assessment_id=assessment["id"],
        search_query=search_query,
        evidence_type_filter=type_filter,
        review_status_filter=status_filter,
        include_archived=include_archived,
    )

    st.markdown(f"**Found {len(filtered)} evidence artifact(s)**")

    if not filtered:
        render_empty_state(
            title="No Evidence Artifacts Found",
            message="No evidence matches your filter criteria. Upload files using the 'Upload New Evidence' tab above.",
        )
        return

    # Render each evidence item
    for ev in filtered:
        ev_id = ev["id"]
        size_kb = ev["file_size"] / 1024
        size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb / 1024:.2f} MB"

        # Format mapped controls tags
        mapped_ctrls = ev.get("mapped_controls", [])
        if mapped_ctrls:
            ctrl_tags_html = " ".join(
                f'<span style="background-color: #EFF6FF; color: #1E40AF; border: 1px solid #BFDBFE; padding: 0.1rem 0.4rem; border-radius: 2px; font-size: 0.725rem; font-weight: 600;">{c["control_identifier"]}</span>'
                for c in mapped_ctrls
            )
        else:
            ctrl_tags_html = '<span style="color: #9CA3AF; font-size: 0.75rem; font-style: italic;">No controls mapped</span>'

        st.markdown(
            f"""
            <div style="background-color: #FFFFFF; border: 1px solid #E5E7EB; border-radius: 4px; padding: 1.15rem; margin-bottom: 0.75rem; box-shadow: 0 1px 2px rgba(0,0,0,0.03);">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <span style="font-size: 1.05rem; font-weight: 700; color: #1F2937;">{ev['evidence_identifier']} – {ev['title']}</span>
                        <div style="font-size: 0.8rem; color: #6B7280; margin-top: 0.2rem;">
                            Type: <strong>{ev['evidence_type']}</strong> &bull;
                            Source: <strong>{ev.get('source_department') or 'Unspecified'}</strong> &bull;
                            File: <code>{ev.get('original_file_name') or ev['file_name']}</code> ({size_str})
                        </div>
                    </div>
                    <div style="display: flex; gap: 0.5rem; align-items: center;">
                        {render_review_badge(ev['review_status'])}
                        {render_integrity_badge(ev.get('integrity_status', 'Not yet verified'))}
                    </div>
                </div>
                {f'''<div style="font-size: 0.825rem; color: #4B5563; margin-top: 0.5rem; background: #F9FAFB; padding: 0.4rem 0.65rem; border-radius: 3px;">{ev['description']}</div>''' if ev.get('description') else ''}
                <div style="margin-top: 0.6rem; display: flex; justify-content: space-between; align-items: center; font-size: 0.775rem; color: #6B7280;">
                    <div>
                        <strong>Mapped Controls:</strong> {ctrl_tags_html}
                    </div>
                    <div>
                        Uploaded: <strong>{ev['uploaded_at'][:10]}</strong> by {ev['uploaded_by']}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Action buttons
        b1, b2, b3, b4 = st.columns([1.5, 1.5, 1.5, 3])

        with b1:
            if st.button("Review Details", key=f"btn_rev_{ev_id}", use_container_width=True):
                st.session_state["review_evidence_id"] = ev_id
                st.info(f"Loaded '{ev['evidence_identifier']}' into the Review tab above.")

        with b2:
            if st.button("Verify Integrity", key=f"btn_chk_{ev_id}", use_container_width=True):
                res = verify_evidence_integrity(ev_id)
                status = res["integrity_status"]
                if status == "Verified":
                    st.success(f"{ev['evidence_identifier']}: Cryptographic SHA-256 hash verified successfully!")
                elif status == "Hash mismatch":
                    st.error(f"{ev['evidence_identifier']}: INTEGRITY MISMATCH! File contents on disk differ from original.")
                else:
                    st.error(f"{ev['evidence_identifier']}: File could not be found on storage disk.")
                st.rerun()

        with b3:
            # Safe download button
            try:
                data_bytes, dl_filename = get_evidence_file_bytes(ev_id)
                st.download_button(
                    label="Download",
                    data=data_bytes,
                    file_name=dl_filename,
                    key=f"btn_dl_{ev_id}",
                    use_container_width=True,
                )
            except Exception:
                st.button("Download (Missing)", disabled=True, key=f"btn_dl_miss_{ev_id}", use_container_width=True)

        with b4:
            if not is_archived and not ev.get("is_archived"):
                if st.button("Archive File", key=f"btn_arch_{ev_id}"):
                    archive_evidence(ev_id)
                    st.success(f"Archived {ev['evidence_identifier']}.")
                    st.rerun()

        st.markdown("<div style='margin-bottom: 0.5rem;'></div>", unsafe_allow_html=True)


def _render_upload_tab(assessment: Dict[str, Any], is_archived: bool):
    """Render the evidence upload form with validation and control mapping."""
    st.markdown("#### Upload and Catalog Audit Evidence")
    st.markdown(
        "<p style='color: #6B7280; font-size: 0.85rem; margin-top: -0.5rem;'>"
        "Upload verifiable evidence files (PDF, CSV, TXT, PNG, JPG, XLSX up to 10 MB). "
        "Files are validated, hashed via SHA-256, and isolated within the assessment workspace."
        "</p>",
        unsafe_allow_html=True,
    )

    if is_archived:
        st.warning("Cannot upload files into an Archived assessment.")
        return

    # Fetch controls for mapping multi-select
    all_controls = get_assessment_controls(assessment["id"])
    control_options = {
        f"{c['control_identifier']} – {c['control_title']} ({c['category']})": c["control_id"]
        for c in all_controls
    }

    uploaded_file = st.file_uploader(
        "Select Evidence File *",
        type=["pdf", "csv", "txt", "png", "jpg", "jpeg", "xlsx"],
        help="Supported formats: PDF, CSV, TXT, PNG, JPG, XLSX (Max 10 MB). Executable files are strictly blocked.",
    )

    with st.form("upload_evidence_form", clear_on_submit=False):
        c1, c2 = st.columns(2)
        with c1:
            title = st.text_input("Evidence Title *", placeholder="e.g. Enterprise Password & Authentication Policy v2.4")
            ev_type = st.selectbox("Evidence Category *", options=EVIDENCE_TYPES)
            source_dept = st.text_input("Source Department", placeholder="e.g. Information Security, HR, DevOps")
        with c2:
            col_date = st.date_input("Evidence Collection Date", value=date.today())
            period_covered = st.text_input("Period Covered", placeholder="e.g. FY2025 Q3 - Q4, or Jan 2026")
            uploader = st.text_input("Uploaded By", value=assessment.get("lead_assessor") or "Lead Assessor")

        desc = st.text_area(
            "Evidence Description & Context",
            placeholder="Describe what this evidence artifact demonstrates and which systems or procedures it relates to...",
            height=70,
        )

        selected_ctrl_labels = st.multiselect(
            "Map to Supported Annex A Controls (Optional)",
            options=list(control_options.keys()),
            help="Select one or more controls supported by this evidence file.",
        )

        submit_btn = st.form_submit_button("Upload & Register Evidence", type="primary")

        if submit_btn:
            if not uploaded_file:
                st.error("Please select a file to upload.")
                return

            mapped_cids = [control_options[lbl] for lbl in selected_ctrl_labels]
            date_str = col_date.strftime("%Y-%m-%d") if col_date else ""

            try:
                file_bytes = uploaded_file.getvalue()
                result = upload_evidence(
                    assessment_id=assessment["id"],
                    title=title,
                    file_name=uploaded_file.name,
                    file_bytes=file_bytes,
                    evidence_type=ev_type,
                    description=desc,
                    source_department=source_dept,
                    collection_date=date_str,
                    period_covered=period_covered,
                    uploaded_by=uploader,
                    mapped_control_ids=mapped_cids,
                )
                st.success(
                    f"Evidence '{result['evidence_identifier']} – {result['title']}' uploaded successfully! "
                    f"SHA-256 Hash: {result['sha256_hash'][:16]}..."
                )
                st.rerun()
            except ValueError as ve:
                st.error(f"Validation Error: {str(ve)}")
            except Exception as ex:
                st.error(f"Upload Error: {str(ex)}")


def _render_review_tab(assessment: Dict[str, Any], all_evidence: List[Dict[str, Any]], is_archived: bool):
    """Render the evidence review interface for evaluating relevance, sufficiency, and reliability."""
    st.markdown("#### Review Evidence Suitability & Reliability")

    if not all_evidence:
        render_empty_state(
            title="No Evidence Available to Review",
            message="Upload evidence files first before conducting reviews.",
        )
        return

    ev_options = {
        f"{e['evidence_identifier']} – {e['title']} ({e['review_status']})": e["id"]
        for e in all_evidence
    }

    # Preselected evidence
    preselected_id = st.session_state.get("review_evidence_id")
    def_idx = 0
    if preselected_id:
        for idx, (_, eid) in enumerate(ev_options.items()):
            if eid == preselected_id:
                def_idx = idx
                break

    selected_label = st.selectbox("Select Evidence Artifact to Review", options=list(ev_options.keys()), index=def_idx)
    target_id = ev_options[selected_label]
    ev = get_single_evidence(target_id)
    if not ev:
        st.error("Evidence record could not be loaded.")
        return

    # Metadata & Integrity Card
    st.markdown(
        f"""
        <div style="background-color: #FFFFFF; border: 1px solid #751C35; border-radius: 4px; padding: 1.25rem; margin-bottom: 1.25rem;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <div style="font-size: 1.15rem; font-weight: 700; color: #1F2937;">{ev['evidence_identifier']} – {ev['title']}</div>
                    <div style="font-size: 0.85rem; color: #6B7280; margin-top: 0.2rem;">
                        File: <code>{ev.get('original_file_name') or ev['file_name']}</code> &bull;
                        Type: <strong>{ev['evidence_type']}</strong> &bull;
                        Size: <strong>{ev['file_size']} bytes</strong>
                    </div>
                </div>
                <div>
                    {render_review_badge(ev['review_status'])}
                </div>
            </div>
            <div style="margin-top: 0.75rem; font-size: 0.8rem; color: #4B5563; background: #F9FAFB; padding: 0.6rem; border-radius: 3px; border: 1px solid #E5E7EB;">
                <strong>SHA-256 Hash:</strong> <code>{ev.get('sha256_hash') or ev.get('file_hash')}</code><br/>
                <strong>Integrity Status:</strong> {render_integrity_badge(ev.get('integrity_status', 'Not yet verified'))}
                &nbsp;|&nbsp; Last Checked: {ev.get('integrity_verified_at') or 'Never'}
            </div>
            {f'''<div style="margin-top: 0.5rem; font-size: 0.825rem; color: #374151;"><strong>Context:</strong> {ev['description']}</div>''' if ev.get('description') else ''}
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Check for duplicate hash warnings
    duplicates = ev.get("duplicates", [])
    if duplicates:
        dup_refs = ", ".join(d["evidence_identifier"] for d in duplicates)
        st.warning(
            f"**Potential Duplicate File:** This file's SHA-256 hash matches other active evidence in this assessment ({dup_refs}). "
            "Ensure distinct evidence is uploaded or reference the existing artifact."
        )

    # Review Form
    with st.form(f"review_form_{ev['id']}"):
        st.markdown("##### Auditor Assessment")

        r1, r2 = st.columns(2)
        with r1:
            rev_idx = REVIEW_STATUSES.index(ev["review_status"]) if ev["review_status"] in REVIEW_STATUSES else 0
            new_review_status = st.selectbox("Review Decision *", options=REVIEW_STATUSES, index=rev_idx)
            relevance = st.selectbox(
                "Evidence Relevance",
                options=["Relevant", "Partially Relevant", "Irrelevant"],
                index=["Relevant", "Partially Relevant", "Irrelevant"].index(ev.get("relevance_rating") or "Relevant"),
            )
        with r2:
            reviewer = st.text_input("Reviewer Name *", value=ev.get("reviewer_name") or assessment.get("lead_assessor") or "")
            sufficiency = st.selectbox(
                "Evidence Sufficiency",
                options=["Sufficient", "Partially Sufficient", "Insufficient"],
                index=["Sufficient", "Partially Sufficient", "Insufficient"].index(ev.get("sufficiency_rating") or "Sufficient"),
            )

        reliability = st.selectbox(
            "Evidence Reliability",
            options=["Reliable", "Unverified", "Unreliable"],
            index=["Reliable", "Unverified", "Unreliable"].index(ev.get("reliability_rating") or "Reliable"),
        )

        notes = st.text_area(
            "Reviewer Notes & Conclusion *",
            value=ev.get("reviewer_notes") or "",
            placeholder="Document detailed audit rationale explaining whether this evidence satisfies the audit objective, noted limitations, or reasons for rejection...",
            height=100,
            help="Mandatory when recording an Accepted, Needs Clarification, or Rejected decision.",
        )

        save_review_btn = st.form_submit_button("Save Review Decision", type="primary", disabled=is_archived)

        if save_review_btn:
            if is_archived:
                st.error("Cannot modify evidence in an Archived assessment.")
                return

            try:
                review_evidence(
                    evidence_id=ev["id"],
                    review_status=new_review_status,
                    reviewer_name=reviewer,
                    reviewer_notes=notes,
                    relevance_rating=relevance,
                    sufficiency_rating=sufficiency,
                    reliability_rating=reliability,
                )
                st.success(f"Review decision saved for {ev['evidence_identifier']} ({new_review_status})!")
                st.rerun()
            except ValueError as ve:
                st.error(f"Validation Error: {str(ve)}")
            except Exception as ex:
                st.error(f"Error: {str(ex)}")
