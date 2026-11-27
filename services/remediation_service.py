"""
AuditSphere – Remediation Service
Database operations for Corrective Actions, Root Cause Analysis, Progress, Deadlines, Verifications, and Cross-Module Links.
"""

from __future__ import annotations

import json
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from database import db_session, get_utc_now_iso
from services.activity_service import log_activity
from services.remediation_engine import (
    VALID_PRIORITIES,
    VALID_RCA_METHODS,
    VALID_STATUSES,
    VALID_VERIFICATION_RESULTS,
    validate_closure_eligibility,
    validate_priority_alignment,
    validate_status_transition,
)


def _check_assessment_not_archived(conn, assessment_id: Any) -> int:
    """Ensure the target assessment is active before mutations. Returns integer assessment_id."""
    aid = assessment_id["id"] if isinstance(assessment_id, dict) else int(assessment_id)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM assessments WHERE id = ?", (aid,))
    row = cursor.fetchone()
    if not row:
        raise ValueError(f"Assessment with ID {aid} does not exist.")
    if row["status"] == "Archived":
        raise ValueError("Cannot modify records for an archived assessment.")
    return aid


def get_next_remediation_identifier(conn, assessment_id: int) -> str:
    """Generate next sequential action identifier (e.g. ACT-001)."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT remediation_identifier FROM remediation WHERE assessment_id = ?",
        (assessment_id,),
    )
    rows = cursor.fetchall()
    existing_nums = []
    for r in rows:
        ident = r["remediation_identifier"] or ""
        for prefix in ("ACT-", "REM-"):
            if ident.startswith(prefix):
                try:
                    num = int(ident[len(prefix) :])
                    existing_nums.append(num)
                except ValueError:
                    pass
    next_num = max(existing_nums, default=0) + 1
    return f"ACT-{next_num:03d}"


def create_remediation(
    assessment_id: int,
    data: Dict[str, Any],
    actor: str = "Lead Assessor",
    db_path: Optional[str] = None,
) -> int:
    """
    Create a new corrective action record with mandatory field validation.
    """
    title = (data.get("action_title") or "").strip()
    if not title:
        raise ValueError("Corrective action title is mandatory.")

    owner = (data.get("action_owner") or "").strip()
    if not owner:
        raise ValueError("Responsible action owner is mandatory.")

    target_date = (data.get("target_date") or "").strip()
    if not target_date:
        raise ValueError("Target completion date is mandatory.")

    priority = data.get("action_priority", "Medium")
    if priority not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority '{priority}'. Allowed: {VALID_PRIORITIES}")

    rca_method = data.get("root_cause_analysis_method", "Direct Analysis")
    if rca_method not in VALID_RCA_METHODS:
        raise ValueError(f"Invalid RCA method '{rca_method}'. Allowed: {VALID_RCA_METHODS}")

    with db_session(db_path) as conn:
        assessment_id = _check_assessment_not_archived(conn, assessment_id)

        ident = data.get("remediation_identifier")
        if not ident or not ident.strip():
            ident = get_next_remediation_identifier(conn, assessment_id)
        else:
            ident = ident.strip()

        original_target_date = data.get("original_target_date") or target_date
        now_iso = get_utc_now_iso()

        # Handle root_cause_details (serialize dict/list to JSON if passed)
        rc_details = data.get("root_cause_details")
        if isinstance(rc_details, (dict, list)):
            rc_details_str = json.dumps(rc_details)
        else:
            rc_details_str = rc_details

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO remediation (
                assessment_id, finding_id, risk_id, remediation_identifier,
                action_title, action_description, immediate_correction, root_cause,
                root_cause_analysis_method, root_cause_details, contributing_factors,
                long_term_corrective_action, expected_outcome, action_priority,
                priority_justification, action_owner, responsible_department,
                assigned_date, target_date, original_target_date, progress_percentage,
                status, implementation_summary, verification_requirements,
                created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                'Open', ?, ?,
                ?, ?
            )
            """,
            (
                assessment_id,
                data.get("finding_id"),
                data.get("risk_id"),
                ident,
                title,
                data.get("action_description"),
                data.get("immediate_correction"),
                data.get("root_cause"),
                rca_method,
                rc_details_str,
                data.get("contributing_factors"),
                data.get("long_term_corrective_action"),
                data.get("expected_outcome"),
                priority,
                data.get("priority_justification"),
                owner,
                data.get("responsible_department"),
                data.get("assigned_date") or date.today().isoformat(),
                target_date,
                original_target_date,
                int(data.get("progress_percentage", 0)),
                data.get("implementation_summary"),
                data.get("verification_requirements"),
                now_iso,
                now_iso,
            ),
        )
        new_id = cursor.lastrowid

        # If primary finding_id or risk_id passed, populate many-to-many relationship tables
        if data.get("finding_id"):
            cursor.execute(
                """
                INSERT OR IGNORE INTO remediation_findings (assessment_id, remediation_id, finding_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (assessment_id, new_id, data["finding_id"], now_iso),
            )

        if data.get("risk_id"):
            cursor.execute(
                """
                INSERT OR IGNORE INTO remediation_risks (assessment_id, remediation_id, risk_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (assessment_id, new_id, data["risk_id"], now_iso),
            )

        # Handle linked lists if provided
        for fid in data.get("linked_finding_ids", []):
            cursor.execute(
                """
                INSERT OR IGNORE INTO remediation_findings (assessment_id, remediation_id, finding_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (assessment_id, new_id, fid, now_iso),
            )

        for rid in data.get("linked_risk_ids", []):
            cursor.execute(
                """
                INSERT OR IGNORE INTO remediation_risks (assessment_id, remediation_id, risk_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (assessment_id, new_id, rid, now_iso),
            )

        for cid in data.get("linked_control_ids", []):
            cursor.execute(
                """
                INSERT OR IGNORE INTO remediation_controls (assessment_id, remediation_id, control_assessment_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (assessment_id, new_id, cid, now_iso),
            )

        for eid in data.get("linked_evidence_ids", []):
            cursor.execute(
                """
                INSERT OR IGNORE INTO remediation_evidence (assessment_id, remediation_id, evidence_id, evidence_type, created_at)
                VALUES (?, ?, ?, 'Remediation Evidence', ?)
                """,
                (assessment_id, new_id, eid, now_iso),
            )

    log_activity(
        assessment_id=assessment_id,
        event_type="REMEDIATION_CREATED",
        description=f"Created corrective action '{ident}: {title}' assigned to {owner} (Priority: {priority}).",
        actor=actor,
        db_path=db_path,
    )

    return new_id


def update_remediation(
    remediation_id: int,
    data: Dict[str, Any],
    actor: str = "Lead Assessor",
    db_path: Optional[str] = None,
) -> None:
    """
    Update an existing corrective action record. Validates status transitions and governance rules.
    """
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation WHERE id = ?", (remediation_id,))
        current = cursor.fetchone()
        if not current:
            raise ValueError(f"Corrective action with ID {remediation_id} not found.")

        assessment_id = current["assessment_id"]
        _check_assessment_not_archived(conn, assessment_id)

        current_dict = dict(current)
        new_status = data.get("status", current_dict["status"])

        # Fetch verifications and evidence if status transition involves verification or closure
        cursor.execute(
            "SELECT * FROM remediation_verifications WHERE remediation_id = ? ORDER BY id DESC",
            (remediation_id,),
        )
        verifications = [dict(v) for v in cursor.fetchall()]

        cursor.execute(
            """
            SELECT e.* FROM evidence e
            JOIN remediation_evidence re ON e.id = re.evidence_id
            WHERE re.remediation_id = ?
            """,
            (remediation_id,),
        )
        evidence_list = [dict(e) for e in cursor.fetchall()]

        # Combined action data for validation
        combined_action = {**current_dict, **data}

        # Validate status transition
        if new_status != current_dict["status"]:
            validate_status_transition(
                current_dict["status"],
                new_status,
                action_data=combined_action,
                verifications=verifications,
                evidence_list=evidence_list,
            )

        # Handle root_cause_details serialization
        rc_details = combined_action.get("root_cause_details")
        if isinstance(rc_details, (dict, list)):
            rc_details_str = json.dumps(rc_details)
        else:
            rc_details_str = rc_details

        now_iso = get_utc_now_iso()

        cursor.execute(
            """
            UPDATE remediation
            SET action_title = ?, action_description = ?, immediate_correction = ?,
                root_cause = ?, root_cause_analysis_method = ?, root_cause_details = ?,
                contributing_factors = ?, long_term_corrective_action = ?, expected_outcome = ?,
                action_priority = ?, priority_justification = ?, action_owner = ?,
                responsible_department = ?, target_date = ?, progress_percentage = ?,
                status = ?, cancellation_reason = ?, implementation_summary = ?,
                actual_completion_date = ?, verification_requirements = ?,
                closure_rationale = ?, reopen_justification = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                combined_action.get("action_title", current_dict["action_title"]),
                combined_action.get("action_description"),
                combined_action.get("immediate_correction"),
                combined_action.get("root_cause"),
                combined_action.get("root_cause_analysis_method", "Direct Analysis"),
                rc_details_str,
                combined_action.get("contributing_factors"),
                combined_action.get("long_term_corrective_action"),
                combined_action.get("expected_outcome"),
                combined_action.get("action_priority", "Medium"),
                combined_action.get("priority_justification"),
                combined_action.get("action_owner", current_dict["action_owner"]),
                combined_action.get("responsible_department"),
                combined_action.get("target_date", current_dict["target_date"]),
                int(combined_action.get("progress_percentage", 0)),
                new_status,
                combined_action.get("cancellation_reason"),
                combined_action.get("implementation_summary"),
                combined_action.get("actual_completion_date"),
                combined_action.get("verification_requirements"),
                combined_action.get("closure_rationale"),
                combined_action.get("reopen_justification"),
                now_iso,
                remediation_id,
            ),
        )

        desc = f"Updated corrective action '{current_dict['remediation_identifier']}'."
        if new_status != current_dict["status"]:
            desc += f" Status changed from '{current_dict['status']}' to '{new_status}'."

    log_activity(
        assessment_id=assessment_id,
        event_type="REMEDIATION_UPDATED",
        description=desc,
        actor=actor,
        db_path=db_path,
    )


def record_progress_update(
    remediation_id: int,
    progress_percentage: int,
    description: str,
    blockers: Optional[str] = None,
    updated_by: str = "Action Owner",
    db_path: Optional[str] = None,
) -> None:
    """
    Record an implementation progress update snapshot.
    Validates progress as an integer 0-100.
    Progress 100% does NOT automatically close the action.
    """
    try:
        pct = int(progress_percentage)
    except (ValueError, TypeError):
        raise ValueError("Progress percentage must be an integer between 0 and 100.")

    if pct < 0 or pct > 100:
        raise ValueError(f"Progress percentage must be between 0 and 100 (got {pct}).")

    desc = (description or "").strip()
    if not desc:
        raise ValueError("Progress update description is required.")

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation WHERE id = ?", (remediation_id,))
        rem = cursor.fetchone()
        if not rem:
            raise ValueError(f"Corrective action with ID {remediation_id} not found.")

        assessment_id = rem["assessment_id"]
        _check_assessment_not_archived(conn, assessment_id)

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            INSERT INTO remediation_progress (
                assessment_id, remediation_id, progress_percentage, description,
                blockers, updated_by, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (assessment_id, remediation_id, pct, desc, blockers, updated_by, now_iso),
        )

        # Update remediation progress_percentage and actual_completion_date if 100
        actual_date = rem["actual_completion_date"]
        if pct == 100 and not actual_date:
            actual_date = date.today().isoformat()

        # If previously Open and progress > 0, transition to In Progress automatically
        new_status = rem["status"]
        if rem["status"] == "Open" and pct > 0:
            new_status = "In Progress"

        cursor.execute(
            """
            UPDATE remediation
            SET progress_percentage = ?, actual_completion_date = ?, status = ?, updated_at = ?
            WHERE id = ?
            """,
            (pct, actual_date, new_status, now_iso, remediation_id),
        )

    log_activity(
        assessment_id=assessment_id,
        event_type="REMEDIATION_PROGRESS_UPDATED",
        description=f"Action '{rem['remediation_identifier']}' progress updated to {pct}%: {desc}",
        actor=updated_by,
        db_path=db_path,
    )


def extend_deadline(
    remediation_id: int,
    new_deadline: str,
    extension_reason: str,
    approving_authority: str,
    actor: str = "Lead Assessor",
    db_path: Optional[str] = None,
) -> None:
    """
    Extend a corrective action completion deadline with mandatory justification and audit trail.
    """
    new_d = (new_deadline or "").strip()
    if not new_d:
        raise ValueError("New target completion deadline is required.")

    reason = (extension_reason or "").strip()
    if not reason:
        raise ValueError("Extension reason is mandatory.")

    authority = (approving_authority or "").strip()
    if not authority:
        raise ValueError("Recorded approving authority is mandatory.")

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation WHERE id = ?", (remediation_id,))
        rem = cursor.fetchone()
        if not rem:
            raise ValueError(f"Corrective action with ID {remediation_id} not found.")

        assessment_id = rem["assessment_id"]
        _check_assessment_not_archived(conn, assessment_id)

        previous_deadline = rem["target_date"]
        now_iso = get_utc_now_iso()

        cursor.execute(
            """
            INSERT INTO remediation_deadline_extensions (
                assessment_id, remediation_id, previous_deadline, new_deadline,
                extension_reason, approving_authority, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                remediation_id,
                previous_deadline,
                new_d,
                reason,
                authority,
                now_iso,
            ),
        )

        cursor.execute(
            """
            UPDATE remediation
            SET target_date = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_d, now_iso, remediation_id),
        )

    log_activity(
        assessment_id=assessment_id,
        event_type="REMEDIATION_DEADLINE_EXTENDED",
        description=(
            f"Action '{rem['remediation_identifier']}' deadline extended from {previous_deadline} "
            f"to {new_d}. Approved by: {authority}. Reason: {reason}"
        ),
        actor=actor,
        db_path=db_path,
    )


def record_verification(
    remediation_id: int,
    verification_data: Dict[str, Any],
    actor: str = "Lead Assessor",
    db_path: Optional[str] = None,
) -> int:
    """
    Record a formal effectiveness verification review for a corrective action.
    """
    objective = (verification_data.get("verification_objective") or "").strip()
    if not objective:
        raise ValueError("Verification objective is mandatory.")

    procedure = (verification_data.get("verification_procedure") or "").strip()
    if not procedure:
        raise ValueError("Verification procedure is mandatory.")

    expected = (verification_data.get("expected_outcome") or "").strip()
    if not expected:
        raise ValueError("Expected verification outcome is mandatory.")

    observed = (verification_data.get("observed_outcome") or "").strip()
    if not observed:
        raise ValueError("Observed verification outcome is mandatory.")

    result = verification_data.get("verification_result")
    if result not in VALID_VERIFICATION_RESULTS:
        raise ValueError(
            f"Invalid verification result '{result}'. Allowed: {VALID_VERIFICATION_RESULTS}"
        )

    verifier = (verification_data.get("verifier_name") or actor or "").strip()
    if not verifier:
        raise ValueError("Verifier name is mandatory.")

    v_date = (verification_data.get("verification_date") or date.today().isoformat()).strip()

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation WHERE id = ?", (remediation_id,))
        rem = cursor.fetchone()
        if not rem:
            raise ValueError(f"Corrective action with ID {remediation_id} not found.")

        assessment_id = rem["assessment_id"]
        _check_assessment_not_archived(conn, assessment_id)

        # Generate verification reference
        cursor.execute(
            "SELECT COUNT(*) FROM remediation_verifications WHERE assessment_id = ?",
            (assessment_id,),
        )
        v_count = cursor.fetchone()[0] + 1
        v_ref = f"VRF-{v_count:03d}"

        now_iso = get_utc_now_iso()

        cursor.execute(
            """
            INSERT INTO remediation_verifications (
                assessment_id, remediation_id, verification_reference,
                verification_objective, verification_procedure, expected_outcome,
                observed_outcome, sample_examined, evidence_references,
                related_control_testing_records, evidence_limitations,
                verifier_name, verification_date, verification_result,
                verification_notes, recommended_next_action, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                remediation_id,
                v_ref,
                objective,
                procedure,
                expected,
                observed,
                verification_data.get("sample_examined"),
                verification_data.get("evidence_references"),
                verification_data.get("related_control_testing_records"),
                verification_data.get("evidence_limitations"),
                verifier,
                v_date,
                result,
                verification_data.get("verification_notes"),
                verification_data.get("recommended_next_action"),
                now_iso,
            ),
        )
        new_v_id = cursor.lastrowid

        # Update action status to 'Under Verification' if currently Awaiting Verification
        if rem["status"] == "Awaiting Verification":
            cursor.execute(
                "UPDATE remediation SET status = 'Under Verification', updated_at = ? WHERE id = ?",
                (now_iso, remediation_id),
            )

    log_activity(
        assessment_id=assessment_id,
        event_type="REMEDIATION_VERIFICATION_RECORDED",
        description=(
            f"Recorded verification '{v_ref}' on action '{rem['remediation_identifier']}': "
            f"Result: {result} by {verifier}."
        ),
        actor=actor,
        db_path=db_path,
    )

    return new_v_id


def reopen_remediation(
    remediation_id: int,
    reopen_justification: str,
    actor: str = "Lead Assessor",
    db_path: Optional[str] = None,
) -> None:
    """
    Reopen a corrective action (e.g. following an Ineffective verification or reopened after closure).
    """
    justification = (reopen_justification or "").strip()
    if not justification:
        raise ValueError("A documented justification is required to reopen a corrective action.")

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation WHERE id = ?", (remediation_id,))
        rem = cursor.fetchone()
        if not rem:
            raise ValueError(f"Corrective action with ID {remediation_id} not found.")

        assessment_id = rem["assessment_id"]
        _check_assessment_not_archived(conn, assessment_id)

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            UPDATE remediation
            SET status = 'Reopened', reopen_justification = ?, updated_at = ?
            WHERE id = ?
            """,
            (justification, now_iso, remediation_id),
        )

    log_activity(
        assessment_id=assessment_id,
        event_type="REMEDIATION_REOPENED",
        description=f"Reopened action '{rem['remediation_identifier']}': {justification}",
        actor=actor,
        db_path=db_path,
    )


def close_remediation(
    remediation_id: int,
    closure_rationale: str,
    actor: str = "Lead Assessor",
    db_path: Optional[str] = None,
) -> None:
    """
    Formally close a corrective action after verifying all closure governance criteria.
    """
    rat = (closure_rationale or "").strip()
    if not rat:
        raise ValueError("A documented closure rationale is required to close a corrective action.")

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation WHERE id = ?", (remediation_id,))
        rem = cursor.fetchone()
        if not rem:
            raise ValueError(f"Corrective action with ID {remediation_id} not found.")

        assessment_id = rem["assessment_id"]
        _check_assessment_not_archived(conn, assessment_id)

        # Fetch verifications
        cursor.execute(
            "SELECT * FROM remediation_verifications WHERE remediation_id = ? ORDER BY id DESC",
            (remediation_id,),
        )
        verifications = [dict(v) for v in cursor.fetchall()]

        # Fetch evidence
        cursor.execute(
            """
            SELECT e.* FROM evidence e
            JOIN remediation_evidence re ON e.id = re.evidence_id
            WHERE re.remediation_id = ?
            """,
            (remediation_id,),
        )
        evidence_list = [dict(e) for e in cursor.fetchall()]

        action_dict = dict(rem)
        action_dict["closure_rationale"] = rat

        # Validate closure governance
        validate_closure_eligibility(action_dict, verifications, evidence_list)

        now_iso = get_utc_now_iso()
        actual_date = rem["actual_completion_date"] or date.today().isoformat()

        cursor.execute(
            """
            UPDATE remediation
            SET status = 'Closed', closure_rationale = ?, actual_completion_date = ?, updated_at = ?
            WHERE id = ?
            """,
            (rat, actual_date, now_iso, remediation_id),
        )

    log_activity(
        assessment_id=assessment_id,
        event_type="REMEDIATION_CLOSED",
        description=f"Closed verified corrective action '{rem['remediation_identifier']}': {rat}",
        actor=actor,
        db_path=db_path,
    )


def cancel_remediation(
    remediation_id: int,
    cancellation_reason: str,
    actor: str = "Lead Assessor",
    db_path: Optional[str] = None,
) -> None:
    """
    Cancel an unneeded corrective action with mandatory documented reason.
    """
    reason = (cancellation_reason or "").strip()
    if not reason:
        raise ValueError("A cancellation reason is required to cancel a corrective action.")

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation WHERE id = ?", (remediation_id,))
        rem = cursor.fetchone()
        if not rem:
            raise ValueError(f"Corrective action with ID {remediation_id} not found.")

        assessment_id = rem["assessment_id"]
        _check_assessment_not_archived(conn, assessment_id)

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            UPDATE remediation
            SET status = 'Cancelled', cancellation_reason = ?, updated_at = ?
            WHERE id = ?
            """,
            (reason, now_iso, remediation_id),
        )

    log_activity(
        assessment_id=assessment_id,
        event_type="REMEDIATION_CANCELLED",
        description=f"Cancelled corrective action '{rem['remediation_identifier']}': {reason}",
        actor=actor,
        db_path=db_path,
    )


def archive_remediation(
    remediation_id: int,
    actor: str = "Lead Assessor",
    db_path: Optional[str] = None,
) -> None:
    """Soft archive a corrective action record."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation WHERE id = ?", (remediation_id,))
        rem = cursor.fetchone()
        if not rem:
            raise ValueError(f"Corrective action with ID {remediation_id} not found.")

        assessment_id = rem["assessment_id"]
        _check_assessment_not_archived(conn, assessment_id)

        now_iso = get_utc_now_iso()
        cursor.execute(
            "UPDATE remediation SET is_archived = 1, updated_at = ? WHERE id = ?",
            (now_iso, remediation_id),
        )

    log_activity(
        assessment_id=assessment_id,
        event_type="REMEDIATION_ARCHIVED",
        description=f"Archived corrective action '{rem['remediation_identifier']}'.",
        actor=actor,
        db_path=db_path,
    )


def get_single_remediation(remediation_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve full details of a single corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM remediation WHERE id = ?", (remediation_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)


def get_assessment_remediations(
    assessment_id: int,
    search: Optional[str] = None,
    status_filter: Optional[str] = None,
    priority_filter: Optional[str] = None,
    owner_filter: Optional[str] = None,
    dept_filter: Optional[str] = None,
    finding_id: Optional[int] = None,
    risk_id: Optional[int] = None,
    control_id: Optional[int] = None,
    include_archived: bool = False,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve filterable corrective actions for an assessment.
    """
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT r.* FROM remediation r WHERE r.assessment_id = ?"
        params: List[Any] = [assessment_id]

        if not include_archived:
            query += " AND r.is_archived = 0"

        if status_filter and status_filter != "All":
            query += " AND r.status = ?"
            params.append(status_filter)

        if priority_filter and priority_filter != "All":
            query += " AND r.action_priority = ?"
            params.append(priority_filter)

        if owner_filter and owner_filter != "All":
            query += " AND r.action_owner = ?"
            params.append(owner_filter)

        if dept_filter and dept_filter != "All":
            query += " AND r.responsible_department = ?"
            params.append(dept_filter)

        if finding_id:
            query += """ AND (r.finding_id = ? OR r.id IN (
                SELECT remediation_id FROM remediation_findings WHERE finding_id = ?
            ))"""
            params.extend([finding_id, finding_id])

        if risk_id:
            query += """ AND (r.risk_id = ? OR r.id IN (
                SELECT remediation_id FROM remediation_risks WHERE risk_id = ?
            ))"""
            params.extend([risk_id, risk_id])

        if control_id:
            query += """ AND r.id IN (
                SELECT remediation_id FROM remediation_controls WHERE control_assessment_id = ?
            )"""
            params.append(control_id)

        if search and search.strip():
            s = f"%{search.strip().lower()}%"
            query += """ AND (
                LOWER(r.remediation_identifier) LIKE ? OR
                LOWER(r.action_title) LIKE ? OR
                LOWER(r.action_description) LIKE ? OR
                LOWER(r.action_owner) LIKE ? OR
                LOWER(r.root_cause) LIKE ?
            )"""
            params.extend([s, s, s, s, s])

        query += " ORDER BY r.id ASC"
        cursor.execute(query, params)
        return [dict(r) for r in cursor.fetchall()]


# -------------------------------------------------------------
# Relationship Management (Findings, Risks, Controls, Evidence)
# -------------------------------------------------------------

def link_finding_to_remediation(
    remediation_id: int, finding_id: Any, notes: Optional[str] = None, db_path: Optional[str] = None
) -> None:
    """Link a finding to a corrective action with cross-assessment trigger protection."""
    if isinstance(finding_id, dict):
        finding_id = finding_id["id"]
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT assessment_id FROM remediation WHERE id = ?", (remediation_id,))
        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Corrective action {remediation_id} not found.")
        aid = row["assessment_id"]
        _check_assessment_not_archived(conn, aid)

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            INSERT OR REPLACE INTO remediation_findings (assessment_id, remediation_id, finding_id, notes, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (aid, remediation_id, finding_id, notes, now_iso),
        )


def unlink_finding_from_remediation(
    remediation_id: int, finding_id: int, db_path: Optional[str] = None
) -> None:
    """Unlink a finding from a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM remediation_findings WHERE remediation_id = ? AND finding_id = ?",
            (remediation_id, finding_id),
        )


def get_remediation_findings(remediation_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all findings linked to a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT f.*, rf.notes as link_notes FROM findings f
            JOIN remediation_findings rf ON f.id = rf.finding_id
            WHERE rf.remediation_id = ?
            ORDER BY f.id ASC
            """,
            (remediation_id,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_finding_remediations(finding_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all corrective actions linked to a specific finding."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT r.* FROM remediation r
            WHERE r.finding_id = ? OR r.id IN (
                SELECT remediation_id FROM remediation_findings WHERE finding_id = ?
            )
            ORDER BY r.id ASC
            """,
            (finding_id, finding_id),
        )
        return [dict(r) for r in cursor.fetchall()]


def link_risk_to_remediation(
    remediation_id: int, risk_id: Any, notes: Optional[str] = None, db_path: Optional[str] = None
) -> None:
    """Link a risk to a corrective action with cross-assessment trigger protection."""
    if isinstance(risk_id, dict):
        risk_id = risk_id["id"]
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT assessment_id FROM remediation WHERE id = ?", (remediation_id,))
        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Corrective action {remediation_id} not found.")
        aid = row["assessment_id"]
        _check_assessment_not_archived(conn, aid)

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            INSERT OR REPLACE INTO remediation_risks (assessment_id, remediation_id, risk_id, notes, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (aid, remediation_id, risk_id, notes, now_iso),
        )


def unlink_risk_from_remediation(
    remediation_id: int, risk_id: int, db_path: Optional[str] = None
) -> None:
    """Unlink a risk from a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM remediation_risks WHERE remediation_id = ? AND risk_id = ?",
            (remediation_id, risk_id),
        )


def get_remediation_risks(remediation_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all risks linked to a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT rk.*, rr.notes as link_notes FROM risks rk
            JOIN remediation_risks rr ON rk.id = rr.risk_id
            WHERE rr.remediation_id = ?
            ORDER BY rk.id ASC
            """,
            (remediation_id,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_risk_remediations(risk_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all corrective actions linked to a specific risk."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT r.* FROM remediation r
            WHERE r.risk_id = ? OR r.id IN (
                SELECT remediation_id FROM remediation_risks WHERE risk_id = ?
            )
            ORDER BY r.id ASC
            """,
            (risk_id, risk_id),
        )
        return [dict(r) for r in cursor.fetchall()]


def link_control_to_remediation(
    remediation_id: int, control_assessment_id: Any, notes: Optional[str] = None, db_path: Optional[str] = None
) -> None:
    """Link an Annex A control assessment to a corrective action."""
    if isinstance(control_assessment_id, dict):
        control_assessment_id = control_assessment_id.get("assessment_control_id", control_assessment_id.get("id"))
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT assessment_id FROM remediation WHERE id = ?", (remediation_id,))
        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Corrective action {remediation_id} not found.")
        aid = row["assessment_id"]
        _check_assessment_not_archived(conn, aid)

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            INSERT OR REPLACE INTO remediation_controls (assessment_id, remediation_id, control_assessment_id, notes, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (aid, remediation_id, control_assessment_id, notes, now_iso),
        )


def unlink_control_from_remediation(
    remediation_id: int, control_assessment_id: int, db_path: Optional[str] = None
) -> None:
    """Unlink a control assessment from a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM remediation_controls WHERE remediation_id = ? AND control_assessment_id = ?",
            (remediation_id, control_assessment_id),
        )


def get_remediation_controls(remediation_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all controls linked to a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT ca.*, c.control_identifier, c.title as control_title, c.domain, rc.notes as link_notes
            FROM control_assessments ca
            JOIN controls c ON ca.control_id = c.id
            JOIN remediation_controls rc ON ca.id = rc.control_assessment_id
            WHERE rc.remediation_id = ?
            ORDER BY c.id ASC
            """,
            (remediation_id,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_control_remediations(control_assessment_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all corrective actions linked to a specific control assessment."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT r.* FROM remediation r
            JOIN remediation_controls rc ON r.id = rc.remediation_id
            WHERE rc.control_assessment_id = ?
            ORDER BY r.id ASC
            """,
            (control_assessment_id,),
        )
        return [dict(r) for r in cursor.fetchall()]


def link_evidence_to_remediation(
    remediation_id: int,
    evidence_id: Any,
    evidence_type: str = "Remediation Evidence",
    notes: Optional[str] = None,
    db_path: Optional[str] = None,
) -> None:
    """Link an evidence file to a corrective action."""
    if isinstance(evidence_id, dict):
        evidence_id = evidence_id["id"]
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT assessment_id FROM remediation WHERE id = ?", (remediation_id,))
        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Corrective action {remediation_id} not found.")
        aid = row["assessment_id"]
        _check_assessment_not_archived(conn, aid)

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            INSERT OR REPLACE INTO remediation_evidence (
                assessment_id, remediation_id, evidence_id, evidence_type, notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (aid, remediation_id, evidence_id, evidence_type, notes, now_iso),
        )


def unlink_evidence_from_remediation(
    remediation_id: int, evidence_id: int, db_path: Optional[str] = None
) -> None:
    """Unlink an evidence file from a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM remediation_evidence WHERE remediation_id = ? AND evidence_id = ?",
            (remediation_id, evidence_id),
        )


def get_remediation_evidence(remediation_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all evidence linked to a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT e.*, re.evidence_type as rem_evidence_type, re.notes as link_notes
            FROM evidence e
            JOIN remediation_evidence re ON e.id = re.evidence_id
            WHERE re.remediation_id = ?
            ORDER BY e.id ASC
            """,
            (remediation_id,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_remediation_progress_history(
    remediation_id: int, db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve full progress update ledger for a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM remediation_progress WHERE remediation_id = ? ORDER BY id DESC",
            (remediation_id,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_remediation_deadline_extensions(
    remediation_id: int, db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve full deadline extension ledger for a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM remediation_deadline_extensions WHERE remediation_id = ? ORDER BY id DESC",
            (remediation_id,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_remediation_verifications(
    remediation_id: int, db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve all verification records for a corrective action."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM remediation_verifications WHERE remediation_id = ? ORDER BY id DESC",
            (remediation_id,),
        )
        return [dict(r) for r in cursor.fetchall()]
