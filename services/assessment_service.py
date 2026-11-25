"""
Assessment management service for AuditSphere.

Handles validation, persistence, updates, retrieval, and archival of
ISMS audit assessments.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from database import db_session, get_utc_now_iso
from services.activity_service import log_activity

VALID_STATUSES = ("Draft", "In Progress", "In Review", "Completed", "Archived")
DEFAULT_STANDARD = "ISO/IEC 27001:2022"


def _validate_assessment_payload(
    title: str,
    organization: str,
    industry: str,
    scope: str,
    lead_assessor: str,
    assessment_date: str,
    status: str,
) -> None:
    """Validate mandatory fields and business rules for an assessment."""
    if not title or not title.strip():
        raise ValueError("Assessment title is required and cannot be blank.")
    if not organization or not organization.strip():
        raise ValueError("Organization name is required and cannot be blank.")
    if not industry or not industry.strip():
        raise ValueError("Industry is required and cannot be blank.")
    if not scope or not scope.strip():
        raise ValueError("Assessment scope is required and cannot be blank.")
    if not lead_assessor or not lead_assessor.strip():
        raise ValueError("Lead assessor name is required and cannot be blank.")
    if not assessment_date or not assessment_date.strip():
        raise ValueError("Assessment date is required.")

    # Validate ISO date format YYYY-MM-DD
    try:
        datetime.strptime(assessment_date.strip(), "%Y-%m-%d")
    except ValueError:
        raise ValueError("Assessment date must be in YYYY-MM-DD format.")

    if status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid status '{status}'. Must be one of: {', '.join(VALID_STATUSES)}."
        )


def create_assessment(
    title: str,
    organization: str,
    industry: str,
    scope: str,
    lead_assessor: str,
    assessment_date: str,
    objectives: Optional[str] = None,
    status: str = "Draft",
    standard: str = DEFAULT_STANDARD,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create and persist a new assessment in the database.
    Logs an ASSESSMENT_CREATED activity event.
    """
    title = title.strip() if title else ""
    organization = organization.strip() if organization else ""
    industry = industry.strip() if industry else ""
    scope = scope.strip() if scope else ""
    lead_assessor = lead_assessor.strip() if lead_assessor else ""
    assessment_date = assessment_date.strip() if assessment_date else ""
    objectives = objectives.strip() if objectives else ""

    _validate_assessment_payload(
        title, organization, industry, scope, lead_assessor, assessment_date, status
    )

    now_iso = get_utc_now_iso()

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO assessments (
                title, organization, industry, standard, scope, objectives,
                lead_assessor, assessment_date, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                organization,
                industry,
                standard,
                scope,
                objectives,
                lead_assessor,
                assessment_date,
                status,
                now_iso,
                now_iso,
            ),
        )
        assessment_id = cursor.lastrowid

    # Record activity log
    log_activity(
        assessment_id=assessment_id,
        event_type="ASSESSMENT_CREATED",
        description=f"Assessment '{title}' created for '{organization}' (Status: {status}).",
        actor=lead_assessor,
        db_path=db_path,
    )

    return get_assessment(assessment_id, db_path=db_path)  # type: ignore


def update_assessment(
    assessment_id: int,
    title: str,
    organization: str,
    industry: str,
    scope: str,
    lead_assessor: str,
    assessment_date: str,
    status: str,
    objectives: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Update an existing assessment's details.
    Logs an ASSESSMENT_EDITED activity event.
    """
    existing = get_assessment(assessment_id, db_path=db_path)
    if not existing:
        raise ValueError(f"Assessment with ID {assessment_id} does not exist.")

    title = title.strip() if title else ""
    organization = organization.strip() if organization else ""
    industry = industry.strip() if industry else ""
    scope = scope.strip() if scope else ""
    lead_assessor = lead_assessor.strip() if lead_assessor else ""
    assessment_date = assessment_date.strip() if assessment_date else ""
    objectives = objectives.strip() if objectives else ""

    _validate_assessment_payload(
        title, organization, industry, scope, lead_assessor, assessment_date, status
    )

    now_iso = get_utc_now_iso()

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE assessments
            SET title = ?, organization = ?, industry = ?, scope = ?,
                objectives = ?, lead_assessor = ?, assessment_date = ?,
                status = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                title,
                organization,
                industry,
                scope,
                objectives,
                lead_assessor,
                assessment_date,
                status,
                now_iso,
                assessment_id,
            ),
        )

    log_activity(
        assessment_id=assessment_id,
        event_type="ASSESSMENT_EDITED",
        description=f"Assessment '{title}' updated (Status: {status}).",
        actor=lead_assessor,
        db_path=db_path,
    )

    return get_assessment(assessment_id, db_path=db_path)  # type: ignore


def archive_assessment(
    assessment_id: int,
    actor: str = "Lead Assessor",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Archive an assessment by setting its status to 'Archived'.
    Logs an ASSESSMENT_ARCHIVED activity event.
    """
    existing = get_assessment(assessment_id, db_path=db_path)
    if not existing:
        raise ValueError(f"Assessment with ID {assessment_id} does not exist.")

    if existing["status"] == "Archived":
        return existing

    now_iso = get_utc_now_iso()

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE assessments
            SET status = 'Archived', updated_at = ?
            WHERE id = ?
            """,
            (now_iso, assessment_id),
        )

    log_activity(
        assessment_id=assessment_id,
        event_type="ASSESSMENT_ARCHIVED",
        description=f"Assessment '{existing['title']}' was archived.",
        actor=actor,
        db_path=db_path,
    )

    return get_assessment(assessment_id, db_path=db_path)  # type: ignore


def get_assessment(
    assessment_id: int, db_path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Retrieve a single assessment by its primary key ID."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def list_assessments(
    include_archived: bool = True,
    status_filter: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List all assessments ordered by updated_at descending."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM assessments"
        params: List[Any] = []
        conditions: List[str] = []

        if not include_archived:
            conditions.append("status != 'Archived'")
        if status_filter and status_filter != "All":
            conditions.append("status = ?")
            params.append(status_filter)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY updated_at DESC, id DESC"
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
