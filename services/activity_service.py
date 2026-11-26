"""
Activity logging service for AuditSphere.

Records important assessment lifecycle and control assessment events:
- ASSESSMENT_CREATED
- ASSESSMENT_EDITED
- ASSESSMENT_ARCHIVED
- CONTROL_ASSESSMENT_INITIALIZED
- CONTROL_ASSESSMENT_UPDATED
- CONTROL_STATUS_CHANGED
- CONTROL_APPLICABILITY_CHANGED

Note: This is an internal operational audit log, not a cryptographically
tamper-proof ledger.
"""

from typing import Any, Dict, List, Optional
from database import db_session, get_utc_now_iso


def log_activity(
    assessment_id: Optional[int],
    event_type: str,
    description: str,
    actor: str = "Lead Assessor",
    control_reference: Optional[str] = None,
    previous_status: Optional[str] = None,
    new_status: Optional[str] = None,
    db_path: Optional[str] = None,
) -> int:
    """Record a lifecycle or control assessment event in the activity_log table."""
    now_iso = get_utc_now_iso()
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO activity_log (
                assessment_id, event_type, description, actor,
                control_reference, previous_status, new_status, timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                event_type,
                description,
                actor,
                control_reference,
                previous_status,
                new_status,
                now_iso,
            ),
        )
        return cursor.lastrowid  # type: ignore


def get_recent_activities(
    assessment_id: Optional[int] = None,
    limit: int = 20,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve the most recent activity log entries, optionally filtered by assessment."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        if assessment_id is not None:
            cursor.execute(
                """
                SELECT a.id, a.assessment_id, a.event_type, a.description, a.actor,
                       a.control_reference, a.previous_status, a.new_status, a.timestamp,
                       asm.title AS assessment_title
                FROM activity_log a
                LEFT JOIN assessments asm ON a.assessment_id = asm.id
                WHERE a.assessment_id = ?
                ORDER BY a.timestamp DESC, a.id DESC
                LIMIT ?
                """,
                (assessment_id, limit),
            )
        else:
            cursor.execute(
                """
                SELECT a.id, a.assessment_id, a.event_type, a.description, a.actor,
                       a.control_reference, a.previous_status, a.new_status, a.timestamp,
                       asm.title AS assessment_title
                FROM activity_log a
                LEFT JOIN assessments asm ON a.assessment_id = asm.id
                ORDER BY a.timestamp DESC, a.id DESC
                LIMIT ?
                """,
                (limit,),
            )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
