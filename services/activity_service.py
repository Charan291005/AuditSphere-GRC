"""
Activity logging service for AuditSphere.

Records important assessment lifecycle events:
- ASSESSMENT_CREATED
- ASSESSMENT_EDITED
- ASSESSMENT_ARCHIVED

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
    db_path: Optional[str] = None,
) -> int:
    """Record a lifecycle event in the activity_log table."""
    now_iso = get_utc_now_iso()
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO activity_log (assessment_id, event_type, description, actor, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (assessment_id, event_type, description, actor, now_iso),
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
                SELECT a.id, a.assessment_id, a.event_type, a.description, a.actor, a.timestamp,
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
                SELECT a.id, a.assessment_id, a.event_type, a.description, a.actor, a.timestamp,
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
