"""
Dashboard aggregation service for AuditSphere.

Computes metrics and high-level telemetry directly from SQLite records.
Strictly avoids synthetic or fake compliance percentages.
Provides control assessment coverage, weighted readiness scores,
gap counts, and domain progress summaries.
"""

from typing import Any, Dict, Optional
from database import db_session
from services.activity_service import get_recent_activities
from services.assessment_service import get_assessment
from services.assessment_engine import calculate_overall_metrics


def get_dashboard_summary(
    active_assessment_id: Optional[int] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Calculate live summary statistics directly from database records.
    Returns counts for total, active, and archived assessments, active assessment
    metadata, control assessment metrics, and recent activities.
    """
    with db_session(db_path) as conn:
        cursor = conn.cursor()

        # Total assessments count
        cursor.execute("SELECT COUNT(*) FROM assessments")
        total_assessments = cursor.fetchone()[0]

        # Active assessments (all except 'Archived')
        cursor.execute("SELECT COUNT(*) FROM assessments WHERE status != 'Archived'")
        active_assessments = cursor.fetchone()[0]

        # Archived assessments
        cursor.execute("SELECT COUNT(*) FROM assessments WHERE status = 'Archived'")
        archived_assessments = cursor.fetchone()[0]

        # Counts by status
        cursor.execute(
            """
            SELECT status, COUNT(*) as count
            FROM assessments
            GROUP BY status
            """
        )
        status_counts = {row["status"]: row["count"] for row in cursor.fetchall()}

    # Resolve active assessment if specified
    active_assessment = None
    control_metrics = None

    if active_assessment_id is not None:
        active_assessment = get_assessment(active_assessment_id, db_path=db_path)
        if active_assessment:
            from services.control_service import get_assessment_controls

            controls = get_assessment_controls(active_assessment_id, db_path=db_path)
            control_metrics = calculate_overall_metrics(controls)

    # Recent activity stream
    recent_activities = get_recent_activities(
        assessment_id=active_assessment_id, limit=8, db_path=db_path
    )

    return {
        "total_assessments": total_assessments,
        "active_assessments": active_assessments,
        "archived_assessments": archived_assessments,
        "status_distribution": status_counts,
        "active_assessment": active_assessment,
        "control_metrics": control_metrics,
        "recent_activities": recent_activities,
    }
