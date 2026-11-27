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
    evidence_metrics = None
    findings_metrics = None
    test_metrics = None
    risk_metrics = None
    remediation_metrics = None

    if active_assessment_id is not None:
        active_assessment = get_assessment(active_assessment_id, db_path=db_path)
        if active_assessment:
            from services.control_service import get_assessment_controls
            from services.risk_service import get_assessment_risks
            from services.risk_engine import calculate_risk_register_metrics
            from services.remediation_service import get_assessment_remediations
            from services.remediation_engine import calculate_remediation_metrics

            controls = get_assessment_controls(active_assessment_id, db_path=db_path)
            control_metrics = calculate_overall_metrics(controls)

            active_risks = get_assessment_risks(active_assessment_id, db_path=db_path)
            risk_metrics = calculate_risk_register_metrics(active_risks)

            active_remediations = get_assessment_remediations(active_assessment_id, db_path=db_path)
            remediation_metrics = calculate_remediation_metrics(active_remediations)

            with db_session(db_path) as conn:
                cursor = conn.cursor()

                # Evidence metrics
                cursor.execute(
                    """
                    SELECT review_status, COUNT(*) as cnt
                    FROM evidence
                    WHERE assessment_id = ?
                    GROUP BY review_status
                    """,
                    (active_assessment_id,),
                )
                rev_rows = cursor.fetchall()
                rev_counts = {r["review_status"]: r["cnt"] for r in rev_rows}
                total_ev = sum(rev_counts.values())

                cursor.execute(
                    """
                    SELECT COUNT(*) FROM evidence
                    WHERE assessment_id = ? AND integrity_status IN ('Hash mismatch', 'File missing')
                    """,
                    (active_assessment_id,),
                )
                integrity_issues = cursor.fetchone()[0]

                evidence_metrics = {
                    "total_evidence": total_ev,
                    "review_counts": rev_counts,
                    "integrity_issues": integrity_issues,
                }

                # Findings metrics
                cursor.execute(
                    """
                    SELECT severity, status, COUNT(*) as cnt
                    FROM findings
                    WHERE assessment_id = ?
                    GROUP BY severity, status
                    """,
                    (active_assessment_id,),
                )
                fnd_rows = cursor.fetchall()
                sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
                total_fnd = 0
                open_fnd = 0
                closed_fnd = 0

                for r in fnd_rows:
                    sev = r["severity"]
                    st_val = r["status"]
                    cnt = r["cnt"]
                    total_fnd += cnt
                    if sev in sev_counts:
                        sev_counts[sev] += cnt
                    if st_val == "Closed":
                        closed_fnd += cnt
                    else:
                        open_fnd += cnt

                findings_metrics = {
                    "total_findings": total_fnd,
                    "open_findings": open_fnd,
                    "closed_findings": closed_fnd,
                    "severity_counts": sev_counts,
                }

                # Control test metrics
                cursor.execute(
                    """
                    SELECT conclusion, COUNT(*) as cnt
                    FROM control_tests
                    WHERE assessment_id = ?
                    GROUP BY conclusion
                    """,
                    (active_assessment_id,),
                )
                test_rows = cursor.fetchall()
                t_counts = {r["conclusion"]: r["cnt"] for r in test_rows}
                test_metrics = {
                    "total_tests": sum(t_counts.values()),
                    "pass_count": t_counts.get("Pass", 0),
                    "fail_count": t_counts.get("Fail", 0),
                    "inconclusive_count": t_counts.get("Inconclusive", 0),
                }

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
        "evidence_metrics": evidence_metrics,
        "findings_metrics": findings_metrics,
        "test_metrics": test_metrics,
        "risk_metrics": risk_metrics,
        "remediation_metrics": remediation_metrics,
        "recent_activities": recent_activities,
    }
