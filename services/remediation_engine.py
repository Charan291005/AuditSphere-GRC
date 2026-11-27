"""
AuditSphere – Remediation & Corrective Action Engine
Pure calculation, validation, lifecycle transitions, deadline monitoring, and CSV export.
"""

from __future__ import annotations

import csv
import io
from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

VALID_STATUSES = [
    "Open",
    "In Progress",
    "Awaiting Verification",
    "Under Verification",
    "Reopened",
    "Closed",
    "Cancelled",
]

VALID_PRIORITIES = ["Low", "Medium", "High", "Critical"]

VALID_VERIFICATION_RESULTS = ["Effective", "Ineffective", "Inconclusive"]

VALID_RCA_METHODS = [
    "Direct Analysis",
    "5 Whys",
    "Fishbone / Ishikawa",
    "Fault Tree",
    "Under Investigation",
    "Not Appropriate",
]

# Enforced Lifecycle Transitions
# Direct transition from Open or In Progress to Closed is forbidden.
ALLOWED_TRANSITIONS: Dict[str, List[str]] = {
    "Open": ["In Progress", "Cancelled"],
    "In Progress": ["Awaiting Verification", "Cancelled"],
    "Awaiting Verification": ["Under Verification", "In Progress"],
    "Under Verification": ["Closed", "Reopened", "Awaiting Verification"],
    "Reopened": ["In Progress"],
    "Closed": ["Reopened"],
    "Cancelled": ["Open"],  # Allow reversing cancellation with audit trail
}


def validate_status_transition(
    current_status: str,
    new_status: str,
    action_data: Optional[Dict[str, Any]] = None,
    verifications: Optional[List[Dict[str, Any]]] = None,
    evidence_list: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """
    Validate that a proposed corrective action status transition obeys lifecycle rules.
    Raises ValueError with a descriptive message if invalid.
    """
    if current_status == new_status:
        return

    if current_status not in VALID_STATUSES:
        raise ValueError(f"Invalid current status: '{current_status}'. Allowed: {VALID_STATUSES}")

    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid target status: '{new_status}'. Allowed: {VALID_STATUSES}")

    allowed = ALLOWED_TRANSITIONS.get(current_status, [])
    if new_status not in allowed:
        raise ValueError(
            f"Invalid status transition from '{current_status}' to '{new_status}'. "
            f"Permitted next statuses: {allowed}"
        )

    action = action_data or {}

    # Transition to Cancelled requires cancellation reason
    if new_status == "Cancelled":
        reason = (action.get("cancellation_reason") or "").strip()
        if not reason:
            raise ValueError("A cancellation reason is required to cancel a corrective action.")

    # Transition from Closed to Reopened requires justification
    if current_status == "Closed" and new_status == "Reopened":
        justification = (action.get("reopen_justification") or "").strip()
        if not justification:
            raise ValueError(
                "Documented justification is required to reopen a closed corrective action."
            )

    # Transition to Awaiting Verification requires implementation details & progress = 100
    if new_status == "Awaiting Verification":
        progress = action.get("progress_percentage", 0)
        try:
            progress_int = int(progress)
        except (ValueError, TypeError):
            progress_int = 0

        if progress_int < 100:
            raise ValueError(
                f"Corrective action progress must be 100% before requesting verification (currently {progress_int}%)."
            )

        summary = (action.get("implementation_summary") or "").strip()
        if not summary:
            raise ValueError(
                "A documented implementation summary is required before submitting for verification."
            )

    # Transition to Closed requires full closure eligibility
    if new_status == "Closed":
        validate_closure_eligibility(action, verifications or [], evidence_list)


def validate_closure_eligibility(
    action: Dict[str, Any],
    verifications: List[Dict[str, Any]],
    evidence_list: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """
    Strictly enforce closure governance rules before closing a corrective action.
    """
    # 1. Implementation completion & summary
    progress = action.get("progress_percentage", 0)
    try:
        if int(progress) < 100:
            raise ValueError(
                f"Cannot close corrective action: Progress is {progress}%, must be 100%."
            )
    except (ValueError, TypeError):
        raise ValueError("Cannot close corrective action: Progress percentage is invalid.")

    summary = (action.get("implementation_summary") or "").strip()
    if not summary:
        raise ValueError(
            "Cannot close corrective action: Documented implementation summary is required."
        )

    # 2. Closure rationale
    closure_rationale = (action.get("closure_rationale") or "").strip()
    if not closure_rationale:
        raise ValueError(
            "Cannot close corrective action: A documented closure rationale is required."
        )

    # 3. Root cause or justified exception
    rc_method = action.get("root_cause_analysis_method", "Direct Analysis")
    root_cause = (action.get("root_cause") or "").strip()
    if rc_method != "Not Appropriate" and not root_cause:
        raise ValueError(
            "Cannot close corrective action: Documented root cause is required, or method must be 'Not Appropriate' with justification."
        )

    # 4. Verifications verification
    if not verifications:
        raise ValueError(
            "Cannot close corrective action: At least one effectiveness verification record is required."
        )

    # Sort verifications by date or id descending to inspect latest
    latest_verif = sorted(
        verifications,
        key=lambda v: (str(v.get("verification_date") or ""), int(v.get("id") or 0)),
        reverse=True,
    )[0]

    result = latest_verif.get("verification_result")
    if result != "Effective":
        raise ValueError(
            f"Cannot close corrective action: Latest verification result is '{result}'. "
            "Only actions verified as 'Effective' can be closed. "
            "Ineffective actions must be reopened or returned for remediation."
        )

    verif_notes = (latest_verif.get("verification_notes") or "").strip()
    if not verif_notes:
        raise ValueError(
            "Cannot close corrective action: Latest verification record requires verification notes."
        )

    # 5. Evidence check
    if evidence_list is not None:
        if len(evidence_list) == 0:
            raise ValueError(
                "Cannot close corrective action: Relevant supporting remediation evidence is required."
            )

        # Check for unresolved integrity warnings
        for ev in evidence_list:
            integ = ev.get("integrity_status", "")
            if integ in ("Hash mismatch", "File missing"):
                raise ValueError(
                    f"Cannot close corrective action: Evidence '{ev.get('title', 'Unknown')}' has unresolved integrity warning: '{integ}'."
                )


def validate_priority_alignment(
    risk_level: Optional[str],
    action_priority: str,
    priority_justification: Optional[str] = None,
) -> None:
    """
    If an action is linked to a Critical risk but assigned a substantially lower priority (Medium or Low),
    require an explicit documented justification.
    """
    if risk_level == "Critical" and action_priority in ("Low", "Medium"):
        just = (priority_justification or "").strip()
        if not just:
            raise ValueError(
                f"Action priority is '{action_priority}' while linked risk is 'Critical'. "
                "A documented priority justification is required when assigning a substantially lower priority."
            )


def suggest_priority_from_source(
    finding_severity: Optional[str] = None,
    risk_level: Optional[str] = None,
) -> str:
    """
    Suggest an initial corrective action priority based on source finding or risk severity.
    """
    if finding_severity == "Critical" or risk_level == "Critical":
        return "Critical"
    if finding_severity == "High" or risk_level == "High":
        return "High"
    if finding_severity == "Medium" or risk_level == "Medium":
        return "Medium"
    if finding_severity in ("Low", "Informational") or risk_level == "Low":
        return "Low"
    return "Medium"


def parse_iso_date(d_str: Optional[str]) -> Optional[date]:
    """Parse YYYY-MM-DD string to date object safely."""
    if not d_str:
        return None
    try:
        return datetime.strptime(d_str.strip()[:10], "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def calculate_remediation_metrics(
    remediations: List[Dict[str, Any]],
    reference_date: Optional[str | date] = None,
) -> Dict[str, Any]:
    """
    Calculate comprehensive remediation metrics based on actual database records.
    """
    ref_d: date
    if isinstance(reference_date, date):
        ref_d = reference_date
    elif isinstance(reference_date, str):
        parsed = parse_iso_date(reference_date)
        ref_d = parsed if parsed else date.today()
    else:
        ref_d = date.today()

    total_actions = len(remediations)
    active_actions = [r for r in remediations if not r.get("is_archived")]

    status_counts = {
        "Open": 0,
        "In Progress": 0,
        "Awaiting Verification": 0,
        "Under Verification": 0,
        "Reopened": 0,
        "Closed": 0,
        "Cancelled": 0,
    }

    priority_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    overdue_count = 0
    due_today_count = 0
    due_in_7_days_count = 0
    without_deadline_count = 0
    completed_on_time_count = 0
    completed_late_count = 0

    for r in active_actions:
        st = r.get("status", "Open")
        if st in status_counts:
            status_counts[st] += 1

        prio = r.get("action_priority", "Medium")
        if prio in priority_counts:
            priority_counts[prio] += 1

        target_d = parse_iso_date(r.get("target_date"))
        actual_d = parse_iso_date(r.get("actual_completion_date"))

        is_closed = st == "Closed"
        is_cancelled = st == "Cancelled"

        if is_closed:
            if target_d and actual_d:
                if actual_d <= target_d:
                    completed_on_time_count += 1
                else:
                    completed_late_count += 1
            elif target_d and not actual_d:
                completed_on_time_count += 1
        elif not is_cancelled:
            # Active pending action deadline checks
            if not target_d:
                without_deadline_count += 1
            else:
                if target_d < ref_d:
                    overdue_count += 1
                elif target_d == ref_d:
                    due_today_count += 1
                elif ref_d < target_d <= ref_d + timedelta(days=7):
                    due_in_7_days_count += 1

    active_non_cancelled = len([r for r in active_actions if r.get("status") != "Cancelled"])
    closed_count = status_counts["Closed"]

    if active_non_cancelled > 0:
        verified_closure_rate = round((closed_count / active_non_cancelled) * 100.0, 1)
    else:
        verified_closure_rate = None  # N/A

    return {
        "total_actions": total_actions,
        "active_actions_count": len(active_actions),
        "status_counts": status_counts,
        "priority_counts": priority_counts,
        "active_non_cancelled": active_non_cancelled,
        "open": status_counts["Open"],
        "in_progress": status_counts["In Progress"],
        "awaiting_verification": status_counts["Awaiting Verification"],
        "under_verification": status_counts["Under Verification"],
        "reopened": status_counts["Reopened"],
        "closed": closed_count,
        "cancelled": status_counts["Cancelled"],
        "overdue": overdue_count,
        "due_today": due_today_count,
        "due_in_7_days": due_in_7_days_count,
        "without_deadline": without_deadline_count,
        "completed_on_time": completed_on_time_count,
        "completed_late": completed_late_count,
        "verified_closure_rate": verified_closure_rate,
        "reference_date": ref_d.isoformat(),
    }


def sanitize_csv_cell(value: Any) -> str:
    """
    Mitigate formula injection (CWE-1236) by prepending a single quote
    if a text field starts with formula trigger characters (=, +, -, @, tab, CR).
    """
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def export_remediations_to_csv(
    remediations: List[Dict[str, Any]],
    findings_map: Optional[Dict[int, str]] = None,
    risks_map: Optional[Dict[int, str]] = None,
    controls_map: Optional[Dict[int, str]] = None,
    verifications_map: Optional[Dict[int, str]] = None,
) -> str:
    """
    Export corrective actions to a sanitized, standard CSV format.
    """
    f_map = findings_map or {}
    r_map = risks_map or {}
    c_map = controls_map or {}
    v_map = verifications_map or {}

    headers = [
        "Action Reference",
        "Action Title",
        "Priority",
        "Status",
        "Progress (%)",
        "Responsible Owner",
        "Responsible Department",
        "Target Completion Date",
        "Original Target Date",
        "Implementation Completion Date",
        "Root Cause Method",
        "Root Cause",
        "Immediate Correction",
        "Long-Term Corrective Action",
        "Expected Outcome",
        "Implementation Summary",
        "Latest Verification Result",
        "Closure Rationale",
        "Linked Findings",
        "Linked Risks",
        "Linked Controls",
        "Created Date",
        "Updated Date",
    ]

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(headers)

    for item in remediations:
        rid = item.get("id", 0)
        row = [
            sanitize_csv_cell(item.get("remediation_identifier")),
            sanitize_csv_cell(item.get("action_title")),
            sanitize_csv_cell(item.get("action_priority")),
            sanitize_csv_cell(item.get("status")),
            sanitize_csv_cell(item.get("progress_percentage", 0)),
            sanitize_csv_cell(item.get("action_owner")),
            sanitize_csv_cell(item.get("responsible_department")),
            sanitize_csv_cell(item.get("target_date")),
            sanitize_csv_cell(item.get("original_target_date")),
            sanitize_csv_cell(item.get("actual_completion_date")),
            sanitize_csv_cell(item.get("root_cause_analysis_method")),
            sanitize_csv_cell(item.get("root_cause")),
            sanitize_csv_cell(item.get("immediate_correction")),
            sanitize_csv_cell(item.get("long_term_corrective_action")),
            sanitize_csv_cell(item.get("expected_outcome")),
            sanitize_csv_cell(item.get("implementation_summary")),
            sanitize_csv_cell(v_map.get(rid, "")),
            sanitize_csv_cell(item.get("closure_rationale")),
            sanitize_csv_cell(f_map.get(rid, "")),
            sanitize_csv_cell(r_map.get(rid, "")),
            sanitize_csv_cell(c_map.get(rid, "")),
            sanitize_csv_cell(item.get("created_at")),
            sanitize_csv_cell(item.get("updated_at")),
        ]
        writer.writerow(row)

    return output.getvalue()
