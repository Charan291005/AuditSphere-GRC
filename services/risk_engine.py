"""
Risk Scoring Engine for AuditSphere.

Provides pure, reusable, independently testable functions for:
- Likelihood and impact validation (1 to 5 scale)
- Risk score calculation (Likelihood × Impact)
- Risk severity classification (Low, Medium, High, Critical, or Not Assessed)
- Risk threshold configuration & validation
- 5×5 Risk heatmap matrix aggregation
- Risk distribution summaries
- Overdue review calculations
- Risk comparison & anomaly detection
- Formula-safe CSV export generation
"""

import csv
import io
import re
from datetime import datetime, date
from typing import Any, Dict, List, Optional, Tuple

# Default project-defined risk thresholds (1 to 25 scale)
# Note: These thresholds are project-defined for simulated ISMS assessments
# and are not presented as official ISO/IEC 27001 requirements.
DEFAULT_RISK_THRESHOLDS = {
    "Low": (1, 5),
    "Medium": (6, 11),
    "High": (12, 19),
    "Critical": (20, 25),
}

RISK_SEVERITY_COLORS = {
    "Low": "#15803D",        # Enterprise Green
    "Medium": "#D97706",     # Enterprise Amber
    "High": "#EA580C",       # Enterprise Orange
    "Critical": "#DC2626",   # Enterprise Red
    "Not Assessed": "#6B7280" # Slate Gray
}

RISK_CATEGORIES = [
    "Access Management",
    "Data Protection",
    "Network Security",
    "Application Security",
    "Physical Security",
    "Third-Party Security",
    "Business Continuity",
    "Security Awareness",
    "Governance and Compliance",
    "Incident Management",
    "Other",
]

TREATMENT_STRATEGIES = [
    "Mitigate",
    "Accept",
    "Transfer",
    "Avoid",
]

RISK_STATUSES = [
    "Identified",
    "Under Assessment",
    "Open",
    "Treatment Planned",
    "Under Treatment",
    "Under Review",
    "Accepted",
    "Closed",
]

APPROVAL_STATUSES = [
    "Not Requested",
    "Pending Approval",
    "Approved",
    "Rejected",
]


def validate_score_dimension(val: Optional[Any], name: str = "Dimension") -> Optional[int]:
    """
    Validate that likelihood or impact is an integer between 1 and 5, or None if unassessed.
    """
    if val is None or val == "" or str(val).strip() == "":
        return None
    try:
        int_val = int(val)
    except (ValueError, TypeError):
        raise ValueError(f"{name} must be an integer between 1 and 5, got '{val}'.")

    if int_val < 1 or int_val > 5:
        raise ValueError(f"{name} must be between 1 and 5, got {int_val}.")

    return int_val


def calculate_risk_score(
    likelihood: Optional[int],
    impact: Optional[int],
) -> Optional[int]:
    """
    Calculate Risk Score = Likelihood × Impact (1 to 25).
    Returns None if either likelihood or impact is unassessed (None).
    Never returns a misleading score of 0 for unassessed risks.
    """
    valid_l = validate_score_dimension(likelihood, "Likelihood")
    valid_i = validate_score_dimension(impact, "Impact")

    if valid_l is None or valid_i is None:
        return None

    return valid_l * valid_i


def classify_risk_score(
    score: Optional[int],
    thresholds: Optional[Dict[str, Tuple[int, int]]] = None,
) -> str:
    """
    Classify a calculated risk score into severity level.
    Returns 'Not Assessed' if score is None.
    Default thresholds:
      Low: 1 - 5
      Medium: 6 - 11
      High: 12 - 19
      Critical: 20 - 25
    """
    if score is None:
        return "Not Assessed"

    thresh = thresholds or DEFAULT_RISK_THRESHOLDS

    for level in ["Critical", "High", "Medium", "Low"]:
        if level in thresh:
            low_b, high_b = thresh[level]
            if low_b <= score <= high_b:
                return level

    return "Low" if score <= 5 else "Critical"


def validate_custom_thresholds(thresholds: Dict[str, Tuple[int, int]]) -> bool:
    """
    Validate that configurable thresholds form complete, non-overlapping, ordered ranges from 1 to 25.
    """
    required_levels = ["Low", "Medium", "High", "Critical"]
    for lvl in required_levels:
        if lvl not in thresholds:
            raise ValueError(f"Thresholds dictionary missing required level '{lvl}'.")

    low_min, low_max = thresholds["Low"]
    med_min, med_max = thresholds["Medium"]
    high_min, high_max = thresholds["High"]
    crit_min, crit_max = thresholds["Critical"]

    if low_min != 1:
        raise ValueError("Low threshold minimum must start at 1.")
    if med_min != low_max + 1:
        raise ValueError(f"Medium threshold must begin at {low_max + 1}, got {med_min}.")
    if high_min != med_max + 1:
        raise ValueError(f"High threshold must begin at {med_max + 1}, got {high_min}.")
    if crit_min != high_max + 1:
        raise ValueError(f"Critical threshold must begin at {high_max + 1}, got {crit_min}.")
    if crit_max != 25:
        raise ValueError(f"Critical threshold maximum must be 25, got {crit_max}.")

    return True


def evaluate_risk_record(
    likelihood: Optional[int],
    impact: Optional[int],
    thresholds: Optional[Dict[str, Tuple[int, int]]] = None,
) -> Tuple[Optional[int], str]:
    """
    Helper to calculate score and classification together.
    Returns (score, classification).
    """
    score = calculate_risk_score(likelihood, impact)
    classification = classify_risk_score(score, thresholds=thresholds)
    return score, classification


def compare_risk_evaluations(
    inherent_score: Optional[int],
    residual_score: Optional[int],
    target_score: Optional[int],
) -> Dict[str, Any]:
    """
    Analyze the trajectory from Inherent -> Current Residual -> Target Residual risk.
    Flags potential assessment anomalies (e.g., residual exceeding inherent risk).
    """
    anomalies = []

    if inherent_score is not None and residual_score is not None:
        if residual_score > inherent_score:
            anomalies.append(
                f"Current residual risk ({residual_score}) exceeds inherent risk ({inherent_score}). "
                "Ensure documented justification explains control side-effects or elevated baseline exposure."
            )

    if residual_score is not None and target_score is not None:
        if target_score > residual_score:
            anomalies.append(
                f"Target residual risk ({target_score}) exceeds current residual risk ({residual_score}). "
                "Target risk represents expected post-treatment exposure and should typically be lower or equal."
            )

    reduction_pct = None
    if inherent_score and residual_score and inherent_score > 0:
        reduction_pct = round(((inherent_score - residual_score) / inherent_score) * 100, 1)

    return {
        "anomalies": anomalies,
        "has_anomalies": len(anomalies) > 0,
        "risk_reduction_pct": reduction_pct,
    }


def is_review_overdue(review_date_str: Optional[str], as_of_date: Optional[str] = None) -> bool:
    """
    Check if a risk review date has passed.
    Dates are formatted as YYYY-MM-DD.
    """
    if not review_date_str or not review_date_str.strip():
        return False

    try:
        rev_d = datetime.strptime(review_date_str.strip(), "%Y-%m-%d").date()
    except ValueError:
        return False

    ref_d = datetime.strptime(as_of_date.strip(), "%Y-%m-%d").date() if as_of_date else date.today()
    return rev_d < ref_d


def calculate_risk_register_metrics(risks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute aggregate risk register summary metrics from a list of risk records.
    All metrics are computed strictly from database records without synthetic numbers.
    """
    total = len(risks)
    crit_count = 0
    high_count = 0
    med_count = 0
    low_count = 0
    unassessed_count = 0
    accepted_count = 0
    under_treatment_count = 0
    overdue_count = 0

    category_counts: Dict[str, int] = {cat: 0 for cat in RISK_CATEGORIES}
    status_counts: Dict[str, int] = {st: 0 for st in RISK_STATUSES}
    treatment_counts: Dict[str, int] = {tr: 0 for tr in TREATMENT_STRATEGIES}

    for r in risks:
        # Residual level breakdown
        level = r.get("residual_risk_level")
        score = r.get("residual_risk_score")

        if score is None or level is None or level == "Not Assessed":
            unassessed_count += 1
        elif level == "Critical":
            crit_count += 1
        elif level == "High":
            high_count += 1
        elif level == "Medium":
            med_count += 1
        elif level == "Low":
            low_count += 1

        # Status counts
        status = r.get("status", "Identified")
        status_counts[status] = status_counts.get(status, 0) + 1
        if status == "Accepted":
            accepted_count += 1
        elif status in ("Treatment Planned", "Under Treatment"):
            under_treatment_count += 1

        # Category counts
        cat = r.get("risk_category", "Other")
        category_counts[cat] = category_counts.get(cat, 0) + 1

        # Treatment counts
        tr = r.get("treatment_strategy", "Mitigate")
        treatment_counts[tr] = treatment_counts.get(tr, 0) + 1

        # Review date check
        rev_date = r.get("review_date")
        if status != "Closed" and is_review_overdue(rev_date):
            overdue_count += 1

    return {
        "total_risks": total,
        "critical_risks": crit_count,
        "high_risks": high_count,
        "medium_risks": med_count,
        "low_risks": low_count,
        "unassessed_risks": unassessed_count,
        "accepted_risks": accepted_count,
        "under_treatment_risks": under_treatment_count,
        "overdue_reviews": overdue_count,
        "category_counts": category_counts,
        "status_counts": status_counts,
        "treatment_counts": treatment_counts,
    }


def aggregate_risk_heatmap_data(
    risks: List[Dict[str, Any]],
    evaluation_type: str = "current_residual",  # 'inherent', 'current_residual', or 'target_residual'
) -> Dict[str, Any]:
    """
    Aggregate risk records into a 5×5 matrix (Likelihood 1-5 × Impact 1-5).
    Returns cell counts, lists of risks per cell, and count of unassessed risks.
    """
    matrix: Dict[Tuple[int, int], List[Dict[str, Any]]] = {
        (l, i): [] for l in range(1, 6) for i in range(1, 6)
    }
    unassessed_list: List[Dict[str, Any]] = []

    for r in risks:
        if evaluation_type == "inherent":
            l = r.get("inherent_likelihood") or r.get("likelihood")
            i = r.get("inherent_impact") or r.get("impact")
        elif evaluation_type == "target_residual":
            l = r.get("target_likelihood")
            i = r.get("target_impact")
        else:  # default 'current_residual'
            l = r.get("residual_likelihood")
            i = r.get("residual_impact")

        if l is not None and i is not None and 1 <= l <= 5 and 1 <= i <= 5:
            matrix[(l, i)].append(r)
        else:
            unassessed_list.append(r)

    # Format into cell details
    cell_data = []
    for l in range(5, 0, -1):  # Vertical axis: Likelihood 5 down to 1
        for i in range(1, 6):   # Horizontal axis: Impact 1 up to 5
            cell_risks = matrix[(l, i)]
            score = l * i
            cell_data.append(
                {
                    "likelihood": l,
                    "impact": i,
                    "score": score,
                    "severity": classify_risk_score(score),
                    "count": len(cell_risks),
                    "risks": [
                        {
                            "id": r["id"],
                            "risk_identifier": r["risk_identifier"],
                            "title": r["title"],
                            "category": r.get("risk_category", "Other"),
                            "status": r.get("status", "Identified"),
                            "owner": r.get("risk_owner", "Unassigned"),
                        }
                        for r in cell_risks
                    ],
                }
            )

    return {
        "evaluation_type": evaluation_type,
        "cells": cell_data,
        "unassessed_count": len(unassessed_list),
        "unassessed_risks": unassessed_list,
        "total_assessed": len(risks) - len(unassessed_list),
    }


def sanitize_csv_cell(value: Any) -> str:
    """
    Defend against CSV / Spreadsheet Formula Injection (CWE-1236).
    If cell begins with '=', '+', '-', '@', tab, or carriage return,
    prefix with single quote "'" so spreadsheet programs render it as raw literal text.
    """
    if value is None:
        return ""

    text = str(value)
    if not text:
        return ""

    first_char = text[0]
    if first_char in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{text}"

    return text


def export_risks_to_csv(risks: List[Dict[str, Any]]) -> str:
    """
    Generate an RFC 4180-compliant CSV string containing the risk register.
    Applies formula injection protection to all text columns and excludes sensitive file paths.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    headers = [
        "Risk Reference",
        "Risk Title",
        "Risk Category",
        "Asset / Process",
        "Threat",
        "Vulnerability",
        "Potential Consequence",
        "Existing Controls",
        "Inherent Likelihood",
        "Inherent Impact",
        "Inherent Score",
        "Inherent Classification",
        "Inherent Rationale",
        "Current Residual Likelihood",
        "Current Residual Impact",
        "Current Residual Score",
        "Current Residual Classification",
        "Current Residual Rationale",
        "Target Residual Likelihood",
        "Target Residual Impact",
        "Target Residual Score",
        "Target Residual Classification",
        "Treatment Strategy",
        "Proposed Treatment",
        "Treatment Owner",
        "Target Treatment Date",
        "Approval Status",
        "Approving Authority",
        "Approval Date",
        "Review Date",
        "Risk Status",
        "Risk Owner",
        "Responsible Department",
        "Assessor",
        "Assessment Date",
    ]
    writer.writerow(headers)

    for r in risks:
        row = [
            sanitize_csv_cell(r.get("risk_identifier")),
            sanitize_csv_cell(r.get("title")),
            sanitize_csv_cell(r.get("risk_category")),
            sanitize_csv_cell(r.get("asset_or_process")),
            sanitize_csv_cell(r.get("threat")),
            sanitize_csv_cell(r.get("vulnerability")),
            sanitize_csv_cell(r.get("consequence")),
            sanitize_csv_cell(r.get("existing_controls")),
            sanitize_csv_cell(r.get("inherent_likelihood") or r.get("likelihood")),
            sanitize_csv_cell(r.get("inherent_impact") or r.get("impact")),
            sanitize_csv_cell(r.get("inherent_risk_score")),
            sanitize_csv_cell(r.get("inherent_risk_level")),
            sanitize_csv_cell(r.get("inherent_rationale")),
            sanitize_csv_cell(r.get("residual_likelihood")),
            sanitize_csv_cell(r.get("residual_impact")),
            sanitize_csv_cell(r.get("residual_risk_score")),
            sanitize_csv_cell(r.get("residual_risk_level")),
            sanitize_csv_cell(r.get("residual_rationale")),
            sanitize_csv_cell(r.get("target_likelihood")),
            sanitize_csv_cell(r.get("target_impact")),
            sanitize_csv_cell(r.get("target_risk_score")),
            sanitize_csv_cell(r.get("target_risk_level")),
            sanitize_csv_cell(r.get("treatment_strategy")),
            sanitize_csv_cell(r.get("proposed_treatment")),
            sanitize_csv_cell(r.get("treatment_owner")),
            sanitize_csv_cell(r.get("target_treatment_date")),
            sanitize_csv_cell(r.get("approval_status")),
            sanitize_csv_cell(r.get("approving_authority")),
            sanitize_csv_cell(r.get("approval_date")),
            sanitize_csv_cell(r.get("review_date")),
            sanitize_csv_cell(r.get("status")),
            sanitize_csv_cell(r.get("risk_owner")),
            sanitize_csv_cell(r.get("responsible_department")),
            sanitize_csv_cell(r.get("assessor_name")),
            sanitize_csv_cell(r.get("assessment_date")),
        ]
        writer.writerow(row)

    return output.getvalue()
