"""
Assessment Scoring and Readiness Engine for AuditSphere.

Pure calculation functions for evaluating ISMS control implementation progress,
assessment coverage, weighted readiness scores, and potential gap identification
against ISO/IEC 27001:2022.

Methodology Rules:
1. Applicable Controls = Total selected controls excluding 'Not Applicable'.
2. Assessed Applicable Controls = Controls marked 'Implemented', 'Partially Implemented', or 'Not Implemented'.
3. Assessment Coverage (%) = (Assessed Applicable / Total Applicable) * 100.
4. Weighted Readiness (%) = ((Implemented + 0.5 * Partially Implemented) / Assessed Applicable) * 100.
   - 'Not Implemented' contributes 0 to the numerator.
   - 'Not Assessed' and 'Not Applicable' are excluded from the readiness denominator.
   - If no applicable controls or assessed controls exist, returns None (displayed as 'N/A').
   - Never outputs misleading 100% readiness for an unassessed or partially assessed organization.
5. Potential Gaps = Partially Implemented + Not Implemented.
"""

from typing import Any, Dict, List, Optional

VALID_CONTROL_STATUSES = (
    "Not Assessed",
    "Implemented",
    "Partially Implemented",
    "Not Implemented",
    "Not Applicable",
)


def calculate_control_status_counts(records: List[Dict[str, Any]]) -> Dict[str, int]:
    """Calculate counts for each standard implementation status."""
    counts = {status: 0 for status in VALID_CONTROL_STATUSES}
    for r in records:
        status = r.get("status", "Not Assessed")
        if status in counts:
            counts[status] += 1
        else:
            counts["Not Assessed"] += 1
    counts["total"] = len(records)
    return counts


def calculate_applicable_controls_count(records: List[Dict[str, Any]]) -> int:
    """Return count of all controls excluding 'Not Applicable'."""
    return sum(1 for r in records if r.get("status") != "Not Applicable")


def calculate_assessed_controls_count(records: List[Dict[str, Any]]) -> int:
    """
    Return count of evaluated applicable controls.
    Consists of Implemented, Partially Implemented, and Not Implemented.
    """
    return sum(
        1
        for r in records
        if r.get("status") in ("Implemented", "Partially Implemented", "Not Implemented")
    )


def calculate_pending_controls_count(records: List[Dict[str, Any]]) -> int:
    """Return count of controls remaining in 'Not Assessed' state."""
    return sum(1 for r in records if r.get("status", "Not Assessed") == "Not Assessed")


def calculate_potential_gaps(records: List[Dict[str, Any]]) -> int:
    """
    Potential control gaps comprise controls that are either Partially Implemented
    or Not Implemented.
    """
    return sum(
        1
        for r in records
        if r.get("status") in ("Partially Implemented", "Not Implemented")
    )


def calculate_assessment_coverage(records: List[Dict[str, Any]]) -> Optional[float]:
    """
    Calculate the percentage of applicable controls that have been assessed.
    Coverage = (Assessed Applicable / Total Applicable) * 100.
    Returns None if there are 0 applicable controls.
    """
    applicable = calculate_applicable_controls_count(records)
    if applicable == 0:
        return None
    assessed = calculate_assessed_controls_count(records)
    return round((assessed / applicable) * 100.0, 2)


def calculate_weighted_readiness(records: List[Dict[str, Any]]) -> Optional[float]:
    """
    Calculate the weighted implementation readiness score across assessed controls.
    Score = ((Implemented + 0.5 * Partially Implemented) / Assessed Applicable) * 100.
    Returns None if no applicable controls have been assessed yet.
    """
    assessed = calculate_assessed_controls_count(records)
    if assessed == 0:
        return None

    implemented = sum(1 for r in records if r.get("status") == "Implemented")
    partially_implemented = sum(
        1 for r in records if r.get("status") == "Partially Implemented"
    )

    weighted_points = implemented + (0.5 * partially_implemented)
    return round((weighted_points / assessed) * 100.0, 2)


def calculate_category_summary(
    records: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """
    Compute domain/category-level breakdown for the 4 ISO/IEC 27001:2022 themes:
    Organizational, People, Physical, Technological.
    """
    categories = ["Organizational", "People", "Physical", "Technological"]
    summary: Dict[str, Dict[str, Any]] = {}

    for cat in categories:
        cat_records = [
            r
            for r in records
            if (r.get("domain") or r.get("category", "")).lower() == cat.lower()
        ]
        status_counts = calculate_control_status_counts(cat_records)
        applicable = calculate_applicable_controls_count(cat_records)
        assessed = calculate_assessed_controls_count(cat_records)
        coverage = calculate_assessment_coverage(cat_records)
        readiness = calculate_weighted_readiness(cat_records)
        gaps = calculate_potential_gaps(cat_records)

        summary[cat] = {
            "total": len(cat_records),
            "implemented": status_counts.get("Implemented", 0),
            "partially_implemented": status_counts.get("Partially Implemented", 0),
            "not_implemented": status_counts.get("Not Implemented", 0),
            "not_assessed": status_counts.get("Not Assessed", 0),
            "not_applicable": status_counts.get("Not Applicable", 0),
            "applicable": applicable,
            "assessed": assessed,
            "coverage_pct": coverage,
            "weighted_readiness_pct": readiness,
            "potential_gaps": gaps,
        }

    return summary


def calculate_overall_metrics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Calculate full aggregated metrics package for an assessment's control records.
    """
    status_counts = calculate_control_status_counts(records)
    applicable = calculate_applicable_controls_count(records)
    assessed = calculate_assessed_controls_count(records)
    pending = calculate_pending_controls_count(records)
    gaps = calculate_potential_gaps(records)
    coverage = calculate_assessment_coverage(records)
    readiness = calculate_weighted_readiness(records)
    category_summary = calculate_category_summary(records)

    return {
        "total_controls": len(records),
        "status_counts": status_counts,
        "applicable_controls": applicable,
        "assessed_controls": assessed,
        "pending_controls": pending,
        "potential_gaps": gaps,
        "coverage_pct": coverage,
        "weighted_readiness_pct": readiness,
        "category_summary": category_summary,
    }
