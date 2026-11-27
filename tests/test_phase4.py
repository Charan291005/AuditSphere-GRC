"""
Phase 4 Automated Test Suite for AuditSphere-GRC.

Covers:
1. Risk Scoring Engine & Threshold Calculations (Score = L × I, Severity classification, unassessed handling)
2. Validation Rules (Likelihood/impact 1-5, mandatory title, threshold boundaries)
3. Three-Tier Evaluation Model (Inherent, Current Residual, Target Residual)
4. Treatment Strategy & Acceptance Governance (Approval validation, justification)
5. Status Transitions & Closure Verification (Mandatory closure rationale)
6. Many-to-Many Mappings (Findings, Controls, Evidence) & Cross-Assessment Isolation
7. Reassessment History Tracking
8. Heatmap Aggregation & Overdue Review Calculations
9. CSV Export & Formula Injection (CWE-1236) Protection
10. Repeat-Safe FinCore Demonstration Dataset Verification
"""

import os
import shutil
import sqlite3
import tempfile
import pytest
from pathlib import Path

from database import init_db, db_session
from services.assessment_service import create_assessment, archive_assessment
from services.control_service import (
    get_assessment_controls,
    create_fincore_demo_assessment,
)
from services.gap_engine import create_finding
from services.evidence_manager import upload_evidence
from services.risk_engine import (
    calculate_risk_score,
    classify_risk_score,
    validate_score_dimension,
    validate_custom_thresholds,
    evaluate_risk_record,
    compare_risk_evaluations,
    is_review_overdue,
    calculate_risk_register_metrics,
    aggregate_risk_heatmap_data,
    sanitize_csv_cell,
    export_risks_to_csv,
    DEFAULT_RISK_THRESHOLDS,
)
from services.risk_service import (
    create_risk,
    update_risk,
    archive_risk,
    get_single_risk,
    get_assessment_risks,
    link_finding_to_risk,
    unlink_finding_from_risk,
    link_control_to_risk,
    unlink_control_from_risk,
    link_evidence_to_risk,
    unlink_evidence_from_risk,
)
from services.activity_service import get_recent_activities


@pytest.fixture
def temp_env():
    """Create a temporary database and temporary storage directory."""
    temp_dir = tempfile.mkdtemp()
    db_file = os.path.join(temp_dir, "test_auditsphere_p4.db")
    storage_path = Path(temp_dir) / "evidence_storage"
    storage_path.mkdir(parents=True, exist_ok=True)

    init_db(db_path=db_file)

    yield {"db_path": db_file, "storage_dir": storage_path, "root_dir": temp_dir}

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


# =========================================================================
# 1. RISK SCORING ENGINE & THRESHOLD VALIDATION
# =========================================================================


def test_score_dimension_validation():
    """Verify that likelihood and impact must be integer values between 1 and 5, or None."""
    assert validate_score_dimension(1) == 1
    assert validate_score_dimension(5) == 5
    assert validate_score_dimension("3") == 3
    assert validate_score_dimension(None) is None
    assert validate_score_dimension("") is None

    with pytest.raises(ValueError, match="must be between 1 and 5"):
        validate_score_dimension(0)

    with pytest.raises(ValueError, match="must be between 1 and 5"):
        validate_score_dimension(6)

    with pytest.raises(ValueError, match="must be an integer"):
        validate_score_dimension("invalid")


def test_risk_score_calculation():
    """
    Verify Risk Score = Likelihood × Impact (1 to 25).
    Unassessed inputs must return None, never a misleading zero.
    """
    assert calculate_risk_score(1, 1) == 1
    assert calculate_risk_score(5, 5) == 25
    assert calculate_risk_score(3, 4) == 12
    assert calculate_risk_score(None, 4) is None
    assert calculate_risk_score(4, None) is None
    assert calculate_risk_score(None, None) is None


def test_risk_severity_classification_boundaries():
    """
    Verify exact project-defined threshold boundaries:
    - Low: 1 to 5
    - Medium: 6 to 11
    - High: 12 to 19
    - Critical: 20 to 25
    - None / Unassessed: 'Not Assessed'
    """
    assert classify_risk_score(None) == "Not Assessed"
    assert classify_risk_score(1) == "Low"
    assert classify_risk_score(5) == "Low"
    assert classify_risk_score(6) == "Medium"
    assert classify_risk_score(11) == "Medium"
    assert classify_risk_score(12) == "High"
    assert classify_risk_score(19) == "High"
    assert classify_risk_score(20) == "Critical"
    assert classify_risk_score(25) == "Critical"


def test_custom_threshold_validation():
    """Verify validation of complete, non-overlapping, ordered custom thresholds."""
    valid_custom = {
        "Low": (1, 4),
        "Medium": (5, 10),
        "High": (11, 18),
        "Critical": (19, 25),
    }
    assert validate_custom_thresholds(valid_custom) is True

    # Gap in threshold range
    invalid_gap = {
        "Low": (1, 5),
        "Medium": (7, 11),  # gap at 6
        "High": (12, 19),
        "Critical": (20, 25),
    }
    with pytest.raises(ValueError, match="Medium threshold must begin at 6"):
        validate_custom_thresholds(invalid_gap)


# =========================================================================
# 2. RISK CREATION, EDITING & VALIDATION RULES
# =========================================================================


def test_risk_creation_and_retrieval(temp_env):
    """Verify creating a risk record with 3-tier scores and retrieving full details."""
    db_path = temp_env["db_path"]

    asm = create_assessment(
        title="Risk Test ISMS",
        organization="Apex Technologies",
        industry="Technology",
        scope="Cloud Enclave",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )

    risk = create_risk(
        assessment_id=asm["id"],
        title="Unauthenticated API Endpoints",
        description="Public API endpoints in customer portal lack token validation.",
        asset_or_process="Customer Portal API",
        threat="External automated bot attacks",
        vulnerability="Missing authentication middleware on v1 routes",
        consequence="Unauthorized data leakage and compute resource exhaustion",
        risk_category="Application Security",
        existing_controls="Rate limiting via WAF",
        risk_owner="Head of Engineering",
        responsible_department="Product Engineering",
        # Inherent: 4 x 5 = 20 (Critical)
        inherent_likelihood=4,
        inherent_impact=5,
        inherent_rationale="Publicly reachable without credentials.",
        # Residual: 2 x 4 = 8 (Medium)
        residual_likelihood=2,
        residual_impact=4,
        residual_rationale="WAF rate limits mitigate automated scanning, but endpoint is still accessible.",
        # Target: 1 x 4 = 4 (Low)
        target_likelihood=1,
        target_impact=4,
        target_rationale="JWT middleware deployment will block all unauthenticated requests.",
        treatment_strategy="Mitigate",
        proposed_treatment="Implement OAuth2/JWT middleware validation across all routes.",
        treatment_owner="API Team Lead",
        target_treatment_date="2026-07-31",
        status="Open",
        review_date="2026-09-30",
        db_path=db_path,
    )

    assert risk["id"] is not None
    assert risk["risk_identifier"] == "RSK-001"
    assert risk["title"] == "Unauthenticated API Endpoints"
    assert risk["inherent_risk_score"] == 20
    assert risk["inherent_risk_level"] == "Critical"
    assert risk["residual_risk_score"] == 8
    assert risk["residual_risk_level"] == "Medium"
    assert risk["target_risk_score"] == 4
    assert risk["target_risk_level"] == "Low"
    assert risk["status"] == "Open"


def test_mandatory_title_validation(temp_env):
    """Risk creation must reject blank titles."""
    db_path = temp_env["db_path"]
    asm = create_assessment(
        title="Validation Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )

    with pytest.raises(ValueError, match="Risk title is required"):
        create_risk(assessment_id=asm["id"], title="", db_path=db_path)


def test_archived_assessment_blocks_risk_mutation(temp_env):
    """Archived assessments must strictly reject risk creation and updates."""
    db_path = temp_env["db_path"]
    asm = create_assessment(
        title="Archived Risk Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    r = create_risk(assessment_id=asm["id"], title="Initial Risk", db_path=db_path)

    # Archive assessment
    archive_assessment(asm["id"], db_path=db_path)

    with pytest.raises(PermissionError, match="is Archived"):
        create_risk(assessment_id=asm["id"], title="New Risk", db_path=db_path)

    with pytest.raises(PermissionError, match="is Archived"):
        update_risk(risk_id=r["id"], title="Updated Title", db_path=db_path)


# =========================================================================
# 3. ACCEPTANCE & CLOSURE GOVERNANCE
# =========================================================================


def test_risk_acceptance_governance_rules(temp_env):
    """
    Transition to 'Accepted' requires:
    - approval_status == 'Approved'
    - documented acceptance justification
    """
    db_path = temp_env["db_path"]
    asm = create_assessment(
        title="Acceptance Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    r = create_risk(assessment_id=asm["id"], title="Acceptance Target", db_path=db_path)

    # Attempt Accepted status without approval decision
    with pytest.raises(ValueError, match="recorded 'Approved' decision"):
        update_risk(
            risk_id=r["id"],
            title=r["title"],
            status="Accepted",
            approval_status="Not Requested",
            acceptance_justification="Low impact",
            db_path=db_path,
        )

    # Attempt Accepted status without justification
    with pytest.raises(ValueError, match="acceptance justification is required"):
        update_risk(
            risk_id=r["id"],
            title=r["title"],
            status="Accepted",
            approval_status="Approved",
            acceptance_justification="",
            db_path=db_path,
        )

    # Successful acceptance
    acc_risk = update_risk(
        risk_id=r["id"],
        title=r["title"],
        status="Accepted",
        approval_status="Approved",
        approving_authority="Risk Committee",
        approval_date="2026-06-01",
        acceptance_justification="Commercial cost of mitigation exceeds potential loss.",
        review_date="2026-12-01",
        db_path=db_path,
    )
    assert acc_risk["status"] == "Accepted"
    assert acc_risk["approval_status"] == "Approved"


def test_risk_closure_governance_rules(temp_env):
    """Closing a risk strictly requires documented closure rationale."""
    db_path = temp_env["db_path"]
    asm = create_assessment(
        title="Closure Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    r = create_risk(assessment_id=asm["id"], title="To Close", db_path=db_path)

    # Attempt closure without rationale
    with pytest.raises(ValueError, match="strictly requires a documented closure rationale"):
        update_risk(
            risk_id=r["id"],
            title=r["title"],
            status="Closed",
            closure_rationale="",
            db_path=db_path,
        )

    # Successful closure
    closed_risk = update_risk(
        risk_id=r["id"],
        title=r["title"],
        status="Closed",
        closure_rationale="Legacy server decommissioned and retired from asset inventory.",
        db_path=db_path,
    )
    assert closed_risk["status"] == "Closed"
    assert closed_risk["closure_rationale"] is not None


# =========================================================================
# 4. REASSESSMENT HISTORY TRACKING
# =========================================================================


def test_reassessment_history_recording(temp_env):
    """When residual likelihood or impact changes, record previous score in risk_reviews."""
    db_path = temp_env["db_path"]
    asm = create_assessment(
        title="History Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )

    r = create_risk(
        assessment_id=asm["id"],
        title="Reassessment Test",
        residual_likelihood=4,
        residual_impact=4,  # Score: 16 (High)
        db_path=db_path,
    )
    assert r["residual_risk_score"] == 16

    # Reassess risk to residual 2 x 3 = 6 (Medium)
    updated = update_risk(
        risk_id=r["id"],
        title=r["title"],
        residual_likelihood=2,
        residual_impact=3,
        reassessment_reason="Deployment of centralized patch management reduced residual likelihood.",
        assessor_name="Auditor Marcus",
        db_path=db_path,
    )

    assert updated["residual_risk_score"] == 6
    assert updated["residual_risk_level"] == "Medium"
    assert len(updated["review_history"]) == 1

    entry = updated["review_history"][0]
    assert entry["previous_score"] == 16
    assert entry["previous_level"] == "High"
    assert entry["new_score"] == 6
    assert entry["new_level"] == "Medium"
    assert "patch management" in entry["reason_for_change"]


# =========================================================================
# 5. MANY-TO-MANY LINKAGES & CROSS-ASSESSMENT ISOLATION
# =========================================================================


def test_finding_to_risk_mapping_and_triggers(temp_env):
    """Verify many-to-many finding mappings and cross-assessment trigger rejection."""
    db_path = temp_env["db_path"]

    # Assessment 1
    a1 = create_assessment(
        title="Assessment 1",
        organization="Org 1",
        industry="Tech",
        scope="Scope 1",
        lead_assessor="Auditor 1",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    ctrls1 = get_assessment_controls(a1["id"], db_path=db_path)
    ca1 = ctrls1[0]["assessment_control_id"]

    f1 = create_finding(
        assessment_id=a1["id"],
        control_assessment_id=ca1,
        title="Finding 1",
        criteria="ISO 27001",
        condition="Condition",
        effect="Effect",
        recommendation="Recommendation",
        supporting_evidence_references="None",
        evidence_limitations="Documented limitation",
        db_path=db_path,
    )
    f2 = create_finding(
        assessment_id=a1["id"],
        control_assessment_id=ca1,
        title="Finding 2",
        criteria="ISO 27001",
        condition="Condition 2",
        effect="Effect 2",
        recommendation="Recommendation 2",
        supporting_evidence_references="None",
        evidence_limitations="Documented limitation",
        db_path=db_path,
    )

    r1 = create_risk(assessment_id=a1["id"], title="Risk 1", db_path=db_path)
    r2 = create_risk(assessment_id=a1["id"], title="Risk 2", db_path=db_path)

    # 1. Multiple findings linked to one risk
    link_finding_to_risk(r1["id"], f1["id"], db_path=db_path)
    link_finding_to_risk(r1["id"], f2["id"], db_path=db_path)

    r1_full = get_single_risk(r1["id"], db_path=db_path)
    assert len(r1_full["linked_findings"]) == 2

    # 2. One finding linked to multiple risks
    link_finding_to_risk(r2["id"], f1["id"], db_path=db_path)
    r2_full = get_single_risk(r2["id"], db_path=db_path)
    assert len(r2_full["linked_findings"]) == 1

    # 3. Cross-assessment linkage attempt
    a2 = create_assessment(
        title="Assessment 2",
        organization="Org 2",
        industry="Finance",
        scope="Scope 2",
        lead_assessor="Auditor 2",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    r_a2 = create_risk(assessment_id=a2["id"], title="Risk in A2", db_path=db_path)

    with pytest.raises(ValueError, match="Cross-assessment violation"):
        link_finding_to_risk(r_a2["id"], f1["id"], db_path=db_path)

    # Direct database trigger check
    with pytest.raises(sqlite3.IntegrityError, match="Cross-assessment violation"):
        with db_session(db_path) as conn:
            conn.execute(
                "INSERT INTO risk_findings (assessment_id, risk_id, finding_id, created_at) VALUES (?, ?, ?, ?)",
                (a2["id"], r_a2["id"], f1["id"], "2026-06-01T00:00:00Z"),
            )


def test_control_and_evidence_mappings_to_risk(temp_env):
    """Verify linking controls and evidence artifacts to risk records."""
    db_path = temp_env["db_path"]
    storage_dir = temp_env["storage_dir"]

    asm = create_assessment(
        title="Linkage Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=db_path)
    ca_id = ctrls[0]["assessment_control_id"]

    ev = upload_evidence(
        assessment_id=asm["id"],
        title="Supporting Policy",
        file_name="policy.txt",
        file_bytes=b"Policy text content",
        storage_dir=storage_dir,
        db_path=db_path,
    )

    r = create_risk(assessment_id=asm["id"], title="Linked Entities Risk", db_path=db_path)

    # Link control & evidence
    link_control_to_risk(r["id"], ca_id, db_path=db_path)
    link_evidence_to_risk(r["id"], ev["id"], db_path=db_path)

    r_detail = get_single_risk(r["id"], db_path=db_path)
    assert len(r_detail["linked_controls"]) == 1
    assert r_detail["linked_controls"][0]["control_assessment_id"] == ca_id
    assert len(r_detail["linked_evidence"]) == 1
    assert r_detail["linked_evidence"][0]["id"] == ev["id"]

    # Unlink
    unlink_control_from_risk(r["id"], ca_id, db_path=db_path)
    unlink_evidence_from_risk(r["id"], ev["id"], db_path=db_path)

    r_after = get_single_risk(r["id"], db_path=db_path)
    assert len(r_after["linked_controls"]) == 0
    assert len(r_after["linked_evidence"]) == 0


# =========================================================================
# 6. HEATMAP AGGREGATION & OVERDUE REVIEWS
# =========================================================================


def test_heatmap_aggregation_and_unassessed_separation(temp_env):
    """Verify 5x5 heatmap cell placement and separate counting of unassessed risks."""
    db_path = temp_env["db_path"]
    asm = create_assessment(
        title="Heatmap Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )

    # 1. Risk at L=5, I=5 (Critical)
    create_risk(assessment_id=asm["id"], title="R1", residual_likelihood=5, residual_impact=5, db_path=db_path)
    # 2. Risk at L=5, I=5 (Critical)
    create_risk(assessment_id=asm["id"], title="R2", residual_likelihood=5, residual_impact=5, db_path=db_path)
    # 3. Risk at L=1, I=2 (Low)
    create_risk(assessment_id=asm["id"], title="R3", residual_likelihood=1, residual_impact=2, db_path=db_path)
    # 4. Unassessed risk
    create_risk(assessment_id=asm["id"], title="R4_Unassessed", residual_likelihood=None, residual_impact=None, db_path=db_path)

    all_r = get_assessment_risks(asm["id"], db_path=db_path)
    hm_data = aggregate_risk_heatmap_data(all_r, evaluation_type="current_residual")

    assert hm_data["total_assessed"] == 3
    assert hm_data["unassessed_count"] == 1

    # Check cell (L=5, I=5)
    cell_55 = next(c for c in hm_data["cells"] if c["likelihood"] == 5 and c["impact"] == 5)
    assert cell_55["count"] == 2
    assert cell_55["score"] == 25
    assert cell_55["severity"] == "Critical"

    # Check cell (L=1, I=2)
    cell_12 = next(c for c in hm_data["cells"] if c["likelihood"] == 1 and c["impact"] == 2)
    assert cell_12["count"] == 1
    assert cell_12["score"] == 2
    assert cell_12["severity"] == "Low"


def test_overdue_review_calculations():
    """Verify overdue review date detection."""
    assert is_review_overdue("2020-01-01", as_of_date="2026-06-01") is True
    assert is_review_overdue("2026-12-31", as_of_date="2026-06-01") is False
    assert is_review_overdue(None) is False
    assert is_review_overdue("") is False


# =========================================================================
# 7. CSV EXPORT & FORMULA INJECTION DEFENSE (CWE-1236)
# =========================================================================


def test_csv_formula_injection_defense():
    """Verify that cell strings beginning with =, +, -, @, tab, or carriage return are sanitized."""
    assert sanitize_csv_cell("=cmd|'/C calc'!A0") == "'=cmd|'/C calc'!A0"
    assert sanitize_csv_cell("+12345") == "'+12345"
    assert sanitize_csv_cell("-10+20") == "'-10+20"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("Normal Text") == "Normal Text"
    assert sanitize_csv_cell(None) == ""


def test_export_risks_to_csv(temp_env):
    """Verify generating RFC 4180 CSV export of risk register records."""
    db_path = temp_env["db_path"]
    asm = create_assessment(
        title="CSV Test",
        organization="FinCore Corp",
        industry="Tech",
        scope="Scope",
        lead_assessor="Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    create_risk(
        assessment_id=asm["id"],
        title="=HYPERLINK('http://malicious.com','Click Me')",
        risk_category="Data Protection",
        residual_likelihood=3,
        residual_impact=4,
        db_path=db_path,
    )

    risks = get_assessment_risks(asm["id"], db_path=db_path)
    csv_output = export_risks_to_csv(risks)

    assert "Risk Reference" in csv_output
    assert "Risk Title" in csv_output
    # Must contain sanitized single quote for formula injection protection
    assert "'=HYPERLINK" in csv_output


# =========================================================================
# 8. ACTIVITY LOGGING
# =========================================================================


def test_risk_activity_logging(temp_env):
    """Verify activity log events are generated for risk lifecycle milestones."""
    db_path = temp_env["db_path"]
    asm = create_assessment(
        title="Log Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )

    r = create_risk(assessment_id=asm["id"], title="Logged Risk", db_path=db_path)
    archive_risk(r["id"], db_path=db_path)

    activities = get_recent_activities(assessment_id=asm["id"], db_path=db_path)
    events = [a["event_type"] for a in activities]

    assert "RISK_CREATED" in events
    assert "RISK_ARCHIVED" in events


# =========================================================================
# 9. FINCORE DEMONSTRATION PHASE 4 DATASET
# =========================================================================


def test_fincore_demo_phase4_expansion(temp_env):
    """
    Verify FinCore demonstration assessment creates exact required Phase 4 risks:
    - Exactly 5 risks
    - Expected current residual distribution:
      - Critical: 1 (Risk 1: 4x5=20)
      - High: 2 (Risk 2: 3x5=15, Risk 3: 3x4=12)
      - Medium: 1 (Risk 4: 2x4=8)
      - Low: 1 (Risk 5: 2x2=4, Approved Acceptance)
    - Repeat-safe / idempotent.
    """
    db_path = temp_env["db_path"]

    demo1 = create_fincore_demo_assessment(db_path=db_path)
    asm_id = demo1["assessment"]["id"]

    risks = get_assessment_risks(asm_id, db_path=db_path)
    assert len(risks) == 5

    metrics = calculate_risk_register_metrics(risks)
    assert metrics["total_risks"] == 5
    assert metrics["critical_risks"] == 1
    assert metrics["high_risks"] == 2
    assert metrics["medium_risks"] == 1
    assert metrics["low_risks"] == 1
    assert metrics["accepted_risks"] == 1

    # Verify Risk 1 (A.8.5)
    r1 = next(r for r in risks if "A.8.5" in [c["control_identifier"] for c in r.get("linked_controls", [])])
    assert r1["inherent_risk_score"] == 25
    assert r1["residual_risk_score"] == 20
    assert r1["residual_risk_level"] == "Critical"
    assert r1["target_risk_score"] == 5
    assert r1["treatment_strategy"] == "Mitigate"

    # Verify Risk 5 (A.6.3 - Accepted)
    r5 = next(r for r in risks if "A.6.3" in [c["control_identifier"] for c in r.get("linked_controls", [])])
    assert r5["residual_risk_score"] == 4
    assert r5["residual_risk_level"] == "Low"
    assert r5["status"] == "Accepted"
    assert r5["approval_status"] == "Approved"
    assert r5["approving_authority"] == "FinCore Information Security Risk Committee"

    # Verify repeat-safety: calling create_fincore_demo_assessment again does not duplicate records
    demo2 = create_fincore_demo_assessment(db_path=db_path)
    assert demo2["assessment"]["id"] == asm_id
    risks_after = get_assessment_risks(asm_id, db_path=db_path)
    assert len(risks_after) == 5
