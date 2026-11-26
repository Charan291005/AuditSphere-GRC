"""
Automated unit and integration test suite for AuditSphere Phase 2:
ISO 27001 Selected-Control Assessment Engine.

Covers:
- Catalogue verification (exactly 20 unique controls, 4 themes)
- Correct category distribution (6 Org, 4 People, 4 Physical, 6 Tech)
- Idempotent catalogue synchronization
- Control assessment initialization for assessments
- Control assessment updates and persistence
- Cross-assessment data isolation
- Validation: invalid status rejection
- Validation: Not Applicable justification requirement
- Validation: Required observations and recommendations
- Archived assessment update protection
- Assessment coverage calculation
- Weighted readiness score calculation
- Edge case handling: zero assessed controls
- Edge case handling: zero applicable controls
- Potential gap count calculation
- Activity log capture for control changes
- Demonstration dataset generation (FinCore Technologies) and exact metric verification
- Persistence across database reconnection
"""

import json
import sqlite3
import pytest
from pathlib import Path

from database import (
    init_db,
    db_session,
    get_db_connection,
    CONTROLS_JSON_PATH,
    sync_controls_catalogue,
    initialize_assessment_controls,
)
from services.assessment_service import (
    create_assessment,
    archive_assessment,
    get_assessment,
)
from services.control_service import (
    get_assessment_controls,
    get_single_control_assessment,
    update_control_assessment,
    create_fincore_demo_assessment,
)
from services.assessment_engine import (
    calculate_control_status_counts,
    calculate_applicable_controls_count,
    calculate_assessed_controls_count,
    calculate_pending_controls_count,
    calculate_potential_gaps,
    calculate_assessment_coverage,
    calculate_weighted_readiness,
    calculate_category_summary,
    calculate_overall_metrics,
)
from services.activity_service import get_recent_activities


@pytest.fixture
def temp_db(tmp_path: Path) -> str:
    """Fixture to provide a clean temporary SQLite database with catalogue initialized."""
    db_file = tmp_path / "test_phase2_auditsphere.db"
    init_db(str(db_file))
    return str(db_file)


# 1. CATALOGUE SPECIFICATION TESTS


def test_catalogue_contains_exact_20_unique_controls():
    """Verify that data/controls.json contains exactly 20 unique Annex A controls."""
    assert CONTROLS_JSON_PATH.exists(), "controls.json catalogue file does not exist"
    with open(CONTROLS_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    controls = data.get("controls", [])
    assert len(controls) == 20, f"Expected exactly 20 controls, found {len(controls)}"

    identifiers = [c["control_identifier"] for c in controls]
    assert len(set(identifiers)) == 20, "Control identifiers must be unique"

    for c in controls:
        assert "control_id" in c
        assert "title" in c and len(c["title"]) > 0
        assert "category" in c
        assert "description" in c and len(c["description"]) > 0
        assert "objective" in c and len(c["objective"]) > 0
        assert "assessment_questions" in c and len(c["assessment_questions"]) > 0
        assert "suggested_evidence" in c and len(c["suggested_evidence"]) > 0
        assert "example_gaps" in c and len(c["example_gaps"]) > 0
        assert "example_recommendations" in c and len(c["example_recommendations"]) > 0


def test_catalogue_theme_distribution():
    """Verify the expected distribution: 6 Org, 4 People, 4 Physical, 6 Tech."""
    with open(CONTROLS_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    controls = data.get("controls", [])
    categories = [c["category"] for c in controls]

    assert categories.count("Organizational") == 6
    assert categories.count("People") == 4
    assert categories.count("Physical") == 4
    assert categories.count("Technological") == 6


def test_idempotent_catalogue_sync(temp_db: str):
    """Ensure running sync_controls_catalogue repeatedly produces exactly 20 controls."""
    with db_session(temp_db) as conn:
        sync_controls_catalogue(conn)
        sync_controls_catalogue(conn)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM controls")
        count = cursor.fetchone()[0]
        assert count == 20


# 2. ASSESSMENT CONTROL INITIALIZATION & PERSISTENCE


def test_control_assessment_initialization(temp_db: str):
    """When a new assessment is created, all 20 controls must initialize with 'Not Assessed'."""
    asm = create_assessment(
        title="Init Test",
        organization="Init Org",
        industry="Tech",
        scope="Cloud Enclave",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )

    controls = get_assessment_controls(asm["id"], db_path=temp_db)
    assert len(controls) == 20

    for c in controls:
        assert c["status"] == "Not Assessed"
        assert c["assessment_id"] == asm["id"]


def test_repeated_initialization_preserves_assessments(temp_db: str):
    """Verify repeated initialization calls never overwrite existing evaluations."""
    asm = create_assessment(
        title="Preserve Test",
        organization="Preserve Org",
        industry="Tech",
        scope="Cloud Enclave",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )

    controls = get_assessment_controls(asm["id"], db_path=temp_db)
    target_cid = controls[0]["control_id"]

    # Evaluate the first control
    update_control_assessment(
        assessment_id=asm["id"],
        control_id=target_cid,
        status="Implemented",
        control_owner="SecOps",
        assessment_observation="Custom evaluation note that must survive.",
        testing_notes="Sampled 10 records.",
        assessor_name="Auditor A",
        assessment_date="2026-06-02",
        db_path=temp_db,
    )

    # Re-run initialization
    with db_session(temp_db) as conn:
        initialize_assessment_controls(conn, asm["id"])

    # Verify evaluated control retains custom observations
    reloaded = get_single_control_assessment(asm["id"], target_cid, db_path=temp_db)
    assert reloaded is not None
    assert reloaded["status"] == "Implemented"
    assert reloaded["assessment_observation"] == "Custom evaluation note that must survive."
    assert reloaded["control_owner"] == "SecOps"


def test_control_assessment_updates_and_persistence(temp_db: str):
    """Test modifying and persisting a control assessment record."""
    asm = create_assessment(
        title="Update Test",
        organization="Update Corp",
        industry="Fintech",
        scope="Production",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )

    controls = get_assessment_controls(asm["id"], db_path=temp_db)
    cid = controls[0]["control_id"]

    updated = update_control_assessment(
        assessment_id=asm["id"],
        control_id=cid,
        status="Partially Implemented",
        control_owner="Jane Owner",
        assessment_observation="Observed partial gap in policy compliance.",
        testing_notes="Walkthrough of repository.",
        evidence_notes="EVD-001",
        recommendation="Automate review alerts.",
        assessor_name="Lead Auditor",
        assessment_date="2026-06-05",
        db_path=temp_db,
    )

    assert updated["status"] == "Partially Implemented"
    assert updated["control_owner"] == "Jane Owner"
    assert updated["recommendation"] == "Automate review alerts."
    assert updated["assessed_by"] == "Lead Auditor"


# 3. ASSESSMENT ISOLATION TESTS


def test_assessment_data_isolation(temp_db: str):
    """Verify that updating controls on Assessment A has zero impact on Assessment B."""
    asm1 = create_assessment(
        title="Assessment One",
        organization="Org One",
        industry="Tech",
        scope="Scope 1",
        lead_assessor="Auditor 1",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )
    asm2 = create_assessment(
        title="Assessment Two",
        organization="Org Two",
        industry="Finance",
        scope="Scope 2",
        lead_assessor="Auditor 2",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )

    ctrls1 = get_assessment_controls(asm1["id"], db_path=temp_db)
    ctrls2 = get_assessment_controls(asm2["id"], db_path=temp_db)

    cid = ctrls1[0]["control_id"]

    # Update on Assessment 1
    update_control_assessment(
        assessment_id=asm1["id"],
        control_id=cid,
        status="Implemented",
        control_owner="Owner 1",
        assessment_observation="Observation for Assessment 1.",
        assessor_name="Auditor 1",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )

    # Check Assessment 1
    a1_ctrl = get_single_control_assessment(asm1["id"], cid, db_path=temp_db)
    assert a1_ctrl["status"] == "Implemented"

    # Check Assessment 2 - must still be 'Not Assessed'
    a2_ctrl = get_single_control_assessment(asm2["id"], cid, db_path=temp_db)
    assert a2_ctrl["status"] == "Not Assessed"
    assert a2_ctrl["assessment_observation"] is None


# 4. VALIDATION & ARCHIVED PROTECTION TESTS


def test_invalid_status_rejection(temp_db: str):
    """Reject unrecognized status values."""
    asm = create_assessment(
        title="Status Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=temp_db)
    cid = ctrls[0]["control_id"]

    with pytest.raises(ValueError, match="Invalid implementation status"):
        update_control_assessment(
            assessment_id=asm["id"],
            control_id=cid,
            status="Fully Compliant",  # invalid
            assessment_observation="Observation",
            assessor_name="Auditor",
            assessment_date="2026-06-01",
            db_path=temp_db,
        )


def test_required_observation_and_recommendation_validation(temp_db: str):
    """Test validation rules for Implemented, Partially Implemented, and Not Implemented."""
    asm = create_assessment(
        title="Rule Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=temp_db)
    cid = ctrls[0]["control_id"]

    # 1. Implemented requires observation
    with pytest.raises(ValueError, match="require documented assessment observations"):
        update_control_assessment(
            assessment_id=asm["id"],
            control_id=cid,
            status="Implemented",
            assessment_observation="",  # empty
            assessor_name="Auditor",
            assessment_date="2026-06-01",
            db_path=temp_db,
        )

    # 2. Partially Implemented requires observation AND recommendation
    with pytest.raises(ValueError, match="require documented assessment observations"):
        update_control_assessment(
            assessment_id=asm["id"],
            control_id=cid,
            status="Partially Implemented",
            assessment_observation="",
            recommendation="Some rec",
            assessor_name="Auditor",
            assessment_date="2026-06-01",
            db_path=temp_db,
        )

    with pytest.raises(ValueError, match="require remediation recommendations"):
        update_control_assessment(
            assessment_id=asm["id"],
            control_id=cid,
            status="Partially Implemented",
            assessment_observation="Some obs",
            recommendation="",  # empty
            assessor_name="Auditor",
            assessment_date="2026-06-01",
            db_path=temp_db,
        )

    # 3. Not Implemented requires recommendation
    with pytest.raises(ValueError, match="require remediation recommendations"):
        update_control_assessment(
            assessment_id=asm["id"],
            control_id=cid,
            status="Not Implemented",
            assessment_observation="Some obs",
            recommendation="",  # empty
            assessor_name="Auditor",
            assessment_date="2026-06-01",
            db_path=temp_db,
        )


def test_not_applicable_justification_validation(temp_db: str):
    """Not Applicable requires a documented justification."""
    asm = create_assessment(
        title="NA Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=temp_db)
    cid = ctrls[0]["control_id"]

    # Without justification -> error
    with pytest.raises(ValueError, match="require a documented justification"):
        update_control_assessment(
            assessment_id=asm["id"],
            control_id=cid,
            status="Not Applicable",
            applicability_justification="",
            assessor_name="Auditor",
            assessment_date="2026-06-01",
            db_path=temp_db,
        )

    # With justification -> success
    updated = update_control_assessment(
        assessment_id=asm["id"],
        control_id=cid,
        status="Not Applicable",
        applicability_justification="Organization does not own or operate physical data centers.",
        assessor_name="Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )
    assert updated["status"] == "Not Applicable"


def test_archived_assessment_protection(temp_db: str):
    """Prevent modifying controls belonging to an archived assessment."""
    asm = create_assessment(
        title="Archived Guard Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=temp_db)
    cid = ctrls[0]["control_id"]

    # Archive assessment
    archive_assessment(asm["id"], db_path=temp_db)

    with pytest.raises(PermissionError, match="is Archived and cannot be modified"):
        update_control_assessment(
            assessment_id=asm["id"],
            control_id=cid,
            status="Implemented",
            assessment_observation="Observation",
            assessor_name="Auditor",
            assessment_date="2026-06-01",
            db_path=temp_db,
        )


# 5. ASSESSMENT SCORING ENGINE PURE FUNCTION TESTS


def test_assessment_coverage_calculation():
    """Verify coverage = assessed_applicable / applicable * 100."""
    # 20 controls: 10 Implemented, 5 Not Assessed, 5 Not Applicable
    records = (
        [{"status": "Implemented"}] * 10
        + [{"status": "Not Assessed"}] * 5
        + [{"status": "Not Applicable"}] * 5
    )
    # Total applicable = 20 - 5 = 15
    # Assessed = 10
    # Coverage = 10 / 15 * 100 = 66.67%
    cov = calculate_assessment_coverage(records)
    assert cov == 66.67


def test_weighted_readiness_calculation():
    """
    Verify readiness = (Implemented + 0.5 * Partial) / assessed_applicable * 100.
    Not Implemented contributes 0.
    """
    # 4 Implemented, 2 Partial, 2 Not Implemented, 2 Not Assessed, 2 Not Applicable
    records = (
        [{"status": "Implemented"}] * 4
        + [{"status": "Partially Implemented"}] * 2
        + [{"status": "Not Implemented"}] * 2
        + [{"status": "Not Assessed"}] * 2
        + [{"status": "Not Applicable"}] * 2
    )
    # Assessed = 4 + 2 + 2 = 8
    # Points = 4 + 0.5 * 2 = 5.0
    # Readiness = 5.0 / 8 * 100 = 62.5%
    readiness = calculate_weighted_readiness(records)
    assert readiness == 62.5


def test_zero_assessed_controls_handling():
    """When zero controls are assessed, readiness must return None (N/A). Never misleading 100%."""
    records = [{"status": "Not Assessed"}] * 20
    assert calculate_assessed_controls_count(records) == 0
    assert calculate_assessment_coverage(records) == 0.0
    assert calculate_weighted_readiness(records) is None


def test_zero_applicable_controls_handling():
    """When all controls are Not Applicable, coverage and readiness return None."""
    records = [{"status": "Not Applicable"}] * 20
    assert calculate_applicable_controls_count(records) == 0
    assert calculate_assessment_coverage(records) is None
    assert calculate_weighted_readiness(records) is None


def test_potential_gaps_calculation():
    """Potential gaps = Partial + Not Implemented."""
    records = (
        [{"status": "Implemented"}] * 5
        + [{"status": "Partially Implemented"}] * 3
        + [{"status": "Not Implemented"}] * 2
    )
    assert calculate_potential_gaps(records) == 5


# 6. ACTIVITY LOGGING & DEMONSTRATION TESTS


def test_activity_logging_on_control_updates(temp_db: str):
    """Verify that updating a control logs structured events."""
    asm = create_assessment(
        title="Activity Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=temp_db)
    cid = ctrls[0]["control_id"]

    update_control_assessment(
        assessment_id=asm["id"],
        control_id=cid,
        status="Implemented",
        assessment_observation="Satisfied",
        assessor_name="Auditor A",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )

    activities = get_recent_activities(assessment_id=asm["id"], db_path=temp_db)
    event_types = [a["event_type"] for a in activities]
    assert "CONTROL_STATUS_CHANGED" in event_types


def test_fincore_demo_creation_and_exact_metrics(temp_db: str):
    """
    Verify the official FinCore demonstration dataset generates the exact required metrics:
    - Total: 20
    - Assessed: 12
    - Implemented: 7
    - Partially Implemented: 3
    - Not Implemented: 2
    - Not Assessed: 8
    - Not Applicable: 0
    - Coverage: 60.0%
    - Weighted Readiness: 70.83%
    - Potential Gaps: 5
    - Pending: 8
    """
    demo_result = create_fincore_demo_assessment(db_path=temp_db)
    metrics = demo_result["metrics"]

    assert metrics["total_controls"] == 20
    assert metrics["assessed_controls"] == 12
    assert metrics["status_counts"]["Implemented"] == 7
    assert metrics["status_counts"]["Partially Implemented"] == 3
    assert metrics["status_counts"]["Not Implemented"] == 2
    assert metrics["status_counts"]["Not Assessed"] == 8
    assert metrics["status_counts"]["Not Applicable"] == 0
    assert metrics["coverage_pct"] == 60.0
    assert metrics["weighted_readiness_pct"] == 70.83
    assert metrics["potential_gaps"] == 5
    assert metrics["pending_controls"] == 8

    # Repeat-safe execution: calling again should not create duplicate assessments
    demo_result2 = create_fincore_demo_assessment(db_path=temp_db)
    assert demo_result2["assessment"]["id"] == demo_result["assessment"]["id"]


def test_persistence_after_database_reconnection(temp_db: str):
    """Verify data persists after completely closing and reopening SQLite connection."""
    asm = create_assessment(
        title="Reconnect Test",
        organization="Reconnect Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=temp_db)
    cid = ctrls[0]["control_id"]

    update_control_assessment(
        assessment_id=asm["id"],
        control_id=cid,
        status="Implemented",
        assessment_observation="Persisted observation test across reboots.",
        assessor_name="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=temp_db,
    )

    # New fresh connection
    conn = get_db_connection(temp_db)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT status, assessment_observation FROM control_assessments WHERE assessment_id = ? AND control_id = ?",
        (asm["id"], cid),
    )
    row = cursor.fetchone()
    conn.close()

    assert row["status"] == "Implemented"
    assert row["assessment_observation"] == "Persisted observation test across reboots."
