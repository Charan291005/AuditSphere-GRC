"""
Automated unit and integration test suite for AuditSphere Phase 1.

Covers:
- Database initialization & schema verification
- Idempotent re-initialization (zero data loss)
- Assessment creation with full parameterization
- Required field and business rule validation
- Assessment editing and lifecycle transitions
- Assessment archival
- Status filtering and search queries
- Foreign key enforcement
- Cross-assessment relational isolation triggers (evidence, findings, risks, remediation)
- Activity log event capture and limits
- Dashboard metric computations
"""

import sqlite3
import pytest
from pathlib import Path

from database import init_db, db_session, get_db_connection
from services.assessment_service import (
    create_assessment,
    update_assessment,
    archive_assessment,
    get_assessment,
    list_assessments,
)
from services.activity_service import get_recent_activities, log_activity
from services.dashboard_service import get_dashboard_summary


@pytest.fixture
def temp_db_path(tmp_path: Path) -> str:
    """Fixture to provide a clean temporary SQLite database path."""
    db_file = tmp_path / "test_auditsphere.db"
    init_db(str(db_file))
    return str(db_file)


def test_database_initialization(temp_db_path: str):
    """Verify that all core tables, indices, and pragmas are created properly."""
    with db_session(temp_db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row[0] for row in cursor.fetchall()}

        expected_tables = {
            "assessments",
            "controls",
            "control_assessments",
            "evidence",
            "control_evidence",
            "findings",
            "risks",
            "remediation",
            "activity_log",
        }
        for table in expected_tables:
            assert table in tables, f"Expected table '{table}' was not created."

        # Verify foreign keys are enabled
        cursor.execute("PRAGMA foreign_keys;")
        assert cursor.fetchone()[0] == 1


def test_repeated_initialization_no_data_loss(temp_db_path: str):
    """Ensure that calling init_db repeatedly does not wipe existing records."""
    created = create_assessment(
        title="Persistent Assessment",
        organization="Fintech Global",
        industry="Financial Services",
        scope="Production Cloud VPC",
        lead_assessor="Alice Assessor",
        assessment_date="2026-03-01",
        status="In Progress",
        db_path=temp_db_path,
    )
    assert created["id"] is not None

    # Re-run initialization multiple times
    init_db(temp_db_path)
    init_db(temp_db_path)

    # Verify data persists untouched
    reloaded = get_assessment(created["id"], db_path=temp_db_path)
    assert reloaded is not None
    assert reloaded["title"] == "Persistent Assessment"
    assert reloaded["organization"] == "Fintech Global"


def test_assessment_creation_and_retrieval(temp_db_path: str):
    """Test full creation workflow with all attributes and persistence."""
    assessment = create_assessment(
        title="Core Banking ISMS Review",
        organization="Acme Payments",
        industry="Fintech",
        scope="AWS Infrastructure and Core Payments Gateway",
        objectives="Validate Annex A control posture against ISO 27001:2022",
        lead_assessor="John Doe, CISA",
        assessment_date="2026-04-15",
        status="Draft",
        db_path=temp_db_path,
    )

    assert assessment["id"] > 0
    assert assessment["title"] == "Core Banking ISMS Review"
    assert assessment["organization"] == "Acme Payments"
    assert assessment["industry"] == "Fintech"
    assert assessment["scope"] == "AWS Infrastructure and Core Payments Gateway"
    assert assessment["lead_assessor"] == "John Doe, CISA"
    assert assessment["assessment_date"] == "2026-04-15"
    assert assessment["status"] == "Draft"
    assert assessment["standard"] == "ISO/IEC 27001:2022"
    assert assessment["created_at"] is not None
    assert assessment["updated_at"] is not None

    # Verify retrieval
    fetched = get_assessment(assessment["id"], db_path=temp_db_path)
    assert fetched == assessment


def test_assessment_validation_rules(temp_db_path: str):
    """Verify input validation rejects empty mandatory fields and invalid values."""
    # Blank title
    with pytest.raises(ValueError, match="title is required"):
        create_assessment(
            title="",
            organization="Org",
            industry="Tech",
            scope="Scope",
            lead_assessor="Assessor",
            assessment_date="2026-01-01",
            db_path=temp_db_path,
        )

    # Blank organization
    with pytest.raises(ValueError, match="Organization name is required"):
        create_assessment(
            title="Title",
            organization="   ",
            industry="Tech",
            scope="Scope",
            lead_assessor="Assessor",
            assessment_date="2026-01-01",
            db_path=temp_db_path,
        )

    # Blank industry
    with pytest.raises(ValueError, match="Industry is required"):
        create_assessment(
            title="Title",
            organization="Org",
            industry="   ",
            scope="Scope",
            lead_assessor="Assessor",
            assessment_date="2026-01-01",
            db_path=temp_db_path,
        )

    # Blank scope
    with pytest.raises(ValueError, match="scope is required"):
        create_assessment(
            title="Title",
            organization="Org",
            industry="Tech",
            scope="   ",
            lead_assessor="Assessor",
            assessment_date="2026-01-01",
            db_path=temp_db_path,
        )

    # Blank lead assessor
    with pytest.raises(ValueError, match="Lead assessor name is required"):
        create_assessment(
            title="Title",
            organization="Org",
            industry="Tech",
            scope="Scope",
            lead_assessor="   ",
            assessment_date="2026-01-01",
            db_path=temp_db_path,
        )

    # Invalid date format
    with pytest.raises(ValueError, match="YYYY-MM-DD format"):
        create_assessment(
            title="Title",
            organization="Org",
            industry="Tech",
            scope="Scope",
            lead_assessor="Assessor",
            assessment_date="15-04-2026",
            db_path=temp_db_path,
        )

    # Invalid status
    with pytest.raises(ValueError, match="Invalid status"):
        create_assessment(
            title="Title",
            organization="Org",
            industry="Tech",
            scope="Scope",
            lead_assessor="Assessor",
            assessment_date="2026-04-15",
            status="NonExistentStatus",
            db_path=temp_db_path,
        )


def test_assessment_editing(temp_db_path: str):
    """Test modifying assessment attributes and verifying activity log."""
    created = create_assessment(
        title="Initial Title",
        organization="HealthTech Inc",
        industry="Healthcare",
        scope="HIPAA/ISO Cloud Enclave",
        lead_assessor="Jane Assessor",
        assessment_date="2026-05-01",
        status="Draft",
        db_path=temp_db_path,
    )

    updated = update_assessment(
        assessment_id=created["id"],
        title="Updated Title",
        organization="HealthTech Solutions Inc",
        industry="Digital Health",
        scope="Expanded Multi-Cloud Scope",
        lead_assessor="Jane Assessor, CISSP",
        assessment_date="2026-05-10",
        status="In Progress",
        objectives="Updated annual compliance audit",
        db_path=temp_db_path,
    )

    assert updated["title"] == "Updated Title"
    assert updated["organization"] == "HealthTech Solutions Inc"
    assert updated["industry"] == "Digital Health"
    assert updated["scope"] == "Expanded Multi-Cloud Scope"
    assert updated["status"] == "In Progress"
    assert updated["updated_at"] >= created["updated_at"]

    # Test editing non-existent assessment
    with pytest.raises(ValueError, match="does not exist"):
        update_assessment(
            assessment_id=99999,
            title="Title",
            organization="Org",
            industry="Tech",
            scope="Scope",
            lead_assessor="Assessor",
            assessment_date="2026-05-10",
            status="In Progress",
            db_path=temp_db_path,
        )


def test_assessment_archival(temp_db_path: str):
    """Test archival lifecycle transition."""
    created = create_assessment(
        title="Legacy Audit",
        organization="Retail Corp",
        industry="Retail",
        scope="POS Terminals",
        lead_assessor="Mark Assessor",
        assessment_date="2025-12-01",
        status="Completed",
        db_path=temp_db_path,
    )

    archived = archive_assessment(created["id"], db_path=temp_db_path)
    assert archived["status"] == "Archived"

    # Archiving again is idempotent
    archived_again = archive_assessment(created["id"], db_path=temp_db_path)
    assert archived_again["status"] == "Archived"

    # Archiving non-existent assessment
    with pytest.raises(ValueError, match="does not exist"):
        archive_assessment(99999, db_path=temp_db_path)

    # Verify listing with and without archived
    all_assessments = list_assessments(include_archived=True, db_path=temp_db_path)
    active_assessments = list_assessments(include_archived=False, db_path=temp_db_path)

    assert len(all_assessments) == 1
    assert len(active_assessments) == 0


def test_list_assessments_filtering(temp_db_path: str):
    """Test status filtering in list_assessments."""
    create_assessment(
        title="Draft Assessment",
        organization="Org 1",
        industry="Tech",
        scope="Scope 1",
        lead_assessor="Assessor 1",
        assessment_date="2026-01-01",
        status="Draft",
        db_path=temp_db_path,
    )
    create_assessment(
        title="In Progress Assessment",
        organization="Org 2",
        industry="Finance",
        scope="Scope 2",
        lead_assessor="Assessor 2",
        assessment_date="2026-01-02",
        status="In Progress",
        db_path=temp_db_path,
    )
    a3 = create_assessment(
        title="To Archive",
        organization="Org 3",
        industry="Healthcare",
        scope="Scope 3",
        lead_assessor="Assessor 3",
        assessment_date="2026-01-03",
        status="Completed",
        db_path=temp_db_path,
    )
    archive_assessment(a3["id"], db_path=temp_db_path)

    drafts = list_assessments(status_filter="Draft", db_path=temp_db_path)
    assert len(drafts) == 1
    assert drafts[0]["title"] == "Draft Assessment"

    in_prog = list_assessments(status_filter="In Progress", db_path=temp_db_path)
    assert len(in_prog) == 1
    assert in_prog[0]["title"] == "In Progress Assessment"

    archived = list_assessments(status_filter="Archived", db_path=temp_db_path)
    assert len(archived) == 1
    assert archived[0]["title"] == "To Archive"


def test_foreign_key_enforcement(temp_db_path: str):
    """Verify that SQLite strictly rejects orphaned child records."""
    with pytest.raises(sqlite3.IntegrityError):
        with db_session(temp_db_path) as conn:
            conn.execute(
                """
                INSERT INTO control_assessments (
                    assessment_id, control_id, status, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                (99999, 1, "Implemented", "2026-01-01T00:00:00Z"),
            )


def test_cross_assessment_isolation_triggers(temp_db_path: str):
    """
    Verify that SQLite triggers prevent cross-assessment linking for
    evidence, findings, risks, and remediation.
    """
    # Create two distinct assessments
    a1 = create_assessment(
        title="Assessment A",
        organization="Org A",
        industry="Tech",
        scope="Scope A",
        lead_assessor="Assessor A",
        assessment_date="2026-01-01",
        db_path=temp_db_path,
    )
    a2 = create_assessment(
        title="Assessment B",
        organization="Org B",
        industry="Finance",
        scope="Scope B",
        lead_assessor="Assessor B",
        assessment_date="2026-01-01",
        db_path=temp_db_path,
    )

    with db_session(temp_db_path) as conn:
        # Get existing control from catalogue or create custom one
        row = conn.execute("SELECT id FROM controls WHERE control_identifier = 'A.5.1'").fetchone()
        if row:
            ctrl_id = row[0]
        else:
            cursor = conn.execute(
                """
                INSERT INTO controls (clause, control_identifier, title, description, domain, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("A.5", "A.5.1", "Policies for info security", "Desc", "Organizational", "2026-01-01"),
            )
            ctrl_id = cursor.lastrowid

        # Assessment A control_assessment
        ca_row = conn.execute(
            "SELECT id FROM control_assessments WHERE assessment_id = ? AND control_id = ?",
            (a1["id"], ctrl_id),
        ).fetchone()
        if ca_row:
            ca_id_a1 = ca_row[0]
        else:
            cursor = conn.execute(
                """
                INSERT INTO control_assessments (assessment_id, control_id, status, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (a1["id"], ctrl_id, "Implemented", "2026-01-01T00:00:00Z"),
            )
            ca_id_a1 = cursor.lastrowid

        # Assessment B evidence
        cursor = conn.execute(
            """
            INSERT INTO evidence (
                assessment_id, evidence_identifier, title, file_name, file_path, uploaded_by, uploaded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (a2["id"], "EVD-001", "B Policy Doc", "policy.pdf", "/storage/policy.pdf", "Assessor B", "2026-01-01"),
        )
        evd_id_a2 = cursor.lastrowid

        # Assessment A finding
        cursor = conn.execute(
            """
            INSERT INTO findings (
                assessment_id, finding_identifier, title, finding_type, severity, description, status, identified_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (a1["id"], "FND-001", "Finding A", "Major Non-Conformity", "High", "Desc", "Open", "2026-01-01", "2026-01-01"),
        )

        # Assessment B finding
        cursor = conn.execute(
            """
            INSERT INTO findings (
                assessment_id, finding_identifier, title, finding_type, severity, description, status, identified_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (a2["id"], "FND-002", "Finding B", "Minor Non-Conformity", "Medium", "Desc", "Open", "2026-01-01", "2026-01-01"),
        )
        fnd_id_a2 = cursor.lastrowid

    # 1. Attempt to link Assessment B evidence to Assessment A control assessment
    with pytest.raises(sqlite3.IntegrityError, match="Cross-assessment violation"):
        with db_session(temp_db_path) as conn:
            conn.execute(
                """
                INSERT INTO control_evidence (
                    assessment_id, control_assessment_id, evidence_id, mapped_at
                ) VALUES (?, ?, ?, ?)
                """,
                (a1["id"], ca_id_a1, evd_id_a2, "2026-01-01T00:00:00Z"),
            )

    # 2. Attempt to link Assessment B finding into Assessment A risk
    with pytest.raises(sqlite3.IntegrityError, match="Cross-assessment violation"):
        with db_session(temp_db_path) as conn:
            conn.execute(
                """
                INSERT INTO risks (
                    assessment_id, finding_id, risk_identifier, title, likelihood, impact, inherent_risk_score, inherent_risk_level, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (a1["id"], fnd_id_a2, "RSK-001", "Mismatched Risk", 3, 3, 9, "Medium", "2026-01-01", "2026-01-01"),
            )

    # 3. Attempt to link Assessment B finding into Assessment A remediation
    with pytest.raises(sqlite3.IntegrityError, match="Cross-assessment violation"):
        with db_session(temp_db_path) as conn:
            conn.execute(
                """
                INSERT INTO remediation (
                    assessment_id, finding_id, remediation_identifier, action_title, action_description, action_owner, target_date, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (a1["id"], fnd_id_a2, "REM-001", "Action", "Desc", "Owner", "2026-06-01", "2026-01-01", "2026-01-01"),
            )


def test_activity_logging(temp_db_path: str):
    """Verify that creation, update, and archival events generate structured log entries."""
    assessment = create_assessment(
        title="Audit Trail Test",
        organization="Audit Corp",
        industry="Security",
        scope="Global",
        lead_assessor="Lead Auditor",
        assessment_date="2026-01-01",
        db_path=temp_db_path,
    )

    update_assessment(
        assessment_id=assessment["id"],
        title="Audit Trail Test Updated",
        organization="Audit Corp",
        industry="Security",
        scope="Global",
        lead_assessor="Lead Auditor",
        assessment_date="2026-01-01",
        status="In Progress",
        db_path=temp_db_path,
    )

    archive_assessment(assessment["id"], db_path=temp_db_path)

    activities = get_recent_activities(assessment_id=assessment["id"], db_path=temp_db_path)
    assert len(activities) == 3

    event_types = [a["event_type"] for a in activities]
    assert "ASSESSMENT_ARCHIVED" in event_types
    assert "ASSESSMENT_EDITED" in event_types
    assert "ASSESSMENT_CREATED" in event_types

    # Test limit filtering
    limited = get_recent_activities(assessment_id=assessment["id"], limit=1, db_path=temp_db_path)
    assert len(limited) == 1
    assert limited[0]["event_type"] == "ASSESSMENT_ARCHIVED"


def test_dashboard_service_metrics(temp_db_path: str):
    """Verify that dashboard service calculates live metrics from real records."""
    # Empty DB summary
    summary_empty = get_dashboard_summary(db_path=temp_db_path)
    assert summary_empty["total_assessments"] == 0
    assert summary_empty["active_assessments"] == 0
    assert summary_empty["archived_assessments"] == 0

    # Create 2 assessments: 1 Active, 1 Archived
    a1 = create_assessment(
        title="Active ISMS",
        organization="Org 1",
        industry="Tech",
        scope="Scope 1",
        lead_assessor="Lead 1",
        assessment_date="2026-02-01",
        status="In Progress",
        db_path=temp_db_path,
    )
    a2 = create_assessment(
        title="To Archive",
        organization="Org 2",
        industry="Tech",
        scope="Scope 2",
        lead_assessor="Lead 2",
        assessment_date="2026-02-01",
        status="Completed",
        db_path=temp_db_path,
    )
    archive_assessment(a2["id"], db_path=temp_db_path)

    summary = get_dashboard_summary(active_assessment_id=a1["id"], db_path=temp_db_path)
    assert summary["total_assessments"] == 2
    assert summary["active_assessments"] == 1
    assert summary["archived_assessments"] == 1
    assert summary["active_assessment"]["id"] == a1["id"]
    assert len(summary["recent_activities"]) > 0
