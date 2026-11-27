"""
AuditSphere - SQLite Database Initialization and Connection Management.

Features:
- Parameterized SQL execution
- SQLite foreign key enforcement enabled on every connection
- Context manager for robust transaction lifecycle (commit / rollback)
- Strict relational integrity preventing cross-assessment linking
- Idempotent schema initialization and repeat-safe migrations that preserve existing records
- Automated synchronization of the ISO/IEC 27001:2022 20-control catalogue
- Automatic initialization of Not Assessed control assessment rows for all assessments
- Phase 3 Evidence Management, Control Testing, and Audit Findings schema support
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional, List, Dict, Any

# Paths to SQLite database and controls catalogue
DEFAULT_DB_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "auditsphere.db"
CONTROLS_JSON_PATH = DEFAULT_DB_DIR / "controls.json"
STORAGE_DIR = Path(__file__).resolve().parent / "storage"
EVIDENCE_STORAGE_DIR = STORAGE_DIR / "evidence"


def get_utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_db_connection(db_path: Optional[str | Path] = None) -> sqlite3.Connection:
    """
    Establish and return a SQLite connection with foreign keys enabled
    and row factory set to sqlite3.Row for dict-like access.
    """
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_session(db_path: Optional[str | Path] = None) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager providing a transactional database connection.
    Automatically commits on normal exit, rolls back on exception,
    and reliably closes the connection.
    """
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# SQL Schema definition for AuditSphere
SCHEMA_SQL = """
-- 1. Assessments Table
CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    organization TEXT NOT NULL,
    industry TEXT NOT NULL,
    standard TEXT NOT NULL DEFAULT 'ISO/IEC 27001:2022',
    scope TEXT NOT NULL,
    objectives TEXT,
    lead_assessor TEXT NOT NULL,
    assessment_date TEXT NOT NULL, -- YYYY-MM-DD
    status TEXT NOT NULL CHECK(status IN ('Draft', 'In Progress', 'In Review', 'Completed', 'Archived')) DEFAULT 'Draft',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 2. Reference Security Controls (ISO/IEC 27001:2022 20-Control Subset)
CREATE TABLE IF NOT EXISTS controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    standard TEXT NOT NULL DEFAULT 'ISO/IEC 27001:2022',
    clause TEXT NOT NULL, -- e.g. 'Annex A.5', 'Annex A.6'
    control_identifier TEXT NOT NULL UNIQUE, -- e.g. 'A.5.1'
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    domain TEXT NOT NULL, -- 'Organizational', 'People', 'Physical', 'Technological'
    guidance TEXT,
    objective TEXT,
    assessment_questions TEXT, -- JSON array of questions
    suggested_evidence TEXT,   -- JSON array of evidence types
    example_gaps TEXT,         -- JSON array of typical gaps
    example_recommendations TEXT, -- JSON array of remediation guidance
    created_at TEXT NOT NULL
);

-- 3. Control Assessments (Evaluation of a specific control within an assessment)
CREATE TABLE IF NOT EXISTS control_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK(status IN ('Not Assessed', 'Implemented', 'Partially Implemented', 'Not Implemented', 'Not Applicable')) DEFAULT 'Not Assessed',
    effectiveness_score INTEGER CHECK(effectiveness_score IS NULL OR (effectiveness_score BETWEEN 0 AND 5)),
    maturity_level INTEGER CHECK(maturity_level IS NULL OR (maturity_level BETWEEN 0 AND 5)),
    finding_summary TEXT,
    notes TEXT,
    assessed_by TEXT,
    assessed_at TEXT,
    control_owner TEXT,
    assessment_observation TEXT,
    testing_notes TEXT,
    evidence_notes TEXT,
    recommendation TEXT,
    applicability_justification TEXT,
    created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
    updated_at TEXT NOT NULL,
    UNIQUE(assessment_id, control_id)
);

-- 4. Evidence Artifacts
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    evidence_identifier TEXT NOT NULL, -- e.g. 'EVD-001'
    title TEXT NOT NULL,
    description TEXT,
    evidence_type TEXT NOT NULL DEFAULT 'Other',
    file_name TEXT NOT NULL,
    original_file_name TEXT,
    storage_identifier TEXT,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    file_hash TEXT, -- SHA-256 integrity hash
    sha256_hash TEXT,
    source_department TEXT,
    collection_date TEXT,
    period_covered TEXT,
    review_status TEXT NOT NULL DEFAULT 'Pending Review' CHECK(review_status IN ('Pending Review', 'Accepted', 'Needs Clarification', 'Rejected')),
    reviewer_name TEXT,
    reviewer_notes TEXT,
    reviewed_at TEXT,
    relevance_rating TEXT DEFAULT 'Relevant',
    sufficiency_rating TEXT DEFAULT 'Sufficient',
    reliability_rating TEXT DEFAULT 'Reliable',
    integrity_status TEXT NOT NULL DEFAULT 'Not yet verified' CHECK(integrity_status IN ('Not yet verified', 'Verified', 'Hash mismatch', 'File missing')),
    integrity_verified_at TEXT,
    is_archived INTEGER NOT NULL DEFAULT 0,
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    updated_at TEXT,
    UNIQUE(assessment_id, evidence_identifier)
);

-- 5. Control-Evidence Mappings
CREATE TABLE IF NOT EXISTS control_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    control_assessment_id INTEGER NOT NULL REFERENCES control_assessments(id) ON DELETE CASCADE,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    mapped_at TEXT NOT NULL,
    notes TEXT,
    UNIQUE(control_assessment_id, evidence_id)
);

-- 6. Control Testing Records (Phase 3)
CREATE TABLE IF NOT EXISTS control_tests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    control_assessment_id INTEGER NOT NULL REFERENCES control_assessments(id) ON DELETE CASCADE,
    test_reference TEXT NOT NULL, -- e.g. 'TST-001'
    test_type TEXT NOT NULL CHECK(test_type IN ('Design effectiveness', 'Operating effectiveness', 'Walkthrough', 'Document review', 'Configuration review')),
    testing_objective TEXT NOT NULL,
    testing_procedure TEXT NOT NULL,
    sample_examined TEXT,
    assessment_period TEXT,
    expected_result TEXT NOT NULL,
    observed_result TEXT NOT NULL,
    supporting_evidence_references TEXT,
    evidence_limitations TEXT,
    assessor_name TEXT NOT NULL,
    testing_date TEXT NOT NULL, -- YYYY-MM-DD
    conclusion TEXT NOT NULL CHECK(conclusion IN ('Pass', 'Fail', 'Inconclusive', 'Not tested')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(assessment_id, test_reference)
);

-- 7. Audit Findings (Gaps, Non-conformities, Observations)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    control_assessment_id INTEGER REFERENCES control_assessments(id) ON DELETE SET NULL,
    finding_identifier TEXT NOT NULL, -- e.g. 'FND-001'
    title TEXT NOT NULL,
    finding_type TEXT NOT NULL DEFAULT 'Major Non-Conformity' CHECK(finding_type IN ('Major Non-Conformity', 'Minor Non-Conformity', 'Opportunity for Improvement', 'Observation')),
    severity TEXT NOT NULL CHECK(severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    description TEXT,
    criteria TEXT,
    condition TEXT,
    cause TEXT,
    effect TEXT,
    recommendation TEXT,
    supporting_evidence_references TEXT,
    evidence_limitations TEXT,
    supporting_test_references TEXT,
    responsible_department TEXT,
    assessor_name TEXT NOT NULL DEFAULT 'Lead Assessor',
    status TEXT NOT NULL CHECK(status IN ('Draft', 'Open', 'Under Review', 'Closed', 'Remediation In Progress', 'Remediated', 'Accepted Risk')) DEFAULT 'Draft',
    verification_notes TEXT,
    identified_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',
    updated_at TEXT NOT NULL,
    UNIQUE(assessment_id, finding_identifier)
);

-- 8. Risk Register
CREATE TABLE IF NOT EXISTS risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    risk_identifier TEXT NOT NULL, -- e.g. 'RSK-001'
    title TEXT NOT NULL,
    description TEXT,
    asset_threat_vulnerability TEXT,
    asset_or_process TEXT,
    threat TEXT,
    vulnerability TEXT,
    consequence TEXT,
    risk_category TEXT NOT NULL DEFAULT 'Other',
    existing_controls TEXT,
    risk_owner TEXT,
    responsible_department TEXT,
    likelihood INTEGER CHECK(likelihood IS NULL OR (likelihood BETWEEN 1 AND 5)),
    impact INTEGER CHECK(impact IS NULL OR (impact BETWEEN 1 AND 5)),
    inherent_likelihood INTEGER CHECK(inherent_likelihood IS NULL OR (inherent_likelihood BETWEEN 1 AND 5)),
    inherent_impact INTEGER CHECK(inherent_impact IS NULL OR (inherent_impact BETWEEN 1 AND 5)),
    inherent_risk_score INTEGER,
    inherent_risk_level TEXT CHECK(inherent_risk_level IS NULL OR (inherent_risk_level IN ('Low', 'Medium', 'High', 'Critical'))),
    inherent_rationale TEXT,
    treatment_strategy TEXT NOT NULL CHECK(treatment_strategy IN ('Mitigate', 'Transfer', 'Avoid', 'Accept')) DEFAULT 'Mitigate',
    treatment_justification TEXT,
    proposed_treatment TEXT,
    treatment_owner TEXT,
    target_treatment_date TEXT,
    residual_likelihood INTEGER CHECK(residual_likelihood IS NULL OR (residual_likelihood BETWEEN 1 AND 5)),
    residual_impact INTEGER CHECK(residual_impact IS NULL OR (residual_impact BETWEEN 1 AND 5)),
    residual_risk_score INTEGER,
    residual_risk_level TEXT CHECK(residual_risk_level IS NULL OR (residual_risk_level IN ('Low', 'Medium', 'High', 'Critical'))),
    residual_rationale TEXT,
    target_likelihood INTEGER CHECK(target_likelihood IS NULL OR (target_likelihood BETWEEN 1 AND 5)),
    target_impact INTEGER CHECK(target_impact IS NULL OR (target_impact BETWEEN 1 AND 5)),
    target_risk_score INTEGER,
    target_risk_level TEXT CHECK(target_risk_level IS NULL OR (target_risk_level IN ('Low', 'Medium', 'High', 'Critical'))),
    target_rationale TEXT,
    acceptance_justification TEXT,
    approving_authority TEXT,
    approval_status TEXT NOT NULL CHECK(approval_status IN ('Not Requested', 'Pending Approval', 'Approved', 'Rejected')) DEFAULT 'Not Requested',
    approval_date TEXT,
    review_date TEXT,
    status TEXT NOT NULL CHECK(status IN ('Identified', 'Under Assessment', 'Open', 'Treatment Planned', 'Under Treatment', 'Under Review', 'Accepted', 'Closed')) DEFAULT 'Identified',
    closure_rationale TEXT,
    assessor_name TEXT NOT NULL DEFAULT 'Lead Assessor',
    assessment_date TEXT,
    is_archived INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(assessment_id, risk_identifier)
);

-- 8a. Risk-to-Finding Mappings (Many-to-Many)
CREATE TABLE IF NOT EXISTS risk_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    notes TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(risk_id, finding_id)
);

-- 8b. Risk-to-Control Mappings (Many-to-Many)
CREATE TABLE IF NOT EXISTS risk_controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    control_assessment_id INTEGER NOT NULL REFERENCES control_assessments(id) ON DELETE CASCADE,
    notes TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(risk_id, control_assessment_id)
);

-- 8c. Risk-to-Evidence Mappings (Many-to-Many)
CREATE TABLE IF NOT EXISTS risk_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    notes TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(risk_id, evidence_id)
);

-- 8d. Risk Review & Reassessment History
CREATE TABLE IF NOT EXISTS risk_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    previous_likelihood INTEGER,
    previous_impact INTEGER,
    previous_score INTEGER,
    previous_level TEXT,
    new_likelihood INTEGER,
    new_impact INTEGER,
    new_score INTEGER,
    new_level TEXT,
    evaluation_type TEXT NOT NULL DEFAULT 'Current Residual',
    reason_for_change TEXT NOT NULL,
    supporting_evidence_references TEXT,
    reviewer_name TEXT NOT NULL,
    review_timestamp TEXT NOT NULL
);

-- 9. Remediation / Corrective Actions Tracker
CREATE TABLE IF NOT EXISTS remediation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    risk_id INTEGER REFERENCES risks(id) ON DELETE SET NULL,
    remediation_identifier TEXT NOT NULL, -- e.g. 'ACT-001' or 'REM-001'
    action_title TEXT NOT NULL,
    action_description TEXT,
    immediate_correction TEXT,
    root_cause TEXT,
    root_cause_analysis_method TEXT NOT NULL DEFAULT 'Direct Analysis' CHECK(root_cause_analysis_method IN ('Direct Analysis', '5 Whys', 'Fishbone / Ishikawa', 'Fault Tree', 'Under Investigation', 'Not Appropriate')),
    root_cause_details TEXT, -- JSON or structured text for 5 Whys analysis
    contributing_factors TEXT,
    long_term_corrective_action TEXT,
    expected_outcome TEXT,
    action_priority TEXT NOT NULL DEFAULT 'Medium' CHECK(action_priority IN ('Low', 'Medium', 'High', 'Critical')),
    priority_justification TEXT,
    action_owner TEXT NOT NULL,
    responsible_department TEXT,
    assigned_date TEXT,
    target_date TEXT NOT NULL, -- Current target completion date (YYYY-MM-DD)
    original_target_date TEXT, -- Original deadline before extensions
    actual_completion_date TEXT, -- YYYY-MM-DD
    progress_percentage INTEGER NOT NULL DEFAULT 0 CHECK(progress_percentage BETWEEN 0 AND 100),
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open', 'In Progress', 'Awaiting Verification', 'Under Verification', 'Reopened', 'Closed', 'Cancelled')),
    cancellation_reason TEXT,
    implementation_summary TEXT,
    verification_requirements TEXT,
    closure_rationale TEXT,
    reopen_justification TEXT,
    is_archived INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(assessment_id, remediation_identifier)
);

-- 9a. Remediation-to-Finding Mappings (Many-to-Many)
CREATE TABLE IF NOT EXISTS remediation_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    notes TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(remediation_id, finding_id)
);

-- 9b. Remediation-to-Risk Mappings (Many-to-Many)
CREATE TABLE IF NOT EXISTS remediation_risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
    risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
    notes TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(remediation_id, risk_id)
);

-- 9c. Remediation-to-Control Mappings (Many-to-Many)
CREATE TABLE IF NOT EXISTS remediation_controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
    control_assessment_id INTEGER NOT NULL REFERENCES control_assessments(id) ON DELETE CASCADE,
    notes TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(remediation_id, control_assessment_id)
);

-- 9d. Remediation-to-Evidence Mappings (Many-to-Many)
CREATE TABLE IF NOT EXISTS remediation_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL DEFAULT 'Remediation Evidence' CHECK(evidence_type IN ('Remediation Evidence', 'Verification Evidence', 'Audit Evidence', 'Supporting Policy', 'Other')),
    notes TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(remediation_id, evidence_id)
);

-- 9e. Remediation Progress History
CREATE TABLE IF NOT EXISTS remediation_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
    progress_percentage INTEGER NOT NULL CHECK(progress_percentage BETWEEN 0 AND 100),
    description TEXT NOT NULL,
    blockers TEXT,
    updated_by TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

-- 9f. Remediation Deadline Extension History
CREATE TABLE IF NOT EXISTS remediation_deadline_extensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
    previous_deadline TEXT NOT NULL,
    new_deadline TEXT NOT NULL,
    extension_reason TEXT NOT NULL,
    approving_authority TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

-- 9g. Remediation Verification Records
CREATE TABLE IF NOT EXISTS remediation_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
    verification_reference TEXT NOT NULL, -- e.g. 'VRF-001'
    verification_objective TEXT NOT NULL,
    verification_procedure TEXT NOT NULL,
    expected_outcome TEXT NOT NULL,
    observed_outcome TEXT NOT NULL,
    sample_examined TEXT,
    evidence_references TEXT,
    related_control_testing_records TEXT,
    evidence_limitations TEXT,
    verifier_name TEXT NOT NULL,
    verification_date TEXT NOT NULL, -- YYYY-MM-DD
    verification_result TEXT NOT NULL CHECK(verification_result IN ('Effective', 'Ineffective', 'Inconclusive')),
    verification_notes TEXT,
    recommended_next_action TEXT,
    created_at TEXT NOT NULL
);

-- 10. Activity Log (Assessment lifecycle history)
CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER REFERENCES assessments(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'Lead Assessor',
    control_reference TEXT,
    previous_status TEXT,
    new_status TEXT,
    timestamp TEXT NOT NULL
);
"""

INDICES_SQL = """
-- Performance indices
CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);
CREATE INDEX IF NOT EXISTS idx_control_assessments_aid ON control_assessments(assessment_id);
CREATE INDEX IF NOT EXISTS idx_control_assessments_cid ON control_assessments(control_id);
CREATE INDEX IF NOT EXISTS idx_control_assessments_status ON control_assessments(status);
CREATE INDEX IF NOT EXISTS idx_evidence_aid ON evidence(assessment_id);
CREATE INDEX IF NOT EXISTS idx_evidence_review_status ON evidence(review_status);
CREATE INDEX IF NOT EXISTS idx_control_evidence_caid ON control_evidence(control_assessment_id);
CREATE INDEX IF NOT EXISTS idx_control_evidence_eid ON control_evidence(evidence_id);
CREATE INDEX IF NOT EXISTS idx_control_tests_aid ON control_tests(assessment_id);
CREATE INDEX IF NOT EXISTS idx_control_tests_caid ON control_tests(control_assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_aid ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_caid ON findings(control_assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_risks_aid ON risks(assessment_id);
CREATE INDEX IF NOT EXISTS idx_risks_status ON risks(status);
CREATE INDEX IF NOT EXISTS idx_risks_cat ON risks(risk_category);
CREATE INDEX IF NOT EXISTS idx_risks_cur_score ON risks(residual_risk_score);
CREATE INDEX IF NOT EXISTS idx_risk_findings_aid ON risk_findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_risk_findings_rid ON risk_findings(risk_id);
CREATE INDEX IF NOT EXISTS idx_risk_findings_fid ON risk_findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_risk_controls_aid ON risk_controls(assessment_id);
CREATE INDEX IF NOT EXISTS idx_risk_controls_rid ON risk_controls(risk_id);
CREATE INDEX IF NOT EXISTS idx_risk_controls_caid ON risk_controls(control_assessment_id);
CREATE INDEX IF NOT EXISTS idx_risk_evidence_aid ON risk_evidence(assessment_id);
CREATE INDEX IF NOT EXISTS idx_risk_evidence_rid ON risk_evidence(risk_id);
CREATE INDEX IF NOT EXISTS idx_risk_evidence_eid ON risk_evidence(evidence_id);
CREATE INDEX IF NOT EXISTS idx_risk_reviews_aid ON risk_reviews(assessment_id);
CREATE INDEX IF NOT EXISTS idx_risk_reviews_rid ON risk_reviews(risk_id);
CREATE INDEX IF NOT EXISTS idx_remediation_aid ON remediation(assessment_id);
CREATE INDEX IF NOT EXISTS idx_remediation_status ON remediation(status);
CREATE INDEX IF NOT EXISTS idx_remediation_priority ON remediation(action_priority);
CREATE INDEX IF NOT EXISTS idx_remediation_target_date ON remediation(target_date);
CREATE INDEX IF NOT EXISTS idx_rem_findings_aid ON remediation_findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_rem_findings_rem_id ON remediation_findings(remediation_id);
CREATE INDEX IF NOT EXISTS idx_rem_findings_fid ON remediation_findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_rem_risks_aid ON remediation_risks(assessment_id);
CREATE INDEX IF NOT EXISTS idx_rem_risks_rem_id ON remediation_risks(remediation_id);
CREATE INDEX IF NOT EXISTS idx_rem_risks_rid ON remediation_risks(risk_id);
CREATE INDEX IF NOT EXISTS idx_rem_controls_aid ON remediation_controls(assessment_id);
CREATE INDEX IF NOT EXISTS idx_rem_controls_rem_id ON remediation_controls(remediation_id);
CREATE INDEX IF NOT EXISTS idx_rem_controls_caid ON remediation_controls(control_assessment_id);
CREATE INDEX IF NOT EXISTS idx_rem_evidence_aid ON remediation_evidence(assessment_id);
CREATE INDEX IF NOT EXISTS idx_rem_evidence_rem_id ON remediation_evidence(remediation_id);
CREATE INDEX IF NOT EXISTS idx_rem_evidence_eid ON remediation_evidence(evidence_id);
CREATE INDEX IF NOT EXISTS idx_rem_progress_aid ON remediation_progress(assessment_id);
CREATE INDEX IF NOT EXISTS idx_rem_progress_rem_id ON remediation_progress(remediation_id);
CREATE INDEX IF NOT EXISTS idx_rem_verif_aid ON remediation_verifications(assessment_id);
CREATE INDEX IF NOT EXISTS idx_rem_verif_rem_id ON remediation_verifications(remediation_id);
CREATE INDEX IF NOT EXISTS idx_rem_deadlines_aid ON remediation_deadline_extensions(assessment_id);
CREATE INDEX IF NOT EXISTS idx_rem_deadlines_rem_id ON remediation_deadline_extensions(remediation_id);
CREATE INDEX IF NOT EXISTS idx_activity_aid ON activity_log(assessment_id);
CREATE INDEX IF NOT EXISTS idx_activity_time ON activity_log(timestamp DESC);
"""

# SQLite Triggers to strictly enforce that related entities belong to the same assessment
TRIGGERS_SQL = """
-- Prevent mapping evidence to a control assessment from a different assessment
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_control_evidence_insert
BEFORE INSERT ON control_evidence
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM control_assessments WHERE id = NEW.control_assessment_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: control_assessment does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM evidence WHERE id = NEW.evidence_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: evidence does not belong to specified assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_control_evidence_update
BEFORE UPDATE ON control_evidence
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM control_assessments WHERE id = NEW.control_assessment_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: control_assessment does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM evidence WHERE id = NEW.evidence_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: evidence does not belong to specified assessment')
    END;
END;

-- Prevent linking control tests to a control assessment from a different assessment
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_control_test_insert
BEFORE INSERT ON control_tests
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM control_assessments WHERE id = NEW.control_assessment_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: control_assessment does not belong to test assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_control_test_update
BEFORE UPDATE ON control_tests
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM control_assessments WHERE id = NEW.control_assessment_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: control_assessment does not belong to test assessment')
    END;
END;

-- Prevent linking findings to a control assessment from a different assessment
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_finding_insert
BEFORE INSERT ON findings
WHEN NEW.control_assessment_id IS NOT NULL
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM control_assessments WHERE id = NEW.control_assessment_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: control_assessment does not belong to finding assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_finding_update
BEFORE UPDATE ON findings
WHEN NEW.control_assessment_id IS NOT NULL
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM control_assessments WHERE id = NEW.control_assessment_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: control_assessment does not belong to finding assessment')
    END;
END;

-- Prevent linking risks to a finding from a different assessment
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_risk_insert
BEFORE INSERT ON risks
WHEN NEW.finding_id IS NOT NULL
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM findings WHERE id = NEW.finding_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: finding does not belong to risk assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_risk_update
BEFORE UPDATE ON risks
WHEN NEW.finding_id IS NOT NULL
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM findings WHERE id = NEW.finding_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: finding does not belong to risk assessment')
    END;
END;

-- Prevent linking remediation to a finding or risk from a different assessment
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_remediation_insert
BEFORE INSERT ON remediation
BEGIN
    SELECT CASE
        WHEN NEW.finding_id IS NOT NULL AND (SELECT assessment_id FROM findings WHERE id = NEW.finding_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: finding does not belong to remediation assessment')
        WHEN NEW.risk_id IS NOT NULL AND (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to remediation assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_remediation_update
BEFORE UPDATE ON remediation
BEGIN
    SELECT CASE
        WHEN NEW.finding_id IS NOT NULL AND (SELECT assessment_id FROM findings WHERE id = NEW.finding_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: finding does not belong to remediation assessment')
        WHEN NEW.risk_id IS NOT NULL AND (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to remediation assessment')
    END;
END;

-- Phase 5: Prevent linking remediation to findings from different assessments
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_finding_insert
BEFORE INSERT ON remediation_findings
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM findings WHERE id = NEW.finding_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: finding does not belong to specified assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_finding_update
BEFORE UPDATE ON remediation_findings
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM findings WHERE id = NEW.finding_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: finding does not belong to specified assessment')
    END;
END;

-- Prevent linking remediation to risks from different assessments
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_risk_insert
BEFORE INSERT ON remediation_risks
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to specified assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_risk_update
BEFORE UPDATE ON remediation_risks
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to specified assessment')
    END;
END;

-- Prevent linking remediation to controls from different assessments
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_control_insert
BEFORE INSERT ON remediation_controls
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM control_assessments WHERE id = NEW.control_assessment_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: control assessment does not belong to specified assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_control_update
BEFORE UPDATE ON remediation_controls
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM control_assessments WHERE id = NEW.control_assessment_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: control assessment does not belong to specified assessment')
    END;
END;

-- Prevent linking remediation to evidence from different assessments
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_evidence_insert
BEFORE INSERT ON remediation_evidence
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM evidence WHERE id = NEW.evidence_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: evidence does not belong to specified assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_evidence_update
BEFORE UPDATE ON remediation_evidence
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM evidence WHERE id = NEW.evidence_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: evidence does not belong to specified assessment')
    END;
END;

-- Prevent linking progress, verifications, and deadlines to remediation from different assessments
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_progress_insert
BEFORE INSERT ON remediation_progress
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to progress assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_verif_insert
BEFORE INSERT ON remediation_verifications
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to verification assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_rem_deadline_insert
BEFORE INSERT ON remediation_deadline_extensions
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM remediation WHERE id = NEW.remediation_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: remediation does not belong to deadline extension assessment')
    END;
END;

-- Phase 4: Prevent linking risks to findings from different assessments in risk_findings
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_risk_finding_insert
BEFORE INSERT ON risk_findings
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM findings WHERE id = NEW.finding_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: finding does not belong to specified assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_risk_finding_update
BEFORE UPDATE ON risk_findings
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM findings WHERE id = NEW.finding_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: finding does not belong to specified assessment')
    END;
END;

-- Prevent linking risks to control assessments from different assessments in risk_controls
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_risk_control_insert
BEFORE INSERT ON risk_controls
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM control_assessments WHERE id = NEW.control_assessment_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: control assessment does not belong to specified assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_risk_control_update
BEFORE UPDATE ON risk_controls
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM control_assessments WHERE id = NEW.control_assessment_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: control assessment does not belong to specified assessment')
    END;
END;

-- Prevent linking risks to evidence from different assessments in risk_evidence
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_risk_evidence_insert
BEFORE INSERT ON risk_evidence
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM evidence WHERE id = NEW.evidence_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: evidence does not belong to specified assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_risk_evidence_update
BEFORE UPDATE ON risk_evidence
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to specified assessment')
        WHEN (SELECT assessment_id FROM evidence WHERE id = NEW.evidence_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: evidence does not belong to specified assessment')
    END;
END;

-- Prevent recording risk review for a risk belonging to a different assessment
CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_risk_review_insert
BEFORE INSERT ON risk_reviews
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to review assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_risk_review_update
BEFORE UPDATE ON risk_reviews
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to review assessment')
    END;
END;
"""


def run_migrations(conn: sqlite3.Connection) -> None:
    """
    Safely execute repeat-safe schema migrations for existing databases
    to ensure all Phase 2 and Phase 3 columns and tables exist.
    """
    cursor = conn.cursor()

    # 1. Migrate 'controls' table
    cursor.execute("PRAGMA table_info(controls);")
    controls_cols = {row["name"] for row in cursor.fetchall()}
    columns_to_add_controls = {
        "objective": "TEXT",
        "assessment_questions": "TEXT",
        "suggested_evidence": "TEXT",
        "example_gaps": "TEXT",
        "example_recommendations": "TEXT",
    }
    for col_name, col_type in columns_to_add_controls.items():
        if col_name not in controls_cols:
            cursor.execute(f"ALTER TABLE controls ADD COLUMN {col_name} {col_type};")

    # 2. Migrate 'control_assessments' table
    cursor.execute("PRAGMA table_info(control_assessments);")
    ca_cols = {row["name"] for row in cursor.fetchall()}
    columns_to_add_ca = {
        "control_owner": "TEXT",
        "assessment_observation": "TEXT",
        "testing_notes": "TEXT",
        "evidence_notes": "TEXT",
        "recommendation": "TEXT",
        "applicability_justification": "TEXT",
        "created_at": "TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z'",
    }
    for col_name, col_type in columns_to_add_ca.items():
        if col_name not in ca_cols:
            cursor.execute(f"ALTER TABLE control_assessments ADD COLUMN {col_name} {col_type};")

    # 3. Migrate 'evidence' table
    cursor.execute("PRAGMA table_info(evidence);")
    ev_cols = {row["name"] for row in cursor.fetchall()}
    columns_to_add_ev = {
        "evidence_type": "TEXT NOT NULL DEFAULT 'Other'",
        "original_file_name": "TEXT",
        "storage_identifier": "TEXT",
        "sha256_hash": "TEXT",
        "source_department": "TEXT",
        "collection_date": "TEXT",
        "period_covered": "TEXT",
        "review_status": "TEXT NOT NULL DEFAULT 'Pending Review'",
        "reviewer_name": "TEXT",
        "reviewer_notes": "TEXT",
        "reviewed_at": "TEXT",
        "relevance_rating": "TEXT DEFAULT 'Relevant'",
        "sufficiency_rating": "TEXT DEFAULT 'Sufficient'",
        "reliability_rating": "TEXT DEFAULT 'Reliable'",
        "integrity_status": "TEXT NOT NULL DEFAULT 'Not yet verified'",
        "integrity_verified_at": "TEXT",
        "is_archived": "INTEGER NOT NULL DEFAULT 0",
        "updated_at": "TEXT",
    }
    for col_name, col_type in columns_to_add_ev.items():
        if col_name not in ev_cols:
            cursor.execute(f"ALTER TABLE evidence ADD COLUMN {col_name} {col_type};")

    # Backfill sha256_hash from file_hash or original_file_name from file_name if missing
    cursor.execute("UPDATE evidence SET sha256_hash = file_hash WHERE sha256_hash IS NULL AND file_hash IS NOT NULL;")
    cursor.execute("UPDATE evidence SET original_file_name = file_name WHERE original_file_name IS NULL AND file_name IS NOT NULL;")

    # 4. Migrate 'findings' table
    cursor.execute("PRAGMA table_info(findings);")
    fnd_cols = {row["name"] for row in cursor.fetchall()}
    columns_to_add_fnd = {
        "supporting_evidence_references": "TEXT",
        "evidence_limitations": "TEXT",
        "supporting_test_references": "TEXT",
        "responsible_department": "TEXT",
        "assessor_name": "TEXT NOT NULL DEFAULT 'Lead Assessor'",
        "verification_notes": "TEXT",
        "created_at": "TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z'",
    }
    for col_name, col_type in columns_to_add_fnd.items():
        if col_name not in fnd_cols:
            cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type};")

    # 5. Migrate 'activity_log' table
    cursor.execute("PRAGMA table_info(activity_log);")
    act_cols = {row["name"] for row in cursor.fetchall()}
    columns_to_add_act = {
        "control_reference": "TEXT",
        "previous_status": "TEXT",
        "new_status": "TEXT",
    }
    for col_name, col_type in columns_to_add_act.items():
        if col_name not in act_cols:
            cursor.execute(f"ALTER TABLE activity_log ADD COLUMN {col_name} {col_type};")

    # 6. Migrate 'risks' table (Phase 4)
    cursor.execute("PRAGMA table_info(risks);")
    risk_cols = {row["name"] for row in cursor.fetchall()}
    columns_to_add_risk = {
        "asset_or_process": "TEXT",
        "threat": "TEXT",
        "vulnerability": "TEXT",
        "consequence": "TEXT",
        "risk_category": "TEXT NOT NULL DEFAULT 'Other'",
        "existing_controls": "TEXT",
        "responsible_department": "TEXT",
        "inherent_likelihood": "INTEGER",
        "inherent_impact": "INTEGER",
        "inherent_rationale": "TEXT",
        "residual_rationale": "TEXT",
        "target_likelihood": "INTEGER",
        "target_impact": "INTEGER",
        "target_risk_score": "INTEGER",
        "target_risk_level": "TEXT",
        "target_rationale": "TEXT",
        "treatment_justification": "TEXT",
        "proposed_treatment": "TEXT",
        "treatment_owner": "TEXT",
        "target_treatment_date": "TEXT",
        "acceptance_justification": "TEXT",
        "approving_authority": "TEXT",
        "approval_status": "TEXT NOT NULL DEFAULT 'Not Requested'",
        "approval_date": "TEXT",
        "review_date": "TEXT",
        "closure_rationale": "TEXT",
        "assessor_name": "TEXT NOT NULL DEFAULT 'Lead Assessor'",
        "assessment_date": "TEXT",
        "is_archived": "INTEGER NOT NULL DEFAULT 0",
    }
    for col_name, col_type in columns_to_add_risk.items():
        if col_name not in risk_cols:
            cursor.execute(f"ALTER TABLE risks ADD COLUMN {col_name} {col_type};")

    # Ensure Phase 4 relationship tables exist
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
            finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            notes TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(risk_id, finding_id)
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_controls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
            control_assessment_id INTEGER NOT NULL REFERENCES control_assessments(id) ON DELETE CASCADE,
            notes TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(risk_id, control_assessment_id)
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
            evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
            notes TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(risk_id, evidence_id)
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
            previous_likelihood INTEGER,
            previous_impact INTEGER,
            previous_score INTEGER,
            previous_level TEXT,
            new_likelihood INTEGER,
            new_impact INTEGER,
            new_score INTEGER,
            new_level TEXT,
            evaluation_type TEXT NOT NULL DEFAULT 'Current Residual',
            reason_for_change TEXT NOT NULL,
            supporting_evidence_references TEXT,
            reviewer_name TEXT NOT NULL,
            review_timestamp TEXT NOT NULL
        );
        """
    )

    # 7. Migrate 'remediation' table and child tables (Phase 5)
    cursor.execute("PRAGMA table_info(remediation);")
    rem_cols = {row["name"] for row in cursor.fetchall()}
    if "immediate_correction" not in rem_cols:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS remediation_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
                risk_id INTEGER REFERENCES risks(id) ON DELETE SET NULL,
                remediation_identifier TEXT NOT NULL,
                action_title TEXT NOT NULL,
                action_description TEXT,
                immediate_correction TEXT,
                root_cause TEXT,
                root_cause_analysis_method TEXT NOT NULL DEFAULT 'Direct Analysis' CHECK(root_cause_analysis_method IN ('Direct Analysis', '5 Whys', 'Fishbone / Ishikawa', 'Fault Tree', 'Under Investigation', 'Not Appropriate')),
                root_cause_details TEXT,
                contributing_factors TEXT,
                long_term_corrective_action TEXT,
                expected_outcome TEXT,
                action_priority TEXT NOT NULL DEFAULT 'Medium' CHECK(action_priority IN ('Low', 'Medium', 'High', 'Critical')),
                priority_justification TEXT,
                action_owner TEXT NOT NULL,
                responsible_department TEXT,
                assigned_date TEXT,
                target_date TEXT NOT NULL,
                original_target_date TEXT,
                actual_completion_date TEXT,
                progress_percentage INTEGER NOT NULL DEFAULT 0 CHECK(progress_percentage BETWEEN 0 AND 100),
                status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open', 'In Progress', 'Awaiting Verification', 'Under Verification', 'Reopened', 'Closed', 'Cancelled')),
                cancellation_reason TEXT,
                implementation_summary TEXT,
                verification_requirements TEXT,
                closure_rationale TEXT,
                reopen_justification TEXT,
                is_archived INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(assessment_id, remediation_identifier)
            );
            """
        )
        # Copy existing data if remediation has rows
        cursor.execute("SELECT COUNT(*) FROM remediation;")
        old_count = cursor.fetchone()[0]
        if old_count > 0:
            cursor.execute(
                """
                INSERT INTO remediation_new (
                    id, assessment_id, finding_id, risk_id, remediation_identifier,
                    action_title, action_description, action_owner, target_date,
                    actual_completion_date, status, verification_requirements,
                    created_at, updated_at
                )
                SELECT
                    id, assessment_id, finding_id, risk_id, remediation_identifier,
                    action_title, action_description, action_owner, target_date,
                    actual_completion_date,
                    CASE status
                        WHEN 'Not Started' THEN 'Open'
                        WHEN 'In Progress' THEN 'In Progress'
                        WHEN 'Pending Verification' THEN 'Awaiting Verification'
                        WHEN 'Verified & Closed' THEN 'Closed'
                        WHEN 'Deferred' THEN 'Cancelled'
                        ELSE 'Open'
                    END,
                    verification_notes, created_at, updated_at
                FROM remediation;
                """
            )
        cursor.execute("DROP TABLE remediation;")
        cursor.execute("ALTER TABLE remediation_new RENAME TO remediation;")

    # Ensure child tables exist
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
            finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            notes TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(remediation_id, finding_id)
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_risks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
            risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
            notes TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(remediation_id, risk_id)
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_controls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
            control_assessment_id INTEGER NOT NULL REFERENCES control_assessments(id) ON DELETE CASCADE,
            notes TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(remediation_id, control_assessment_id)
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
            evidence_id INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
            evidence_type TEXT NOT NULL DEFAULT 'Remediation Evidence' CHECK(evidence_type IN ('Remediation Evidence', 'Verification Evidence', 'Audit Evidence', 'Supporting Policy', 'Other')),
            notes TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(remediation_id, evidence_id)
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
            progress_percentage INTEGER NOT NULL CHECK(progress_percentage BETWEEN 0 AND 100),
            description TEXT NOT NULL,
            blockers TEXT,
            updated_by TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_deadline_extensions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
            previous_deadline TEXT NOT NULL,
            new_deadline TEXT NOT NULL,
            extension_reason TEXT NOT NULL,
            approving_authority TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS remediation_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            remediation_id INTEGER NOT NULL REFERENCES remediation(id) ON DELETE CASCADE,
            verification_reference TEXT NOT NULL,
            verification_objective TEXT NOT NULL,
            verification_procedure TEXT NOT NULL,
            expected_outcome TEXT NOT NULL,
            observed_outcome TEXT NOT NULL,
            sample_examined TEXT,
            evidence_references TEXT,
            related_control_testing_records TEXT,
            evidence_limitations TEXT,
            verifier_name TEXT NOT NULL,
            verification_date TEXT NOT NULL,
            verification_result TEXT NOT NULL CHECK(verification_result IN ('Effective', 'Ineffective', 'Inconclusive')),
            verification_notes TEXT,
            recommended_next_action TEXT,
            created_at TEXT NOT NULL
        );
        """
    )


def sync_controls_catalogue(conn: sqlite3.Connection, catalogue_path: Optional[Path] = None) -> None:
    """
    Idempotently sync the 20 selected ISO 27001 Annex A controls from data/controls.json into
    the controls table. Updates metadata while preserving primary keys.
    """
    path = catalogue_path or CONTROLS_JSON_PATH
    if not path.exists():
        return

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    controls_list = data.get("controls", [])
    now_iso = get_utc_now_iso()
    cursor = conn.cursor()

    for ctrl in controls_list:
        clause = ctrl.get("clause", "Annex A")
        ident = ctrl["control_identifier"]
        title = ctrl["title"]
        desc = ctrl["description"]
        domain = ctrl["category"]
        objective = ctrl.get("objective", "")
        questions_json = json.dumps(ctrl.get("assessment_questions", []))
        evidence_json = json.dumps(ctrl.get("suggested_evidence", []))
        gaps_json = json.dumps(ctrl.get("example_gaps", []))
        recs_json = json.dumps(ctrl.get("example_recommendations", []))

        cursor.execute("SELECT id FROM controls WHERE control_identifier = ?", (ident,))
        row = cursor.fetchone()

        if row:
            cursor.execute(
                """
                UPDATE controls
                SET clause = ?, title = ?, description = ?, domain = ?,
                    objective = ?, assessment_questions = ?, suggested_evidence = ?,
                    example_gaps = ?, example_recommendations = ?
                WHERE control_identifier = ?
                """,
                (
                    clause,
                    title,
                    desc,
                    domain,
                    objective,
                    questions_json,
                    evidence_json,
                    gaps_json,
                    recs_json,
                    ident,
                ),
            )
        else:
            cursor.execute(
                """
                INSERT INTO controls (
                    standard, clause, control_identifier, title, description, domain,
                    objective, assessment_questions, suggested_evidence,
                    example_gaps, example_recommendations, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "ISO/IEC 27001:2022",
                    clause,
                    ident,
                    title,
                    desc,
                    domain,
                    objective,
                    questions_json,
                    evidence_json,
                    gaps_json,
                    recs_json,
                    now_iso,
                ),
            )


def initialize_assessment_controls(conn: sqlite3.Connection, assessment_id: int) -> int:
    """
    Ensure all 20 catalogue controls exist for a given assessment with 'Not Assessed' status.
    Repeated calls are idempotent and do NOT overwrite existing observations, owners, or statuses.
    Returns the number of newly initialized control assessment rows.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT id, control_identifier FROM controls ORDER BY id ASC")
    all_controls = cursor.fetchall()
    now_iso = get_utc_now_iso()
    inserted_count = 0

    for c in all_controls:
        cid = c["id"]
        cursor.execute(
            "SELECT id FROM control_assessments WHERE assessment_id = ? AND control_id = ?",
            (assessment_id, cid),
        )
        if not cursor.fetchone():
            cursor.execute(
                """
                INSERT INTO control_assessments (
                    assessment_id, control_id, status, created_at, updated_at
                ) VALUES (?, ?, 'Not Assessed', ?, ?)
                """,
                (assessment_id, cid, now_iso, now_iso),
            )
            inserted_count += 1

    return inserted_count


def initialize_missing_controls_for_all_assessments(conn: sqlite3.Connection) -> None:
    """
    Safely initialize missing control assessment rows for any existing assessments
    (such as assessments created during Phase 1) without overwriting existing data.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM assessments")
    assessments = cursor.fetchall()
    for asm in assessments:
        initialize_assessment_controls(conn, asm["id"])


def init_db(db_path: Optional[str | Path] = None) -> None:
    """
    Idempotently initialize SQLite database tables, indices, triggers, migrations,
    controls catalogue synchronization, and assessment control rows.
    Does NOT overwrite or erase existing records if tables or data already exist.
    """
    with db_session(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        run_migrations(conn)
        conn.executescript(INDICES_SQL)
        conn.executescript(TRIGGERS_SQL)
        sync_controls_catalogue(conn)
        initialize_missing_controls_for_all_assessments(conn)

    # Ensure storage directory exists
    EVIDENCE_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
