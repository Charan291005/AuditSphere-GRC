"""
AuditSphere - SQLite Database Initialization and Connection Management.

Features:
- Parameterized SQL execution
- SQLite foreign key enforcement enabled on every connection
- Context manager for robust transaction lifecycle (commit / rollback)
- Strict relational integrity preventing cross-assessment linking
- Idempotent schema initialization that preserves existing records
"""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, Optional

# Default path to SQLite database file
DEFAULT_DB_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "auditsphere.db"


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

-- 2. Reference Security Controls (ISO/IEC 27001:2022)
CREATE TABLE IF NOT EXISTS controls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    standard TEXT NOT NULL DEFAULT 'ISO/IEC 27001:2022',
    clause TEXT NOT NULL, -- e.g. 'Annex A.5', 'Annex A.6'
    control_identifier TEXT NOT NULL UNIQUE, -- e.g. 'A.5.1'
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    domain TEXT NOT NULL, -- 'Organizational', 'People', 'Physical', 'Technological'
    guidance TEXT,
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
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    file_hash TEXT, -- SHA-256 integrity hash
    uploaded_by TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
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

-- 6. Audit Findings (Gaps, Non-conformities, Observations)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    control_assessment_id INTEGER REFERENCES control_assessments(id) ON DELETE SET NULL,
    finding_identifier TEXT NOT NULL, -- e.g. 'FND-001'
    title TEXT NOT NULL,
    finding_type TEXT NOT NULL CHECK(finding_type IN ('Major Non-Conformity', 'Minor Non-Conformity', 'Opportunity for Improvement', 'Observation')),
    severity TEXT NOT NULL CHECK(severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    description TEXT NOT NULL,
    criteria TEXT,
    condition TEXT,
    cause TEXT,
    effect TEXT,
    recommendation TEXT,
    status TEXT NOT NULL CHECK(status IN ('Open', 'Under Review', 'Remediation In Progress', 'Remediated', 'Accepted Risk', 'Closed')) DEFAULT 'Open',
    identified_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(assessment_id, finding_identifier)
);

-- 7. Risk Register
CREATE TABLE IF NOT EXISTS risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    finding_id INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    risk_identifier TEXT NOT NULL, -- e.g. 'RSK-001'
    title TEXT NOT NULL,
    description TEXT,
    asset_threat_vulnerability TEXT,
    likelihood INTEGER NOT NULL CHECK(likelihood BETWEEN 1 AND 5),
    impact INTEGER NOT NULL CHECK(impact BETWEEN 1 AND 5),
    inherent_risk_score INTEGER NOT NULL, -- likelihood * impact
    inherent_risk_level TEXT NOT NULL CHECK(inherent_risk_level IN ('Low', 'Medium', 'High', 'Critical')),
    treatment_strategy TEXT NOT NULL CHECK(treatment_strategy IN ('Mitigate', 'Transfer', 'Avoid', 'Accept')) DEFAULT 'Mitigate',
    residual_likelihood INTEGER CHECK(residual_likelihood IS NULL OR (residual_likelihood BETWEEN 1 AND 5)),
    residual_impact INTEGER CHECK(residual_impact IS NULL OR (residual_impact BETWEEN 1 AND 5)),
    residual_risk_score INTEGER,
    residual_risk_level TEXT CHECK(residual_risk_level IS NULL OR (residual_risk_level IN ('Low', 'Medium', 'High', 'Critical'))),
    risk_owner TEXT,
    status TEXT NOT NULL CHECK(status IN ('Identified', 'Evaluated', 'Treatment Planned', 'Monitoring', 'Closed')) DEFAULT 'Identified',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(assessment_id, risk_identifier)
);

-- 8. Remediation Tracker
CREATE TABLE IF NOT EXISTS remediation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    risk_id INTEGER REFERENCES risks(id) ON DELETE SET NULL,
    remediation_identifier TEXT NOT NULL, -- e.g. 'REM-001'
    action_title TEXT NOT NULL,
    action_description TEXT NOT NULL,
    action_owner TEXT NOT NULL,
    target_date TEXT NOT NULL, -- YYYY-MM-DD
    actual_completion_date TEXT, -- YYYY-MM-DD
    status TEXT NOT NULL CHECK(status IN ('Not Started', 'In Progress', 'Pending Verification', 'Verified & Closed', 'Deferred')) DEFAULT 'Not Started',
    verification_notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(assessment_id, remediation_identifier)
);

-- 9. Activity Log (Assessment lifecycle history)
CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER REFERENCES assessments(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL, -- e.g. 'ASSESSMENT_CREATED', 'ASSESSMENT_EDITED', 'ASSESSMENT_ARCHIVED'
    description TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'Lead Assessor',
    timestamp TEXT NOT NULL
);

-- Performance indices
CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);
CREATE INDEX IF NOT EXISTS idx_control_assessments_aid ON control_assessments(assessment_id);
CREATE INDEX IF NOT EXISTS idx_control_assessments_cid ON control_assessments(control_id);
CREATE INDEX IF NOT EXISTS idx_evidence_aid ON evidence(assessment_id);
CREATE INDEX IF NOT EXISTS idx_control_evidence_caid ON control_evidence(control_assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_aid ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_risks_aid ON risks(assessment_id);
CREATE INDEX IF NOT EXISTS idx_remediation_aid ON remediation(assessment_id);
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
        WHEN (SELECT assessment_id FROM findings WHERE id = NEW.finding_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: finding does not belong to remediation assessment')
        WHEN NEW.risk_id IS NOT NULL AND (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to remediation assessment')
    END;
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_cross_assessment_remediation_update
BEFORE UPDATE ON remediation
BEGIN
    SELECT CASE
        WHEN (SELECT assessment_id FROM findings WHERE id = NEW.finding_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: finding does not belong to remediation assessment')
        WHEN NEW.risk_id IS NOT NULL AND (SELECT assessment_id FROM risks WHERE id = NEW.risk_id) != NEW.assessment_id
        THEN RAISE(ABORT, 'Cross-assessment violation: risk does not belong to remediation assessment')
    END;
END;
"""


def init_db(db_path: Optional[str | Path] = None) -> None:
    """
    Idempotently initialize SQLite database tables, indices, and triggers.
    Does NOT overwrite or erase existing records if tables already exist.
    """
    with db_session(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.executescript(TRIGGERS_SQL)
