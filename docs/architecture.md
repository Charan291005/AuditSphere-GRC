# AuditSphere Architecture Documentation

## 1. System Overview

AuditSphere is a portfolio-grade Governance, Risk and Compliance (GRC) platform engineered to simulate an **ISO/IEC 27001:2022** assessment lifecycle. The system provides structured assessment workspace management, Annex A security control evaluation, evidence traceability, gap analysis, qualitative risk registers, and remediation workflows.

```
+-------------------------------------------------------------+
|                     Streamlit UI Shell                      |
|  (App Router, Persistent Sidebar, Theme Engine, Layouts)   |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                       Service Layer                         |
|   (AssessmentService, ControlService, AssessmentEngine,     |
|             DashboardService, ActivityService)              |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                     Data Access Layer                       |
|   (SQLite Parameterized Engine, Transactions, WAL Mode)     |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                   SQLite Relational Store                   |
|       (Foreign Keys ON, Cross-Assessment Triggers)          |
+-------------------------------------------------------------+
```

---

## 2. Architectural Design Principles

1. **Simplicity and Modularity**: Clear separation of user interface rendering (`pages/`, `ui_components.py`), domain services (`services/`), and data storage (`database.py`).
2. **Defensive Data Integrity**:
   - Parameterized SQL execution exclusively (`?` placeholders) to eliminate SQL injection vulnerabilities.
   - Enforced SQLite foreign keys (`PRAGMA foreign_keys = ON;`) on every connection.
   - Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) for high concurrency.
   - Cross-assessment relational isolation enforced via database triggers to prevent linking artifacts across distinct assessment boundaries.
   - Archived assessments are strictly protected against modification.
3. **Authentic GRC Metrics & Scoring Engine**:
   - Deterministic calculations implemented via pure functions in `services/assessment_engine.py`.
   - Coverage: $\frac{\text{Assessed Applicable}}{\text{Total Applicable}} \times 100$.
   - Weighted Readiness: $\frac{\text{Implemented} + 0.5 \times \text{Partially Implemented}}{\text{Assessed Applicable}} \times 100$.
   - Zero hardcoded or simulated percentages; unassessed assessments display `N/A`.
4. **Idempotency & Repeat-Safe Operations**:
   - Schema creation and column migrations run repeat-safely.
   - Control catalogue (`data/controls.json`) synchronizes without overwriting custom observations.
   - Fictional demonstration dataset (FinCore Technologies) can be generated repeatedly without duplicate assessment pollution.
5. **Portability**: Uses exclusively free and open-source libraries (Python, Streamlit, SQLite, Pandas, Plotly, Pytest).

---

## 3. Database Schema & Entity-Relationship Model

```mermaid
erDiagram
    assessments ||--o{ control_assessments : "contains"
    assessments ||--o{ evidence : "holds"
    assessments ||--o{ findings : "identifies"
    assessments ||--o{ risks : "evaluates"
    assessments ||--o{ remediation : "tracks"
    assessments ||--o{ activity_log : "logs"

    controls ||--o{ control_assessments : "referenced by"

    control_assessments ||--o{ control_evidence : "supported by"
    evidence ||--o{ control_evidence : "mapped to"

    control_assessments ||--o{ findings : "originates"
    findings ||--o{ risks : "manifests"
    findings ||--o{ remediation : "remediated by"
    risks ||--o{ remediation : "mitigated by"

    assessments {
        int id PK
        string title
        string organization
        string industry
        string standard
        string scope
        string objectives
        string lead_assessor
        string assessment_date
        string status
        string created_at
        string updated_at
    }

    controls {
        int id PK
        string standard
        string clause
        string control_identifier UK
        string title
        string description
        string domain
        string objective
        string assessment_questions
        string suggested_evidence
        string example_gaps
        string example_recommendations
        string created_at
    }

    control_assessments {
        int id PK
        int assessment_id FK
        int control_id FK
        string status
        string control_owner
        string assessment_observation
        string testing_notes
        string evidence_notes
        string recommendation
        string applicability_justification
        string assessed_by
        string assessed_at
        string created_at
        string updated_at
    }

    evidence {
        int id PK
        int assessment_id FK
        string evidence_identifier
        string title
        string description
        string file_name
        string file_path
        int file_size
        string file_hash
        string uploaded_by
        string uploaded_at
    }

    control_evidence {
        int id PK
        int assessment_id FK
        int control_assessment_id FK
        int evidence_id FK
        string mapped_at
        string notes
    }

    findings {
        int id PK
        int assessment_id FK
        int control_assessment_id FK
        string finding_identifier
        string title
        string finding_type
        string severity
        string description
        string criteria
        string condition
        string cause
        string effect
        string recommendation
        string status
        string identified_at
        string updated_at
    }

    risks {
        int id PK
        int assessment_id FK
        int finding_id FK
        string risk_identifier
        string title
        string description
        string asset_threat_vulnerability
        int likelihood
        int impact
        int inherent_risk_score
        string inherent_risk_level
        string treatment_strategy
        int residual_likelihood
        int residual_impact
        int residual_risk_score
        string residual_risk_level
        string risk_owner
        string status
        string created_at
        string updated_at
    }

    remediation {
        int id PK
        int assessment_id FK
        int finding_id FK
        int risk_id FK
        string remediation_identifier
        string action_title
        string action_description
        string action_owner
        string target_date
        string actual_completion_date
        string status
        string verification_notes
        string created_at
        string updated_at
    }

    activity_log {
        int id PK
        int assessment_id FK
        string event_type
        string description
        string actor
        string control_reference
        string previous_status
        string new_status
        string timestamp
    }
```

---

## 4. Cross-Assessment Relational Isolation Triggers

To prevent evidence, findings, and risks from one assessment accidentally becoming mapped to another assessment, SQLite triggers are compiled directly into the database engine:

1. `trg_prevent_cross_assessment_control_evidence_insert / update`: Aborts operation if `control_assessments.assessment_id != NEW.assessment_id` or `evidence.assessment_id != NEW.assessment_id`.
2. `trg_prevent_cross_assessment_finding_insert / update`: Aborts operation if `control_assessments.assessment_id != NEW.assessment_id`.
3. `trg_prevent_cross_assessment_risk_insert / update`: Aborts operation if `findings.assessment_id != NEW.assessment_id`.
4. `trg_prevent_cross_assessment_remediation_insert / update`: Aborts operation if `findings.assessment_id != NEW.assessment_id` or `risks.assessment_id != NEW.assessment_id`.

---

## 5. Control Evaluation State Machine

```
   +---------------------+
   |    Not Assessed     | (Initial state)
   +----------+----------+
              |
              +-------------------+--------------------+
              |                   |                    |
              v                   v                    v
     +-----------------+  +-----------------+  +----------------+
     |   Implemented   |  |   Partially     |  | Not Applicable |
     | (Observation    |  |  Implemented    |  | (Justification |
     |  Required)      |  | & Not Implem.   |  |  Required)     |
     +-----------------+  | (Obs + Rec Req) |  +----------------+
                          +-----------------+
```
