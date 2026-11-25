# AuditSphere – ISMS Audit & Compliance Assessment Platform

AuditSphere is a portfolio-grade Governance, Risk and Compliance (GRC) application that simulates an **ISO/IEC 27001:2022** assessment lifecycle.

> [!IMPORTANT]
> **Educational & Portfolio Disclaimer:**
> AuditSphere is an educational simulation and portfolio GRC software tool. It is **not** an accredited certification auditing platform. Conducting an assessment within this software does not constitute formal certification, accredited compliance, or official conformity with ISO/IEC 27001 or any legal regulatory regime.

---

## 1. Problem Statement

Security control assessments, audit evidence artifacts, identified gap findings, risk registers, and corrective action remediation plans are frequently fragmented across disparate spreadsheets, emails, and shared folders.

This fragmentation leads to:
- Broken audit trails and lost evidence context.
- Lack of traceability from identified gaps to risk treatment plans.
- High administrative overhead during annual internal audits or surveillance reviews.

AuditSphere solves this by providing a unified assessment workspace with structured relational records, foreign key integrity, lifecycle traceability, and reporting.

---

## 2. Technology Stack

- **Application Framework:** Python 3.13+, Streamlit
- **Database Engine:** SQLite (WAL Mode, Parameterized Queries, Foreign Keys Enforced)
- **Data & Visualizations:** Pandas, Plotly
- **Document Generation:** ReportLab
- **Testing:** Pytest
- **VCS:** Git

No external LLM APIs, paid services, microservices, or complex container dependencies are required.

---

## 3. Implemented Phase 1 Functionality

- **Project Foundation:**
  - Standard enterprise directory structure (`pages/`, `services/`, `data/`, `storage/`, `tests/`, `docs/`).
  - Strict `.gitignore` preventing database files or uploaded artifacts from being committed.
  - Streamlit configuration with custom enterprise palette (Primary accent: `#751C35`).
- **Relational Database Foundation:**
  - Idempotent schema initialization across 9 tables: `assessments`, `controls`, `control_assessments`, `evidence`, `control_evidence`, `findings`, `risks`, `remediation`, `activity_log`.
  - SQLite foreign key enforcement enabled on every connection.
  - Multi-level triggers ensuring cross-assessment relational isolation.
- **Application Shell & Design System:**
  - Persistent left sidebar with AuditSphere branding and active assessment selector.
  - Navigation across all 9 planned modules with Phase status labeling.
  - Custom CSS styling with accessible contrast, professional card hierarchy, and status badges.
- **Assessment Management Module (Fully Functional):**
  - Create assessments (Title, Organization, Industry, Scope, Objectives, Lead Assessor, Target Date, Initial Status).
  - Validation of mandatory inputs and date formats.
  - Directory view with status filter, search query, and active workspace indicator.
  - Inline editing of existing assessments.
  - Archival of assessments.
- **Overview Dashboard (Fully Functional):**
  - Live KPI cards calculated directly from SQLite records (Total, Active, Archived, Current Context).
  - Active assessment scope and detail card.
  - Assessment pipeline status breakdown.
  - Activity log stream showing recent lifecycle events.
  - Zero hardcoded or fake compliance metrics.
- **Activity Logging:**
  - Automatic recording of `ASSESSMENT_CREATED`, `ASSESSMENT_EDITED`, and `ASSESSMENT_ARCHIVED` events.
- **Automated Verification:**
  - 10 comprehensive unit and integration tests passing with 100% success.

---

## 4. Planned Functionality (Subsequent Phases)

- **Phase 2:**
  - ISO/IEC 27001:2022 Control Assessment Module (Annex A domains).
  - Evidence Management (Upload, SHA-256 integrity hashing, control mapping).
  - Gap Analysis (Findings taxonomy, CCCER structure).
- **Phase 3:**
  - Qualitative Risk Register (5x5 matrix, inherent vs residual risk).
  - Remediation Tracker (Corrective Action Plans, target dates, verification).
  - Assessment Reports (Executive PDF summary export via ReportLab, CSV exports).
  - System Settings & Framework Customization.

---

## 5. Installation Instructions

### Prerequisites
- Python 3.10+ (Python 3.13 recommended)
- Git

### Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd Auditsphere
   ```

2. **Create and activate a virtual environment:**
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 6. Application Launch Command

Launch the Streamlit application:

```bash
streamlit run app.py
```

The application will be accessible at: `http://localhost:8501`

---

## 7. Running Automated Tests

Run the full pytest suite:

```bash
pytest tests/ -v
```

All 10 tests should pass cleanly without errors.
