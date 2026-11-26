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
- **Testing:** Pytest (30 automated tests)
- **VCS:** Git

No external LLM APIs, paid services, microservices, or complex container dependencies are required.

---

## 3. Implemented Capabilities

### Phase 1 Foundation
- Enterprise directory structure and strict `.gitignore` (database and uploaded files are never committed).
- Idempotent SQLite relational schema across 9 tables with foreign keys and multi-level triggers preventing cross-assessment linking.
- Assessment Management: Create, edit, filter, archive, and select active assessment workspaces.
- Overview Dashboard with genuine database-derived KPIs and operational activity logging.

### Phase 2: ISO 27001 Selected-Control Assessment Engine
- **Educational Control Catalogue (`data/controls.json`):**
  - Exactly **20 selected Annex A controls** representing all four ISO/IEC 27001:2022 themes:
    - **Organizational (6):** `A.5.1`, `A.5.15`, `A.5.18`, `A.5.24`, `A.5.31`, `A.5.34`
    - **People (4):** `A.6.1`, `A.6.3`, `A.6.6`, `A.6.8`
    - **Physical (4):** `A.7.1`, `A.7.2`, `A.7.4`, `A.7.7`
    - **Technological (6):** `A.8.2`, `A.8.5`, `A.8.8`, `A.8.13`, `A.8.15`, `A.8.24`
  - Each control includes control ID, Annex A reference, objective, paraphrased description, practical assessment questions, suggested evidence types, example gaps, and remediation guidance.
- **Control Evaluation Workspace (`pages/control_assessment_page.py`):**
  - Real-time search by reference, title, or owner.
  - Domain filter (Organizational, People, Physical, Technological) and status filter.
  - Interactive assessment form supporting: Implementation Status, Control Owner, Assessment Observation, Testing Notes, Evidence References, Recommendation, Applicability Justification, Assessor Name, and Assessment Date.
  - **Strict Validation Rules:**
    - `Implemented` controls require documented observations.
    - `Partially Implemented` and `Not Implemented` require observations and recommendations.
    - `Not Applicable` requires an applicability justification.
    - Assessed controls require assessor name and assessment date.
    - Archived assessments are strictly protected against modifications.
- **Deterministic Assessment Scoring Engine (`services/assessment_engine.py`):**
  - **Applicable Controls:** Selected controls excluding `Not Applicable`.
  - **Assessed Applicable Controls:** Controls marked `Implemented`, `Partially Implemented`, or `Not Implemented`.
  - **Assessment Coverage (%):** $(\text{Assessed Applicable} / \text{Total Applicable}) \times 100$.
  - **Weighted Readiness Score (%):** $(\text{Implemented} + 0.5 \times \text{Partially Implemented}) / \text{Assessed Applicable} \times 100$.
  - **Potential Control Gaps:** $\text{Partially Implemented} + \text{Not Implemented}$.
  - Zero-assessed or zero-applicable assessments display `N/A`.
- **Upgraded Overview Dashboard (`pages/overview_page.py`):**
  - Live control assessment KPI cards.
  - Plotly donut chart of control implementation status distribution.
  - Plotly stacked bar chart of assessment progress by control theme.
  - Plotly grouped bar chart of domain weighted readiness scores.
- **Fictional Demonstration Dataset (FinCore Technologies):**
  - Repeat-safe demo generator seeding 20 controls: 7 Implemented, 3 Partially Implemented, 2 Not Implemented, 8 Not Assessed, 0 Not Applicable.
  - Produces exact verified metrics: 60.0% Coverage, 70.83% Weighted Readiness, 5 Potential Gaps, 8 Pending.

---

## 4. Demonstration Dataset Instructions

To explore AuditSphere with a pre-populated, realistic simulated assessment:

1. Launch the application: `streamlit run app.py`
2. Navigate to **ISO 27001 Control Assessment** or **Overview Dashboard**.
3. Click the **"Load Demo Data (FinCore)"** button.
4. The system will load the fictional assessment for **FinCore Technologies** ($ID\ \#2$).
5. Inspect the 12 evaluated controls, audit observations, testing notes, and live readiness charts.

---

## 5. Installation Instructions

### Prerequisites
- Python 3.10+ (Python 3.13 tested)
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

Access the interface at: `http://localhost:8501`

---

## 7. Running Automated Tests

Run the full pytest suite (covering Phase 1 and Phase 2):

```bash
pytest tests/ -v
```

All 30 automated unit and integration tests pass with 100% success.
