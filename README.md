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
- **Testing:** Pytest (82 automated tests)
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
### Phase 3: Evidence Management, Control Testing & Gap Analysis
- **Audit Evidence Repository (`pages/evidence_page.py`, `services/evidence_manager.py`):**
  - File upload with strict magic-byte validation (PDF, PNG, JPG, CSV, TXT, XLSX) and 10 MB size limits.
  - Safe storage path traversal defense with unique UUID server-side storage naming.
  - SHA-256 cryptographic hashing with on-demand local file integrity checks (`Verified`, `Hash mismatch`, `File missing`).
  - Comprehensive 4-tier auditor review workflow (`Pending Review`, `Accepted`, `Needs Clarification`, `Rejected`) with mandatory reviewer name, notes, and quality ratings (relevance, sufficiency, reliability).
  - Many-to-many evidence-to-control mapping backed by SQLite cross-assessment database isolation triggers.
- **Control Testing Documentation (`services/gap_engine.py`):**
  - Structured test recording for Design effectiveness, Operating effectiveness, Walkthroughs, Document reviews, and Configuration reviews.
  - Enforced test conclusion governance (Pass, Fail, Inconclusive, Not tested) requiring documented expected and observed outcomes.
- **Automated Gap Analysis & Deficiency Engine (`pages/gap_analysis_page.py`):**
  - Heuristic detection of implementation gaps, failed tests, evidence deficiencies, and pending controls without auto-mutating manual control evaluations.
  - One-click promotion from identified gaps into formal audit findings.
- **Formal CCCER Audit Findings Lifecycle:**
  - Comprehensive 5-part CCCER methodology: Criteria, Condition, Cause, Effect/Impact, Recommendation.
  - Mandatory evidence references or explicitly documented evidence limitations.
  - Severity classification (Critical, High, Medium, Low, Informational) and non-conformity types.
  - Strict closure governance requiring auditor verification notes before transitioning to `Closed`.
  - Full working-paper traceability view: Control -> Evidence -> Test Record -> Formal Finding.
- **Expanded Fictional Demonstration Dataset (FinCore Technologies):**
  - Pre-seeded with 5 original evidence artifacts, 1 failed operating effectiveness test (`TST-001` on `A.8.5`), and 1 confirmed High-severity finding (`FND-001` on `A.8.5`).
  - Completely repeat-safe / idempotent generation.

### Phase 4: Risk Register, Scoring Engine & Interactive Heatmap
- **Risk Register Workspace (`pages/risk_page.py`, `services/risk_service.py`):**
  - Comprehensive risk directory with real-time text search, category filters, severity filters, and treatment status filters.
  - Multi-tab architecture: Directory, 5×5 Plotly Heatmap, 5-Section Risk Entry/Edit Form, and Working Paper Detail View.
  - CSV export with formula injection defense (CWE-1236) neutralizing spreadsheet formula prefixes.
- **Three-Tier Qualitative Risk Evaluation Engine (`services/risk_engine.py`):**
  - **Inherent Risk:** Pre-control baseline exposure ($1 \le L \le 5$, $1 \le I \le 5$).
  - **Current Residual Risk:** Active post-control operational posture.
  - **Target Residual Risk:** Desired post-treatment goal. (Strictly preserved as an aspirational target that never overwrites active current residual scores).
  - Explicit handling for unassessed risks (`Score = None`, `Severity = "Not Assessed"`), strictly avoiding misleading `0` values.
  - Severity thresholds: Critical (20–25, `#751C35`), High (12–19, `#D9534F`), Medium (6–11, `#F0AD4E`), Low (1–5, `#5CB85C`).
- **Traceability & Relational Links:**
  - Direct many-to-many linkages from risks to confirmed audit findings (`risk_findings`), Annex A controls (`risk_controls`), and verified evidence files (`risk_evidence`).
  - Cross-assessment isolation enforced via compiled SQLite database triggers preventing cross-boundary references.
  - One-click risk creation from Gap Analysis findings pre-populating title, threat, consequence, and recommended treatment.
- **Governance Controls & Review Ledger:**
  - Enforced Risk Acceptance gate requiring documented justification and approval status `Approved`.
  - Enforced Risk Closure gate requiring documented closure rationale.
  - Automated reassessment tracking logging historical score adjustments to `risk_reviews`.
  - Overdue review tracking based on residual severity cadences (Monthly, Quarterly, Semi-Annually, Annually).
- **Interactive 5×5 Plotly Heatmap:**
  - Visual matrix with dynamic tier toggle (Inherent, Current Residual, Target Residual).
  - Interactive cell inspection displaying matching risk records with their current treatment strategies.
- **FinCore Technologies Phase 4 Risk Expansion:**
  - 5 realistic demonstration risks seeded with diverse severity: Critical (`RSK-001`), High (`RSK-002`, `RSK-003`), Medium (`RSK-004`), Low (`RSK-005`).

### Phase 5: Remediation and Corrective Action Management
- **Remediation Tracker Workspace (`pages/remediation_page.py`):**
  - Complete 4-tab interface: Action Directory & Register, 5-Section Corrective Action Form, Working Paper & Traceability View, and Lifecycle & Governance Actions.
  - Multi-criteria filtering by lifecycle status, priority, owner, department, linked finding, risk, or control.
  - CSV export with formula injection defense (CWE-1236) neutralizing spreadsheet formula prefixes.
- **Root Cause Analysis (RCA) Engine (`services/remediation_engine.py`):**
  - Distinction between immediate containment (correction) and systemic corrective action (Clause 10.2).
  - Interactive **5 Whys Problem Decomposition** interface with structured problem statement, iterative why-levels, and root cause synthesis.
  - Support for Direct Analysis and justified exceptions (`Not Appropriate` with mandatory rationale).
- **Corrective Action Lifecycle State Machine:**
  - Permitted transitions: `Open`, `In Progress`, `Awaiting Verification`, `Under Verification`, `Reopened`, `Closed`, `Cancelled`.
  - Prohibited direct jumps (e.g. `Open` -> `Closed`, `In Progress` -> `Closed` are strictly blocked).
  - Strict closure governance: requires 100% progress, implementation summary, supporting evidence without integrity warnings, latest verification `Effective`, documented closure rationale, and root cause or justification.
- **Progress Tracking & Deadline Extension Governance:**
  - Granular progress percentage tracking (0% to 100%) with immutable chronological history ledger.
  - Formal deadline extensions capturing previous deadline, new deadline, justification, and approving authority.
- **Effectiveness Verification Ledger:**
  - Structured verification working paper documenting objective, procedure, expected vs. observed outcome, sample examined, verifier identity, date, and result (`Effective`, `Partially Effective`, `Ineffective`).
- **Audit Findings Downstream Traceability Gate:**
  - Audit findings cannot be marked `Closed` if any linked corrective actions remain open or unverified.
- **Explicit Control & Risk Reassessments:**
  - Closing an action does not auto-mutate control statuses or risk scores; dedicated forms support explicit, documented reassessments with audit logging.
- **FinCore Technologies Phase 5 Remediation Expansion:**
  - 5 realistic demonstration corrective actions seeded: `ACT-001` (In Progress, 60%), `ACT-002` (Open, 0%), `ACT-003` (Open, 0%), `ACT-004` (Awaiting Verification, 100%), `ACT-005` (Closed, 100%, Verified Effective). Verified closure rate: 20%.

---

## 4. Demonstration Dataset Instructions

To explore AuditSphere with a pre-populated, realistic simulated assessment:

1. Launch the application: `streamlit run app.py`
2. Navigate to **Overview Dashboard**, **ISO 27001 Control Assessment**, **Evidence Management**, **Gap Analysis & Findings**, **Risk Register**, or **Remediation Tracker**.
3. Click the **"Load Demo Data (FinCore)"** button if not already loaded.
4. The system will load the fictional assessment for **FinCore Technologies** ($ID\ \#2$).
5. Inspect the 12 evaluated controls, 5 evidence files with SHA-256 verification, failed control test `TST-001`, corroborated finding `FND-001`, 5 classified risks with active residual heatmap distribution, and 5 corrective actions with 20% verified closure rate.

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

Run the full pytest suite (covering Phases 1 through 5):

```bash
pytest tests/ -v
```

All 82 automated unit and integration tests pass with 100% success.
