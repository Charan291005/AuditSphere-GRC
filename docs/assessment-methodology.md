# AuditSphere – Assessment & Scoring Methodology

## 1. Overview & Purpose

AuditSphere provides a structured, simulated evaluation engine aligned with the principles of **ISO/IEC 27001:2022**. This document explains the quantitative and qualitative methodology used to calculate control status counts, assessment coverage, weighted readiness scores, and potential control gaps.

> [!IMPORTANT]
> **Educational Simulation Disclaimer:**
> AuditSphere is an educational simulation and portfolio GRC demonstration tool. The metrics, readiness scores, and gap calculations produced by this application reflect a selected subset of 20 Annex A controls and do **not** constitute an accredited ISO/IEC 27001 certification audit, formal gap assessment, or statement of regulatory conformity.

---

## 2. Selected Annex A Control Scope

Phase 2 introduces an educational subset of exactly **20 reference controls** from ISO/IEC 27001:2022 Annex A, categorized into the 4 standard domains:

| Theme | Selected Controls | Reference Identifiers |
|---|---|---|
| **Organizational (Clause 5)** | 6 Controls | `A.5.1` (Policies), `A.5.15` (Access Control), `A.5.18` (Access Rights), `A.5.24` (Incident Prep), `A.5.31` (Legal/Regulatory), `A.5.34` (PII Protection) |
| **People (Clause 6)** | 4 Controls | `A.6.1` (Screening), `A.6.3` (Security Awareness), `A.6.6` (NDAs/Confidentiality), `A.6.8` (Event Reporting) |
| **Physical (Clause 7)** | 4 Controls | `A.7.1` (Security Perimeters), `A.7.2` (Physical Entry), `A.7.4` (Monitoring), `A.7.7` (Clear Desk & Screen) |
| **Technological (Clause 8)** | 6 Controls | `A.8.2` (Privileged Access), `A.8.5` (Authentication), `A.8.8` (Vulnerability Mgmt), `A.8.13` (Backup), `A.8.15` (Logging), `A.8.24` (Cryptography) |

---

## 3. Implementation Statuses & Validation Criteria

An assessor evaluates each control against one of five strictly validated implementation states:

| Status | Weight | Meaning & Evidence Standard | Mandatory Input Rules |
|---|---|---|---|
| **Not Assessed** | N/A | Default state. Control has not yet been audited. | No requirements; excluded from readiness calculations. |
| **Implemented** | 1.0 | Control is fully designed, documented, and operational according to organizational policy. | Requires documented **assessment observations**. Requires assessor name and date. |
| **Partially Implemented** | 0.5 | Control is partially operational, inconsistently applied, or lacks complete documentation/coverage. | Requires documented **observations** AND actionable **remediation recommendations**. Requires assessor name and date. |
| **Not Implemented** | 0.0 | Control is completely missing, ineffective, or neglected despite being in scope. | Requires documented **observations** AND actionable **remediation recommendations**. Requires assessor name and date. |
| **Not Applicable** | Excluded | Control is formally justified as outside the ISMS boundary (e.g. no physical facilities). | Requires documented **applicability justification**. Requires assessor name and date. |

---

## 4. Quantitative Scoring Formulas

All metrics are calculated via pure deterministic functions in `services/assessment_engine.py`:

### A. Applicable Controls
Defined as all controls within the selected catalogue excluding controls marked as `Not Applicable`:
$$\text{Applicable Controls} = \text{Total Selected Controls} - \text{Count}(\text{Not Applicable})$$

### B. Assessed Applicable Controls
Controls within scope that have received an evaluation:
$$\text{Assessed Controls} = \text{Count}(\text{Implemented}) + \text{Count}(\text{Partially Implemented}) + \text{Count}(\text{Not Implemented})$$

### C. Assessment Coverage (%)
The percentage of in-scope controls that have been assessed by the auditor:
$$\text{Assessment Coverage (\%)} = \left( \frac{\text{Assessed Applicable Controls}}{\text{Total Applicable Controls}} \right) \times 100$$
*Note: If Total Applicable Controls is 0, Coverage returns `N/A`.*

### D. Weighted Readiness Score (%)
Reflects implementation maturity across **only the assessed controls**. `Not Implemented` contributes 0 points. `Not Assessed` and `Not Applicable` controls are excluded from the denominator:
$$\text{Weighted Readiness (\%)} = \left( \frac{\text{Count}(\text{Implemented}) + (0.5 \times \text{Count}(\text{Partially Implemented}))}{\text{Assessed Applicable Controls}} \right) \times 100$$
*Integrity Rules:*
- If Assessed Applicable Controls is 0, Weighted Readiness returns `N/A`.
- AuditSphere **never** outputs a misleading 100% readiness score for an unassessed organization.

### E. Potential Control Gaps
Total count of controls that fail to meet full implementation criteria:
$$\text{Potential Gaps} = \text{Count}(\text{Partially Implemented}) + \text{Count}(\text{Not Implemented})$$

---

## 5. Critical Distinction: Implementation vs. Control Effectiveness

In enterprise Information Security audits, it is essential to distinguish between:
1. **Design & Implementation:** Verifying that a policy exists, procedures are documented, and technical configurations are turned on.
2. **Operating Effectiveness:** Verifying through statistical sampling, technical inspection, penetration testing, and longitudinal log analysis that the control operates reliably over time without failure or bypass.

AuditSphere Phase 2 records **Implementation Assessments**. A status of "Implemented" indicates that an assessor reviewed evidence and confirmed implementation at a point in time; it does **not** replace continuous technical monitoring or formal third-party certification audits.

---

## 6. Difference: Potential Gaps vs. Confirmed Audit Findings

- **Potential Control Gap (Phase 2):** A high-level deficiency detected during initial Annex A control review (e.g., A.8.8 patching SLA overdue, or A.6.3 training completion below target).
- **Confirmed Audit Finding (Phase 3):** A structured, formal non-conformity categorized by severity (Major Non-Conformity, Minor Non-Conformity, Observation) using the **CCCER** methodology (Condition, Criteria, Cause, Effect, Recommendation) linked to evidentiary proof and formal corrective action plans (CAP).
