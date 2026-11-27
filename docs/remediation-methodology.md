# AuditSphere – Remediation and Corrective Action Methodology

## 1. Executive Summary & Educational Disclaimer

AuditSphere implements a comprehensive Corrective Action and Remediation Management workflow aligned with **ISO/IEC 27001:2022 Clause 10.2 (Nonconformity and Corrective Action)** and **ISO 19011:2018 (Guidelines for Auditing Management Systems)**.

> [!IMPORTANT]
> **Educational & Portfolio Simulation Disclaimer:**
> AuditSphere is an educational simulation and portfolio GRC software tool. It is **not** an accredited certification auditing platform or legally binding regulatory system. The workflows, verifications, and closure rules described herein illustrate industry-standard information security governance practices within an academic and portfolio context.

---

## 2. Immediate Correction vs. Long-Term Corrective Action

In alignment with ISO/IEC 27001:2022 Clause 10.2, AuditSphere strictly distinguishes between **Immediate Containment (Correction)** and **Long-Term Corrective Action**:

| Attribute | Immediate Correction (Containment) | Long-Term Corrective Action |
| :--- | :--- | :--- |
| **Objective** | Stop immediate harm, mitigate active vulnerability, or contain immediate incident exposure. | Address underlying root causes to prevent recurrence or occurrence elsewhere. |
| **Scope** | Point-in-time remediation of the specific observed non-conformity. | Systemic process, technical, governance, or cultural enhancement across the organization. |
| **Lifecycle** | Short-term tactical fix (e.g., revoking a rogue API key, terminating an inactive contractor account). | Strategic multi-week/month project (e.g., deploying automated IAM Identity Center with SCIM sync). |
| **Closure Impact** | Does **not** qualify a non-conformity or finding for closure on its own. | Qualifies for formal verification and closure once proven effective. |

---

## 3. Root Cause Analysis (RCA) Framework

A corrective action cannot be verified or closed without identifying why the non-conformity occurred. AuditSphere supports two formal RCA methodologies:

### A. The 5 Whys Interactive Problem Decomposition
The **5 Whys** iterative questioning technique drills down through layers of proximate symptoms into systemic, organizational, or architectural root causes:
1. **Problem Statement:** The factual, observable deficiency (e.g., *"Contractor accounts accessed payment enclaves without multi-factor authentication"*).
2. **Why 1 (Direct Cause):** Legacy contractor gateway `gw-legacy.fincore.internal` remained active.
3. **Why 2 (Process Cause):** Decommissioning project was deprioritized due to billing software migration.
4. **Why 3 (Technical Cause):** Contractor firm lacked compatible mobile authenticator devices.
5. **Why 4 (Procurement Cause):** Hardware token procurement request was stalled in procurement review.
6. **Why 5 (Root Cause / Systemic Flaw):** Vendor security onboarding standard did not mandate hardware security keys before contract execution.

### B. Direct Analysis & Justified Exceptions
For straightforward deficiencies or isolated administrative oversights, assessors may document a direct root cause description. If root cause analysis is determined to be non-applicable (e.g., an external zero-day vulnerability without prior vendor patch availability), the assessor must select **"Not Appropriate"** and provide an explicit documented justification.

---

## 4. Action Ownership, Priorities & Governance Alignment

### Ownership & Single Accountability
Every corrective action mandates:
- **Action Owner:** A named individual responsible for driving implementation to completion.
- **Responsible Department:** The organizational unit accountable for resources and execution.
- **Assigned Date & Target Completion Date:** Measurable timeline for completion.

### Priority Assignment & Relational Alignment
Priority tiers:
- **Critical:** Severe security vulnerabilities, unmitigated major non-conformities, or critical risks requiring immediate executive visibility.
- **High:** Significant control failures with material impact on confidentiality, integrity, or availability.
- **Medium:** Standard non-conformities or moderate risks with compensating procedural safeguards.
- **Low:** Minor observations or procedural opportunities for improvement.

#### Alignment Governance Rule
If a corrective action addresses a **Critical** or **High** severity finding or risk, assigning a lower action priority (e.g., Medium or Low) **strictly requires documented priority justification** explaining the compensating factors or staged roadmap.

---

## 5. Corrective Action Lifecycle State Machine

AuditSphere enforces a deterministic state machine preventing invalid lifecycle jumps:

```
      [ Open ]
         |
         v
  [ In Progress ] <--------------------+
         |                             |
         v                             | Reopen (Ineffective)
[ Awaiting Verification ]              |
         |                             |
         v                             |
[ Under Verification ]                 |
         |                             |
         +--- Verification Failed -----+
         |
         +--- Verification Effective
         |
         v
     [ Closed ]

  (Any state -> Cancelled [Mandatory Justification Required])
```

### Prohibited Transitions:
- `Open` $\rightarrow$ `Closed` (Direct closure without implementation or verification is strictly blocked).
- `In Progress` $\rightarrow$ `Closed` (Direct closure without formal verification is strictly blocked).
- `In Progress` $\rightarrow$ `Awaiting Verification` (Requires `progress_percentage = 100` and a documented `implementation_summary`).
- Any State $\rightarrow$ `Cancelled` (Requires a non-empty `cancellation_reason`).

---

## 6. Progress Tracking, Deadlines & Extension Governance

- **Progress Percentage:** Quantified progress from 0% to 100%. Recording progress automatically transitions an `Open` action to `In Progress`.
- **Progress History Ledger:** Every update captures timestamp, previous percentage, new percentage, work description, documented blockers, and author.
- **Target Dates & Deadline Extensions:**
  - The initial target date is immutably preserved as `original_target_date`.
  - When a target date must be postponed, an assessor or manager records a formal **Deadline Extension** capturing:
    - Previous deadline and new deadline.
    - Documented justification for delay (e.g., supply chain disruption, change freeze).
    - Approving authority (e.g., CISO, VP Engineering).
    - Immutable ledger entry in `remediation_deadline_extensions`.

---

## 7. Implementation Evidence & Effectiveness Verification

A corrective action cannot rely on verbal assertions. AuditSphere mandates independent verification:

### Supporting Implementation Evidence
- Remediation owners must link objective evidence files (e.g., configuration dumps, authenticated vulnerability scan reports, updated policy documents, training LMS export CSVs).
- Evidence files undergo cryptographic SHA-256 hash validation. Actions linked to evidence with **Hash Mismatch** or **File Missing** warnings cannot be closed.

### Verification Working Paper
Before closure, an independent auditor or verifier evaluates effectiveness across 8 criteria:
1. **Verification Objective:** What condition was verified.
2. **Verification Procedure:** Technical test, inspection, or sample walkthrough performed.
3. **Expected Outcome:** Clear benchmark of success.
4. **Observed Outcome:** Factual test observations.
5. **Sample Examined:** Population size and sample selection (e.g., 100% of workforce, 25 sampled firewall nodes).
6. **Verification Result:**
   - **Effective:** Controls operate reliably, root cause eliminated.
   - **Partially Effective:** Improvement noted but residual deficiencies remain.
   - **Ineffective:** Non-conformity still reproduces; action must be reopened.
7. **Verifier Name & Date:** Identity of the auditor performing verification.
8. **Verification Notes & Recommended Next Action:** Formal commentary.

---

## 8. Strict Closure Governance Gates

To transition an action to `Closed`, the engine validates five mandatory criteria:
1. **100% Progress:** Progress percentage must equal 100%.
2. **Implementation Summary:** Comprehensive narrative detailing what was deployed or changed.
3. **Valid Evidence:** At least one linked evidence artifact with verified integrity.
4. **Effective Verification:** At least one verification record with result `Effective`. Ineffective or inconclusive results prevent closure.
5. **Closure Rationale:** Assessor's final formal sign-off statement explaining why the action is resolved.

---

## 9. Downstream Traceability: Finding Closure Gate

Audit findings cannot be closed in isolation:
- An audit finding in `findings` cannot transition to `Closed` if any linked corrective action in `remediation` is still `Open`, `In Progress`, `Awaiting Verification`, `Under Verification`, `Reopened`, or unverified.
- This ensures full audit integrity: **Observations $\rightarrow$ Findings $\rightarrow$ Risks $\rightarrow$ Actions $\rightarrow$ Verification $\rightarrow$ Finding Closure**.

---

## 10. Explicit Control & Risk Reassessments

In compliance with professional audit standards, **remediation completion does not automatically alter control statuses or risk scores**:

### No Auto-Mutation
- Closing a corrective action does **not** automatically mark an Annex A control as `Implemented`.
- Closing a corrective action does **not** automatically reduce current residual risk to target residual estimates.

### Formal Reassessment Requirement
- **Control Reassessment:** The assessor must navigate to the Control Assessment workspace, review post-remediation evidence, document a new assessment observation, and explicitly update the control status.
- **Risk Reassessment:** The risk owner or assessor must conduct an explicit risk reassessment, evaluate current residual likelihood and impact, provide justification, and update the risk score. Every reassessment is permanently appended to `risk_reviews`.

---

## 11. Remediation Metrics & KPI Calculations

AuditSphere calculates transparent, real-time remediation metrics:

$$\text{Verified Closure Rate (\%)} = \frac{\text{Closed Actions}}{\text{Active Actions (Total Actions} - \text{Cancelled Actions)}} \times 100$$

$$\text{Overdue Actions} = \sum [\text{Status} \notin \{\text{Closed}, \text{Cancelled}\} \land \text{Target Date} < \text{Today}]$$

$$\text{Due in 7 Days} = \sum [\text{Status} \notin \{\text{Closed}, \text{Cancelled}\} \land \text{Today} \le \text{Target Date} \le (\text{Today} + 7)]$$

Formula injection protection (CWE-1236) is enforced across all CSV export routines by prefixing dangerous characters (`=`, `+`, `-`, `@`, `\t`, `\r`) with a single quote (`'`).
