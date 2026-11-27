# AuditSphere Risk Management Methodology

## 1. Introduction & Executive Summary

AuditSphere implements a structured, quantitative-qualitative Information Security Risk Management methodology aligned with principles from **ISO/IEC 27005:2022** and **ISO 31000:2018**. 

The methodology provides assessment teams, risk owners, and security leaders with an objective, traceable framework to:
1. Identify risks stemming from business assets, threat sources, and security control vulnerabilities.
2. Trace risks directly to ISO/IEC 27001:2022 Annex A controls, audit evidence, and formal gap analysis findings.
3. Quantify risk exposure across a three-tier lifecycle model: **Inherent Risk**, **Current Residual Risk**, and **Target Residual Risk**.
4. Formulate risk treatment plans across four recognized strategies: *Mitigate*, *Accept*, *Transfer*, and *Avoid*.
5. Enforce governance gates on risk acceptance and risk closure.
6. Monitor risk exposure dynamically via an interactive 5×5 Likelihood × Impact Risk Heatmap.

> [!IMPORTANT]
> **Educational & Portfolio Disclaimer:**
> AuditSphere is an educational simulation and portfolio GRC demonstration tool. It does not provide certified risk calculations, formal accreditation, or legally binding risk acceptance signatures. All calculations and thresholds are intended for educational and demonstration purposes.

---

## 2. Risk Identification & Relational Traceability

AuditSphere contextualizes every risk within the target assessment boundary:

- **Asset Reference**: The business system, data repository, infrastructure component, or process exposed to harm (e.g., `Core Banking Transaction Engine`, `Corporate Identity Provider (Azure AD)`).
- **Threat**: The circumstance, agent, or event with the potential to adversely impact operations or information assets (e.g., `Credential Stuffing`, `Ransomware Deployment`, `Insider Exfiltration`).
- **Vulnerability**: The weakness in system security procedures, design, implementation, or internal controls that can be exploited by a threat (e.g., `Absence of Phishing-Resistant MFA`, `Delayed Security Patch Cycles`).
- **Consequence / Impact**: The business, operational, regulatory, or financial damage resulting from threat occurrence (e.g., `Account takeover, unauthorized funds transfer, regulatory fines under PSD2/GDPR`).
- **Risk Category**: Classification across core GRC domains:
  - `Governance & Strategy`
  - `Access & Identity`
  - `Data Protection & Privacy`
  - `Threat & Vulnerability`
  - `Incident & Continuity`
  - `Supplier & Third-Party`
  - `Physical & Environmental`
  - `Compliance & Legal`

### Multi-Dimensional Traceability Links
Risks in AuditSphere are not isolated data rows. They maintain many-to-many relationships enforced by SQLite foreign keys and database triggers:
1. **Linked Formal Findings (`risk_findings`)**: Connects risks directly to confirmed audit non-conformities identified in the Gap Analysis module.
2. **Linked Controls (`risk_controls`)**: Maps risks to the 20 ISO/IEC 27001:2022 Annex A controls evaluated in the Control Assessment engine.
3. **Linked Evidence Artifacts (`risk_evidence`)**: References cryptographically verified documentation, logs, or policies uploaded to the Evidence Repository.

---

## 3. Three-Tier Evaluation Model

To provide authentic GRC visibility, AuditSphere distinctly separates three tiers of risk evaluation. 

```
+---------------------+         +----------------------------+         +----------------------------+
|    Inherent Risk    |  --->   |   Current Residual Risk    |  --->   |    Target Residual Risk    |
| (Pre-Control State) |         | (Live Post-Control Posture)|         |  (Estimated Post-Treatment)|
+---------------------+         +----------------------------+         +----------------------------+
```

### 1. Inherent Risk (Baseline Exposure)
- **Definition**: The level of risk that exists in the absence of internal controls, safeguards, or deliberate security countermeasures.
- **Purpose**: Establishes the gross organizational exposure and justifies why control investments are necessary.
- **Dimensions**: Evaluated as Inherent Likelihood ($1 \le L \le 5$) and Inherent Impact ($1 \le I \le 5$).

### 2. Current Residual Risk (Live Posture)
- **Definition**: The risk remaining after taking into account the verified operating effectiveness of *currently existing* controls and safeguards.
- **Purpose**: Represents the organization's real-time risk exposure. This is the active metric used for management decision-making, executive reporting, and audit scrutiny.
- **Dimensions**: Evaluated as Residual Likelihood ($1 \le L \le 5$) and Residual Impact ($1 \le I \le 5$).

### 3. Target Residual Risk (Desired Post-Treatment Goal)
- **Definition**: The projected risk level expected to be attained *after* planned remediation tasks, technical controls, or treatment actions are fully designed, implemented, and verified.
- **Purpose**: Articulates management's risk appetite and provides a measurable benchmark for treatment success.
- **Critical Architectural Rule**: **Target Residual Risk does NOT replace Current Residual Risk.** Projecting a future lower score does not reduce live risk exposure today. Current Residual Risk is only adjusted when actual reassessment verifies that implemented controls are operating effectively.

---

## 4. Scoring Framework & Severity Thresholds

AuditSphere uses a standard 5×5 Likelihood × Impact scoring matrix.

### Rating Dimensions

| Level | Likelihood Criteria | Impact Criteria |
| :---: | :--- | :--- |
| **1 - Rare** | Unlikely to occur; once every 5+ years; extreme difficulty to exploit. | Negligible impact; minimal financial or operational disruption (< \$10k). |
| **2 - Unlikely** | Low probability; could occur once in 2–5 years; moderate attacker skill required. | Minor impact; contained locally; no regulatory reporting required (< \$50k). |
| **3 - Possible** | Realistic possibility; occurs annually; standard tools and exploits exist. | Moderate impact; localized operational disruption; possible minor regulatory inquiry (< \$250k). |
| **4 - Likely** | High probability; occurs multiple times per year; known active exploitation. | Major impact; substantial financial losses, brand damage, reportable breach (< \$1M). |
| **5 - Almost Certain** | Expected to occur frequently; ongoing attacks; trivial vulnerability exploitation. | Critical / Catastrophic impact; existential business threat, severe regulatory sanctions (> \$1M). |

### Score Formulation
$$\text{Risk Score} = \text{Likelihood} \times \text{Impact} \quad (1 \le \text{Score} \le 25)$$

### Severity Classification Thresholds

| Severity Tier | Score Range | Colour Code | Action / Priority Standard |
| :--- | :---: | :---: | :--- |
| **Critical** | **20 – 25** | Dark Maroon (`#751C35`) | Immediate executive escalation; urgent remediation required within 7–14 days. |
| **High** | **12 – 19** | Strong Orange (`#D9534F`) | High-priority treatment; formal corrective action required within 30–60 days. |
| **Medium** | **6 – 11** | Amber / Yellow (`#F0AD4E`) | Planned treatment; review during regular maintenance cycles within 90 days. |
| **Low** | **1 – 5** | Soft Green (`#5CB85C`) | Acceptable operational variance; maintain existing controls and monitor annually. |

### Unassessed Handling
Unassessed risks (where likelihood or impact has not yet been selected) evaluate to `Score = None` and `Severity = "Not Assessed"`. AuditSphere strictly rejects assigning an artificial numerical `0`, which would dangerously distort risk metrics and falsely portray unassessed risks as "zero risk".

---

## 5. Risk Treatment Strategies & Governance Gates

AuditSphere supports four standard risk treatment strategies:

1. **Mitigate (Reduce)**: Implement technical, operational, or architectural controls to reduce likelihood, impact, or both.
2. **Accept (Tolerate)**: Acknowledge the risk within organizational risk appetite without additional technical controls.
3. **Transfer (Share)**: Shift risk exposure to a third party (e.g., cyber insurance, managed security service providers, vendor indemnity clauses).
4. **Avoid (Terminate)**: Eliminate the risk by discontinuing the risky activity, system, or business relationship.

### Enforced Governance Rules

To uphold audit integrity, AuditSphere enforces strict transactional governance rules:

#### 1. Risk Acceptance Gate
A risk cannot be transitioned to the `Accepted` status unless:
- A documented **Risk Acceptance Justification** is recorded (explaining business rationale, cost-benefit trade-offs, and compensating safeguards).
- The formal **Acceptance Approval Status** is set to `Approved`.
- An approving authority and target review date are registered.

#### 2. Risk Closure Gate
A risk cannot be transitioned to the `Closed` status unless:
- A comprehensive **Closure Rationale** is documented (verifying that the threat is neutralized, the asset decommissioned, or treatment controls confirmed effective by audit testing).

#### 3. Reassessment Audit Trail
Whenever an assessor updates any likelihood or impact dimension on an existing risk:
- AuditSphere automatically records a snapshot into the `risk_reviews` historical table.
- Captures previous vs. updated scores, review notes, assessor name, and timestamp, maintaining an unalterable review ledger.

#### 4. CSV Formula Injection Defense (CWE-1236)
When exporting risk register data to CSV, AuditSphere sanitizes all text fields beginning with formula execution characters (`=`, `+`, `-`, `@`, `\t`, `\r`) by prepending a single quote (`'`), protecting downstream spreadsheet applications from formula execution exploits.

---

## 6. Review Cadences & Heatmap Monitoring

AuditSphere schedules and flags risk review cadences based on residual severity:

| Severity Level | Recommended Review Frequency | Overdue Threshold |
| :--- | :--- | :--- |
| **Critical** | Monthly (every 30 days) | > 30 days since last review |
| **High** | Quarterly (every 90 days) | > 90 days since last review |
| **Medium** | Semi-Annually (every 180 days) | > 180 days since last review |
| **Low** | Annually (every 365 days) | > 365 days since last review |

The interactive 5×5 Plotly Risk Heatmap allows security leaders to switch seamlessly between **Inherent**, **Current Residual**, and **Target Residual** views. Clicking on any cell instantly inspects all risk entries mapped to that specific likelihood and impact coordinate.
