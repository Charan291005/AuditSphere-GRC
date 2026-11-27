"""
Control Assessment Service for AuditSphere.

Handles retrieval, filtering, validation, and persistence of individual control
evaluations within an ISMS assessment context. Also provides an idempotent
demonstration assessment generator for FinCore Technologies.
"""

import json
from datetime import datetime, date
from typing import Any, Dict, List, Optional
from database import db_session, get_utc_now_iso, initialize_assessment_controls
from services.assessment_service import get_assessment, create_assessment
from services.activity_service import log_activity
from services.assessment_engine import (
    VALID_CONTROL_STATUSES,
    calculate_overall_metrics,
)


def get_assessment_controls(
    assessment_id: int,
    status_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
    search_query: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve all control assessment evaluations joined with reference control metadata
    for a specific assessment, with optional status, category, and search filters.
    """
    with db_session(db_path) as conn:
        # First ensure all 20 controls are initialized for this assessment
        initialize_assessment_controls(conn, assessment_id)

        query = """
        SELECT
            ca.id AS assessment_control_id,
            ca.assessment_id,
            ca.control_id,
            ca.status,
            ca.control_owner,
            ca.assessment_observation,
            ca.testing_notes,
            ca.evidence_notes,
            ca.recommendation,
            ca.applicability_justification,
            ca.assessed_by,
            ca.assessed_at,
            ca.created_at AS assessment_created_at,
            ca.updated_at AS assessment_updated_at,
            c.control_identifier,
            c.clause,
            c.title AS control_title,
            c.description AS control_description,
            c.domain AS category,
            c.objective,
            c.assessment_questions,
            c.suggested_evidence,
            c.example_gaps,
            c.example_recommendations
        FROM control_assessments ca
        JOIN controls c ON ca.control_id = c.id
        WHERE ca.assessment_id = ?
        """
        params: List[Any] = [assessment_id]

        if status_filter and status_filter != "All Statuses":
            query += " AND ca.status = ?"
            params.append(status_filter)

        if category_filter and category_filter != "All Categories":
            query += " AND LOWER(c.domain) = LOWER(?)"
            params.append(category_filter)

        if search_query and search_query.strip():
            q = f"%{search_query.strip().lower()}%"
            query += " AND (LOWER(c.control_identifier) LIKE ? OR LOWER(c.title) LIKE ? OR LOWER(COALESCE(ca.control_owner, '')) LIKE ?)"
            params.extend([q, q, q])

        query += " ORDER BY c.id ASC"

        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        results = []
        for r in rows:
            d = dict(r)
            # Parse JSON fields safely
            for json_col in (
                "assessment_questions",
                "suggested_evidence",
                "example_gaps",
                "example_recommendations",
            ):
                val = d.get(json_col)
                if val and isinstance(val, str):
                    try:
                        d[json_col] = json.loads(val)
                    except Exception:
                        d[json_col] = []
                elif not val:
                    d[json_col] = []
            results.append(d)

        return results


def get_single_control_assessment(
    assessment_id: int, control_id: int, db_path: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Retrieve full details for a single control evaluation within an assessment."""
    controls = get_assessment_controls(assessment_id=assessment_id, db_path=db_path)
    for c in controls:
        if c["control_id"] == control_id or c["control_identifier"] == str(control_id):
            return c
    return None


def validate_control_assessment_payload(
    status: str,
    assessment_observation: Optional[str],
    recommendation: Optional[str],
    applicability_justification: Optional[str],
    assessor_name: Optional[str],
    assessment_date: Optional[str],
) -> None:
    """
    Validate business rules for evaluating an individual security control:
    - Status must be a recognized value.
    - Implemented controls require documented observations.
    - Partially Implemented and Not Implemented require observations AND recommendations.
    - Not Applicable requires an applicability justification.
    - Any evaluated control (Implemented, Partial, Not Implemented, Not Applicable) requires
      assessor name and a valid assessment date (YYYY-MM-DD).
    """
    if status not in VALID_CONTROL_STATUSES:
        raise ValueError(
            f"Invalid implementation status '{status}'. Must be one of: {', '.join(VALID_CONTROL_STATUSES)}."
        )

    obs = (assessment_observation or "").strip()
    rec = (recommendation or "").strip()
    just = (applicability_justification or "").strip()
    assessor = (assessor_name or "").strip()
    ass_date = (assessment_date or "").strip()

    if status == "Implemented":
        if not obs:
            raise ValueError(
                "Controls marked as 'Implemented' require documented assessment observations detailing how the control is satisfied."
            )

    elif status in ("Partially Implemented", "Not Implemented"):
        if not obs:
            raise ValueError(
                f"Controls marked as '{status}' require documented assessment observations detailing current conditions and deficiencies."
            )
        if not rec:
            raise ValueError(
                f"Controls marked as '{status}' require remediation recommendations to guide corrective actions."
            )

    elif status == "Not Applicable":
        if not just:
            raise ValueError(
                "Controls marked as 'Not Applicable' require a documented justification explaining why the control is excluded from the ISMS scope."
            )

    # For any status other than 'Not Assessed', assessor name and date are mandatory
    if status != "Not Assessed":
        if not assessor:
            raise ValueError(
                "Assessor name is required when recording a control assessment."
            )
        if not ass_date:
            raise ValueError(
                "Assessment date is required when recording a control assessment."
            )
        try:
            datetime.strptime(ass_date, "%Y-%m-%d")
        except ValueError:
            raise ValueError("Assessment date must be in YYYY-MM-DD format.")


def update_control_assessment(
    assessment_id: int,
    control_id: int,
    status: str,
    control_owner: Optional[str] = None,
    assessment_observation: Optional[str] = None,
    testing_notes: Optional[str] = None,
    evidence_notes: Optional[str] = None,
    recommendation: Optional[str] = None,
    applicability_justification: Optional[str] = None,
    assessor_name: Optional[str] = None,
    assessment_date: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Persist an assessor's evaluation for a specific control.
    Prevents updates to archived assessments.
    Enforces validation rules, logs activity events, and maintains audit isolation.
    """
    # 1. Verify assessment exists and is NOT archived
    asm = get_assessment(assessment_id, db_path=db_path)
    if not asm:
        raise ValueError(f"Assessment ID {assessment_id} does not exist.")
    if asm["status"] == "Archived":
        raise PermissionError(
            f"Assessment '{asm['title']}' is Archived and cannot be modified. Unarchive the assessment before making changes."
        )

    # 2. Validate payload
    validate_control_assessment_payload(
        status=status,
        assessment_observation=assessment_observation,
        recommendation=recommendation,
        applicability_justification=applicability_justification,
        assessor_name=assessor_name,
        assessment_date=assessment_date,
    )

    now_iso = get_utc_now_iso()

    with db_session(db_path) as conn:
        cursor = conn.cursor()

        # Fetch current record to detect previous status and control identifier
        cursor.execute(
            """
            SELECT ca.status, c.control_identifier, c.title
            FROM control_assessments ca
            JOIN controls c ON ca.control_id = c.id
            WHERE ca.assessment_id = ? AND ca.control_id = ?
            """,
            (assessment_id, control_id),
        )
        row = cursor.fetchone()
        if not row:
            raise ValueError(
                f"Control ID {control_id} not found for Assessment ID {assessment_id}."
            )

        prev_status = row["status"]
        control_ref = row["control_identifier"]
        control_title = row["title"]

        # Persist update
        cursor.execute(
            """
            UPDATE control_assessments
            SET status = ?,
                control_owner = ?,
                assessment_observation = ?,
                finding_summary = ?,
                testing_notes = ?,
                notes = ?,
                evidence_notes = ?,
                recommendation = ?,
                applicability_justification = ?,
                assessed_by = ?,
                assessed_at = ?,
                updated_at = ?
            WHERE assessment_id = ? AND control_id = ?
            """,
            (
                status,
                control_owner.strip() if control_owner else None,
                assessment_observation.strip() if assessment_observation else None,
                assessment_observation.strip() if assessment_observation else None,
                testing_notes.strip() if testing_notes else None,
                testing_notes.strip() if testing_notes else None,
                evidence_notes.strip() if evidence_notes else None,
                recommendation.strip() if recommendation else None,
                applicability_justification.strip() if applicability_justification else None,
                assessor_name.strip() if assessor_name else None,
                assessment_date.strip() if assessment_date else None,
                now_iso,
                assessment_id,
                control_id,
            ),
        )

    # Determine event type for activity log
    if prev_status != status:
        if status == "Not Applicable" or prev_status == "Not Applicable":
            event_type = "CONTROL_APPLICABILITY_CHANGED"
            desc = f"Control {control_ref} ({control_title}) applicability changed: {prev_status} -> {status}."
        else:
            event_type = "CONTROL_STATUS_CHANGED"
            desc = f"Control {control_ref} ({control_title}) status changed from '{prev_status}' to '{status}'."
    else:
        event_type = "CONTROL_ASSESSMENT_UPDATED"
        desc = f"Control {control_ref} ({control_title}) assessment details updated."

    log_activity(
        assessment_id=assessment_id,
        event_type=event_type,
        description=desc,
        actor=assessor_name or asm["lead_assessor"],
        control_reference=control_ref,
        previous_status=prev_status,
        new_status=status,
        db_path=db_path,
    )

    return get_single_control_assessment(
        assessment_id=assessment_id, control_id=control_id, db_path=db_path
    )  # type: ignore


# Demonstration dataset for FinCore Technologies
DEMO_ORG_NAME = "FinCore Technologies"
DEMO_TITLE = "FinCore Technologies – ISO/IEC 27001:2022 Demonstration Assessment"

DEMO_CONTROL_EVALUATIONS = {
    # 7 Implemented
    "A.5.1": {
        "status": "Implemented",
        "owner": "Head of InfoSec",
        "observation": "Comprehensive Information Security Policy suite is published, approved by the Board, and reviewed within the last 8 months. Annual employee policy re-acknowledgment rate stands at 98.4%.",
        "testing_notes": "Reviewed Board minutes dated 2025-10-15 and verified LMS policy acknowledgment logs.",
        "evidence_notes": "EVD-POL-01 (Approved ISMS Policy 2025 v3.2), LMS acknowledgment export.",
        "recommendation": "",
        "justification": "",
    },
    "A.5.15": {
        "status": "Implemented",
        "owner": "IT Operations Lead",
        "observation": "Access control policy enforces least privilege and RBAC. Access requests require managerial and asset-owner sign-off via Jira Service Desk.",
        "testing_notes": "Sampled 15 user access requests across engineering and finance teams; all showed documented approvals prior to provisioning.",
        "evidence_notes": "RBAC Matrix v2.1, Jira Access Request queue export.",
        "recommendation": "",
        "justification": "",
    },
    "A.6.1": {
        "status": "Implemented",
        "owner": "VP Human Resources",
        "observation": "Standard pre-employment screening is strictly conducted for all staff, including criminal record verification, identity verification, and previous employment confirmation.",
        "testing_notes": "Inspected 10 anonymized personnel screening dossiers. All were cleared prior to first working day.",
        "evidence_notes": "HR Background Check Policy and quarterly background verification audit logs.",
        "recommendation": "",
        "justification": "",
    },
    "A.6.6": {
        "status": "Implemented",
        "owner": "Corporate Legal Counsel",
        "observation": "Non-disclosure and confidentiality clauses are embedded in standard employment agreements and third-party contracts, with explicit post-employment survival terms.",
        "testing_notes": "Reviewed standard employment contract template and verified 5 vendor Master Services Agreements.",
        "evidence_notes": "Standard Employment Agreement Section 8, Third-Party Vendor NDA Registry.",
        "recommendation": "",
        "justification": "",
    },
    "A.7.2": {
        "status": "Implemented",
        "owner": "Facilities Manager",
        "observation": "Electronic badge access controls all building perimeters and the primary data closet. Visitors must register via digital kiosk and remain escorted.",
        "testing_notes": "Inspected turnstiles, badge logs for past 30 days, and electronic visitor sign-in logs.",
        "evidence_notes": "Badge access report, Visitor sign-in kiosk audit export.",
        "recommendation": "",
        "justification": "",
    },
    "A.8.2": {
        "status": "Implemented",
        "owner": "Cloud Security Architect",
        "observation": "Privileged access rights are isolated from everyday user accounts. Administrative access to AWS cloud environments requires Just-In-Time (JIT) elevation via Teleport PAM with mandatory hardware token MFA.",
        "testing_notes": "Observed live administrative session initiation via Teleport; session video recording was captured and stored in append-only S3 bucket.",
        "evidence_notes": "Teleport PAM configuration, IAM role policy documents, Hardware MFA enforcement rule.",
        "recommendation": "",
        "justification": "",
    },
    "A.8.24": {
        "status": "Implemented",
        "owner": "Security Engineering Lead",
        "observation": "Strong cryptographic protections are enforced. Production data at rest is encrypted with AES-256 via AWS KMS with automatic annual key rotation. Data in transit is strictly TLS 1.3.",
        "testing_notes": "Executed SSL Labs probe on public API endpoints (rated A+). Inspected KMS key policies and EBS volume encryption status.",
        "evidence_notes": "KMS Key Rotation logs, SSL Labs A+ report, Terraform encryption enforcement module.",
        "recommendation": "",
        "justification": "",
    },
    # 3 Partially Implemented
    "A.5.18": {
        "status": "Partially Implemented",
        "owner": "IT Operations Lead",
        "observation": "User onboarding and de-provisioning procedures are automated via Okta SCIM. However, quarterly access re-certifications are performed manually and two departments missed their Q4 reviews.",
        "testing_notes": "Sampled termination records; accounts disabled within 2 hours of HR notice. However, finance department access review had not been completed for 7 months.",
        "evidence_notes": "Okta de-provisioning logs, Q3 Access Review sign-offs, missing Q4 finance review note.",
        "recommendation": "Deploy automated access certification campaigns in Okta to enforce mandatory quarterly sign-offs with automatic managerial escalations.",
        "justification": "",
    },
    "A.6.3": {
        "status": "Partially Implemented",
        "owner": "Security Training Coordinator",
        "observation": "Security onboarding training is mandatory for all new hires, but annual refresher training completion stands at only 74%, failing the 95% organizational target.",
        "testing_notes": "Checked LMS dashboard; 62 out of 240 active employees have overdue annual security awareness modules.",
        "evidence_notes": "KnowBe4 LMS completion report for FY2026.",
        "recommendation": "Institute automated reminder notifications and introduce managerial accountability metrics for overdue security training.",
        "justification": "",
    },
    "A.8.8": {
        "status": "Partially Implemented",
        "owner": "Vulnerability Management Lead",
        "observation": "Monthly automated vulnerability scans are conducted across internal and cloud networks. However, remediation SLAs for High-severity findings (30 days) were breached in 4 instances.",
        "testing_notes": "Reviewed Tenable.io reports; 4 High-severity CVEs older than 45 days remain unpatched in staging environment.",
        "evidence_notes": "Tenable.io Executive Summary, Vulnerability Management SLA tracker.",
        "recommendation": "Integrate vulnerability ticketing directly into engineering sprint backlogs with automated SLA breach alerts to executive leadership.",
        "justification": "",
    },
    # 2 Not Implemented
    "A.7.7": {
        "status": "Not Implemented",
        "owner": "Facilities & Office Manager",
        "observation": "No formal clear desk and clear screen policy is documented or enforced. Multiple unattended workstations were observed unlocked in the open-plan floor during assessment walkthrough.",
        "testing_notes": "Conducted physical walkthrough at 18:30; found 3 unlocked laptops and confidential customer invoices left on shared printer trays.",
        "evidence_notes": "Physical audit walkthrough notes, unmanaged printer photo log.",
        "recommendation": "Formulate and publish a Clear Desk and Clear Screen policy, deploy centralized MDM 10-minute inactivity auto-lock, and configure secure badge-release printing.",
        "justification": "",
    },
    "A.8.13": {
        "status": "Not Implemented",
        "owner": "Database Administrator",
        "observation": "Daily automated database snapshots are taken, but backup restoration drills have never been formally executed or timed. Backups are stored in the same cloud account without immutable protection against ransomware.",
        "testing_notes": "Interviewed DBA; confirmed restoration procedures have not been tested in over 18 months. No documented RTO/RPO verification exists.",
        "evidence_notes": "AWS RDS snapshot schedule, DBA interview transcript.",
        "recommendation": "Implement AWS Backup Vault Lock (WORM storage) in an isolated secondary account and execute a scheduled quarterly disaster recovery restoration drill.",
        "justification": "",
    },
    # 8 Not Assessed:
    # A.5.24, A.5.31, A.5.34, A.6.8, A.7.1, A.7.4, A.8.5, A.8.15
}


def create_fincore_demo_assessment(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate the official FinCore Technologies demonstration assessment.
    Repeat-safe: If an assessment titled 'FinCore Technologies...' already exists,
    returns the existing record without creating duplicate assessments.
    """
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM assessments WHERE organization = ? AND title = ?",
            (DEMO_ORG_NAME, DEMO_TITLE),
        )
        existing = cursor.fetchone()

    if existing:
        asm_id = existing["id"]
    else:
        # Create fresh assessment
        created = create_assessment(
            title=DEMO_TITLE,
            organization=DEMO_ORG_NAME,
            industry="Financial Services & Banking",
            scope="Core payment gateway, multi-tenant customer vaults, AWS production cloud enclave, and corporate headquarters.",
            objectives="Demonstration assessment illustrating ISO/IEC 27001:2022 Annex A selected control assessment progress and metric calculations.",
            lead_assessor="Marcus Vance, Lead Auditor ISO 27001",
            assessment_date="2026-05-15",
            status="In Progress",
            db_path=db_path,
        )
        asm_id = created["id"]

    # Now populate the 12 evaluated controls (7 Implemented, 3 Partial, 2 Not Implemented)
    # The remaining 8 stay 'Not Assessed'.
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT ca.id, ca.control_id, c.control_identifier
            FROM control_assessments ca
            JOIN controls c ON ca.control_id = c.id
            WHERE ca.assessment_id = ?
            """,
            (asm_id,),
        )
        ctrl_map = {row["control_identifier"]: row["control_id"] for row in cursor.fetchall()}

    now_iso = get_utc_now_iso()

    for ident, eval_data in DEMO_CONTROL_EVALUATIONS.items():
        if ident in ctrl_map:
            cid = ctrl_map[ident]
            update_control_assessment(
                assessment_id=asm_id,
                control_id=cid,
                status=eval_data["status"],
                control_owner=eval_data["owner"],
                assessment_observation=eval_data["observation"],
                testing_notes=eval_data["testing_notes"],
                evidence_notes=eval_data["evidence_notes"],
                recommendation=eval_data["recommendation"],
                applicability_justification=eval_data["justification"],
                assessor_name="Marcus Vance, Lead Auditor ISO 27001",
                assessment_date="2026-05-15",
                db_path=db_path,
            )

    # Seed Phase 3 Evidence, Testing, and Findings records
    seed_fincore_phase3_artifacts(asm_id, db_path=db_path)

    # Seed Phase 4 Risk records
    seed_fincore_phase4_risks(asm_id, db_path=db_path)

    # Seed Phase 5 Remediation and Corrective Action records
    seed_fincore_phase5_remediations(asm_id, db_path=db_path)

    # Verify metrics for demonstration dataset
    controls = get_assessment_controls(asm_id, db_path=db_path)
    metrics = calculate_overall_metrics(controls)

    return {
        "assessment": get_assessment(asm_id, db_path=db_path),
        "metrics": metrics,
    }


def seed_fincore_phase3_artifacts(asm_id: int, db_path: Optional[str] = None) -> None:
    """
    Seed original fictional audit evidence files, control testing records, and formal
    findings for FinCore Technologies demonstration assessment.
    Repeat-safe / idempotent.
    """
    from services.evidence_manager import (
        upload_evidence,
        review_evidence,
        verify_evidence_integrity,
    )
    from services.gap_engine import create_control_test, create_finding

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM evidence WHERE assessment_id = ?", (asm_id,))
        ev_count = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT ca.id, c.control_identifier
            FROM control_assessments ca
            JOIN controls c ON ca.control_id = c.id
            WHERE ca.assessment_id = ?
            """,
            (asm_id,),
        )
        ca_map = {r["control_identifier"]: r["id"] for r in cursor.fetchall()}

    # 1. Seed Evidence Files if none exist
    if ev_count == 0:
        evidence_defs = [
            {
                "title": "Corporate Information Access Control Policy v3.2",
                "file_name": "FIN-POL-001_Access_Control_Policy_v3.2.txt",
                "content": (
                    "FINCORE TECHNOLOGIES INC. - INFORMATION ACCESS CONTROL POLICY\n"
                    "Document Reference: POL-SEC-001 | Version: 3.2 | Classification: Confidential\n"
                    "Effective Date: 2026-01-10 | Review Owner: CISO\n\n"
                    "1. PURPOSE & SCOPE\n"
                    "This policy defines mandatory requirements for user identity management, credential complexity,\n"
                    "least privilege authorization, and privileged access safeguards across all FinCore payment enclaves.\n\n"
                    "2. ACCESS PROVISIONING & DE-PROVISIONING\n"
                    "All access requests require documented department head approval. User offboarding must be executed\n"
                    "via automated SCIM synchronization within 4 hours of HR notification.\n\n"
                    "3. ACCESS RE-CERTIFICATION\n"
                    "Quarterly access re-certification campaigns must be completed by line managers for all sensitive systems.\n"
                ).encode("utf-8"),
                "type": "Security policy",
                "dept": "Information Security & Compliance",
                "controls": ["A.5.15", "A.5.18"],
                "review_status": "Accepted",
                "confidence": "High",
                "review_notes": "Comprehensive access control policy covering least privilege, RBAC, and de-provisioning workflows. Duly signed by CISO.",
            },
            {
                "title": "Okta Adaptive MFA Global Policy Rule Configuration Export",
                "file_name": "FIN-CFG-002_Okta_MFA_Enforcement_Export.txt",
                "content": (
                    "OKTA TENANT POLICY EXPORT - FINCORE PRODUCTION (tenant: fincore.okta.com)\n"
                    "Generated: 2026-04-12T09:15:00Z | Exported By: iam-admin@fincore.internal\n\n"
                    "RULE: Global-Default-MFA\n"
                    "- Status: ACTIVE\n"
                    "- Priority: 1\n"
                    "- Enforce MFA: Prompt on every untrusted network or device session\n"
                    "- Allowed Factors: FIDO2 / WebAuthn, Okta Verify Push, TOTP\n"
                    "- SMS/Email Factors: DISABLED (Phishing-resistance enforcement)\n\n"
                    "EXCEPTION POLICY: Legacy-Partner-VPN-Rule\n"
                    "- Status: ACTIVE\n"
                    "- Target Endpoint: gw-legacy.fincore.internal\n"
                    "- Policy: Passwords only (Bypass MFA - Temp contractor access)\n"
                    "- WARNING: Policy flagged for deprecation in Q1 2025; currently overdue.\n"
                ).encode("utf-8"),
                "type": "Configuration record",
                "dept": "Identity & Access Management",
                "controls": ["A.8.5"],
                "review_status": "Accepted",
                "confidence": "High",
                "review_notes": "Direct configuration export confirming global MFA enforcement in Okta, but also demonstrating an active MFA exception on legacy contractor VPN.",
            },
            {
                "title": "AWS RDS Automated Snapshot Restoration Drill Execution Log",
                "file_name": "FIN-LOG-003_RDS_Restoration_Test_Failure.txt",
                "content": (
                    "AWS CLOUDWATCH AUTOMATION LOG - DISASTER RECOVERY DRILL\n"
                    "Execution ID: exec-dr-2026-03-20-001\n"
                    "Target Database: rds-prod-pg-payments-primary\n"
                    "Snapshot ID: rds:rds-prod-pg-payments-2026-03-19-03-00\n"
                    "Initiated By: scheduled-ssm-maintenance-dr-drill\n\n"
                    "[2026-03-20T02:00:10Z] INFO: Initiating snapshot restore to isolated VPC subnet-0814a...\n"
                    "[2026-03-20T02:14:32Z] INFO: DB instance creating... status: creating\n"
                    "[2026-03-20T02:45:00Z] ERROR: Restore timeout exceeded (45 minutes). Target RTO threshold breached (RTO Target: 30 minutes).\n"
                    "[2026-03-20T02:45:05Z] ERROR: KMS Decryption Permission Denied for cross-account KMS key alias/fin-backup-key-dr.\n"
                    "[2026-03-20T02:45:10Z] FAILED: DR restoration failed to achieve ready status. Drill terminated with failure code E_KMS_AUTH_FAIL.\n"
                ).encode("utf-8"),
                "type": "System log",
                "dept": "Cloud Platform Operations",
                "controls": ["A.8.13"],
                "review_status": "Accepted",
                "confidence": "High",
                "review_notes": "Restoration drill log demonstrates backup restoration failure due to cross-account KMS decryption permissions and timeout.",
            },
            {
                "title": "FY2026 Annual Security Awareness and Phishing Campaign Roster",
                "file_name": "FIN-REC-004_FY26_Security_Awareness_Attendance.csv",
                "content": (
                    "Employee_ID,Name,Department,Assigned_Course,Completion_Date,Status,Phishing_Sim_Result\n"
                    "EMP-1001,Johnathan Doe,Engineering,Core InfoSec 2026,2026-02-15,Completed,Passed\n"
                    "EMP-1002,Sarah Jenkins,Finance,Core InfoSec 2026,2026-02-18,Completed,Passed\n"
                    "EMP-1003,Marcus Vance,Compliance,Core InfoSec 2026,2026-01-20,Completed,Passed\n"
                    "EMP-1004,Elena Rostova,Customer Support,Core InfoSec 2026,,Overdue,Failed\n"
                    "EMP-1005,Tariq Al-Mansoor,Sales,Core InfoSec 2026,,Overdue,Reported\n"
                    "EMP-1006,Chloe Bennett,Marketing,Core InfoSec 2026,2026-03-01,Completed,Passed\n"
                    "EMP-1007,David Miller,DevOps,Core InfoSec 2026,,Overdue,Passed\n"
                ).encode("utf-8"),
                "type": "Training record",
                "dept": "People Operations & HR",
                "controls": ["A.6.3"],
                "review_status": "Needs Clarification",
                "confidence": "Medium",
                "review_notes": "Sample attendance log shows 3 out of 7 sampled records overdue (completion rate approx 74% organization-wide). Clarification requested regarding HR escalation procedure.",
            },
            {
                "title": "Privileged Infrastructure Access and IAM Administrator Inventory",
                "file_name": "FIN-REC-005_Privileged_Accounts_Inventory.txt",
                "content": (
                    "FINCORE TECHNOLOGIES - PRIVILEGED ACCESS INVENTORY\n"
                    "Quarterly Re-certification Cycle: Q1 2026 | Date: 2026-03-31\n\n"
                    "DOMAIN / PLATFORM: AWS Production Cloud\n"
                    "- Total IAM Roles with AdministratorAccess: 4\n"
                    "- Break-glass root accounts: Protected via hardware YubiKey in physical safe\n"
                    "- Active federated Admin users: 6 engineers\n\n"
                    "DOMAIN: Active Directory Corporate HQ\n"
                    "- Domain Admins group count: 5 named users\n"
                    "- Service Accounts with elevated rights: 8 accounts (password rotation managed via CyberArk)\n"
                    "- Status: Re-certification signed off by IT Director on 2026-04-02.\n"
                ).encode("utf-8"),
                "type": "Access record",
                "dept": "IT Security Operations",
                "controls": ["A.5.18"],
                "review_status": "Accepted",
                "confidence": "High",
                "review_notes": "Verified privileged access roster. Hardware MFA confirmed for root break-glass accounts.",
            },
        ]

        for ed in evidence_defs:
            mapped_cids = [ca_map[ident] for ident in ed["controls"] if ident in ca_map]
            ev = upload_evidence(
                assessment_id=asm_id,
                title=ed["title"],
                file_name=ed["file_name"],
                file_bytes=ed["content"],
                evidence_type=ed["type"],
                description=ed["title"],
                source_department=ed["dept"],
                collection_date="2026-05-15",
                uploaded_by="Marcus Vance, Lead Auditor ISO 27001",
                mapped_control_ids=mapped_cids,
                db_path=db_path,
            )
            # Review the evidence
            review_evidence(
                evidence_id=ev["id"],
                review_status=ed["review_status"],
                reviewer_name="Marcus Vance, Lead Auditor ISO 27001",
                reviewer_notes=ed["review_notes"],
                relevance_rating="Highly Relevant",
                sufficiency_rating="Sufficient",
                reliability_rating="Reliable",
                db_path=db_path,
            )
            # Verify file integrity
            verify_evidence_integrity(evidence_id=ev["id"], db_path=db_path)

    # 2. Seed Control Test if none exist
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM control_tests WHERE assessment_id = ?", (asm_id,))
        test_count = cursor.fetchone()[0]

    if test_count == 0 and "A.8.5" in ca_map:
        a85_ca_id = ca_map["A.8.5"]
        create_control_test(
            assessment_id=asm_id,
            control_assessment_id=a85_ca_id,
            test_type="Operating effectiveness",
            testing_objective="Verify mandatory multi-factor authentication enforcement across all external ingress paths and administrative entry points.",
            testing_procedure="Sampled 25 interactive login attempts across corporate VPN gateways, customer support portal, and bastion jump hosts.",
            expected_result="100% of logins enforce secondary challenge (hardware security key or authenticator push notification).",
            observed_result="Legacy VPN portal 'gw-legacy.fincore.internal' permitted password-only authentication for 12 contractor accounts without secondary MFA challenge.",
            conclusion="Fail",
            sample_examined="25 administrator and contractor access logs from Okta and VPN gateways",
            assessment_period="2026-01-01 to 2026-04-30",
            supporting_evidence_references="FIN-CFG-002",
            assessor_name="Marcus Vance, Lead Auditor ISO 27001",
            testing_date="2026-05-15",
            db_path=db_path,
        )

    # 3. Seed Formal Finding if none exist
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM findings WHERE assessment_id = ?", (asm_id,))
        fnd_count = cursor.fetchone()[0]

    if fnd_count == 0 and "A.8.5" in ca_map:
        a85_ca_id = ca_map["A.8.5"]
        create_finding(
            assessment_id=asm_id,
            control_assessment_id=a85_ca_id,
            title="Single-Factor Authentication Permitted on Legacy Remote Access Gateway",
            criteria="ISO/IEC 27001:2022 Control A.8.5 (Secure authentication) mandates that authentication systems prevent unauthorized access through robust authentication mechanisms, specifically requiring multi-factor authentication for remote access.",
            condition="During operating effectiveness testing (TST-001), 12 third-party contractor accounts were verified accessing production network segments via legacy gateway 'gw-legacy.fincore.internal' using single-factor password authentication without MFA.",
            cause="Legacy gateway configuration was excluded from recent Okta SSO/MFA migration roadmap due to perceived deprecation timelines.",
            effect="Elevated risk of unauthorized network intrusion, credential stuffing exploitation, and lateral movement into the customer payment processing zone.",
            recommendation="Decommission legacy gateway gw-legacy.fincore.internal immediately and route all remote access through the centralized Okta SAML proxy with mandatory WebAuthn/push MFA.",
            severity="High",
            finding_type="Major Non-Conformity",
            status="Open",
            supporting_evidence_references="FIN-CFG-002",
            supporting_test_references="TST-001",
            responsible_department="Infrastructure & Network Engineering",
            assessor_name="Marcus Vance, Lead Auditor ISO 27001",
            db_path=db_path,
        )


def seed_fincore_phase4_risks(asm_id: int, db_path: Optional[str] = None) -> None:
    """
    Seed 5 fictional risk records for FinCore Technologies demonstration assessment.
    Repeat-safe / idempotent.
    Distribution: Critical: 1, High: 2, Medium: 1, Low: 1. Total: 5.
    """
    from services.risk_service import create_risk

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM risks WHERE assessment_id = ?", (asm_id,))
        if cursor.fetchone()[0] > 0:
            return  # Already seeded

        # Fetch control assessments map
        cursor.execute(
            """
            SELECT ca.id, c.control_identifier
            FROM control_assessments ca
            JOIN controls c ON ca.control_id = c.id
            WHERE ca.assessment_id = ?
            """,
            (asm_id,),
        )
        ca_map = {r["control_identifier"]: r["id"] for r in cursor.fetchall()}

        # Fetch FND-001 finding ID
        cursor.execute(
            "SELECT id FROM findings WHERE assessment_id = ? AND finding_identifier = 'FND-001'",
            (asm_id,),
        )
        fnd_row = cursor.fetchone()
        fnd_001_id = fnd_row["id"] if fnd_row else None

    # Risk 1: Unauthorized Account Access via Legacy Remote Gateway (Control A.8.5)
    # Inherent 5x5=25, Current Residual 4x5=20 (Critical), Target 1x5=5, Mitigate
    create_risk(
        assessment_id=asm_id,
        title="Unauthorized Account Access via Legacy Remote Gateway",
        description="Contractors and external administrators can authenticate to legacy VPN ingress using single-factor passwords, bypassing corporate Okta adaptive MFA.",
        asset_or_process="Corporate payment gateway and administrative jump hosts",
        threat="External credential stuffing and password spray attacks",
        vulnerability="Legacy VPN gateway permits single-factor password authentication for contractors without secondary challenge",
        consequence="Unauthorized production access, credential theft, and lateral movement into the customer payment processing zone",
        risk_category="Access Management",
        existing_controls="Okta MFA enforced on corporate employees; network perimeter firewall rate-limiting",
        risk_owner="Chief Information Security Officer",
        responsible_department="Infrastructure & Network Engineering",
        inherent_likelihood=5,
        inherent_impact=5,
        inherent_rationale="High exposure surface with credential-based attacks frequently targeting remote access endpoints.",
        residual_likelihood=4,
        residual_impact=5,
        residual_rationale="Contractors currently access legacy gateway without secondary factor; probability of compromised credential remains high.",
        target_likelihood=1,
        target_impact=5,
        target_rationale="Mandatory WebAuthn/FIDO2 hardware MFA reduces credential stuffing success probability to rare.",
        treatment_strategy="Mitigate",
        treatment_justification="Critical operational exposure requiring immediate architecture migration.",
        proposed_treatment="Enforce MFA for relevant accounts by decommissioning gw-legacy.fincore.internal and routing contractors through Okta SAML proxy.",
        treatment_owner="Head of Infrastructure",
        target_treatment_date="2026-06-30",
        status="Under Treatment",
        assessor_name="Marcus Vance, Lead Auditor ISO 27001",
        assessment_date="2026-05-15",
        review_date="2026-08-30",
        linked_control_ids=[ca_map["A.8.5"]] if "A.8.5" in ca_map else [],
        linked_finding_ids=[fnd_001_id] if fnd_001_id else [],
        db_path=db_path,
    )

    # Risk 2: Sensitive Customer Data Exposure in Cloud Archive Storage (Control A.8.24)
    # Inherent 5x5=25, Current Residual 3x5=15 (High), Target 1x5=5, Mitigate
    create_risk(
        assessment_id=asm_id,
        title="Sensitive Customer Data Exposure in Cloud Archive Storage",
        description="Historical customer transaction archive buckets in AWS S3 lack customer-managed KMS encryption and TLS transport enforcement.",
        asset_or_process="Multi-tenant customer payment transaction archives (S3)",
        threat="Cloud credential compromise, insider data exfiltration, or storage misconfiguration",
        vulnerability="Payment transaction archive bucket lacked mandatory KMS encryption and strict transport policy",
        consequence="Cardholder data disclosure, regulatory investigation under PCI-DSS/GDPR, and customer trust loss",
        risk_category="Data Protection",
        existing_controls="AWS IAM least privilege role policies; VPC private endpoint routing",
        risk_owner="Head of Data Governance",
        responsible_department="Cloud Infrastructure & Security",
        inherent_likelihood=5,
        inherent_impact=5,
        inherent_rationale="Payment card data is a prime target for cloud-targeted exfiltration.",
        residual_likelihood=3,
        residual_impact=5,
        residual_rationale="VPC private endpoint restricts public network access, but lack of KMS encryption leaves data exposed to internal IAM compromise.",
        target_likelihood=1,
        target_impact=5,
        target_rationale="Enforced KMS customer-managed key (CMK) encryption with strict key policy mitigates unauthorized data readability.",
        treatment_strategy="Mitigate",
        treatment_justification="Protection of data at rest is a non-negotiable regulatory mandate.",
        proposed_treatment="Apply AWS KMS CMK encryption and enforce bucket policy denying non-TLS transport.",
        treatment_owner="Cloud Security Architect",
        target_treatment_date="2026-07-15",
        status="Treatment Planned",
        assessor_name="Marcus Vance, Lead Auditor ISO 27001",
        assessment_date="2026-05-15",
        review_date="2026-09-30",
        linked_control_ids=[ca_map["A.8.24"]] if "A.8.24" in ca_map else [],
        db_path=db_path,
    )

    # Risk 3: Permanent Payment Database Loss and Extended Outage (Control A.8.13)
    # Inherent 4x5=20, Current Residual 3x4=12 (High), Target 1x4=4, Mitigate
    create_risk(
        assessment_id=asm_id,
        title="Permanent Payment Database Loss and Extended Outage",
        description="Production RDS PostgreSQL database snapshots exist, but restoration drill failed due to cross-account KMS decryption permissions and timeout.",
        asset_or_process="Production PostgreSQL database instance (rds-prod-pg-payments)",
        threat="Ransomware encryption, underlying EBS storage corruption, or regional AWS outage",
        vulnerability="Restoration procedures untested; DR drill failed due to cross-account KMS decryption permissions and timeout",
        consequence="Unrecoverable transaction data loss, recovery time exceeding 45 minutes RTO threshold, and payment gateway downtime",
        risk_category="Business Continuity",
        existing_controls="Automated daily RDS snapshots; cross-region snapshot replication",
        risk_owner="Director of Engineering",
        responsible_department="Database & Cloud Operations",
        inherent_likelihood=4,
        inherent_impact=5,
        inherent_rationale="Database failure directly threatens operational solvency.",
        residual_likelihood=3,
        residual_impact=4,
        residual_rationale="Snapshots exist but unverified recovery capabilities mean restore time in a real crisis remains uncertain.",
        target_likelihood=1,
        target_impact=4,
        target_rationale="Automated monthly DR restoration verification with fixed KMS policies guarantees reliable recovery within 30-minute RTO.",
        treatment_strategy="Mitigate",
        treatment_justification="RTO compliance is contractual with tier-1 banking partners.",
        proposed_treatment="Update cross-account KMS key access policy and schedule recurring automated restoration tests.",
        treatment_owner="Database Operations Lead",
        target_treatment_date="2026-08-01",
        status="Open",
        assessor_name="Marcus Vance, Lead Auditor ISO 27001",
        assessment_date="2026-05-15",
        review_date="2026-10-15",
        linked_control_ids=[ca_map["A.8.13"]] if "A.8.13" in ca_map else [],
        db_path=db_path,
    )

    # Risk 4: Privileged Infrastructure Access Misuse and Unapproved Changes (Control A.8.2)
    # Inherent 4x4=16, Current Residual 2x4=8 (Medium), Target 1x4=4, Mitigate
    create_risk(
        assessment_id=asm_id,
        title="Privileged Infrastructure Access Misuse and Unapproved Changes",
        description="Standing administrative access across 6 engineers in AWS console creates risk of unmonitored or unapproved infrastructure changes.",
        asset_or_process="Production AWS Cloud Management Console and Active Directory Domain Controllers",
        threat="Malicious insider or hijacked administrator credential",
        vulnerability="Standing administrative privileges across 6 engineers with quarterly reviews performed manually",
        consequence="Unauthorized architecture changes, silent disabling of audit logging, and undetected sabotage",
        risk_category="Access Management",
        existing_controls="Root break-glass hardware YubiKey stored in physical safe; CyberArk vault for domain admin service accounts",
        risk_owner="VP of Infrastructure",
        responsible_department="IT Security Operations",
        inherent_likelihood=4,
        inherent_impact=4,
        inherent_rationale="Full administrative access provides unfettered ability to modify production systems.",
        residual_likelihood=2,
        residual_impact=4,
        residual_rationale="Hardware token safeguards root account; standing admin accounts exist but are limited to senior vetted engineers.",
        target_likelihood=1,
        target_impact=4,
        target_rationale="Just-in-time (JIT) access elevation eliminates standing administrative privileges.",
        treatment_strategy="Mitigate",
        treatment_justification="Zero-standing-privilege architecture aligns with corporate security roadmap.",
        proposed_treatment="Implement AWS IAM Identity Center with temporary permission sets and mandatory approval workflows.",
        treatment_owner="IAM Team Lead",
        target_treatment_date="2026-09-15",
        status="Treatment Planned",
        assessor_name="Marcus Vance, Lead Auditor ISO 27001",
        assessment_date="2026-05-15",
        review_date="2026-11-15",
        linked_control_ids=[ca_map["A.8.2"]] if "A.8.2" in ca_map else [],
        db_path=db_path,
    )

    # Risk 5: Social Engineering and Employee Phishing Credential Theft (Control A.6.3)
    # Inherent 3x4=12, Current Residual 2x2=4 (Low), Target 2x2=4, Accept
    create_risk(
        assessment_id=asm_id,
        title="Social Engineering and Employee Phishing Credential Theft",
        description="Annual security awareness training completion rate stands at 74% with 62 non-technical staff overdue.",
        asset_or_process="Corporate workforce email and workstation endpoints",
        threat="Sophisticated spear phishing campaigns and business email compromise (BEC)",
        vulnerability="Annual security awareness training completion rate at 74% (62 employees overdue)",
        consequence="Employee credential theft leading to corporate network entry",
        risk_category="Security Awareness",
        existing_controls="Mandatory new-hire security onboarding; automated email warning banners on external communications; endpoint EDR agents",
        risk_owner="Director of People & Culture",
        responsible_department="People Operations & HR",
        inherent_likelihood=3,
        inherent_impact=4,
        inherent_rationale="Human error is consistently targeted by external threat actors.",
        residual_likelihood=2,
        residual_impact=2,
        residual_rationale="Overdue personnel are in non-technical sales roles with restricted access to production data. Defense-in-depth controls (EDR, mail gateway filtering) substantially contain the impact.",
        target_likelihood=2,
        target_impact=2,
        target_rationale="Residual exposure is already at acceptable threshold; ongoing automated LMS reminders will maintain baseline compliance.",
        treatment_strategy="Accept",
        treatment_justification="Risk exposure is within organizational risk tolerance; cost of immediate disciplinary measures outweighs incremental security gain.",
        acceptance_justification="Formal risk acceptance authorized by CISO and Risk Committee due to compensating technical controls (EDR, email gateway filtering) and low access privileges of non-compliant personnel.",
        approving_authority="FinCore Information Security Risk Committee",
        approval_status="Approved",
        approval_date="2026-05-15",
        status="Accepted",
        assessor_name="Marcus Vance, Lead Auditor ISO 27001",
        assessment_date="2026-05-15",
        review_date="2026-11-30",
        linked_control_ids=[ca_map["A.6.3"]] if "A.6.3" in ca_map else [],
        db_path=db_path,
    )


def seed_fincore_phase5_remediations(asm_id: int, db_path: Optional[str] = None) -> None:
    """
    Seed 5 realistic demonstration corrective actions for FinCore Technologies.
    Repeat-safe / idempotent.
    Distribution: Open: 2, In Progress: 1, Awaiting Verification: 1, Closed: 1.
    Verified Closure Rate: 20%.
    """
    from services.remediation_service import (
        create_remediation,
        update_remediation,
        record_progress_update,
        record_verification,
        close_remediation,
        link_control_to_remediation,
        link_finding_to_remediation,
        link_risk_to_remediation,
        link_evidence_to_remediation,
    )

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM remediation WHERE assessment_id = ?", (asm_id,))
        if cursor.fetchone()[0] > 0:
            return  # Repeat-safe

        # Control IDs map
        cursor.execute(
            """
            SELECT ca.id, c.control_identifier
            FROM control_assessments ca
            JOIN controls c ON ca.control_id = c.id
            WHERE ca.assessment_id = ?
            """,
            (asm_id,),
        )
        ca_map = {r["control_identifier"]: r["id"] for r in cursor.fetchall()}

        # Finding map
        cursor.execute(
            "SELECT id, finding_identifier FROM findings WHERE assessment_id = ?",
            (asm_id,),
        )
        fnd_map = {r["finding_identifier"]: r["id"] for r in cursor.fetchall()}

        # Risk map
        cursor.execute(
            "SELECT id, risk_identifier FROM risks WHERE assessment_id = ?",
            (asm_id,),
        )
        rsk_map = {r["risk_identifier"]: r["id"] for r in cursor.fetchall()}

        # Evidence map
        cursor.execute(
            "SELECT id, title FROM evidence WHERE assessment_id = ?",
            (asm_id,),
        )
        ev_rows = cursor.fetchall()
        ev_backup_id = next((r["id"] for r in ev_rows if "Snapshot" in r["title"] or "Backup" in r["title"] or "RDS" in r["title"]), None)
        ev_train_id = next((r["id"] for r in ev_rows if "Awareness" in r["title"] or "Training" in r["title"]), None)
        if not ev_train_id and ev_rows:
            ev_train_id = ev_rows[0]["id"]
        if not ev_backup_id and ev_rows:
            ev_backup_id = ev_rows[0]["id"]

    # Action 1: Enforce MFA for Remote Accounts (Control A.8.5, Finding FND-001, Risk RSK-001)
    # Priority Critical, In Progress, 60%
    act1_id = create_remediation(
        assessment_id=asm_id,
        data={
            "remediation_identifier": "ACT-001",
            "action_title": "Enforce MFA for Remote Accounts",
            "action_description": "Decommission legacy contractor VPN gateway and mandate Azure AD Conditional Access with FIDO2 WebAuthn authentication.",
            "immediate_correction": "Implemented temporary IP whitelisting and 15-minute inactivity session limits on legacy VPN gateway.",
            "root_cause_analysis_method": "5 Whys",
            "root_cause_details": {
                "problem_statement": "Remote contractors accessed core systems without phishing-resistant MFA.",
                "why1": "Legacy contractor gateway gw-legacy.fincore.internal remained active.",
                "why2": "Decommissioning project was deprioritized due to billing software migration.",
                "why3": "Contractor firm lacked compatible soft-token mobile authenticator devices.",
                "why4": "Hardware token procurement request was stalled in procurement review.",
                "why5": "Vendor security onboarding standard did not mandate hardware security keys before contract execution.",
            },
            "root_cause": "Absence of mandatory contractor onboarding security controls allowed unmanaged legacy gateway access exceptions to persist.",
            "contributing_factors": "Third-party vendor dependency and procurement approval bottlenecks.",
            "long_term_corrective_action": "Procure and mandate FIDO2 hardware security keys for all external contractors; completely decommission legacy gateway.",
            "expected_outcome": "100% MFA enforcement on all remote contractor and privileged sessions.",
            "action_priority": "Critical",
            "action_owner": "IT Security Manager",
            "responsible_department": "Information Security",
            "assigned_date": "2026-05-15",
            "target_date": "2026-06-30",
            "progress_percentage": 60,
            "implementation_summary": "60% of contractor accounts migrated to Azure AD Conditional Access; remaining 12 contractors scheduled for hardware key cutover.",
            "verification_requirements": "Inspect Azure AD sign-in logs and verify DNS de-registration of gw-legacy.fincore.internal.",
            "finding_id": fnd_map.get("FND-001"),
            "risk_id": rsk_map.get("RSK-001"),
            "linked_control_ids": [ca_map["A.8.5"]] if "A.8.5" in ca_map else [],
        },
        actor="Marcus Vance, Lead Auditor ISO 27001",
        db_path=db_path,
    )
    # Set status to In Progress
    update_remediation(act1_id, {"status": "In Progress"}, db_path=db_path)

    # Action 2: Review Privileged Access Permissions (Control A.8.2)
    # Priority High, Open, 0%
    create_remediation(
        assessment_id=asm_id,
        data={
            "remediation_identifier": "ACT-002",
            "action_title": "Review Privileged Access Permissions",
            "action_description": "Execute comprehensive access re-certification for all engineers with AWS IAM standing administrative privileges.",
            "immediate_correction": "Revoked standing administrative access for 2 inactive consultant accounts.",
            "root_cause_analysis_method": "Direct Analysis",
            "root_cause": "Quarterly access reviews were managed manually across disconnected spreadsheets without automated revocation.",
            "contributing_factors": "Rapid engineering headcount expansion and lack of centralized IAM governance tooling.",
            "long_term_corrective_action": "Deploy AWS IAM Identity Center with temporary just-in-time access elevation workflows and automated managerial review campaigns.",
            "expected_outcome": "Zero standing administrative privileges; 100% quarterly access re-certification completion.",
            "action_priority": "High",
            "action_owner": "IT Operations",
            "responsible_department": "Infrastructure Operations",
            "assigned_date": "2026-05-15",
            "target_date": "2026-07-31",
            "progress_percentage": 0,
            "verification_requirements": "Inspect IAM Identity Center permission sets and quarterly review audit trail.",
            "linked_control_ids": [ca_map["A.8.2"]] if "A.8.2" in ca_map else [],
            "linked_risk_ids": [rsk_map.get("RSK-004")] if "RSK-004" in rsk_map else [],
        },
        actor="Marcus Vance, Lead Auditor ISO 27001",
        db_path=db_path,
    )

    # Action 3: Perform Backup Restoration Testing (Control A.8.13)
    # Priority High, Awaiting Verification, 100%
    act3_id = create_remediation(
        assessment_id=asm_id,
        data={
            "remediation_identifier": "ACT-003",
            "action_title": "Perform Backup Restoration Testing",
            "action_description": "Execute automated cross-account restore drill for production PostgreSQL payment database to verify RTO under 45 minutes.",
            "immediate_correction": "Re-verified automated cross-region snapshot replication into secondary AWS DR region.",
            "root_cause_analysis_method": "Direct Analysis",
            "root_cause": "Cross-account KMS encryption key policy omitted the DR restore IAM execution role.",
            "contributing_factors": "Complex multi-account AWS Landing Zone permission architecture.",
            "long_term_corrective_action": "Update KMS key policies to authorize DR restore roles and automate recurring quarterly restoration simulations.",
            "expected_outcome": "Production RDS PostgreSQL database restores cleanly within 30 minutes.",
            "action_priority": "High",
            "action_owner": "Infrastructure",
            "responsible_department": "Cloud Architecture",
            "assigned_date": "2026-05-15",
            "target_date": "2026-05-30",
            "progress_percentage": 100,
            "implementation_summary": "KMS key policy updated; executed full database restore in staging VPC. Restoration succeeded in 22 minutes with 100% checksum consistency.",
            "verification_requirements": "Inspect AWS Backup restoration logs and verify checksum validation report.",
            "linked_control_ids": [ca_map["A.8.13"]] if "A.8.13" in ca_map else [],
            "linked_risk_ids": [rsk_map.get("RSK-003")] if "RSK-003" in rsk_map else [],
            "linked_evidence_ids": [ev_backup_id] if ev_backup_id else [],
        },
        actor="Marcus Vance, Lead Auditor ISO 27001",
        db_path=db_path,
    )
    # Move status to Awaiting Verification
    update_remediation(act3_id, {"status": "In Progress"}, db_path=db_path)
    update_remediation(act3_id, {"status": "Awaiting Verification", "implementation_summary": "KMS key policy updated; executed full database restore in staging VPC. Restoration succeeded in 22 minutes with 100% checksum consistency.", "progress_percentage": 100}, db_path=db_path)

    # Action 4: Update Information Security Policy (Control A.5.1)
    # Priority Medium, Open, 0%
    create_remediation(
        assessment_id=asm_id,
        data={
            "remediation_identifier": "ACT-004",
            "action_title": "Update Information Security Policy",
            "action_description": "Update and distribute Information Security Policy v3.3 incorporating ISO/IEC 27001:2022 control updates and threat intelligence procedures.",
            "immediate_correction": "Published policy addendum covering threat intelligence and cloud data masking.",
            "root_cause_analysis_method": "Direct Analysis",
            "root_cause": "Annual policy review schedule was out of sync with technical architecture migrations.",
            "contributing_factors": "High operational velocity in engineering overshadowing policy revision schedules.",
            "long_term_corrective_action": "Institute bi-annual policy governance committee reviews with automated distribution acknowledgments.",
            "expected_outcome": "Approved, published policy distributed with 100% employee acknowledgment.",
            "action_priority": "Medium",
            "action_owner": "Compliance",
            "responsible_department": "Governance, Risk & Compliance",
            "assigned_date": "2026-05-15",
            "target_date": "2026-08-15",
            "progress_percentage": 0,
            "verification_requirements": "Verify executive sign-off and intranet publication logs.",
            "linked_control_ids": [ca_map["A.5.1"]] if "A.5.1" in ca_map else [],
        },
        actor="Marcus Vance, Lead Auditor ISO 27001",
        db_path=db_path,
    )

    # Action 5: Complete Security Awareness Training (Control A.6.3)
    # Priority Medium, Closed, 100%
    act5_id = create_remediation(
        assessment_id=asm_id,
        data={
            "remediation_identifier": "ACT-005",
            "action_title": "Complete Security Awareness Training",
            "action_description": "Achieve >95% workforce completion rate for annual security awareness training curriculum.",
            "immediate_correction": "Issued automated email reminders and managerial escalation notices to 62 non-compliant personnel.",
            "root_cause_analysis_method": "Direct Analysis",
            "root_cause": "Training completion was not tracked as a managerial KPI.",
            "contributing_factors": "Lack of automated escalation to department heads for overdue modules.",
            "long_term_corrective_action": "Integrate LMS completion metrics into monthly executive leadership KPI dashboards.",
            "expected_outcome": "Workforce security awareness training completion >= 95%.",
            "action_priority": "Medium",
            "action_owner": "Human Resources",
            "responsible_department": "People Operations",
            "assigned_date": "2026-05-01",
            "target_date": "2026-05-10",
            "progress_percentage": 100,
            "implementation_summary": "Targeted completion campaign executed; 238 of 240 active personnel completed annual curriculum.",
            "verification_requirements": "Inspect KnowBe4 LMS completion export against HR active employee roster.",
            "linked_control_ids": [ca_map["A.6.3"]] if "A.6.3" in ca_map else [],
            "linked_risk_ids": [rsk_map.get("RSK-005")] if "RSK-005" in rsk_map else [],
            "linked_evidence_ids": [ev_train_id] if ev_train_id else [],
        },
        actor="Marcus Vance, Lead Auditor ISO 27001",
        db_path=db_path,
    )
    # Transition to In Progress, Awaiting Verification, Under Verification
    update_remediation(act5_id, {"status": "In Progress"}, db_path=db_path)
    update_remediation(act5_id, {"status": "Awaiting Verification", "implementation_summary": "Targeted completion campaign executed; 238 of 240 active personnel completed annual curriculum.", "progress_percentage": 100}, db_path=db_path)

    # Record verification for Action 5
    record_verification(
        remediation_id=act5_id,
        verification_data={
            "verification_objective": "Verify workforce security awareness training completion rate exceeds 95% target.",
            "verification_procedure": "Extracted KnowBe4 LMS completion report and reconciled against active employee HR master roster.",
            "expected_outcome": "Workforce completion rate >= 95% with zero overdue high-privilege staff.",
            "observed_outcome": "238 of 240 active personnel completed training (99.2% completion rate). Zero high-privilege users overdue.",
            "sample_examined": "100% of workforce (240 active employees across all departments)",
            "verification_result": "Effective",
            "verifier_name": "Marcus Vance, Lead Auditor ISO 27001",
            "verification_date": "2026-05-15",
            "verification_notes": "Effectiveness verified. The remediation goal has been met and verified with supporting LMS logs.",
            "recommended_next_action": "Formally close corrective action ACT-005.",
        },
        actor="Marcus Vance, Lead Auditor ISO 27001",
        db_path=db_path,
    )

    # Formally close Action 5
    close_remediation(
        remediation_id=act5_id,
        closure_rationale="Verified through KnowBe4 LMS completion records that 99.2% of workforce completed annual security training. Verification VRF-001 confirmed Effective.",
        actor="Marcus Vance, Lead Auditor ISO 27001",
        db_path=db_path,
    )
