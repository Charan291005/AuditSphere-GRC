"""
AuditSphere – Phase 5 Automated Test Suite
Testing Corrective Action Register, Root Cause Analysis (5 Whys), Progress Tracking,
Deadline Extensions, Effectiveness Verification, Governance Closure Rules, Finding/Control/Risk
Integrations, CSV Export (CWE-1236 Defense), and Demonstration Dataset.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
from datetime import date, timedelta
from pathlib import Path
import pytest

import database
from services.activity_service import get_recent_activities
from services.assessment_service import archive_assessment, create_assessment
from services.control_service import (
    create_fincore_demo_assessment,
    get_assessment_controls,
    update_control_assessment,
)
from services.dashboard_service import get_dashboard_summary
from services.evidence_manager import upload_evidence
from services.gap_engine import create_finding, get_single_finding, update_finding
from services.remediation_engine import (
    calculate_remediation_metrics,
    export_remediations_to_csv,
    sanitize_csv_cell,
    suggest_priority_from_source,
    validate_closure_eligibility,
    validate_priority_alignment,
    validate_status_transition,
)
from services.remediation_service import (
    cancel_remediation,
    close_remediation,
    create_remediation,
    extend_deadline,
    get_assessment_remediations,
    get_control_remediations,
    get_finding_remediations,
    get_remediation_controls,
    get_remediation_deadline_extensions,
    get_remediation_evidence,
    get_remediation_findings,
    get_remediation_progress_history,
    get_remediation_risks,
    get_remediation_verifications,
    get_risk_remediations,
    get_single_remediation,
    link_control_to_remediation,
    link_evidence_to_remediation,
    link_finding_to_remediation,
    link_risk_to_remediation,
    record_progress_update,
    record_verification,
    reopen_remediation,
    update_remediation,
)
from services.risk_service import create_risk, get_single_risk, update_risk


@pytest.fixture
def temp_db():
    """Create an isolated, temporary SQLite database with all tables, triggers, and migrations."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database.init_db(path)
    yield path
    try:
        os.remove(path)
    except OSError:
        pass


@pytest.fixture
def sample_assessment(temp_db):
    """Create an active test assessment."""
    res = create_assessment(
        title="Payment Security Assessment 2026",
        organization="Apex Pay Corp",
        industry="Financial Services",
        standard="ISO/IEC 27001:2022",
        scope="Cloud payment processing environment",
        lead_assessor="Lead Auditor",
        assessment_date="2026-05-15",
        db_path=temp_db,
    )
    return res["id"] if isinstance(res, dict) else res


# =========================================================================
# 1. Action Creation, Editing & Mandatory Field Validation
# =========================================================================

def test_corrective_action_creation_and_retrieval(temp_db, sample_assessment):
    """Test creating a corrective action with mandatory fields and verifying persistence."""
    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={
            "action_title": "Enforce Multi-Factor Authentication for Database Admins",
            "action_description": "Deploy hardware security tokens for all RDS database administrators.",
            "action_owner": "Security Engineering Lead",
            "responsible_department": "IT Security",
            "action_priority": "High",
            "target_date": "2026-08-31",
            "immediate_correction": "Enabled temporary SMS MFA as an interim containment control.",
            "root_cause_analysis_method": "Direct Analysis",
            "root_cause": "Legacy database management bastion lacked WebAuthn support.",
            "long_term_corrective_action": "Migrate database administration bastion to AWS IAM Identity Center.",
            "expected_outcome": "Zero administrative logins without hardware key authentication.",
        },
        db_path=temp_db,
    )

    action = get_single_remediation(act_id, db_path=temp_db)
    assert action is not None
    assert action["remediation_identifier"] == "ACT-001"
    assert action["action_title"] == "Enforce Multi-Factor Authentication for Database Admins"
    assert action["status"] == "Open"
    assert action["progress_percentage"] == 0
    assert action["action_priority"] == "High"
    assert action["target_date"] == "2026-08-31"
    assert action["original_target_date"] == "2026-08-31"


def test_mandatory_field_validations(temp_db, sample_assessment):
    """Test validation rejection for missing mandatory title, owner, or target date."""
    # Missing title
    with pytest.raises(ValueError, match="title is mandatory"):
        create_remediation(
            assessment_id=sample_assessment,
            data={"action_title": "", "action_owner": "Admin", "target_date": "2026-10-10"},
            db_path=temp_db,
        )

    # Missing owner
    with pytest.raises(ValueError, match="owner is mandatory"):
        create_remediation(
            assessment_id=sample_assessment,
            data={"action_title": "Title", "action_owner": "", "target_date": "2026-10-10"},
            db_path=temp_db,
        )

    # Missing target date
    with pytest.raises(ValueError, match="Target completion date is mandatory"):
        create_remediation(
            assessment_id=sample_assessment,
            data={"action_title": "Title", "action_owner": "Admin", "target_date": ""},
            db_path=temp_db,
        )

    # Invalid priority
    with pytest.raises(ValueError, match="Invalid priority"):
        create_remediation(
            assessment_id=sample_assessment,
            data={"action_title": "Title", "action_owner": "Admin", "target_date": "2026-10-10", "action_priority": "UltraHigh"},
            db_path=temp_db,
        )


def test_archived_assessment_blocks_remediation_mutations(temp_db, sample_assessment):
    """Verify archived assessment strictly prevents creating or updating corrective actions."""
    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={"action_title": "Action Pre-Archive", "action_owner": "Owner", "target_date": "2026-10-10"},
        db_path=temp_db,
    )

    archive_assessment(sample_assessment, db_path=temp_db)

    # Block new action creation
    with pytest.raises(ValueError, match="Cannot modify records for an archived assessment"):
        create_remediation(
            assessment_id=sample_assessment,
            data={"action_title": "New Action Post-Archive", "action_owner": "Owner", "target_date": "2026-10-10"},
            db_path=temp_db,
        )

    # Block action updating
    with pytest.raises(ValueError, match="Cannot modify records for an archived assessment"):
        update_remediation(act_id, {"action_title": "Updated Title"}, db_path=temp_db)


# =========================================================================
# 2. Relational Mapping, Multi-Action Linkages & Cross-Assessment Triggers
# =========================================================================

def test_relational_mappings_findings_risks_controls(temp_db, sample_assessment):
    """Test linking findings, risks, and controls to a corrective action."""
    # Create finding
    fnd = create_finding(
        assessment_id=sample_assessment,
        title="Unencrypted S3 Bucket Backup",
        criteria="A.8.24 requires data protection at rest.",
        condition="Customer backups stored without KMS encryption.",
        effect="Potential data exposure if bucket compromised.",
        recommendation="Enable AWS KMS CMK encryption.",
        severity="High",
        supporting_evidence_references="EVD-001",
        db_path=temp_db,
    )
    fnd_id = fnd["id"]

    # Create risk
    rsk = create_risk(
        assessment_id=sample_assessment,
        title="Cloud Storage Exposure Risk",
        inherent_likelihood=4,
        inherent_impact=4,
        residual_likelihood=3,
        residual_impact=4,
        db_path=temp_db,
    )
    rsk_id = rsk["id"]

    # Get a control assessment
    ctrls = get_assessment_controls(sample_assessment, db_path=temp_db)
    ca_id = ctrls[0]["assessment_control_id"]

    # Create corrective action
    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={
            "action_title": "Remediate S3 Storage Encryption",
            "action_owner": "Cloud Architect",
            "target_date": "2026-09-01",
            "linked_finding_ids": [fnd_id],
            "linked_risk_ids": [rsk_id],
            "linked_control_ids": [ca_id],
        },
        db_path=temp_db,
    )

    linked_f = get_remediation_findings(act_id, db_path=temp_db)
    assert len(linked_f) == 1
    assert linked_f[0]["id"] == fnd_id

    linked_r = get_remediation_risks(act_id, db_path=temp_db)
    assert len(linked_r) == 1
    assert linked_r[0]["id"] == rsk_id

    linked_c = get_remediation_controls(act_id, db_path=temp_db)
    assert len(linked_c) == 1
    assert linked_c[0]["id"] == ca_id

    # Reverse queries
    f_actions = get_finding_remediations(fnd_id, db_path=temp_db)
    assert len(f_actions) == 1
    assert f_actions[0]["id"] == act_id

    r_actions = get_risk_remediations(rsk_id, db_path=temp_db)
    assert len(r_actions) == 1
    assert r_actions[0]["id"] == act_id

    c_actions = get_control_remediations(ca_id, db_path=temp_db)
    assert len(c_actions) == 1
    assert c_actions[0]["id"] == act_id


def test_multiple_actions_linked_to_one_finding(temp_db, sample_assessment):
    """Verify that one finding can be addressed by multiple distinct corrective actions."""
    fnd = create_finding(
        assessment_id=sample_assessment,
        title="Complex Identity Architecture Gaps",
        criteria="A.8.5 requires secure authentication.",
        condition="Password complexity weak and MFA not enforced for API access.",
        effect="Elevated brute force and credential stuffing exposure.",
        recommendation="Deploy both MFA for portals and OAuth2 mTLS for APIs.",
        severity="Critical",
        supporting_evidence_references="EVD-001",
        db_path=temp_db,
    )
    fnd_id = fnd["id"]

    act1 = create_remediation(
        assessment_id=sample_assessment,
        data={"action_title": "Deploy Portal WebAuthn MFA", "action_owner": "IAM Lead", "target_date": "2026-07-01", "linked_finding_ids": [fnd_id]},
        db_path=temp_db,
    )
    act2 = create_remediation(
        assessment_id=sample_assessment,
        data={"action_title": "Implement OAuth2 mTLS for Core APIs", "action_owner": "API Gateway Lead", "target_date": "2026-08-01", "linked_finding_ids": [fnd_id]},
        db_path=temp_db,
    )

    linked = get_finding_remediations(fnd_id, db_path=temp_db)
    assert len(linked) == 2
    assert {a["id"] for a in linked} == {act1, act2}


def test_cross_assessment_relationship_triggers(temp_db, sample_assessment):
    """Enforce that database triggers abort any attempt to link actions across assessment boundaries."""
    other_res = create_assessment(
        title="Other Org Assessment",
        organization="Other Org",
        industry="Technology",
        scope="Cloud environment",
        lead_assessor="Other Auditor",
        assessment_date="2026-05-15",
        db_path=temp_db,
    )
    other_asm = other_res["id"] if isinstance(other_res, dict) else other_res

    # Create finding in other assessment
    fnd_other = create_finding(
        assessment_id=other_asm,
        title="Other Org Finding",
        criteria="Criteria",
        condition="Condition",
        effect="Effect",
        recommendation="Recommendation",
        severity="Medium",
        supporting_evidence_references="EVD-001",
        db_path=temp_db,
    )

    # Create corrective action in sample_assessment
    act_sample = create_remediation(
        assessment_id=sample_assessment,
        data={"action_title": "Sample Org Action", "action_owner": "Owner", "target_date": "2026-08-01"},
        db_path=temp_db,
    )

    # Attempt cross-assessment link
    with pytest.raises(Exception, match="Cross-assessment violation"):
        link_finding_to_remediation(act_sample, fnd_other["id"], db_path=temp_db)


# =========================================================================
# 3. Root Cause Analysis (5 Whys) & Priority Alignment
# =========================================================================

def test_root_cause_analysis_5_whys_persistence(temp_db, sample_assessment):
    """Test structured 5 Whys analysis serialization and retrieval."""
    five_whys_data = {
        "problem_statement": "Patching SLA was breached for core web payment servers.",
        "why1": "Security patches released in April were deployed in June.",
        "why2": "The staging environment test failed and required manual debugging.",
        "why3": "Staging environment configuration diverged from production.",
        "why4": "Configuration drift occurred due to ad-hoc manual hotfixes.",
        "why5": "Infrastructure as Code (IaC) pipelines were not enforced for emergency changes.",
    }

    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={
            "action_title": "Automate Configuration Drift Detection",
            "action_owner": "DevOps Lead",
            "target_date": "2026-09-30",
            "root_cause_analysis_method": "5 Whys",
            "root_cause_details": five_whys_data,
            "root_cause": "Uncontrolled configuration drift in staging environments delayed critical security patches.",
        },
        db_path=temp_db,
    )

    act = get_single_remediation(act_id, db_path=temp_db)
    assert act["root_cause_analysis_method"] == "5 Whys"
    assert "Uncontrolled configuration drift" in act["root_cause"]


def test_priority_alignment_with_critical_risk():
    """Verify priority alignment validation requiring justification if linked to Critical risk with lower priority."""
    # Critical risk with Medium priority requires justification
    with pytest.raises(ValueError, match="documented priority justification is required"):
        validate_priority_alignment(risk_level="Critical", action_priority="Medium", priority_justification="")

    # With justification passes
    validate_priority_alignment(
        risk_level="Critical",
        action_priority="Medium",
        priority_justification="Interim procedural compensating control; architectural replacement tracked in separate project.",
    )


# =========================================================================
# 4. Lifecycle Status Transitions & Governance Validation
# =========================================================================

def test_valid_status_transitions(temp_db, sample_assessment):
    """Test permitted lifecycle transitions from Open to In Progress to Awaiting Verification."""
    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={"action_title": "Transition Test Action", "action_owner": "Owner", "target_date": "2026-09-01"},
        db_path=temp_db,
    )

    # 1. Open -> In Progress
    update_remediation(act_id, {"status": "In Progress"}, db_path=temp_db)
    act = get_single_remediation(act_id, db_path=temp_db)
    assert act["status"] == "In Progress"

    # 2. In Progress -> Awaiting Verification (requires progress=100 & implementation_summary)
    update_remediation(
        act_id,
        {
            "status": "Awaiting Verification",
            "progress_percentage": 100,
            "implementation_summary": "Implementation fully completed and operational.",
        },
        db_path=temp_db,
    )
    act = get_single_remediation(act_id, db_path=temp_db)
    assert act["status"] == "Awaiting Verification"


def test_invalid_status_transitions_rejected(temp_db, sample_assessment):
    """Test rejection of illegal direct transitions (e.g. Open -> Closed, In Progress -> Closed)."""
    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={"action_title": "Illegal Transition Test", "action_owner": "Owner", "target_date": "2026-09-01"},
        db_path=temp_db,
    )

    # Direct Open -> Closed is forbidden
    with pytest.raises(ValueError, match="Invalid status transition"):
        update_remediation(act_id, {"status": "Closed"}, db_path=temp_db)

    # Transition to Cancelled without reason is rejected
    with pytest.raises(ValueError, match="cancellation reason is required"):
        update_remediation(act_id, {"status": "Cancelled", "cancellation_reason": ""}, db_path=temp_db)

    # Awaiting verification without 100% progress is rejected
    update_remediation(act_id, {"status": "In Progress"}, db_path=temp_db)
    with pytest.raises(ValueError, match="progress must be 100%"):
        update_remediation(
            act_id,
            {"status": "Awaiting Verification", "progress_percentage": 50, "implementation_summary": "Half done"},
            db_path=temp_db,
        )


# =========================================================================
# 5. Progress Tracking, Deadlines & Extensions
# =========================================================================

def test_progress_tracking_and_history(temp_db, sample_assessment):
    """Test progress percentage updates and historical ledger recording."""
    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={"action_title": "Progress Action", "action_owner": "Engineer", "target_date": "2026-08-01"},
        db_path=temp_db,
    )

    # Record 25% progress
    record_progress_update(act_id, progress_percentage=25, description="Initial draft created.", updated_by="Engineer", db_path=temp_db)

    # Record 75% progress with blockers
    record_progress_update(act_id, progress_percentage=75, description="Implemented in staging.", blockers="Awaiting change window.", updated_by="Engineer", db_path=temp_db)

    act = get_single_remediation(act_id, db_path=temp_db)
    assert act["progress_percentage"] == 75
    assert act["status"] == "In Progress"  # Auto-transitioned from Open

    history = get_remediation_progress_history(act_id, db_path=temp_db)
    assert len(history) == 2
    assert history[0]["progress_percentage"] == 75
    assert history[1]["progress_percentage"] == 25


def test_deadline_extension_and_audit_trail(temp_db, sample_assessment):
    """Test extending an action deadline with mandatory justification and approval."""
    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={"action_title": "Deadline Test", "action_owner": "Engineer", "target_date": "2026-06-01"},
        db_path=temp_db,
    )

    extend_deadline(
        remediation_id=act_id,
        new_deadline="2026-07-15",
        extension_reason="Vendor hardware token delivery delay.",
        approving_authority="CISO",
        db_path=temp_db,
    )

    act = get_single_remediation(act_id, db_path=temp_db)
    assert act["target_date"] == "2026-07-15"
    assert act["original_target_date"] == "2026-06-01"

    ext_history = get_remediation_deadline_extensions(act_id, db_path=temp_db)
    assert len(ext_history) == 1
    assert ext_history[0]["previous_deadline"] == "2026-06-01"
    assert ext_history[0]["new_deadline"] == "2026-07-15"
    assert ext_history[0]["approving_authority"] == "CISO"


# =========================================================================
# 6. Verification Records & Closure Governance Rules
# =========================================================================

def test_full_effective_verification_and_closure_lifecycle(temp_db, sample_assessment):
    """Test complete successful workflow: Open -> In Progress -> Awaiting Verification -> Effective Verification -> Closed."""
    # 1. Create action
    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={
            "action_title": "Remediate Patching Vulnerabilities",
            "action_owner": "SecOps",
            "target_date": "2026-07-01",
            "root_cause": "Unmanaged staging configuration drift.",
        },
        db_path=temp_db,
    )

    # 2. Add remediation evidence
    ev_id = upload_evidence(
        assessment_id=sample_assessment,
        title="Tenable Scan Verification",
        file_name="Tenable_Scan_Remediation_Verification.txt",
        file_bytes=b"Audit verification scan output log file.",
        db_path=temp_db,
    )
    link_evidence_to_remediation(act_id, ev_id, db_path=temp_db)

    # 3. Progress to 100% and submit for verification
    record_progress_update(act_id, progress_percentage=100, description="Completed all patching.", db_path=temp_db)
    update_remediation(
        act_id,
        {
            "status": "Awaiting Verification",
            "progress_percentage": 100,
            "implementation_summary": "All 4 High-severity CVEs patched and verified via local agent scan.",
            "actual_completion_date": "2026-06-25",
        },
        db_path=temp_db,
    )

    # 4. Record Effective Verification
    record_verification(
        remediation_id=act_id,
        verification_data={
            "verification_objective": "Confirm zero active High vulnerabilities on web tier.",
            "verification_procedure": "Executed Tenable authenticated scan and inspected package versions.",
            "expected_outcome": "Zero CVEs older than 30 days.",
            "observed_outcome": "Zero high vulnerabilities detected across all 4 production nodes.",
            "verification_result": "Effective",
            "verifier_name": "Senior ISMS Auditor",
            "verification_date": "2026-06-26",
            "verification_notes": "Effectiveness verified. Clean scan output attached.",
        },
        db_path=temp_db,
    )

    # 5. Formally Close
    close_remediation(
        remediation_id=act_id,
        closure_rationale="Verified by independent authenticated vulnerability scan; root cause resolved.",
        db_path=temp_db,
    )

    act = get_single_remediation(act_id, db_path=temp_db)
    assert act["status"] == "Closed"
    assert "Verified by independent authenticated" in act["closure_rationale"]


def test_closure_rejected_if_verification_ineffective(temp_db, sample_assessment):
    """Test that an Ineffective verification blocks closure and allows reopening."""
    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={
            "action_title": "Firewall Rule Hardening",
            "action_owner": "NetOps",
            "target_date": "2026-07-01",
            "progress_percentage": 100,
            "implementation_summary": "Updated firewall rules.",
            "root_cause": "Permissive default ingress rules.",
        },
        db_path=temp_db,
    )

    # Add evidence
    ev_id = upload_evidence(
        assessment_id=sample_assessment,
        title="Firewall Config",
        file_name="FW_Config.txt",
        file_bytes=b"Firewall config dump.",
        db_path=temp_db,
    )
    link_evidence_to_remediation(act_id, ev_id, db_path=temp_db)

    update_remediation(act_id, {"status": "In Progress"}, db_path=temp_db)
    update_remediation(act_id, {"status": "Awaiting Verification", "progress_percentage": 100, "implementation_summary": "Done"}, db_path=temp_db)

    # Record Ineffective verification
    record_verification(
        remediation_id=act_id,
        verification_data={
            "verification_objective": "Verify port 22 blocked from internet.",
            "verification_procedure": "Port scan from external IP.",
            "expected_outcome": "Port 22 filtered/closed.",
            "observed_outcome": "Port 22 still responds open on backup interface.",
            "verification_result": "Ineffective",
            "verifier_name": "Auditor",
            "verification_date": "2026-06-20",
            "verification_notes": "Secondary interface was overlooked.",
        },
        db_path=temp_db,
    )

    # Attempt closure -> must fail!
    with pytest.raises(ValueError, match="Only actions verified as 'Effective' can be closed"):
        close_remediation(act_id, closure_rationale="Testing closure", db_path=temp_db)

    # Reopen action
    reopen_remediation(act_id, reopen_justification="Secondary interface must be patched as well.", db_path=temp_db)
    act = get_single_remediation(act_id, db_path=temp_db)
    assert act["status"] == "Reopened"


def test_finding_closure_enforcement_with_linked_actions(temp_db, sample_assessment):
    """Verify that a finding cannot be closed if it has an unverified, open corrective action."""
    fnd = create_finding(
        assessment_id=sample_assessment,
        title="Weak API Key Rotation",
        criteria="A.8.24 requires key management.",
        condition="API keys are not rotated annually.",
        effect="Key compromise risk.",
        recommendation="Implement automated rotation.",
        severity="High",
        supporting_evidence_references="EVD-001",
        db_path=temp_db,
    )
    fnd_id = fnd["id"]

    act_id = create_remediation(
        assessment_id=sample_assessment,
        data={
            "action_title": "Implement KMS Key Rotation",
            "action_owner": "SecOps",
            "target_date": "2026-09-01",
            "linked_finding_ids": [fnd_id],
        },
        db_path=temp_db,
    )

    # Attempt to close finding while action is Open -> must fail!
    with pytest.raises(ValueError, match="Outstanding linked corrective action"):
        update_finding(
            finding_id=fnd_id,
            title=fnd["title"],
            criteria=fnd["criteria"],
            condition=fnd["condition"],
            effect=fnd["effect"],
            recommendation=fnd["recommendation"],
            severity=fnd["severity"],
            finding_type=fnd["finding_type"],
            status="Closed",
            verification_notes="Auditor attempt to close before action is verified.",
            db_path=temp_db,
        )


# =========================================================================
# 7. Explicit Control & Risk Reassessments
# =========================================================================

def test_control_and_risk_explicit_reassessment(temp_db, sample_assessment):
    """Verify that control implementation status and risk scores require explicit reassessments and do not auto-mutate."""
    ctrls = get_assessment_controls(sample_assessment, db_path=temp_db)
    c = ctrls[0]
    ca_id = c["assessment_control_id"]

    rsk = create_risk(
        assessment_id=sample_assessment,
        title="Unmanaged Remote Access",
        inherent_likelihood=5,
        inherent_impact=5,
        residual_likelihood=4,
        residual_impact=5,
        db_path=temp_db,
    )
    rsk_id = rsk["id"]

    # Explicit control reassessment
    update_control_assessment(
        assessment_id=sample_assessment,
        control_id=c["control_id"],
        status="Implemented",
        assessment_observation="Reassessed following verified MFA deployment across all remote endpoints.",
        assessor_name="Lead Auditor",
        assessment_date="2026-06-30",
        db_path=temp_db,
    )

    updated_ctrls = get_assessment_controls(sample_assessment, db_path=temp_db)
    up_c = next(x for x in updated_ctrls if x["assessment_control_id"] == ca_id)
    assert up_c["status"] == "Implemented"

    # Explicit risk reassessment
    update_risk(
        risk_id=rsk_id,
        title=rsk["title"],
        residual_likelihood=2,
        residual_impact=4,
        residual_rationale="Hardware token MFA verified in production, significantly lowering likelihood.",
        db_path=temp_db,
    )

    updated_rsk = get_single_risk(rsk_id, db_path=temp_db)
    assert updated_rsk["residual_risk_score"] == 8
    assert updated_rsk["residual_risk_level"] == "Medium"
    # Verify reassessment logged to history
    assert len(updated_rsk["review_history"]) == 1


# =========================================================================
# 8. Remediation Metrics & Deadline Calculations
# =========================================================================

def test_remediation_metrics_calculations():
    """Test comprehensive remediation metrics calculation, overdue counts, and closure rate."""
    today = date(2026, 6, 1)

    items = [
        {"id": 1, "status": "Open", "target_date": "2026-05-20", "is_archived": 0},          # Overdue
        {"id": 2, "status": "In Progress", "target_date": "2026-06-01", "is_archived": 0},   # Due today
        {"id": 3, "status": "Awaiting Verification", "target_date": "2026-06-05", "is_archived": 0}, # Due in 7 days
        {"id": 4, "status": "Closed", "target_date": "2026-05-15", "actual_completion_date": "2026-05-10", "is_archived": 0}, # Closed on time
        {"id": 5, "status": "Cancelled", "target_date": "2026-07-01", "is_archived": 0},    # Cancelled
    ]

    metrics = calculate_remediation_metrics(items, reference_date=today)
    assert metrics["total_actions"] == 5
    assert metrics["active_non_cancelled"] == 4
    assert metrics["overdue"] == 1
    assert metrics["due_today"] == 1
    assert metrics["due_in_7_days"] == 1
    assert metrics["closed"] == 1
    assert metrics["cancelled"] == 1
    assert metrics["completed_on_time"] == 1
    assert metrics["verified_closure_rate"] == 25.0  # 1 / 4 * 100


def test_zero_actions_metrics():
    """Verify zero actions metrics return None / N/A without division-by-zero errors."""
    metrics = calculate_remediation_metrics([])
    assert metrics["total_actions"] == 0
    assert metrics["verified_closure_rate"] is None


# =========================================================================
# 9. CSV Export & Formula Injection Defense (CWE-1236)
# =========================================================================

def test_csv_formula_injection_defense():
    """Verify formula injection characters are neutralized by prepending single quote."""
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd|'/C calc'!A0") == "'+cmd|'/C calc'!A0"
    assert sanitize_csv_cell("-100") == "'-100"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("\tTabbed") == "'\tTabbed"
    assert sanitize_csv_cell("Normal Text") == "Normal Text"


def test_export_remediations_to_csv(temp_db, sample_assessment):
    """Test generating a sanitized CSV export of corrective actions."""
    create_remediation(
        assessment_id=sample_assessment,
        data={
            "action_title": "=DDE('cmd';'/C calc';'__test__')",
            "action_owner": "Attacker",
            "target_date": "2026-10-10",
        },
        db_path=temp_db,
    )

    rems = get_assessment_remediations(sample_assessment, db_path=temp_db)
    csv_text = export_remediations_to_csv(rems)

    assert "Action Reference" in csv_text
    assert "Action Title" in csv_text
    # Formula character must be escaped
    assert "'=DDE" in csv_text


# =========================================================================
# 10. Fictional FinCore Demonstration Dataset Verification
# =========================================================================

def test_fincore_demo_phase5_expansion(temp_db):
    """Verify FinCore Technologies demonstration assessment generates exact Phase 5 corrective actions and metrics."""
    res = create_fincore_demo_assessment(db_path=temp_db)
    asm_id = res["assessment"]["id"]

    rems = get_assessment_remediations(asm_id, db_path=temp_db)
    assert len(rems) == 5

    metrics = calculate_remediation_metrics(rems)
    assert metrics["total_actions"] == 5
    assert metrics["open"] == 2
    assert metrics["in_progress"] == 1
    assert metrics["awaiting_verification"] == 1
    assert metrics["closed"] == 1
    assert metrics["verified_closure_rate"] == 20.0  # 1 / 5 * 100

    # Repeat-safe check: calling again does not create duplicates
    create_fincore_demo_assessment(db_path=temp_db)
    rems_again = get_assessment_remediations(asm_id, db_path=temp_db)
    assert len(rems_again) == 5
