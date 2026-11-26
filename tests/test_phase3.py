"""
Phase 3 Automated Test Suite for AuditSphere-GRC.

Covers:
1. Evidence Upload & File Validation (Extensions, magic bytes, size limits, path traversal defenses)
2. SHA-256 Integrity Verification (Verified, Hash mismatch, File missing)
3. Many-to-Many Control-Evidence Mappings & Cross-Assessment Isolation
4. Auditor Evidence Review Workflow & Validation
5. Control Testing Documentation (Design vs Operating effectiveness, Pass/Fail validation)
6. Automated Gap Analysis Engine & Evidence Deficiency Detection
7. Formal CCCER Audit Findings Lifecycle, Traceability & Closure Verification
8. Repeat-Safe FinCore Demonstration Dataset Expansion
"""

import os
import shutil
import sqlite3
import tempfile
import pytest
from pathlib import Path

from database import init_db, db_session
from services.assessment_service import create_assessment, archive_assessment
from services.control_service import (
    get_assessment_controls,
    update_control_assessment,
    create_fincore_demo_assessment,
)
from services.evidence_manager import (
    validate_file_content,
    compute_sha256,
    get_safe_storage_path,
    upload_evidence,
    get_assessment_evidence,
    get_single_evidence,
    verify_evidence_integrity,
    review_evidence,
    archive_evidence,
    map_evidence_to_control,
    unmap_evidence_from_control,
    get_mapped_controls_for_evidence,
    get_mapped_evidence_for_control,
)
from services.gap_engine import (
    create_control_test,
    get_single_control_test,
    get_control_tests,
    identify_potential_gaps,
    create_finding,
    update_finding,
    get_single_finding,
    get_assessment_findings,
    get_full_control_traceability,
)
from services.dashboard_service import get_dashboard_summary


@pytest.fixture
def temp_env():
    """Create a temporary database and temporary storage directory."""
    temp_dir = tempfile.mkdtemp()
    db_file = os.path.join(temp_dir, "test_auditsphere_p3.db")
    storage_path = Path(temp_dir) / "evidence_storage"
    storage_path.mkdir(parents=True, exist_ok=True)

    init_db(db_path=db_file)

    yield {"db_path": db_file, "storage_dir": storage_path, "root_dir": temp_dir}

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


# =========================================================================
# 1. EVIDENCE UPLOAD & FILE VALIDATION
# =========================================================================


def test_file_validation_valid_formats():
    """Verify accepted extensions and correct magic byte validation."""
    # Text file
    txt_bytes = b"Sample plain text policy content"
    ext = validate_file_content("policy.txt", txt_bytes)
    assert ext == "txt"

    # CSV file
    csv_bytes = b"Col1,Col2,Col3\nVal1,Val2,Val3\n"
    ext = validate_file_content("data.csv", csv_bytes)
    assert ext == "csv"

    # PDF file
    pdf_bytes = b"%PDF-1.7\nSample simulated PDF stream\n%%EOF"
    ext = validate_file_content("document.pdf", pdf_bytes)
    assert ext == "pdf"

    # PNG file
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    ext = validate_file_content("screenshot.png", png_bytes)
    assert ext == "png"

    # JPG file
    jpg_bytes = b"\xff\xd8\xff\xe0" + b"\x00" * 20
    ext = validate_file_content("photo.jpg", jpg_bytes)
    assert ext == "jpg"

    # XLSX (ZIP magic bytes)
    xlsx_bytes = b"PK\x03\x04" + b"\x00" * 30
    ext = validate_file_content("spreadsheet.xlsx", xlsx_bytes)
    assert ext == "xlsx"


def test_file_validation_rejections():
    """Verify rejection of unsupported extensions, fake signatures, and oversize files."""
    # Unsupported extension
    with pytest.raises(ValueError, match="Unsupported file extension"):
        validate_file_content("malicious.exe", b"MZ\x90\x00\x03\x00")

    with pytest.raises(ValueError, match="Unsupported file extension"):
        validate_file_content("script.sh", b"#!/bin/bash\necho test\n")

    # Mismatched magic bytes (Fake PDF with plain text content)
    with pytest.raises(ValueError, match="does not match standard"):
        validate_file_content("fake.pdf", b"NOT A REAL PDF FILE")

    # Mismatched magic bytes (Fake PNG)
    with pytest.raises(ValueError, match="does not match standard"):
        validate_file_content("fake.png", b"NOT A REAL PNG FILE")

    # Oversize file
    large_bytes = b"A" * 1000
    with pytest.raises(ValueError, match="exceeds the configured maximum limit"):
        validate_file_content("big.txt", large_bytes, max_size=500)


def test_path_traversal_defense(temp_env):
    """Verify that path traversal attempts in filenames or storage identifiers are prevented."""
    storage_dir = temp_env["storage_dir"]

    # Traversal in storage identifier
    with pytest.raises(ValueError, match="Invalid character in storage identifier"):
        get_safe_storage_path(1, "../../../etc/passwd", base_dir=storage_dir)

    with pytest.raises(ValueError, match="Invalid character in storage identifier"):
        get_safe_storage_path(1, "..\\..\\windows\\system32\\cmd.exe", base_dir=storage_dir)

    # Valid relative storage path stays strictly inside root / assessment_id
    safe_path = get_safe_storage_path(1, "valid_file.txt", base_dir=storage_dir)
    assert str(safe_path).startswith(str(storage_dir.resolve()))
    assert str(1) in str(safe_path)


def test_upload_evidence_success(temp_env):
    """Verify successful upload, file creation on disk, DB record, and SHA-256 calculation."""
    db_path = temp_env["db_path"]
    storage_dir = temp_env["storage_dir"]

    asm = create_assessment(
        title="Evidence Test ISMS",
        organization="Apex Corp",
        industry="Technology",
        scope="Cloud SaaS",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )

    content = b"%PDF-1.4\nSimulated Information Security Policy Content\n%%EOF"
    ev = upload_evidence(
        assessment_id=asm["id"],
        title="Information Security Policy 2026",
        file_name="Apex_Security_Policy.pdf",
        file_bytes=content,
        evidence_type="Security policy",
        description="Formal board-approved policy",
        source_department="InfoSec",
        collection_date="2026-06-01",
        uploaded_by="Lead Auditor",
        storage_dir=storage_dir,
        db_path=db_path,
    )

    assert ev["id"] is not None
    assert ev["evidence_identifier"] == "EVD-001"
    assert ev["original_file_name"] == "Apex_Security_Policy.pdf"
    assert ev["file_size"] == len(content)
    assert ev["sha256_hash"] == compute_sha256(content)
    assert ev["review_status"] == "Pending Review"
    assert ev["integrity_status"] == "Verified"

    # Verify physical file existence
    expected_path = get_safe_storage_path(asm["id"], ev["storage_identifier"], base_dir=storage_dir)
    assert expected_path.exists()
    assert expected_path.read_bytes() == content


def test_archived_assessment_blocks_evidence_upload(temp_env):
    """Archived assessments must reject new evidence uploads."""
    db_path = temp_env["db_path"]
    storage_dir = temp_env["storage_dir"]

    asm = create_assessment(
        title="Archived ISMS",
        organization="Apex Corp",
        industry="Technology",
        scope="Cloud",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    archive_assessment(asm["id"], db_path=db_path)

    with pytest.raises(PermissionError, match="is Archived"):
        upload_evidence(
            assessment_id=asm["id"],
            title="Policy",
            file_name="policy.txt",
            file_bytes=b"Content",
            storage_dir=storage_dir,
            db_path=db_path,
        )


# =========================================================================
# 2. SHA-256 INTEGRITY VERIFICATION
# =========================================================================


def test_integrity_verification_workflow(temp_env):
    """Verify SHA-256 verification detects verified, tampered (mismatch), and missing files."""
    db_path = temp_env["db_path"]
    storage_dir = temp_env["storage_dir"]

    asm = create_assessment(
        title="Integrity Test",
        organization="Apex Corp",
        industry="Technology",
        scope="Cloud",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )

    orig_content = b"Original baseline firewall rule export."
    ev = upload_evidence(
        assessment_id=asm["id"],
        title="Firewall Rules",
        file_name="firewall.txt",
        file_bytes=orig_content,
        storage_dir=storage_dir,
        db_path=db_path,
    )
    file_path = get_safe_storage_path(asm["id"], ev["storage_identifier"], base_dir=storage_dir)

    # 1. Initial check -> Verified
    v1 = verify_evidence_integrity(ev["id"], storage_dir=storage_dir, db_path=db_path)
    assert v1["integrity_status"] == "Verified"

    # 2. Tamper with file content on disk -> Hash mismatch
    with open(file_path, "wb") as f:
        f.write(b"TAMPERED UNAUTHORIZED FIREWALL RULES")

    v2 = verify_evidence_integrity(ev["id"], storage_dir=storage_dir, db_path=db_path)
    assert v2["integrity_status"] == "Hash mismatch"

    # 3. Delete file from disk -> File missing
    os.remove(file_path)
    v3 = verify_evidence_integrity(ev["id"], storage_dir=storage_dir, db_path=db_path)
    assert v3["integrity_status"] == "File missing"


# =========================================================================
# 3. MANY-TO-MANY MAPPINGS & CROSS-ASSESSMENT ISOLATION
# =========================================================================


def test_evidence_control_mapping_and_triggers(temp_env):
    """Verify many-to-many mappings and cross-assessment trigger isolation."""
    db_path = temp_env["db_path"]
    storage_dir = temp_env["storage_dir"]

    # Assessment 1
    a1 = create_assessment(
        title="Assessment One",
        organization="Org 1",
        industry="Tech",
        scope="Scope 1",
        lead_assessor="Auditor 1",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    ctrls1 = get_assessment_controls(a1["id"], db_path=db_path)
    ca1_a = ctrls1[0]["assessment_control_id"]
    ca1_b = ctrls1[1]["assessment_control_id"]

    # Assessment 2
    a2 = create_assessment(
        title="Assessment Two",
        organization="Org 2",
        industry="Finance",
        scope="Scope 2",
        lead_assessor="Auditor 2",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    ctrls2 = get_assessment_controls(a2["id"], db_path=db_path)
    ca2_a = ctrls2[0]["assessment_control_id"]

    # Upload evidence to Assessment 1
    ev1 = upload_evidence(
        assessment_id=a1["id"],
        title="Access Policy",
        file_name="policy.txt",
        file_bytes=b"Access Control Policy",
        storage_dir=storage_dir,
        db_path=db_path,
    )

    # 1. Map ev1 to ca1_a and ca1_b in Assessment 1
    map_evidence_to_control(ev1["id"], ca1_a, db_path=db_path)
    map_evidence_to_control(ev1["id"], ca1_b, db_path=db_path)

    mapped_ctrls = get_mapped_controls_for_evidence(ev1["id"], db_path=db_path)
    assert len(mapped_ctrls) == 2
    mapped_evs = get_mapped_evidence_for_control(ca1_a, db_path=db_path)
    assert len(mapped_evs) == 1
    assert mapped_evs[0]["id"] == ev1["id"]

    # 2. Attempt Cross-Assessment Mapping (ev1 belonging to A1 mapped to ca2_a of A2)
    # The application service checks this AND the SQLite trigger validates it.
    with pytest.raises(ValueError, match="Cross-assessment violation"):
        map_evidence_to_control(ev1["id"], ca2_a, db_path=db_path)

    # Direct database trigger check
    with pytest.raises(sqlite3.IntegrityError, match="Cross-assessment violation"):
        with db_session(db_path) as conn:
            conn.execute(
                "INSERT INTO control_evidence (assessment_id, control_assessment_id, evidence_id, mapped_at) VALUES (?, ?, ?, ?)",
                (a2["id"], ca2_a, ev1["id"], "2026-06-01T00:00:00Z"),
            )

    # 3. Unmap
    unmap_evidence_from_control(ev1["id"], ca1_a, db_path=db_path)
    assert len(get_mapped_controls_for_evidence(ev1["id"], db_path=db_path)) == 1


# =========================================================================
# 4. EVIDENCE REVIEW WORKFLOW
# =========================================================================


def test_evidence_review_workflow(temp_env):
    """Verify evidence review status transitions and required reviewer justifications."""
    db_path = temp_env["db_path"]
    storage_dir = temp_env["storage_dir"]

    asm = create_assessment(
        title="Review Test",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    ev = upload_evidence(
        assessment_id=asm["id"],
        title="Review Doc",
        file_name="doc.txt",
        file_bytes=b"Audit Document Content",
        storage_dir=storage_dir,
        db_path=db_path,
    )

    # Reject without reviewer name
    with pytest.raises(ValueError, match="Reviewer name is required"):
        review_evidence(ev["id"], "Accepted", reviewer_name="", reviewer_notes="Valid policy", db_path=db_path)

    # Reject without reviewer notes
    with pytest.raises(ValueError, match="Reviewer notes are required"):
        review_evidence(ev["id"], "Accepted", reviewer_name="Auditor Jane", reviewer_notes="", db_path=db_path)

    # Successful Acceptance
    rev = review_evidence(
        evidence_id=ev["id"],
        review_status="Accepted",
        reviewer_name="Auditor Jane",
        reviewer_notes="Policy is fully authorized and up to date.",
        relevance_rating="Highly Relevant",
        sufficiency_rating="Sufficient",
        reliability_rating="Reliable",
        db_path=db_path,
    )
    assert rev["review_status"] == "Accepted"
    assert rev["reviewer_name"] == "Auditor Jane"
    assert rev["reviewed_at"] is not None


# =========================================================================
# 5. CONTROL TESTING DOCUMENTATION
# =========================================================================


def test_control_testing_documentation(temp_env):
    """Verify recording of structured control tests with Pass/Fail validation."""
    db_path = temp_env["db_path"]

    asm = create_assessment(
        title="Testing Workflow",
        organization="Org",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=db_path)
    ca_id = ctrls[0]["assessment_control_id"]

    # Pass/Fail requires expected and observed results
    with pytest.raises(ValueError, match="requires both expected result and observed result"):
        create_control_test(
            assessment_id=asm["id"],
            control_assessment_id=ca_id,
            test_type="Operating effectiveness",
            testing_objective="Verify password complexity",
            testing_procedure="Sample 10 password changes",
            expected_result="",
            observed_result="Observed results",
            conclusion="Pass",
            db_path=db_path,
        )

    # Successful Test Record
    test_rec = create_control_test(
        assessment_id=asm["id"],
        control_assessment_id=ca_id,
        test_type="Operating effectiveness",
        testing_objective="Verify multi-factor authentication enforcement on VPN",
        testing_procedure="Sampled 20 remote logins",
        expected_result="100% MFA prompt observed",
        observed_result="All 20 logins successfully prompted and verified via TOTP",
        conclusion="Pass",
        sample_examined="20 Okta login event logs",
        assessor_name="Auditor Jane",
        testing_date="2026-06-01",
        db_path=db_path,
    )

    assert test_rec["id"] is not None
    assert test_rec["test_reference"] == "TST-001"
    assert test_rec["conclusion"] == "Pass"
    assert test_rec["test_type"] == "Operating effectiveness"

    # List tests for control
    tests_for_ctrl = get_control_tests(asm["id"], control_assessment_id=ca_id, db_path=db_path)
    assert len(tests_for_ctrl) == 1
    assert tests_for_ctrl[0]["id"] == test_rec["id"]


# =========================================================================
# 6. AUTOMATED GAP DETECTION ENGINE
# =========================================================================


def test_gap_detection_engine(temp_env):
    """Verify automated detection of implementation gaps, failed tests, and evidence deficiencies."""
    db_path = temp_env["db_path"]
    storage_dir = temp_env["storage_dir"]

    asm = create_assessment(
        title="Gap Detection Test",
        organization="Apex Corp",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=db_path)

    # 1. Set Control 0 to Partially Implemented
    c0 = ctrls[0]
    update_control_assessment(
        assessment_id=asm["id"],
        control_id=c0["control_id"],
        status="Partially Implemented",
        assessment_observation="Partial implementation note: policy drafted but periodic review process is missing.",
        recommendation="Implement formal annual access control review workflow.",
        assessor_name="Auditor Jane",
        assessment_date="2026-06-01",
        db_path=db_path,
    )

    # 2. Record a FAILED test on Control 1
    c1 = ctrls[1]
    create_control_test(
        assessment_id=asm["id"],
        control_assessment_id=c1["assessment_control_id"],
        test_type="Operating effectiveness",
        testing_objective="Verify patch management",
        testing_procedure="Inspect 10 production hosts",
        expected_result="All critical patches applied within 14 days",
        observed_result="3 hosts missing critical CVE-2026-0001 patch older than 60 days",
        conclusion="Fail",
        assessor_name="Auditor Jane",
        db_path=db_path,
    )

    gaps = identify_potential_gaps(asm["id"], db_path=db_path)

    assert gaps["total_potential_gaps"] > 0
    # Implementation gaps should include Control 0
    imp_refs = [g["control_identifier"] for g in gaps["implementation_gaps"]]
    assert c0["control_identifier"] in imp_refs

    # Failed tests should include Control 1
    failed_test_refs = [t["control_identifier"] for t in gaps["failed_tests"]]
    assert c1["control_identifier"] in failed_test_refs

    # Evidence deficiencies should include controls with no evidence
    assert len(gaps["evidence_deficiencies"]) > 0


# =========================================================================
# 7. FORMAL CCCER AUDIT FINDINGS & TRACEABILITY
# =========================================================================


def test_formal_finding_lifecycle_and_closure(temp_env):
    """Verify CCCER validation, mandatory evidence references, and resolution notes for closure."""
    db_path = temp_env["db_path"]

    asm = create_assessment(
        title="Finding Test",
        organization="Apex Corp",
        industry="Tech",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=db_path)
    ca_id = ctrls[0]["assessment_control_id"]

    # Missing evidence reference AND missing limitation note -> Rejected
    with pytest.raises(ValueError, match="requires supporting evidence references or an explicit documented evidence limitation"):
        create_finding(
            assessment_id=asm["id"],
            control_assessment_id=ca_id,
            title="Unencrypted S3 Buckets",
            criteria="ISO 27001 A.8.24",
            condition="Public S3 bucket detected",
            effect="Data leakage risk",
            recommendation="Enable AWS KMS default encryption",
            supporting_evidence_references="",
            evidence_limitations="",
            db_path=db_path,
        )

    # Successful Finding Creation
    fnd = create_finding(
        assessment_id=asm["id"],
        control_assessment_id=ca_id,
        title="Unencrypted Customer Payment S3 Buckets",
        criteria="ISO/IEC 27001:2022 Control A.8.24 mandates protection of data at rest.",
        condition="Customer transaction archive bucket 'fincore-tx-archive' lacked KMS encryption.",
        effect="Unauthorized disclosure of payment card metadata in the event of cloud compromise.",
        recommendation="Apply AWS KMS customer-managed key (CMK) encryption and enforce aws:SecureTransport policy.",
        severity="High",
        finding_type="Major Non-Conformity",
        supporting_evidence_references="EVD-001",
        assessor_name="Marcus Vance",
        status="Open",
        db_path=db_path,
    )

    assert fnd["id"] is not None
    assert fnd["finding_identifier"] == "FND-001"
    assert fnd["status"] == "Open"
    assert fnd["severity"] == "High"

    # Closing finding without verification notes -> Rejected
    with pytest.raises(ValueError, match="Closing a formal finding requires documented verification notes"):
        update_finding(
            finding_id=fnd["id"],
            title=fnd["title"],
            criteria=fnd["criteria"],
            condition=fnd["condition"],
            effect=fnd["effect"],
            recommendation=fnd["recommendation"],
            severity=fnd["severity"],
            finding_type=fnd["finding_type"],
            status="Closed",
            verification_notes="",
            db_path=db_path,
        )

    # Successful Closure with verification notes
    closed_fnd = update_finding(
        finding_id=fnd["id"],
        title=fnd["title"],
        criteria=fnd["criteria"],
        condition=fnd["condition"],
        effect=fnd["effect"],
        recommendation=fnd["recommendation"],
        severity=fnd["severity"],
        finding_type=fnd["finding_type"],
        status="Closed",
        verification_notes="Verified bucket policy now mandates SSE-KMS with aws:SecureTransport.",
        db_path=db_path,
    )
    assert closed_fnd["status"] == "Closed"
    assert closed_fnd["verification_notes"] is not None


def test_full_traceability_matrix(temp_env):
    """Verify end-to-end working paper traceability: Control -> Evidence -> Testing -> Finding."""
    db_path = temp_env["db_path"]
    storage_dir = temp_env["storage_dir"]

    asm = create_assessment(
        title="Traceability Test",
        organization="FinCore",
        industry="Finance",
        scope="Scope",
        lead_assessor="Lead Auditor",
        assessment_date="2026-06-01",
        db_path=db_path,
    )
    ctrls = get_assessment_controls(asm["id"], db_path=db_path)
    ca_id = ctrls[0]["assessment_control_id"]

    # 1. Upload & map evidence
    ev = upload_evidence(
        assessment_id=asm["id"],
        title="Trace Policy",
        file_name="policy.txt",
        file_bytes=b"Traceability content",
        mapped_control_ids=[ca_id],
        storage_dir=storage_dir,
        db_path=db_path,
    )

    # 2. Record control test
    tst = create_control_test(
        assessment_id=asm["id"],
        control_assessment_id=ca_id,
        test_type="Operating effectiveness",
        testing_objective="Verify trace",
        testing_procedure="Procedure",
        expected_result="Expected",
        observed_result="Observed failure",
        conclusion="Fail",
        supporting_evidence_references=ev["evidence_identifier"],
        db_path=db_path,
    )

    # 3. Create formal finding
    fnd = create_finding(
        assessment_id=asm["id"],
        control_assessment_id=ca_id,
        title="Traceability Gap Finding",
        criteria="Criteria",
        condition="Condition",
        effect="Effect",
        recommendation="Recommendation",
        supporting_evidence_references=ev["evidence_identifier"],
        supporting_test_references=tst["test_reference"],
        db_path=db_path,
    )

    trace = get_full_control_traceability(ca_id, db_path=db_path)
    assert trace["control_assessment"]["id"] == ca_id
    assert len(trace["evidence_records"]) == 1
    assert trace["evidence_records"][0]["id"] == ev["id"]
    assert len(trace["test_records"]) == 1
    assert trace["test_records"][0]["id"] == tst["id"]
    assert len(trace["findings"]) == 1
    assert trace["findings"][0]["id"] == fnd["id"]


# =========================================================================
# 8. FINCORE DEMO PHASE 3 EXPANSION
# =========================================================================


def test_fincore_demo_phase3_expansion(temp_env):
    """Verify that FinCore demo seeds 5 evidence files, 1 failed test, 1 finding FND-001, and is repeat-safe."""
    db_path = temp_env["db_path"]

    demo1 = create_fincore_demo_assessment(db_path=db_path)
    asm_id = demo1["assessment"]["id"]

    # Verify 5 evidence records
    ev_list = get_assessment_evidence(asm_id, db_path=db_path)
    assert len(ev_list) == 5

    # Verify 1 control test (TST-001 on A.8.5 with conclusion Fail)
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM control_tests WHERE assessment_id = ?", (asm_id,))
        tests = cursor.fetchall()
        assert len(tests) == 1
        assert tests[0]["test_reference"] == "TST-001"
        assert tests[0]["conclusion"] == "Fail"

    # Verify 1 formal finding (FND-001 on A.8.5 with High severity)
    findings = get_assessment_findings(asm_id, db_path=db_path)
    assert len(findings) == 1
    fnd = findings[0]
    assert fnd["finding_identifier"] == "FND-001"
    assert fnd["severity"] == "High"
    assert fnd["control_identifier"] == "A.8.5"
    assert fnd["supporting_evidence_references"] == "FIN-CFG-002"
    assert fnd["supporting_test_references"] == "TST-001"

    # Verify repeat-safety: calling create_fincore_demo_assessment a second time doesn't duplicate records
    demo2 = create_fincore_demo_assessment(db_path=db_path)
    assert demo2["assessment"]["id"] == asm_id
    ev_list_2 = get_assessment_evidence(asm_id, db_path=db_path)
    assert len(ev_list_2) == 5
    findings_2 = get_assessment_findings(asm_id, db_path=db_path)
    assert len(findings_2) == 1
