"""
Gap Analysis Engine and Control Testing Service for AuditSphere.

Handles:
- Structured control testing records (Design vs. Operating effectiveness, Walkthroughs)
- Automated detection of potential implementation gaps, failed tests, and evidence deficiencies
- Formal audit findings lifecycle (Draft -> Open -> Under Review -> Closed)
- CCCER methodology (Criteria, Condition, Cause, Effect/Impact, Recommendation)
- Traceability: Control -> Evidence -> Testing Record -> Formal Finding
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from database import db_session, get_utc_now_iso
from services.assessment_service import get_assessment
from services.activity_service import log_activity

TEST_TYPES = [
    "Design effectiveness",
    "Operating effectiveness",
    "Walkthrough",
    "Document review",
    "Configuration review",
]

TEST_CONCLUSIONS = ["Pass", "Fail", "Inconclusive", "Not tested"]

FINDING_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]

FINDING_STATUSES = ["Draft", "Open", "Under Review", "Closed"]

FINDING_TYPES = [
    "Major Non-Conformity",
    "Minor Non-Conformity",
    "Opportunity for Improvement",
    "Observation",
]


# ==========================================
# 1. CONTROL TESTING DOCUMENTATION
# ==========================================


def generate_next_test_reference(conn: Any, assessment_id: int) -> str:
    """Generate sequential reference (e.g. TST-001) for control tests in the assessment."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT test_reference FROM control_tests WHERE assessment_id = ? ORDER BY id DESC",
        (assessment_id,),
    )
    rows = cursor.fetchall()
    highest = 0
    for r in rows:
        match = re.search(r"TST-(\d+)", r["test_reference"])
        if match:
            highest = max(highest, int(match.group(1)))
    return f"TST-{highest + 1:03d}"


def create_control_test(
    assessment_id: int,
    control_assessment_id: int,
    test_type: str,
    testing_objective: str,
    testing_procedure: str,
    expected_result: str,
    observed_result: str,
    conclusion: str,
    sample_examined: Optional[str] = None,
    assessment_period: Optional[str] = None,
    supporting_evidence_references: Optional[str] = None,
    evidence_limitations: Optional[str] = None,
    assessor_name: str = "Lead Assessor",
    testing_date: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Record a structured control test.
    Validates test type, conclusion, and ensures adequate documented basis.
    """
    asm = get_assessment(assessment_id, db_path=db_path)
    if not asm:
        raise ValueError(f"Assessment ID {assessment_id} does not exist.")
    if asm["status"] == "Archived":
        raise PermissionError(f"Assessment '{asm['title']}' is Archived. Cannot record testing.")

    if test_type not in TEST_TYPES:
        raise ValueError(f"Invalid test type '{test_type}'. Must be one of: {', '.join(TEST_TYPES)}.")
    if conclusion not in TEST_CONCLUSIONS:
        raise ValueError(f"Invalid conclusion '{conclusion}'. Must be one of: {', '.join(TEST_CONCLUSIONS)}.")

    obj = (testing_objective or "").strip()
    proc = (testing_procedure or "").strip()
    exp = (expected_result or "").strip()
    obs = (observed_result or "").strip()
    assessor = (assessor_name or "").strip()
    t_date = (testing_date or "").strip() or get_utc_now_iso()[:10]

    if not obj:
        raise ValueError("Testing objective is required.")
    if not proc:
        raise ValueError("Testing procedure is required.")
    if conclusion in ("Pass", "Fail"):
        if not exp or not obs:
            raise ValueError(f"Testing conclusion '{conclusion}' requires both expected result and observed result.")
    if not assessor:
        raise ValueError("Assessor name is required.")

    now_iso = get_utc_now_iso()

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        # Verify control_assessment belongs to this assessment
        cursor.execute(
            "SELECT ca.assessment_id, c.control_identifier FROM control_assessments ca JOIN controls c ON ca.control_id = c.id WHERE ca.id = ?",
            (control_assessment_id,),
        )
        ca_row = cursor.fetchone()
        if not ca_row:
            raise ValueError(f"Control assessment ID {control_assessment_id} not found.")
        if ca_row["assessment_id"] != assessment_id:
            raise ValueError("Cross-assessment violation: control assessment does not belong to specified assessment.")

        ref = generate_next_test_reference(conn, assessment_id)
        ctrl_ref = ca_row["control_identifier"]

        cursor.execute(
            """
            INSERT INTO control_tests (
                assessment_id, control_assessment_id, test_reference, test_type,
                testing_objective, testing_procedure, sample_examined, assessment_period,
                expected_result, observed_result, supporting_evidence_references,
                evidence_limitations, assessor_name, testing_date, conclusion,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                control_assessment_id,
                ref,
                test_type,
                obj,
                proc,
                sample_examined.strip() if sample_examined else None,
                assessment_period.strip() if assessment_period else None,
                exp,
                obs,
                supporting_evidence_references.strip() if supporting_evidence_references else None,
                evidence_limitations.strip() if evidence_limitations else None,
                assessor,
                t_date,
                conclusion,
                now_iso,
                now_iso,
            ),
        )
        test_id = cursor.lastrowid

    log_activity(
        assessment_id=assessment_id,
        event_type="CONTROL_TEST_RECORDED",
        description=f"Control test {ref} recorded for {ctrl_ref} ({test_type} -> Conclusion: {conclusion}).",
        actor=assessor,
        control_reference=ctrl_ref,
        db_path=db_path,
    )

    return get_single_control_test(test_id, db_path=db_path)  # type: ignore


def get_control_tests(
    assessment_id: int,
    control_assessment_id: Optional[int] = None,
    conclusion_filter: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve testing records for an assessment, optionally filtered by control or conclusion."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        query = """
        SELECT ct.*, c.control_identifier, c.title AS control_title, c.domain AS category
        FROM control_tests ct
        JOIN control_assessments ca ON ct.control_assessment_id = ca.id
        JOIN controls c ON ca.control_id = c.id
        WHERE ct.assessment_id = ?
        """
        params: List[Any] = [assessment_id]

        if control_assessment_id is not None:
            query += " AND ct.control_assessment_id = ?"
            params.append(control_assessment_id)

        if conclusion_filter and conclusion_filter != "All Conclusions":
            query += " AND ct.conclusion = ?"
            params.append(conclusion_filter)

        query += " ORDER BY ct.id DESC"
        cursor.execute(query, tuple(params))
        return [dict(r) for r in cursor.fetchall()]


def get_single_control_test(test_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve a single control testing record with joined control metadata."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT ct.*, c.control_identifier, c.title AS control_title, c.domain AS category
            FROM control_tests ct
            JOIN control_assessments ca ON ct.control_assessment_id = ca.id
            JOIN controls c ON ca.control_id = c.id
            WHERE ct.id = ?
            """,
            (test_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


# ==========================================
# 2. GAP ANALYSIS & DEFICIENCY IDENTIFICATION
# ==========================================


def identify_potential_gaps(assessment_id: int, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze assessment records and automatically identify:
    - Potential implementation gaps (Partially Implemented, Not Implemented)
    - Failed control tests
    - Controls awaiting assessment (Not Assessed)
    - Evidence deficiencies:
      - Applicable controls without mapped evidence
      - Controls lacking accepted supporting evidence
      - Evidence requiring clarification
      - Evidence integrity mismatches
      - Inconclusive control tests
    Provides clear audit justification for each flagged condition without automatically
    creating confirmed findings.
    """
    from services.control_service import get_assessment_controls
    from services.evidence_manager import get_assessment_evidence

    controls = get_assessment_controls(assessment_id, db_path=db_path)
    tests = get_control_tests(assessment_id, db_path=db_path)
    evidence_list = get_assessment_evidence(assessment_id, db_path=db_path)

    # 1. Implementation Gaps
    implementation_gaps = []
    for c in controls:
        if c["status"] in ("Partially Implemented", "Not Implemented"):
            reason = (
                "Control evaluated as 'Partially Implemented' indicating partial control design or inconsistent operation."
                if c["status"] == "Partially Implemented"
                else "Control evaluated as 'Not Implemented' indicating missing safeguards in an applicable scope."
            )
            implementation_gaps.append(
                {
                    "gap_type": "Implementation Gap",
                    "control_identifier": c["control_identifier"],
                    "control_title": c["control_title"],
                    "control_assessment_id": c["assessment_control_id"],
                    "status": c["status"],
                    "owner": c.get("control_owner") or "Unassigned",
                    "observation": c.get("assessment_observation") or "No observation recorded.",
                    "recommendation": c.get("recommendation") or "Remediation required.",
                    "flagged_reason": reason,
                }
            )

    # 2. Failed Control Tests
    failed_tests = []
    for t in tests:
        if t["conclusion"] == "Fail":
            failed_tests.append(
                {
                    "gap_type": "Failed Test",
                    "test_reference": t["test_reference"],
                    "test_type": t["test_type"],
                    "control_identifier": t["control_identifier"],
                    "control_title": t["control_title"],
                    "control_assessment_id": t["control_assessment_id"],
                    "testing_procedure": t["testing_procedure"],
                    "observed_result": t["observed_result"],
                    "flagged_reason": f"Audit test {t['test_reference']} failed during {t['test_type']} examination.",
                }
            )

    # 3. Pending Assessments
    pending_controls = [
        {
            "control_identifier": c["control_identifier"],
            "control_title": c["control_title"],
            "category": c["category"],
            "control_assessment_id": c["assessment_control_id"],
            "flagged_reason": "Control has not yet been audited and remains in 'Not Assessed' status.",
        }
        for c in controls
        if c["status"] == "Not Assessed"
    ]

    # 4. Evidence Deficiencies
    evidence_deficiencies = []

    # Map evidence IDs to their status
    ev_status_map = {e["id"]: e["review_status"] for e in evidence_list}

    # Fetch mapping counts per control
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT ca.id AS control_assessment_id, c.control_identifier, c.title, ca.status,
                   COUNT(ce.evidence_id) AS mapped_count,
                   SUM(CASE WHEN e.review_status = 'Accepted' THEN 1 ELSE 0 END) AS accepted_count
            FROM control_assessments ca
            JOIN controls c ON ca.control_id = c.id
            LEFT JOIN control_evidence ce ON ca.id = ce.control_assessment_id
            LEFT JOIN evidence e ON ce.evidence_id = e.id AND e.is_archived = 0
            WHERE ca.assessment_id = ?
            GROUP BY ca.id
            """,
            (assessment_id,),
        )
        ctrl_ev_stats = [dict(r) for r in cursor.fetchall()]

    for s in ctrl_ev_stats:
        if s["status"] != "Not Applicable":
            if s["mapped_count"] == 0 and s["status"] in ("Implemented", "Partially Implemented"):
                evidence_deficiencies.append(
                    {
                        "deficiency_type": "Missing Supporting Evidence",
                        "control_identifier": s["control_identifier"],
                        "control_title": s["title"],
                        "control_assessment_id": s["control_assessment_id"],
                        "flagged_reason": f"Control is marked as '{s['status']}' but has 0 supporting evidence files mapped.",
                    }
                )
            elif s["status"] == "Implemented" and s["accepted_count"] == 0:
                evidence_deficiencies.append(
                    {
                        "deficiency_type": "Lacks Accepted Evidence",
                        "control_identifier": s["control_identifier"],
                        "control_title": s["title"],
                        "control_assessment_id": s["control_assessment_id"],
                        "flagged_reason": "Control is marked 'Implemented' but has no evidence with 'Accepted' review status.",
                    }
                )

    # Evidence files needing clarification or having integrity mismatches
    for e in evidence_list:
        if e["review_status"] == "Needs Clarification":
            evidence_deficiencies.append(
                {
                    "deficiency_type": "Evidence Clarification Required",
                    "evidence_identifier": e["evidence_identifier"],
                    "title": e["title"],
                    "flagged_reason": f"Evidence {e['evidence_identifier']} was reviewed and marked as 'Needs Clarification' by reviewer.",
                }
            )
        if e.get("integrity_status") == "Hash mismatch":
            evidence_deficiencies.append(
                {
                    "deficiency_type": "Integrity Mismatch",
                    "evidence_identifier": e["evidence_identifier"],
                    "title": e["title"],
                    "flagged_reason": f"Evidence {e['evidence_identifier']} failed SHA-256 integrity verification (file altered on disk).",
                }
            )

    # Inconclusive tests
    for t in tests:
        if t["conclusion"] == "Inconclusive":
            evidence_deficiencies.append(
                {
                    "deficiency_type": "Inconclusive Control Test",
                    "test_reference": t["test_reference"],
                    "control_identifier": t["control_identifier"],
                    "control_title": t["control_title"],
                    "flagged_reason": f"Test {t['test_reference']} resulted in an 'Inconclusive' outcome and requires follow-up re-testing.",
                }
            )

    return {
        "implementation_gaps": implementation_gaps,
        "failed_tests": failed_tests,
        "pending_controls": pending_controls,
        "evidence_deficiencies": evidence_deficiencies,
        "total_potential_gaps": len(implementation_gaps) + len(failed_tests),
        "total_deficiencies": len(evidence_deficiencies),
    }


# ==========================================
# 3. FORMAL AUDIT FINDINGS
# ==========================================


def generate_next_finding_reference(conn: Any, assessment_id: int) -> str:
    """Generate sequential reference (e.g. FND-001) for audit findings in the assessment."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT finding_identifier FROM findings WHERE assessment_id = ? ORDER BY id DESC",
        (assessment_id,),
    )
    rows = cursor.fetchall()
    highest = 0
    for r in rows:
        match = re.search(r"FND-(\d+)", r["finding_identifier"])
        if match:
            highest = max(highest, int(match.group(1)))
    return f"FND-{highest + 1:03d}"


def create_finding(
    assessment_id: int,
    title: str,
    criteria: str,
    condition: str,
    effect: str,
    recommendation: str,
    control_assessment_id: Optional[int] = None,
    severity: str = "Medium",
    finding_type: str = "Minor Non-Conformity",
    cause: Optional[str] = None,
    supporting_evidence_references: Optional[str] = None,
    evidence_limitations: Optional[str] = None,
    supporting_test_references: Optional[str] = None,
    responsible_department: Optional[str] = None,
    assessor_name: str = "Lead Assessor",
    status: str = "Open",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a formal audit finding with CCCER criteria.
    Enforces title, criteria, condition, impact/effect, recommendation, and
    supporting evidence or documented evidence limitations.
    """
    asm = get_assessment(assessment_id, db_path=db_path)
    if not asm:
        raise ValueError(f"Assessment ID {assessment_id} does not exist.")
    if asm["status"] == "Archived":
        raise PermissionError(f"Assessment '{asm['title']}' is Archived. Cannot create findings.")

    clean_title = (title or "").strip()
    clean_crit = (criteria or "").strip()
    clean_cond = (condition or "").strip()
    clean_eff = (effect or "").strip()
    clean_rec = (recommendation or "").strip()
    ev_refs = (supporting_evidence_references or "").strip()
    ev_limits = (evidence_limitations or "").strip()

    if not clean_title:
        raise ValueError("Finding title is required.")
    if not clean_crit:
        raise ValueError("Finding criteria (e.g. standard clause, policy requirement) is required.")
    if not clean_cond:
        raise ValueError("Observed condition (the factual audit observation) is required.")
    if not clean_eff:
        raise ValueError("Potential effect / impact of the finding is required.")
    if not clean_rec:
        raise ValueError("Remediation recommendation is required.")

    # Must provide either supporting evidence OR explicit documented evidence limitation
    if not ev_refs and not ev_limits:
        raise ValueError(
            "Every formal finding requires supporting evidence references or an explicit documented evidence limitation."
        )

    if severity not in FINDING_SEVERITIES:
        raise ValueError(f"Invalid severity '{severity}'. Must be one of: {', '.join(FINDING_SEVERITIES)}.")
    if status not in FINDING_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Must be one of: {', '.join(FINDING_STATUSES)}.")

    now_iso = get_utc_now_iso()

    with db_session(db_path) as conn:
        cursor = conn.cursor()

        # Validate control_assessment_id if provided
        if control_assessment_id is not None:
            cursor.execute(
                "SELECT assessment_id FROM control_assessments WHERE id = ?",
                (control_assessment_id,),
            )
            ca_row = cursor.fetchone()
            if not ca_row:
                raise ValueError(f"Control assessment ID {control_assessment_id} does not exist.")
            if ca_row["assessment_id"] != assessment_id:
                raise ValueError("Cross-assessment violation: control assessment belongs to different assessment.")

        fnd_ref = generate_next_finding_reference(conn, assessment_id)

        cursor.execute(
            """
            INSERT INTO findings (
                assessment_id, control_assessment_id, finding_identifier, title,
                finding_type, severity, description, criteria, condition, cause,
                effect, recommendation, supporting_evidence_references, evidence_limitations,
                supporting_test_references, responsible_department, assessor_name,
                status, identified_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                control_assessment_id,
                fnd_ref,
                clean_title,
                finding_type,
                severity,
                clean_cond,  # description
                clean_crit,
                clean_cond,
                cause.strip() if cause else None,
                clean_eff,
                clean_rec,
                ev_refs if ev_refs else None,
                ev_limits if ev_limits else None,
                supporting_test_references.strip() if supporting_test_references else None,
                responsible_department.strip() if responsible_department else None,
                assessor_name.strip() if assessor_name else "Lead Assessor",
                status,
                now_iso[:10],
                now_iso,
                now_iso,
            ),
        )
        finding_id = cursor.lastrowid

    log_activity(
        assessment_id=assessment_id,
        event_type="FINDING_CREATED",
        description=f"Formal finding {fnd_ref} ('{clean_title}') created with severity '{severity}'.",
        actor=assessor_name,
        db_path=db_path,
    )

    return get_single_finding(finding_id, db_path=db_path)  # type: ignore


def update_finding(
    finding_id: int,
    title: str,
    criteria: str,
    condition: str,
    effect: str,
    recommendation: str,
    severity: str,
    finding_type: str,
    status: str,
    cause: Optional[str] = None,
    supporting_evidence_references: Optional[str] = None,
    evidence_limitations: Optional[str] = None,
    supporting_test_references: Optional[str] = None,
    responsible_department: Optional[str] = None,
    assessor_name: Optional[str] = None,
    verification_notes: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Update finding details with status transition validation."""
    fnd = get_single_finding(finding_id, db_path=db_path)
    if not fnd:
        raise ValueError(f"Finding ID {finding_id} not found.")

    asm = get_assessment(fnd["assessment_id"], db_path=db_path)
    if asm and asm["status"] == "Archived":
        raise PermissionError(f"Assessment '{asm['title']}' is Archived. Cannot modify findings.")

    clean_title = (title or "").strip()
    clean_crit = (criteria or "").strip()
    clean_cond = (condition or "").strip()
    clean_eff = (effect or "").strip()
    clean_rec = (recommendation or "").strip()
    clean_ver = (verification_notes or "").strip()

    if not clean_title or not clean_crit or not clean_cond or not clean_eff or not clean_rec:
        raise ValueError("Title, criteria, condition, effect/impact, and recommendation are mandatory fields.")

    # Status closure validation
    if status == "Closed" and not clean_ver:
        raise ValueError("Closing a formal finding requires documented verification notes explaining the resolution.")

    now_iso = get_utc_now_iso()
    prev_status = fnd["status"]

    with db_session(db_path) as conn:
        conn.execute(
            """
            UPDATE findings
            SET title = ?, criteria = ?, condition = ?, description = ?,
                cause = ?, effect = ?, recommendation = ?, severity = ?,
                finding_type = ?, status = ?, verification_notes = ?,
                supporting_evidence_references = ?, evidence_limitations = ?,
                supporting_test_references = ?, responsible_department = ?,
                assessor_name = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                clean_title,
                clean_crit,
                clean_cond,
                clean_cond,
                cause.strip() if cause else None,
                clean_eff,
                clean_rec,
                severity,
                finding_type,
                status,
                clean_ver if clean_ver else None,
                supporting_evidence_references.strip() if supporting_evidence_references else None,
                evidence_limitations.strip() if evidence_limitations else None,
                supporting_test_references.strip() if supporting_test_references else None,
                responsible_department.strip() if responsible_department else None,
                assessor_name.strip() if assessor_name else fnd["assessor_name"],
                now_iso,
                finding_id,
            ),
        )

    # Activity logging
    event_type = "FINDING_CLOSED" if status == "Closed" and prev_status != "Closed" else "FINDING_UPDATED"
    log_activity(
        assessment_id=fnd["assessment_id"],
        event_type=event_type,
        description=f"Finding {fnd['finding_identifier']} updated (Status: {status}, Severity: {severity}).",
        actor=assessor_name or fnd["assessor_name"],
        db_path=db_path,
    )

    return get_single_finding(finding_id, db_path=db_path)  # type: ignore


def get_single_finding(finding_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve finding details with joined control assessment and control metadata."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT f.*, c.control_identifier, c.title AS control_title, c.domain AS category
            FROM findings f
            LEFT JOIN control_assessments ca ON f.control_assessment_id = ca.id
            LEFT JOIN controls c ON ca.control_id = c.id
            WHERE f.id = ?
            """,
            (finding_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def get_assessment_findings(
    assessment_id: int,
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    search_query: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve filtered list of formal findings for an assessment."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        query = """
        SELECT f.*, c.control_identifier, c.title AS control_title, c.domain AS category
        FROM findings f
        LEFT JOIN control_assessments ca ON f.control_assessment_id = ca.id
        LEFT JOIN controls c ON ca.control_id = c.id
        WHERE f.assessment_id = ?
        """
        params: List[Any] = [assessment_id]

        if status_filter and status_filter != "All Statuses":
            query += " AND f.status = ?"
            params.append(status_filter)

        if severity_filter and severity_filter != "All Severities":
            query += " AND f.severity = ?"
            params.append(severity_filter)

        if search_query and search_query.strip():
            q = f"%{search_query.strip().lower()}%"
            query += " AND (LOWER(f.title) LIKE ? OR LOWER(f.finding_identifier) LIKE ? OR LOWER(COALESCE(c.control_identifier, '')) LIKE ?)"
            params.extend([q, q, q])

        query += " ORDER BY f.id DESC"
        cursor.execute(query, tuple(params))
        return [dict(r) for r in cursor.fetchall()]


def get_full_control_traceability(control_assessment_id: int, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve complete audit working-paper traceability for a control:
    Control Evaluation Record -> Mapped Evidence Files -> Control Tests -> Formal Findings.
    """
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT ca.*, c.control_identifier, c.title AS control_title, c.domain AS category, c.description AS control_description
            FROM control_assessments ca
            JOIN controls c ON ca.control_id = c.id
            WHERE ca.id = ?
            """,
            (control_assessment_id,),
        )
        ca_row = cursor.fetchone()
        if not ca_row:
            raise ValueError(f"Control assessment ID {control_assessment_id} not found.")

        ca = dict(ca_row)

        # 1. Mapped Evidence
        cursor.execute(
            """
            SELECT e.*, ce.notes AS mapping_notes
            FROM control_evidence ce
            JOIN evidence e ON ce.evidence_id = e.id
            WHERE ce.control_assessment_id = ? AND e.is_archived = 0
            ORDER BY e.id DESC
            """,
            (control_assessment_id,),
        )
        evidence_records = [dict(r) for r in cursor.fetchall()]

        # 2. Control Tests
        cursor.execute(
            """
            SELECT * FROM control_tests
            WHERE control_assessment_id = ?
            ORDER BY id DESC
            """,
            (control_assessment_id,),
        )
        test_records = [dict(r) for r in cursor.fetchall()]

        # 3. Formal Findings
        cursor.execute(
            """
            SELECT * FROM findings
            WHERE control_assessment_id = ?
            ORDER BY id DESC
            """,
            (control_assessment_id,),
        )
        findings = [dict(r) for r in cursor.fetchall()]

        return {
            "control_assessment": ca,
            "evidence_records": evidence_records,
            "test_records": test_records,
            "findings": findings,
        }
