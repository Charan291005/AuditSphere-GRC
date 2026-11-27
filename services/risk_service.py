"""
Risk Service for AuditSphere.

Handles persistence, retrieval, status transition validation, reassessment tracking,
and relational linking for information security risk records.
"""

import re
from typing import Any, Dict, List, Optional
from database import db_session, get_utc_now_iso
from services.assessment_service import get_assessment
from services.activity_service import log_activity
from services.risk_engine import (
    RISK_CATEGORIES,
    TREATMENT_STRATEGIES,
    RISK_STATUSES,
    APPROVAL_STATUSES,
    calculate_risk_score,
    classify_risk_score,
    evaluate_risk_record,
    validate_score_dimension,
)


def generate_next_risk_reference(conn: Any, assessment_id: int) -> str:
    """Generate sequential reference identifier (e.g. RSK-001, RSK-002) for the assessment."""
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT risk_identifier FROM risks
        WHERE assessment_id = ?
        ORDER BY id DESC
        """,
        (assessment_id,),
    )
    rows = cursor.fetchall()
    highest = 0
    for r in rows:
        match = re.search(r"RSK-(\d+)", r["risk_identifier"])
        if match:
            highest = max(highest, int(match.group(1)))
    return f"RSK-{highest + 1:03d}"


def create_risk(
    assessment_id: int,
    title: str,
    description: Optional[str] = None,
    asset_or_process: Optional[str] = None,
    threat: Optional[str] = None,
    vulnerability: Optional[str] = None,
    consequence: Optional[str] = None,
    risk_category: str = "Other",
    existing_controls: Optional[str] = None,
    risk_owner: Optional[str] = None,
    responsible_department: Optional[str] = None,
    # Inherent evaluation
    inherent_likelihood: Optional[int] = None,
    inherent_impact: Optional[int] = None,
    inherent_rationale: Optional[str] = None,
    # Residual evaluation
    residual_likelihood: Optional[int] = None,
    residual_impact: Optional[int] = None,
    residual_rationale: Optional[str] = None,
    # Target evaluation
    target_likelihood: Optional[int] = None,
    target_impact: Optional[int] = None,
    target_rationale: Optional[str] = None,
    # Treatment
    treatment_strategy: str = "Mitigate",
    treatment_justification: Optional[str] = None,
    proposed_treatment: Optional[str] = None,
    treatment_owner: Optional[str] = None,
    target_treatment_date: Optional[str] = None,
    # Acceptance & Approval
    acceptance_justification: Optional[str] = None,
    approving_authority: Optional[str] = None,
    approval_status: str = "Not Requested",
    approval_date: Optional[str] = None,
    review_date: Optional[str] = None,
    # Status & Metadata
    status: str = "Identified",
    assessor_name: str = "Lead Assessor",
    assessment_date: Optional[str] = None,
    # Initial linked entities
    linked_finding_ids: Optional[List[int]] = None,
    linked_control_ids: Optional[List[int]] = None,
    linked_evidence_ids: Optional[List[int]] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a new risk record with multi-tier evaluation (Inherent, Current Residual, Target Residual).
    Enforces assessment boundary protection, score calculations, and treatment rules.
    """
    asm = get_assessment(assessment_id, db_path=db_path)
    if not asm:
        raise ValueError(f"Assessment ID {assessment_id} does not exist.")
    if asm["status"] == "Archived":
        raise PermissionError(f"Assessment '{asm['title']}' is Archived. Cannot create risk records.")

    clean_title = (title or "").strip()
    if not clean_title:
        raise ValueError("Risk title is required and cannot be blank.")

    cat = risk_category if risk_category in RISK_CATEGORIES else "Other"
    strat = treatment_strategy if treatment_strategy in TREATMENT_STRATEGIES else "Mitigate"
    st = status if status in RISK_STATUSES else "Identified"
    appr_st = approval_status if approval_status in APPROVAL_STATUSES else "Not Requested"

    # Status & Acceptance Business Rules
    if st == "Accepted":
        if appr_st != "Approved":
            raise ValueError("A risk cannot be set to 'Accepted' status without a recorded 'Approved' decision.")
        if not acceptance_justification or not acceptance_justification.strip():
            raise ValueError("Documented acceptance justification is required to accept a risk.")

    # Calculate Inherent score
    inh_score, inh_level = evaluate_risk_record(inherent_likelihood, inherent_impact)
    # Calculate Residual score
    res_score, res_level = evaluate_risk_record(residual_likelihood, residual_impact)
    # Calculate Target score
    tgt_score, tgt_level = evaluate_risk_record(target_likelihood, target_impact)

    now_iso = get_utc_now_iso()
    ass_date = assessment_date.strip() if assessment_date else now_iso[:10]

    with db_session(db_path) as conn:
        cursor = conn.cursor()
        risk_ref = generate_next_risk_reference(conn, assessment_id)

        # Legacy backward-compatibility: set likelihood/impact to inherent
        legacy_l = inherent_likelihood if inherent_likelihood is not None else residual_likelihood
        legacy_i = inherent_impact if inherent_impact is not None else residual_impact

        cursor.execute(
            """
            INSERT INTO risks (
                assessment_id, risk_identifier, title, description,
                asset_or_process, threat, vulnerability, consequence,
                risk_category, existing_controls, risk_owner, responsible_department,
                likelihood, impact, inherent_risk_score, inherent_risk_level,
                inherent_likelihood, inherent_impact, inherent_rationale,
                treatment_strategy, treatment_justification, proposed_treatment,
                treatment_owner, target_treatment_date,
                residual_likelihood, residual_impact, residual_risk_score, residual_risk_level, residual_rationale,
                target_likelihood, target_impact, target_risk_score, target_risk_level, target_rationale,
                acceptance_justification, approving_authority, approval_status, approval_date,
                review_date, status, closure_rationale, assessor_name, assessment_date,
                is_archived, created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                0, ?, ?
            )
            """,
            (
                assessment_id,
                risk_ref,
                clean_title,
                description.strip() if description else None,
                asset_or_process.strip() if asset_or_process else None,
                threat.strip() if threat else None,
                vulnerability.strip() if vulnerability else None,
                consequence.strip() if consequence else None,
                cat,
                existing_controls.strip() if existing_controls else None,
                risk_owner.strip() if risk_owner else None,
                responsible_department.strip() if responsible_department else None,
                legacy_l,
                legacy_i,
                inh_score,
                inh_level if inh_score is not None else None,
                inherent_likelihood,
                inherent_impact,
                inherent_rationale.strip() if inherent_rationale else None,
                strat,
                treatment_justification.strip() if treatment_justification else None,
                proposed_treatment.strip() if proposed_treatment else None,
                treatment_owner.strip() if treatment_owner else None,
                target_treatment_date.strip() if target_treatment_date else None,
                residual_likelihood,
                residual_impact,
                res_score,
                res_level if res_score is not None else None,
                residual_rationale.strip() if residual_rationale else None,
                target_likelihood,
                target_impact,
                tgt_score,
                tgt_level if tgt_score is not None else None,
                target_rationale.strip() if target_rationale else None,
                acceptance_justification.strip() if acceptance_justification else None,
                approving_authority.strip() if approving_authority else None,
                appr_st,
                approval_date.strip() if approval_date else None,
                review_date.strip() if review_date else None,
                st,
                None,  # closure_rationale
                assessor_name.strip() if assessor_name else "Lead Assessor",
                ass_date,
                now_iso,
                now_iso,
            ),
        )
        risk_id = cursor.lastrowid

        # Link findings if requested
        if linked_finding_ids:
            for fid in linked_finding_ids:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO risk_findings (
                        assessment_id, risk_id, finding_id, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (assessment_id, risk_id, fid, now_iso),
                )

        # Link controls if requested
        if linked_control_ids:
            for ca_id in linked_control_ids:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO risk_controls (
                        assessment_id, risk_id, control_assessment_id, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (assessment_id, risk_id, ca_id, now_iso),
                )

        # Link evidence if requested
        if linked_evidence_ids:
            for eid in linked_evidence_ids:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO risk_evidence (
                        assessment_id, risk_id, evidence_id, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (assessment_id, risk_id, eid, now_iso),
                )

    log_activity(
        assessment_id=assessment_id,
        event_type="RISK_CREATED",
        description=f"Risk {risk_ref} ('{clean_title}') created (Current Residual: {res_level or 'Not Assessed'}).",
        actor=assessor_name,
        db_path=db_path,
    )

    return get_single_risk(risk_id, db_path=db_path)  # type: ignore


def update_risk(
    risk_id: int,
    title: str,
    description: Optional[str] = None,
    asset_or_process: Optional[str] = None,
    threat: Optional[str] = None,
    vulnerability: Optional[str] = None,
    consequence: Optional[str] = None,
    risk_category: str = "Other",
    existing_controls: Optional[str] = None,
    risk_owner: Optional[str] = None,
    responsible_department: Optional[str] = None,
    # Inherent evaluation
    inherent_likelihood: Optional[int] = None,
    inherent_impact: Optional[int] = None,
    inherent_rationale: Optional[str] = None,
    # Residual evaluation
    residual_likelihood: Optional[int] = None,
    residual_impact: Optional[int] = None,
    residual_rationale: Optional[str] = None,
    # Target evaluation
    target_likelihood: Optional[int] = None,
    target_impact: Optional[int] = None,
    target_rationale: Optional[str] = None,
    # Treatment
    treatment_strategy: str = "Mitigate",
    treatment_justification: Optional[str] = None,
    proposed_treatment: Optional[str] = None,
    treatment_owner: Optional[str] = None,
    target_treatment_date: Optional[str] = None,
    # Acceptance & Approval
    acceptance_justification: Optional[str] = None,
    approving_authority: Optional[str] = None,
    approval_status: str = "Not Requested",
    approval_date: Optional[str] = None,
    review_date: Optional[str] = None,
    # Status & Metadata
    status: str = "Identified",
    closure_rationale: Optional[str] = None,
    assessor_name: Optional[str] = None,
    assessment_date: Optional[str] = None,
    # Reassessment Tracking
    reassessment_reason: Optional[str] = None,
    supporting_evidence_refs: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Update an existing risk record.
    Enforces status transition rules, closure verification, and records history on score changes.
    """
    risk = get_single_risk(risk_id, db_path=db_path)
    if not risk:
        raise ValueError(f"Risk ID {risk_id} does not exist.")

    asm = get_assessment(risk["assessment_id"], db_path=db_path)
    if asm and asm["status"] == "Archived":
        raise PermissionError(f"Assessment '{asm['title']}' is Archived. Cannot modify risk records.")

    clean_title = (title or "").strip()
    if not clean_title:
        raise ValueError("Risk title is required.")

    cat = risk_category if risk_category in RISK_CATEGORIES else "Other"
    strat = treatment_strategy if treatment_strategy in TREATMENT_STRATEGIES else "Mitigate"
    st = status if status in RISK_STATUSES else "Identified"
    appr_st = approval_status if approval_status in APPROVAL_STATUSES else "Not Requested"

    # Status Validation Rules
    if st == "Accepted":
        if appr_st != "Approved":
            raise ValueError("A risk cannot be transitioned to 'Accepted' status without a recorded 'Approved' decision.")
        if not acceptance_justification or not acceptance_justification.strip():
            raise ValueError("Documented acceptance justification is required to accept a risk.")

    if st == "Closed":
        if not closure_rationale or not closure_rationale.strip():
            raise ValueError("Closing a risk strictly requires a documented closure rationale and verification note.")

    # Calculate Scores
    inh_score, inh_level = evaluate_risk_record(inherent_likelihood, inherent_impact)
    res_score, res_level = evaluate_risk_record(residual_likelihood, residual_impact)
    tgt_score, tgt_level = evaluate_risk_record(target_likelihood, target_impact)

    now_iso = get_utc_now_iso()
    ass_date = assessment_date.strip() if assessment_date else (risk.get("assessment_date") or now_iso[:10])

    # Detect Reassessment (Residual score change)
    old_res_l = risk.get("residual_likelihood")
    old_res_i = risk.get("residual_impact")
    old_res_score = risk.get("residual_risk_score")
    old_res_level = risk.get("residual_risk_level")

    is_reassessed = (
        old_res_score is not None
        and res_score is not None
        and (old_res_l != residual_likelihood or old_res_i != residual_impact)
    )

    with db_session(db_path) as conn:
        cursor = conn.cursor()

        # If reassessed, log in risk_reviews
        if is_reassessed:
            reason = (reassessment_reason or "").strip() or "Periodic risk reassessment and control review."
            cursor.execute(
                """
                INSERT INTO risk_reviews (
                    assessment_id, risk_id, previous_likelihood, previous_impact,
                    previous_score, previous_level, new_likelihood, new_impact,
                    new_score, new_level, evaluation_type, reason_for_change,
                    supporting_evidence_references, reviewer_name, review_timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    risk["assessment_id"],
                    risk_id,
                    old_res_l,
                    old_res_i,
                    old_res_score,
                    old_res_level,
                    residual_likelihood,
                    residual_impact,
                    res_score,
                    res_level,
                    "Current Residual",
                    reason,
                    supporting_evidence_refs.strip() if supporting_evidence_refs else None,
                    assessor_name.strip() if assessor_name else (risk.get("assessor_name") or "Lead Assessor"),
                    now_iso,
                ),
            )

        cursor.execute(
            """
            UPDATE risks
            SET title = ?, description = ?, asset_or_process = ?, threat = ?,
                vulnerability = ?, consequence = ?, risk_category = ?,
                existing_controls = ?, risk_owner = ?, responsible_department = ?,
                inherent_likelihood = ?, inherent_impact = ?, inherent_risk_score = ?,
                inherent_risk_level = ?, inherent_rationale = ?,
                treatment_strategy = ?, treatment_justification = ?, proposed_treatment = ?,
                treatment_owner = ?, target_treatment_date = ?,
                residual_likelihood = ?, residual_impact = ?, residual_risk_score = ?,
                residual_risk_level = ?, residual_rationale = ?,
                target_likelihood = ?, target_impact = ?, target_risk_score = ?,
                target_risk_level = ?, target_rationale = ?,
                acceptance_justification = ?, approving_authority = ?,
                approval_status = ?, approval_date = ?, review_date = ?,
                status = ?, closure_rationale = ?, assessor_name = ?,
                assessment_date = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                clean_title,
                description.strip() if description else None,
                asset_or_process.strip() if asset_or_process else None,
                threat.strip() if threat else None,
                vulnerability.strip() if vulnerability else None,
                consequence.strip() if consequence else None,
                cat,
                existing_controls.strip() if existing_controls else None,
                risk_owner.strip() if risk_owner else None,
                responsible_department.strip() if responsible_department else None,
                inherent_likelihood,
                inherent_impact,
                inh_score,
                inh_level if inh_score is not None else None,
                inherent_rationale.strip() if inherent_rationale else None,
                strat,
                treatment_justification.strip() if treatment_justification else None,
                proposed_treatment.strip() if proposed_treatment else None,
                treatment_owner.strip() if treatment_owner else None,
                target_treatment_date.strip() if target_treatment_date else None,
                residual_likelihood,
                residual_impact,
                res_score,
                res_level if res_score is not None else None,
                residual_rationale.strip() if residual_rationale else None,
                target_likelihood,
                target_impact,
                tgt_score,
                tgt_level if tgt_score is not None else None,
                target_rationale.strip() if target_rationale else None,
                acceptance_justification.strip() if acceptance_justification else None,
                approving_authority.strip() if approving_authority else None,
                appr_st,
                approval_date.strip() if approval_date else None,
                review_date.strip() if review_date else None,
                st,
                closure_rationale.strip() if closure_rationale else None,
                assessor_name.strip() if assessor_name else risk.get("assessor_name", "Lead Assessor"),
                ass_date,
                now_iso,
                risk_id,
            ),
        )

    # Activity Logging
    event_type = "RISK_REASSESSED" if is_reassessed else (
        "RISK_CLOSED" if st == "Closed" and risk["status"] != "Closed" else (
            "RISK_ACCEPTED" if st == "Accepted" and risk["status"] != "Accepted" else "RISK_UPDATED"
        )
    )
    log_activity(
        assessment_id=risk["assessment_id"],
        event_type=event_type,
        description=f"Risk {risk['risk_identifier']} updated (Status: {st}, Residual: {res_level or 'Not Assessed'}).",
        actor=assessor_name or risk.get("assessor_name", "Lead Assessor"),
        db_path=db_path,
    )

    return get_single_risk(risk_id, db_path=db_path)  # type: ignore


def archive_risk(risk_id: int, actor: str = "Lead Assessor", db_path: Optional[str] = None) -> None:
    """Safely archive a risk record without destructive deletion, preserving relational integrity."""
    risk = get_single_risk(risk_id, db_path=db_path)
    if not risk:
        raise ValueError(f"Risk ID {risk_id} does not exist.")

    now_iso = get_utc_now_iso()
    with db_session(db_path) as conn:
        conn.execute(
            "UPDATE risks SET is_archived = 1, updated_at = ? WHERE id = ?",
            (now_iso, risk_id),
        )

    log_activity(
        assessment_id=risk["assessment_id"],
        event_type="RISK_ARCHIVED",
        description=f"Risk {risk['risk_identifier']} ('{risk['title']}') was archived.",
        actor=actor,
        db_path=db_path,
    )


def link_finding_to_risk(risk_id: int, finding_id: int, notes: Optional[str] = None, db_path: Optional[str] = None) -> None:
    """Link an audit finding to a risk. Enforces cross-assessment isolation."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT assessment_id, risk_identifier FROM risks WHERE id = ?", (risk_id,))
        r_row = cursor.fetchone()
        if not r_row:
            raise ValueError(f"Risk ID {risk_id} does not exist.")

        cursor.execute("SELECT assessment_id, finding_identifier FROM findings WHERE id = ?", (finding_id,))
        f_row = cursor.fetchone()
        if not f_row:
            raise ValueError(f"Finding ID {finding_id} does not exist.")

        if r_row["assessment_id"] != f_row["assessment_id"]:
            raise ValueError("Cross-assessment violation: risk and finding belong to different assessments.")

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            INSERT OR IGNORE INTO risk_findings (
                assessment_id, risk_id, finding_id, notes, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (r_row["assessment_id"], risk_id, finding_id, notes, now_iso),
        )

    log_activity(
        assessment_id=r_row["assessment_id"],
        event_type="RISK_LINKED_TO_FINDING",
        description=f"Risk {r_row['risk_identifier']} linked to finding {f_row['finding_identifier']}.",
        db_path=db_path,
    )


def unlink_finding_from_risk(risk_id: int, finding_id: int, db_path: Optional[str] = None) -> None:
    """Remove relationship between risk and finding."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT assessment_id, risk_identifier FROM risks WHERE id = ?", (risk_id,))
        r_row = cursor.fetchone()
        if not r_row:
            return

        cursor.execute(
            "DELETE FROM risk_findings WHERE risk_id = ? AND finding_id = ?",
            (risk_id, finding_id),
        )


def link_control_to_risk(risk_id: int, control_assessment_id: int, notes: Optional[str] = None, db_path: Optional[str] = None) -> None:
    """Link a control assessment to a risk. Enforces cross-assessment isolation."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT assessment_id, risk_identifier FROM risks WHERE id = ?", (risk_id,))
        r_row = cursor.fetchone()
        if not r_row:
            raise ValueError(f"Risk ID {risk_id} does not exist.")

        cursor.execute("SELECT assessment_id FROM control_assessments WHERE id = ?", (control_assessment_id,))
        ca_row = cursor.fetchone()
        if not ca_row:
            raise ValueError(f"Control assessment ID {control_assessment_id} does not exist.")

        if r_row["assessment_id"] != ca_row["assessment_id"]:
            raise ValueError("Cross-assessment violation: risk and control belong to different assessments.")

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            INSERT OR IGNORE INTO risk_controls (
                assessment_id, risk_id, control_assessment_id, notes, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (r_row["assessment_id"], risk_id, control_assessment_id, notes, now_iso),
        )

    log_activity(
        assessment_id=r_row["assessment_id"],
        event_type="RISK_LINKED_TO_CONTROL",
        description=f"Risk {r_row['risk_identifier']} linked to control assessment #{control_assessment_id}.",
        db_path=db_path,
    )


def unlink_control_from_risk(risk_id: int, control_assessment_id: int, db_path: Optional[str] = None) -> None:
    """Remove relationship between risk and control assessment."""
    with db_session(db_path) as conn:
        conn.execute(
            "DELETE FROM risk_controls WHERE risk_id = ? AND control_assessment_id = ?",
            (risk_id, control_assessment_id),
        )


def link_evidence_to_risk(risk_id: int, evidence_id: int, notes: Optional[str] = None, db_path: Optional[str] = None) -> None:
    """Link an evidence file to a risk. Enforces cross-assessment isolation."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT assessment_id, risk_identifier FROM risks WHERE id = ?", (risk_id,))
        r_row = cursor.fetchone()
        if not r_row:
            raise ValueError(f"Risk ID {risk_id} does not exist.")

        cursor.execute("SELECT assessment_id, evidence_identifier FROM evidence WHERE id = ?", (evidence_id,))
        ev_row = cursor.fetchone()
        if not ev_row:
            raise ValueError(f"Evidence ID {evidence_id} does not exist.")

        if r_row["assessment_id"] != ev_row["assessment_id"]:
            raise ValueError("Cross-assessment violation: risk and evidence belong to different assessments.")

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            INSERT OR IGNORE INTO risk_evidence (
                assessment_id, risk_id, evidence_id, notes, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (r_row["assessment_id"], risk_id, evidence_id, notes, now_iso),
        )

    log_activity(
        assessment_id=r_row["assessment_id"],
        event_type="RISK_LINKED_TO_EVIDENCE",
        description=f"Risk {r_row['risk_identifier']} linked to evidence {ev_row['evidence_identifier']}.",
        db_path=db_path,
    )


def unlink_evidence_from_risk(risk_id: int, evidence_id: int, db_path: Optional[str] = None) -> None:
    """Remove relationship between risk and evidence."""
    with db_session(db_path) as conn:
        conn.execute(
            "DELETE FROM risk_evidence WHERE risk_id = ? AND evidence_id = ?",
            (risk_id, evidence_id),
        )


def get_single_risk(risk_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieve full details for a risk record including:
    - Linked audit findings
    - Linked Annex A control assessments
    - Linked supporting evidence files
    - Reassessment and review history
    """
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM risks WHERE id = ?", (risk_id,))
        row = cursor.fetchone()
        if not row:
            return None

        risk = dict(row)

        # 1. Linked Findings
        cursor.execute(
            """
            SELECT f.id, f.finding_identifier, f.title, f.severity, f.status, f.finding_type, rf.notes AS link_notes
            FROM risk_findings rf
            JOIN findings f ON rf.finding_id = f.id
            WHERE rf.risk_id = ?
            ORDER BY f.id ASC
            """,
            (risk_id,),
        )
        risk["linked_findings"] = [dict(f) for f in cursor.fetchall()]

        # 2. Linked Controls
        cursor.execute(
            """
            SELECT ca.id AS control_assessment_id, ca.status AS control_status,
                   c.id AS control_id, c.control_identifier, c.title AS control_title, c.domain,
                   rc.notes AS link_notes
            FROM risk_controls rc
            JOIN control_assessments ca ON rc.control_assessment_id = ca.id
            JOIN controls c ON ca.control_id = c.id
            WHERE rc.risk_id = ?
            ORDER BY c.id ASC
            """,
            (risk_id,),
        )
        risk["linked_controls"] = [dict(c) for c in cursor.fetchall()]

        # 3. Linked Evidence
        cursor.execute(
            """
            SELECT e.id, e.evidence_identifier, e.title, e.evidence_type, e.review_status, e.sha256_hash,
                   re.notes AS link_notes
            FROM risk_evidence re
            JOIN evidence e ON re.evidence_id = e.id
            WHERE re.risk_id = ? AND e.is_archived = 0
            ORDER BY e.id ASC
            """,
            (risk_id,),
        )
        risk["linked_evidence"] = [dict(e) for e in cursor.fetchall()]

        # 4. Review History
        cursor.execute(
            """
            SELECT * FROM risk_reviews
            WHERE risk_id = ?
            ORDER BY id DESC
            """,
            (risk_id,),
        )
        risk["review_history"] = [dict(h) for h in cursor.fetchall()]

        return risk


def get_assessment_risks(
    assessment_id: int,
    status_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
    treatment_filter: Optional[str] = None,
    owner_filter: Optional[str] = None,
    search_query: Optional[str] = None,
    include_archived: bool = False,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve filtered list of risk records for an assessment."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM risks WHERE assessment_id = ?"
        params: List[Any] = [assessment_id]

        if not include_archived:
            query += " AND is_archived = 0"

        if status_filter and status_filter != "All Statuses":
            query += " AND status = ?"
            params.append(status_filter)

        if severity_filter and severity_filter != "All Severities":
            query += " AND residual_risk_level = ?"
            params.append(severity_filter)

        if category_filter and category_filter != "All Categories":
            query += " AND risk_category = ?"
            params.append(category_filter)

        if treatment_filter and treatment_filter != "All Strategies":
            query += " AND treatment_strategy = ?"
            params.append(treatment_filter)

        if owner_filter and owner_filter != "All Owners":
            query += " AND risk_owner = ?"
            params.append(owner_filter)

        if search_query and search_query.strip():
            q = f"%{search_query.strip().lower()}%"
            query += " AND (LOWER(title) LIKE ? OR LOWER(risk_identifier) LIKE ? OR LOWER(COALESCE(description, '')) LIKE ? OR LOWER(COALESCE(asset_or_process, '')) LIKE ?)"
            params.extend([q, q, q, q])

        query += " ORDER BY id DESC"
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        results = []
        for r in rows:
            risk_dict = dict(r)

            # Fetch linked counts and primary references
            cursor.execute(
                """
                SELECT f.finding_identifier, f.title
                FROM risk_findings rf
                JOIN findings f ON rf.finding_id = f.id
                WHERE rf.risk_id = ?
                """,
                (risk_dict["id"],),
            )
            risk_dict["linked_findings"] = [dict(f) for f in cursor.fetchall()]

            cursor.execute(
                """
                SELECT c.control_identifier, c.title
                FROM risk_controls rc
                JOIN control_assessments ca ON rc.control_assessment_id = ca.id
                JOIN controls c ON ca.control_id = c.id
                WHERE rc.risk_id = ?
                """,
                (risk_dict["id"],),
            )
            risk_dict["linked_controls"] = [dict(c) for c in cursor.fetchall()]

            results.append(risk_dict)

        return results
