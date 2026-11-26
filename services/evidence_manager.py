"""
Evidence Manager Service for AuditSphere.

Handles secure evidence storage, format and magic-byte signature validation,
SHA-256 integrity hashing, review workflows, many-to-many control mappings,
and path traversal defenses.
"""

import hashlib
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from database import db_session, get_utc_now_iso, EVIDENCE_STORAGE_DIR
from services.assessment_service import get_assessment
from services.activity_service import log_activity

# Maximum allowed upload size (10 MB default)
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10,485,760 bytes

# Supported file extensions
SUPPORTED_EXTENSIONS = {"pdf", "csv", "txt", "png", "jpg", "jpeg", "xlsx"}

# Supported evidence types
EVIDENCE_TYPES = [
    "Security policy",
    "Procedure",
    "Configuration record",
    "System log",
    "Screenshot",
    "Access record",
    "Training record",
    "Test result",
    "Interview or walkthrough notes",
    "Other",
]

# Supported review statuses
REVIEW_STATUSES = [
    "Pending Review",
    "Accepted",
    "Needs Clarification",
    "Rejected",
]

# Supported integrity verification statuses
INTEGRITY_STATUSES = [
    "Not yet verified",
    "Verified",
    "Hash mismatch",
    "File missing",
]


def validate_file_content(file_name: str, file_bytes: bytes, max_size: int = DEFAULT_MAX_FILE_SIZE) -> str:
    """
    Validate file extension, size limit, and magic byte signature.
    Returns normalized file extension if valid, or raises ValueError.
    """
    if not file_bytes:
        raise ValueError("Uploaded file is empty (0 bytes).")

    if len(file_bytes) > max_size:
        max_mb = max_size / (1024 * 1024)
        raise ValueError(
            f"File size exceeds the configured maximum limit of {max_mb:.1f} MB (uploaded: {len(file_bytes) / (1024 * 1024):.2f} MB)."
        )

    # Validate extension
    parts = file_name.rsplit(".", 1)
    if len(parts) < 2:
        raise ValueError(f"File '{file_name}' has no extension. Supported formats: {', '.join(sorted(SUPPORTED_EXTENSIONS))}.")

    ext = parts[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file extension '.{ext}'. Supported formats: {', '.join(sorted(SUPPORTED_EXTENSIONS))}."
        )

    # Magic byte format verification
    if ext == "pdf":
        if not file_bytes.startswith(b"%PDF"):
            raise ValueError("File content does not match standard PDF header signature (%PDF).")
    elif ext == "png":
        if not file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("File content does not match standard PNG header signature.")
    elif ext in ("jpg", "jpeg"):
        if not file_bytes.startswith(b"\xff\xd8\xff"):
            raise ValueError("File content does not match standard JPEG header signature.")
    elif ext == "xlsx":
        # XLSX files are standard ZIP packages starting with PK\x03\x04
        if not file_bytes.startswith(b"PK\x03\x04"):
            raise ValueError("File content does not match standard Microsoft Excel (OOXML/ZIP) signature.")
    elif ext in ("csv", "txt"):
        # Ensure text is decodeable and does not contain raw executable null blocks
        try:
            sample = file_bytes[:4096].decode("utf-8", errors="replace")
            # Disallow binary execution signatures like Windows MZ header or ELF
            if file_bytes.startswith(b"MZ") or file_bytes.startswith(b"\x7fELF"):
                raise ValueError("Executable binary files disguised as text are strictly prohibited.")
        except Exception:
            raise ValueError("File content is not readable as standard text or CSV.")

    return ext


def compute_sha256(file_bytes: bytes) -> str:
    """Compute standard SHA-256 hex digest for integrity tracking."""
    return hashlib.sha256(file_bytes).hexdigest()


def get_safe_storage_path(assessment_id: int, storage_identifier: str, base_dir: Optional[Path] = None) -> Path:
    """
    Resolve and validate storage path to strictly prevent path traversal attacks.
    """
    if ".." in storage_identifier or "/" in storage_identifier or "\\" in storage_identifier:
        raise ValueError("Invalid character in storage identifier. Path traversal characters not permitted.")

    root = (base_dir or EVIDENCE_STORAGE_DIR).resolve()
    target_dir = root / str(assessment_id)
    target_path = (target_dir / storage_identifier).resolve()

    # Verify that the target path is strictly within the target directory
    try:
        target_path.relative_to(root)
    except ValueError:
        raise ValueError("Path traversal attempt detected. File path resolution blocked.")

    return target_path


def generate_next_evidence_reference(conn: Any, assessment_id: int) -> str:
    """Generate sequential reference identifier (e.g. EVD-001, EVD-002) for the assessment."""
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT evidence_identifier FROM evidence
        WHERE assessment_id = ?
        ORDER BY id DESC
        """,
        (assessment_id,),
    )
    rows = cursor.fetchall()
    highest_num = 0
    for r in rows:
        match = re.search(r"EVD-(\d+)", r["evidence_identifier"])
        if match:
            highest_num = max(highest_num, int(match.group(1)))
    return f"EVD-{highest_num + 1:03d}"


def upload_evidence(
    assessment_id: int,
    title: str,
    file_name: str,
    file_bytes: bytes,
    evidence_type: str = "Other",
    description: Optional[str] = None,
    source_department: Optional[str] = None,
    collection_date: Optional[str] = None,
    period_covered: Optional[str] = None,
    uploaded_by: str = "Lead Assessor",
    mapped_control_ids: Optional[List[int]] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    storage_dir: Optional[Path] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Upload and register an evidence artifact.
    Validates file format, stores file with unique server-side UUID,
    computes SHA-256 hash, and maps to initial controls if requested.
    """
    # 1. Verify assessment exists and is not archived
    asm = get_assessment(assessment_id, db_path=db_path)
    if not asm:
        raise ValueError(f"Assessment ID {assessment_id} does not exist.")
    if asm["status"] == "Archived":
        raise PermissionError(f"Assessment '{asm['title']}' is Archived. Cannot upload evidence.")

    clean_title = (title or "").strip()
    if not clean_title:
        raise ValueError("Evidence title is required and cannot be blank.")

    if evidence_type not in EVIDENCE_TYPES:
        evidence_type = "Other"

    # 2. Validate file format and size
    ext = validate_file_content(file_name, file_bytes, max_size=max_file_size)
    sha256_hash = compute_sha256(file_bytes)
    file_size = len(file_bytes)

    # 3. Generate unique storage identifier
    unique_id = uuid.uuid4().hex
    storage_filename = f"{unique_id}.{ext}"
    target_path = get_safe_storage_path(assessment_id, storage_filename, base_dir=storage_dir)
    target_path.parent.mkdir(parents=True, exist_ok=True)

    # Write file to disk
    try:
        with open(target_path, "wb") as f:
            f.write(file_bytes)
    except Exception as ex:
        raise IOError(f"Failed to write evidence file to disk: {str(ex)}")

    now_iso = get_utc_now_iso()
    col_date = collection_date or now_iso[:10]

    # Relative storage path for DB storage
    rel_storage_path = f"storage/evidence/{assessment_id}/{storage_filename}"

    try:
        with db_session(db_path) as conn:
            cursor = conn.cursor()
            ev_ref = generate_next_evidence_reference(conn, assessment_id)

            cursor.execute(
                """
                INSERT INTO evidence (
                    assessment_id, evidence_identifier, title, description,
                    evidence_type, file_name, original_file_name, storage_identifier,
                    file_path, file_size, file_hash, sha256_hash, source_department,
                    collection_date, period_covered, review_status, integrity_status,
                    integrity_verified_at, is_archived, uploaded_by, uploaded_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending Review', 'Verified', ?, 0, ?, ?, ?)
                """,
                (
                    assessment_id,
                    ev_ref,
                    clean_title,
                    description.strip() if description else None,
                    evidence_type,
                    file_name,
                    file_name,
                    storage_filename,
                    rel_storage_path,
                    file_size,
                    sha256_hash,
                    sha256_hash,
                    source_department.strip() if source_department else None,
                    col_date,
                    period_covered.strip() if period_covered else None,
                    now_iso,
                    uploaded_by,
                    now_iso,
                    now_iso,
                ),
            )
            evidence_id = cursor.lastrowid

            # Map to controls if specified
            if mapped_control_ids:
                for cid in mapped_control_ids:
                    # Resolve control_assessment_id for this assessment and control_id
                    cursor.execute(
                        "SELECT id FROM control_assessments WHERE assessment_id = ? AND control_id = ?",
                        (assessment_id, cid),
                    )
                    ca_row = cursor.fetchone()
                    if ca_row:
                        cursor.execute(
                            """
                            INSERT OR IGNORE INTO control_evidence (
                                assessment_id, control_assessment_id, evidence_id, mapped_at, notes
                            ) VALUES (?, ?, ?, ?, ?)
                            """,
                            (assessment_id, ca_row["id"], evidence_id, now_iso, "Initial mapping on upload"),
                        )

    except Exception:
        # Clean up file on disk if DB insertion failed
        if target_path.exists():
            target_path.unlink()
        raise

    # Log activity
    log_activity(
        assessment_id=assessment_id,
        event_type="EVIDENCE_UPLOADED",
        description=f"Evidence '{clean_title}' ({ev_ref}) uploaded by {uploaded_by}.",
        actor=uploaded_by,
        db_path=db_path,
    )

    return get_single_evidence(evidence_id, db_path=db_path, storage_dir=storage_dir)  # type: ignore


def verify_evidence_integrity(evidence_id: int, storage_dir: Optional[Path] = None, db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Recalculate SHA-256 hash of the stored file on disk and compare against the recorded original hash.
    Supported results: Verified, Hash mismatch, File missing.
    Updates the database with the result and timestamp.
    """
    ev = get_single_evidence(evidence_id, db_path=db_path, storage_dir=storage_dir)
    if not ev:
        raise ValueError(f"Evidence ID {evidence_id} not found.")

    storage_identifier = ev.get("storage_identifier") or ev.get("file_name")
    target_path = get_safe_storage_path(ev["assessment_id"], storage_identifier, base_dir=storage_dir)

    now_iso = get_utc_now_iso()
    expected_hash = ev["sha256_hash"] or ev["file_hash"]

    if not target_path.exists():
        new_status = "File missing"
    else:
        try:
            with open(target_path, "rb") as f:
                actual_bytes = f.read()
            actual_hash = compute_sha256(actual_bytes)
            if actual_hash == expected_hash:
                new_status = "Verified"
            else:
                new_status = "Hash mismatch"
        except Exception:
            new_status = "File missing"

    with db_session(db_path) as conn:
        conn.execute(
            """
            UPDATE evidence
            SET integrity_status = ?, integrity_verified_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (new_status, now_iso, now_iso, evidence_id),
        )

    # Log activity if mismatch or verification completed
    event_type = "EVIDENCE_INTEGRITY_MISMATCH" if new_status == "Hash mismatch" else "EVIDENCE_INTEGRITY_VERIFIED"
    log_activity(
        assessment_id=ev["assessment_id"],
        event_type=event_type,
        description=f"Integrity check for {ev['evidence_identifier']} result: {new_status}.",
        db_path=db_path,
    )

    return get_single_evidence(evidence_id, db_path=db_path, storage_dir=storage_dir)  # type: ignore


def review_evidence(
    evidence_id: int,
    review_status: str,
    reviewer_name: str,
    reviewer_notes: str,
    relevance_rating: str = "Relevant",
    sufficiency_rating: str = "Sufficient",
    reliability_rating: str = "Reliable",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluate evidence relevance, sufficiency, and reliability.
    Requires reviewer name and notes when marking completed decisions.
    """
    if review_status not in REVIEW_STATUSES:
        raise ValueError(f"Invalid review status '{review_status}'. Must be one of: {', '.join(REVIEW_STATUSES)}.")

    reviewer = (reviewer_name or "").strip()
    notes = (reviewer_notes or "").strip()

    if review_status != "Pending Review":
        if not reviewer:
            raise ValueError("Reviewer name is required when recording an evidence review decision.")
        if not notes:
            raise ValueError("Reviewer notes are required explaining the assessment of the evidence.")

    ev = get_single_evidence(evidence_id, db_path=db_path)
    if not ev:
        raise ValueError(f"Evidence ID {evidence_id} not found.")

    asm = get_assessment(ev["assessment_id"], db_path=db_path)
    if asm and asm["status"] == "Archived":
        raise PermissionError(f"Assessment '{asm['title']}' is Archived. Cannot modify evidence review.")

    now_iso = get_utc_now_iso()

    with db_session(db_path) as conn:
        conn.execute(
            """
            UPDATE evidence
            SET review_status = ?, reviewer_name = ?, reviewer_notes = ?,
                relevance_rating = ?, sufficiency_rating = ?, reliability_rating = ?,
                reviewed_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                review_status,
                reviewer,
                notes,
                relevance_rating,
                sufficiency_rating,
                reliability_rating,
                now_iso,
                now_iso,
                evidence_id,
            ),
        )

    log_activity(
        assessment_id=ev["assessment_id"],
        event_type="EVIDENCE_REVIEWED",
        description=f"Evidence {ev['evidence_identifier']} review status set to '{review_status}' by {reviewer}.",
        actor=reviewer,
        db_path=db_path,
    )

    return get_single_evidence(evidence_id, db_path=db_path)  # type: ignore


def map_evidence_to_control(
    evidence_id: int,
    control_assessment_id: int,
    notes: Optional[str] = None,
    db_path: Optional[str] = None,
) -> None:
    """
    Map an evidence artifact to a control assessment.
    Enforces that both the evidence and the control assessment belong to the same assessment!
    """
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT assessment_id FROM evidence WHERE id = ?", (evidence_id,))
        ev_row = cursor.fetchone()
        if not ev_row:
            raise ValueError(f"Evidence ID {evidence_id} does not exist.")

        cursor.execute("SELECT assessment_id FROM control_assessments WHERE id = ?", (control_assessment_id,))
        ca_row = cursor.fetchone()
        if not ca_row:
            raise ValueError(f"Control assessment ID {control_assessment_id} does not exist.")

        if ev_row["assessment_id"] != ca_row["assessment_id"]:
            raise ValueError("Cross-assessment violation: evidence and control assessment belong to different assessments.")

        now_iso = get_utc_now_iso()
        cursor.execute(
            """
            INSERT OR IGNORE INTO control_evidence (
                assessment_id, control_assessment_id, evidence_id, mapped_at, notes
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (ev_row["assessment_id"], control_assessment_id, evidence_id, now_iso, notes),
        )

    log_activity(
        assessment_id=ev_row["assessment_id"],
        event_type="EVIDENCE_MAPPED_TO_CONTROL",
        description=f"Evidence #{evidence_id} mapped to control assessment #{control_assessment_id}.",
        db_path=db_path,
    )


def unmap_evidence_from_control(
    evidence_id: int,
    control_assessment_id: int,
    db_path: Optional[str] = None,
) -> None:
    """Remove mapping between an evidence file and a control assessment."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT assessment_id FROM control_evidence WHERE evidence_id = ? AND control_assessment_id = ?",
            (evidence_id, control_assessment_id),
        )
        row = cursor.fetchone()
        if not row:
            return

        aid = row["assessment_id"]
        cursor.execute(
            "DELETE FROM control_evidence WHERE evidence_id = ? AND control_assessment_id = ?",
            (evidence_id, control_assessment_id),
        )

    log_activity(
        assessment_id=aid,
        event_type="EVIDENCE_UNMAPPED",
        description=f"Evidence #{evidence_id} unmapped from control assessment #{control_assessment_id}.",
        db_path=db_path,
    )


def get_mapped_controls_for_evidence(evidence_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve all control assessments mapped to a given evidence file."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT c.id AS control_id, c.control_identifier, c.title, c.domain,
                   ca.id AS control_assessment_id, ca.status AS control_status, ce.notes AS mapping_notes
            FROM control_evidence ce
            JOIN control_assessments ca ON ce.control_assessment_id = ca.id
            JOIN controls c ON ca.control_id = c.id
            WHERE ce.evidence_id = ?
            ORDER BY c.id ASC
            """,
            (evidence_id,),
        )
        return [dict(r) for r in cursor.fetchall()]


def get_mapped_evidence_for_control(control_assessment_id: int, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve all evidence files mapped to a given control assessment."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
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
        return [dict(r) for r in cursor.fetchall()]


def archive_evidence(evidence_id: int, actor: str = "Lead Assessor", db_path: Optional[str] = None) -> None:
    """Safely archive an evidence file without deleting the record or breaking historical findings."""
    now_iso = get_utc_now_iso()
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT assessment_id, evidence_identifier, title FROM evidence WHERE id = ?", (evidence_id,))
        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Evidence ID {evidence_id} does not exist.")

        cursor.execute(
            "UPDATE evidence SET is_archived = 1, updated_at = ? WHERE id = ?",
            (now_iso, evidence_id),
        )

    log_activity(
        assessment_id=row["assessment_id"],
        event_type="EVIDENCE_ARCHIVED",
        description=f"Evidence {row['evidence_identifier']} ('{row['title']}') was archived.",
        actor=actor,
        db_path=db_path,
    )


def get_single_evidence(
    evidence_id: int,
    db_path: Optional[str] = None,
    storage_dir: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Retrieve full details for an evidence artifact along with mapped controls."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
        row = cursor.fetchone()
        if not row:
            return None

        ev = dict(row)

        # Fetch mapped controls
        cursor.execute(
            """
            SELECT c.id AS control_id, c.control_identifier, c.title, c.domain,
                   ca.id AS control_assessment_id, ca.status AS control_status
            FROM control_evidence ce
            JOIN control_assessments ca ON ce.control_assessment_id = ca.id
            JOIN controls c ON ca.control_id = c.id
            WHERE ce.evidence_id = ?
            ORDER BY c.id ASC
            """,
            (evidence_id,),
        )
        ev["mapped_controls"] = [dict(c) for c in cursor.fetchall()]

        # Check for possible duplicate files by SHA-256 in the same assessment
        cursor.execute(
            """
            SELECT id, evidence_identifier, title
            FROM evidence
            WHERE assessment_id = ? AND id != ? AND is_archived = 0 AND sha256_hash = ?
            """,
            (ev["assessment_id"], evidence_id, ev.get("sha256_hash") or ev.get("file_hash")),
        )
        ev["duplicates"] = [dict(d) for d in cursor.fetchall()]

        return ev


def get_assessment_evidence(
    assessment_id: int,
    search_query: Optional[str] = None,
    evidence_type_filter: Optional[str] = None,
    review_status_filter: Optional[str] = None,
    control_filter: Optional[str] = None,
    include_archived: bool = False,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve filtered list of evidence artifacts for an assessment."""
    with db_session(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM evidence WHERE assessment_id = ?"
        params: List[Any] = [assessment_id]

        if not include_archived:
            query += " AND is_archived = 0"

        if evidence_type_filter and evidence_type_filter != "All Types":
            query += " AND evidence_type = ?"
            params.append(evidence_type_filter)

        if review_status_filter and review_status_filter != "All Statuses":
            query += " AND review_status = ?"
            params.append(review_status_filter)

        if search_query and search_query.strip():
            q = f"%{search_query.strip().lower()}%"
            query += " AND (LOWER(title) LIKE ? OR LOWER(evidence_identifier) LIKE ? OR LOWER(COALESCE(description, '')) LIKE ?)"
            params.extend([q, q, q])

        query += " ORDER BY id DESC"
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()

        results = []
        for r in rows:
            ev = dict(r)
            # Fetch mapped controls
            cursor.execute(
                """
                SELECT c.control_identifier, c.title
                FROM control_evidence ce
                JOIN control_assessments ca ON ce.control_assessment_id = ca.id
                JOIN controls c ON ca.control_id = c.id
                WHERE ce.evidence_id = ?
                """,
                (ev["id"],),
            )
            ev["mapped_controls"] = [dict(c) for c in cursor.fetchall()]

            # Filter by control reference if requested
            if control_filter and control_filter != "All Controls":
                if not any(c["control_identifier"] == control_filter for c in ev["mapped_controls"]):
                    continue

            results.append(ev)

        return results


def get_evidence_file_bytes(evidence_id: int, storage_dir: Optional[Path] = None, db_path: Optional[str] = None) -> Tuple[bytes, str]:
    """Safely retrieve evidence file bytes and original filename for downloading."""
    ev = get_single_evidence(evidence_id, db_path=db_path)
    if not ev:
        raise ValueError(f"Evidence ID {evidence_id} not found.")

    storage_identifier = ev.get("storage_identifier") or ev.get("file_name")
    target_path = get_safe_storage_path(ev["assessment_id"], storage_identifier, base_dir=storage_dir)

    if not target_path.exists():
        raise FileNotFoundError(f"Evidence file on disk could not be found.")

    with open(target_path, "rb") as f:
        data = f.read()

    filename = ev.get("original_file_name") or ev.get("file_name") or f"evidence_{evidence_id}.bin"
    return data, filename
