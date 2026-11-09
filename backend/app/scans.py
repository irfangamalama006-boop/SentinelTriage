import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from jose import jwt, JWTError
from sqlalchemy import text

from .auth import SECRET_KEY, ALGORITHM, security
from .database import engine

from sentineltriage.yara_scan import scan_with_yara


router = APIRouter(prefix="/scans", tags=["Scans"])

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_DATA = (PROJECT_ROOT / "test-data").resolve()
RULES_DIR = (PROJECT_ROOT / "rules").resolve()


def get_scan_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )
        user_id = int(payload["sub"])
    except (JWTError, ValueError, KeyError):
        raise HTTPException(
            status_code=401,
            detail="Token tidak valid atau kedaluwarsa",
        )

    with engine.connect() as connection:
        user = connection.execute(
            text("""
                SELECT id, name, email
                FROM users
                WHERE id = :user_id
            """),
            {"user_id": user_id},
        ).mappings().first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Pengguna tidak ditemukan",
        )

    return dict(user)


class ScanCreate(BaseModel):
    case_id: int = Field(gt=0)
    endpoint_id: Optional[int] = Field(default=None, gt=0)


class ScanExecute(BaseModel):
    target_path: str = "test-data/sampel-aman"
    rules_path: str = "test-data/aturan/aturan-uji.yar"


def get_authorized_scan(scan_id: int, user_id: int):
    with engine.connect() as connection:
        scan = connection.execute(
            text("""
                SELECT
                    s.id,
                    s.case_id,
                    s.status,
                    c.organization_id,
                    c.case_number
                FROM scans s
                JOIN cases c ON c.id = s.case_id
                JOIN organization_members om
                    ON om.organization_id = c.organization_id
                WHERE s.id = :scan_id
                AND om.user_id = :user_id
            """),
            {
                "scan_id": scan_id,
                "user_id": user_id,
            },
        ).mappings().first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan tidak ditemukan atau tidak memiliki akses",
        )

    return dict(scan)


@router.get("/")
def list_scans(
    current_user: dict = Depends(get_scan_user),
):
    with engine.connect() as connection:
        rows = connection.execute(
            text("""
                SELECT
                    s.id,
                    s.case_id,
                    s.endpoint_id,
                    s.status,
                    s.started_at,
                    s.completed_at,
                    s.created_at
                FROM scans s
                JOIN cases c ON c.id = s.case_id
                JOIN organization_members om
                    ON om.organization_id = c.organization_id
                WHERE om.user_id = :user_id
                ORDER BY s.id DESC
            """),
            {"user_id": current_user["id"]},
        ).mappings().all()

    return [dict(row) for row in rows]


@router.post("/", status_code=201)
def create_scan(
    data: ScanCreate,
    current_user: dict = Depends(get_scan_user),
):
    with engine.begin() as connection:
        case = connection.execute(
            text("""
                SELECT id, case_number, organization_id
                FROM cases
                WHERE id = :case_id
            """),
            {"case_id": data.case_id},
        ).mappings().first()

        if not case:
            raise HTTPException(
                status_code=404,
                detail="Kasus tidak ditemukan",
            )

        membership = connection.execute(
            text("""
                SELECT id
                FROM organization_members
                WHERE user_id = :user_id
                AND organization_id = :organization_id
            """),
            {
                "user_id": current_user["id"],
                "organization_id": case["organization_id"],
            },
        ).first()

        if not membership:
            raise HTTPException(
                status_code=403,
                detail="Tidak memiliki akses ke kasus ini",
            )

        if data.endpoint_id is not None:
            endpoint = connection.execute(
                text("""
                    SELECT id
                    FROM endpoints
                    WHERE id = :endpoint_id
                    AND organization_id = :organization_id
                """),
                {
                    "endpoint_id": data.endpoint_id,
                    "organization_id": case["organization_id"],
                },
            ).first()

            if not endpoint:
                raise HTTPException(
                    status_code=404,
                    detail="Endpoint tidak ditemukan pada organisasi kasus",
                )

        result = connection.execute(
            text("""
                INSERT INTO scans (case_id, endpoint_id, status)
                VALUES (:case_id, :endpoint_id, 'pending')
            """),
            {
                "case_id": data.case_id,
                "endpoint_id": data.endpoint_id,
            },
        )

        scan_id = result.lastrowid

        connection.execute(
            text("""
                INSERT INTO audit_logs
                    (user_id, organization_id, action, description)
                VALUES
                    (:user_id, :organization_id, 'SCAN_CREATED', :description)
            """),
            {
                "user_id": current_user["id"],
                "organization_id": case["organization_id"],
                "description": (
                    f"Scan #{scan_id} dibuat untuk kasus "
                    f"{case['case_number']}"
                ),
            },
        )

    return {
        "message": "Scan berhasil dibuat",
        "scan_id": scan_id,
        "case_id": data.case_id,
        "status": "pending",
    }


@router.post("/{scan_id}/execute")
def execute_scan(
    scan_id: int,
    data: ScanExecute,
    current_user: dict = Depends(get_scan_user),
):
    scan = get_authorized_scan(scan_id, current_user["id"])

    if scan["status"] not in ("pending", "failed"):
        raise HTTPException(
            status_code=409,
            detail=f"Scan tidak dapat dijalankan dengan status {scan['status']}",
        )

    target = (PROJECT_ROOT / data.target_path).resolve()
    rules_file = (PROJECT_ROOT / data.rules_path).resolve()

    # Batasi target pemindaian ke direktori test-data.
    if not target.is_relative_to(TEST_DATA):
        raise HTTPException(
            status_code=400,
            detail="Target scan harus berada di dalam direktori test-data",
        )

    # Rules hanya boleh berasal dari direktori rules atau test-data/aturan.
    allowed_rules_dirs = [
        RULES_DIR,
        (TEST_DATA / "aturan").resolve(),
    ]

    if not any(rules_file.is_relative_to(folder) for folder in allowed_rules_dirs):
        raise HTTPException(
            status_code=400,
            detail="File YARA harus berada di direktori rules atau test-data/aturan",
        )

    if not target.exists():
        raise HTTPException(
            status_code=404,
            detail="Target scan tidak ditemukan",
        )

    if not rules_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="File aturan YARA tidak ditemukan",
        )

    if rules_file.suffix.lower() not in (".yar", ".yara"):
        raise HTTPException(
            status_code=400,
            detail="File aturan harus berekstensi .yar atau .yara",
        )

    with engine.begin() as connection:
        connection.execute(
            text("""
                UPDATE scans
                SET status = 'running',
                    started_at = CURRENT_TIMESTAMP,
                    completed_at = NULL
                WHERE id = :scan_id
            """),
            {"scan_id": scan_id},
        )

    try:
        result = scan_with_yara(str(target), str(rules_file))

        if result.get("error"):
            raise RuntimeError(result["error"])

        matches = result.get("matches", [])

        with engine.begin() as connection:
            for match in matches:
                metadata = match.get("meta", {})
                severity = str(
                    metadata.get("severity", "info")
                ).lower()

                if severity not in (
                    "critical", "high", "medium", "low", "info"
                ):
                    severity = "info"

                connection.execute(
                    text("""
                        INSERT INTO findings
                            (scan_id, title, description, severity,
                             file_path, status)
                        VALUES
                            (:scan_id, :title, :description, :severity,
                             :file_path, 'open')
                    """),
                    {
                        "scan_id": scan_id,
                        "title": f"YARA: {match['rule']}",
                        "description": json.dumps(
                            {
                                "namespace": match.get("namespace"),
                                "tags": match.get("tags", []),
                                "meta": metadata,
                                "strings": match.get("strings", []),
                            },
                            default=str,
                        ),
                        "severity": severity,
                        "file_path": match.get("path"),
                    },
                )

            connection.execute(
                text("""
                    UPDATE scans
                    SET status = 'completed',
                        completed_at = CURRENT_TIMESTAMP
                    WHERE id = :scan_id
                """),
                {"scan_id": scan_id},
            )

            connection.execute(
                text("""
                    INSERT INTO audit_logs
                        (user_id, organization_id, action, description)
                    VALUES
                        (:user_id, :organization_id,
                         'SCAN_EXECUTED', :description)
                """),
                {
                    "user_id": current_user["id"],
                    "organization_id": scan["organization_id"],
                    "description": (
                        f"Scan #{scan_id} selesai. "
                        f"{len(matches)} temuan YARA."
                    ),
                },
            )

        return {
            "message": "Pemindaian YARA berhasil diselesaikan",
            "scan_id": scan_id,
            "status": "completed",
            "scanned_files": result.get("scanned_files", 0),
            "total_findings": len(matches),
            "matches": matches,
            "scan_errors": result.get("errors", []),
        }

    except Exception as exc:
        with engine.begin() as connection:
            connection.execute(
                text("""
                    UPDATE scans
                    SET status = 'failed',
                        completed_at = CURRENT_TIMESTAMP
                    WHERE id = :scan_id
                """),
                {"scan_id": scan_id},
            )

        raise HTTPException(
            status_code=500,
            detail=f"Eksekusi scan gagal: {str(exc)}",
        )


@router.get("/{scan_id}/findings")
def list_scan_findings(
    scan_id: int,
    current_user: dict = Depends(get_scan_user),
):
    get_authorized_scan(scan_id, current_user["id"])

    with engine.connect() as connection:
        rows = connection.execute(
            text("""
                SELECT
    id,
    scan_id,
    title,
    description,
    severity,
    file_path,
    status,
    analyst_notes,
    created_at
FROM findings
WHERE scan_id = :scan_id
ORDER BY id DESC
            """),
            {"scan_id": scan_id},
        ).mappings().all()

    return [dict(row) for row in rows]

class FindingUpdate(BaseModel):
    status: Optional[str] = Field(default=None, max_length=50)
    severity: Optional[str] = None
    analyst_notes: Optional[str] = None


@router.patch("/{scan_id}/findings/{finding_id}")
def update_finding(
    scan_id: int,
    finding_id: int,
    data: FindingUpdate,
    current_user: dict = Depends(get_scan_user),
):
    # Pastikan pengguna memiliki akses ke scan.
    scan = get_authorized_scan(scan_id, current_user["id"])

    updates = data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="Tidak ada data yang diperbarui",
        )

    allowed_statuses = ("open", "reviewing", "resolved")
    allowed_severities = ("critical", "high", "medium", "low", "info")

    if "status" in updates:
        if updates["status"] not in allowed_statuses:
            raise HTTPException(
                status_code=422,
                detail="Status harus open, reviewing, atau resolved",
            )

    if "severity" in updates:
        if updates["severity"] not in allowed_severities:
            raise HTTPException(
                status_code=422,
                detail="Tingkat risiko tidak valid",
            )

    if "analyst_notes" in updates:
        if updates["analyst_notes"] is not None and len(updates["analyst_notes"]) > 10000:
            raise HTTPException(
                status_code=422,
                detail="Catatan analis maksimal 10.000 karakter",
            )

    with engine.begin() as connection:
        finding = connection.execute(
            text("""
                SELECT id
                FROM findings
                WHERE id = :finding_id
                AND scan_id = :scan_id
            """),
            {
                "finding_id": finding_id,
                "scan_id": scan_id,
            },
        ).first()

        if not finding:
            raise HTTPException(
                status_code=404,
                detail="Temuan tidak ditemukan pada scan ini",
            )

        # Nama kolom berasal dari daftar tetap, bukan input bebas pengguna.
        assignments = []
        params = {
            "finding_id": finding_id,
            "scan_id": scan_id,
        }

        for field in ("status", "severity", "analyst_notes"):
            if field in updates:
                assignments.append(f"{field} = :{field}")
                params[field] = updates[field]

        connection.execute(
            text(f"""
                UPDATE findings
                SET {", ".join(assignments)}
                WHERE id = :finding_id
                AND scan_id = :scan_id
            """),
            params,
        )

        updated = connection.execute(
            text("""
                SELECT
                    id,
                    scan_id,
                    title,
                    description,
                    severity,
                    file_path,
                    status,
                    analyst_notes,
                    created_at
                FROM findings
                WHERE id = :finding_id
            """),
            {"finding_id": finding_id},
        ).mappings().first()

        connection.execute(
            text("""
                INSERT INTO audit_logs
                    (user_id, organization_id, action, description)
                VALUES
                    (:user_id, :organization_id,
                     'FINDING_UPDATED', :description)
            """),
            {
                "user_id": current_user["id"],
                "organization_id": scan["organization_id"],
                "description": (
                    f"Temuan #{finding_id} pada scan #{scan_id} diperbarui"
                ),
            },
        )

    return {
        "message": "Temuan berhasil diperbarui",
        "finding": dict(updated),
    }