from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Request,
)
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from jose import jwt, JWTError
from sqlalchemy import text, bindparam

from .database import engine
from .auth import (
    router as auth_router,
    SECRET_KEY,
    ALGORITHM,
    security,
)
from .scans import router as scans_router

app = FastAPI(
    title="SentinelTriage API",
    description="Digital Forensics dan Malware Triage Platform",
    version="1.1.0",
)

app.include_router(auth_router)
app.include_router(scans_router)

# ==============================
# AUTHENTICATION
# ==============================

def get_current_user(
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


def get_user_organizations(user_id: int):
    with engine.connect() as connection:
        rows = connection.execute(
            text("""
                SELECT organization_id, role
                FROM organization_members
                WHERE user_id = :user_id
            """),
            {"user_id": user_id},
        ).mappings().all()

    return [dict(row) for row in rows]


def check_membership(user_id: int, organization_id: int):
    with engine.connect() as connection:
        membership = connection.execute(
            text("""
                SELECT id, role
                FROM organization_members
                WHERE user_id = :user_id
                AND organization_id = :organization_id
            """),
            {
                "user_id": user_id,
                "organization_id": organization_id,
            },
        ).mappings().first()

    if not membership:
        raise HTTPException(
            status_code=403,
            detail="Kamu tidak memiliki akses ke organisasi ini",
        )

    return dict(membership)


# ==============================
# REQUEST SCHEMAS
# ==============================

class CaseCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: Optional[str] = Field(default=None, max_length=5000)
    organization_id: Optional[int] = None


class CaseUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=30)


# ==============================
# GENERAL ENDPOINTS
# ==============================

@app.get("/")
def home():
    return {
        "application": "SentinelTriage",
        "status": "running",
        "version": "1.1.0",
    }


@app.get("/health")
def health():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return {"status": "healthy"}

    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Service temporarily unavailable",
        )


# ==============================
# CASE MANAGEMENT
# ==============================

@app.get("/cases")
def list_cases(
    organization_id: Optional[int] = None,
    current_user: dict = Depends(get_current_user),
):
    memberships = get_user_organizations(current_user["id"])

    organization_ids = [
        item["organization_id"] for item in memberships
    ]

    if not organization_ids:
        return {
            "total": 0,
            "cases": [],
            "message": "Pengguna belum tergabung dalam organisasi",
        }

    if organization_id is not None:
        if organization_id not in organization_ids:
            raise HTTPException(
                status_code=403,
                detail="Akses organisasi ditolak",
            )
        organization_ids = [organization_id]

    statement = text("""
        SELECT
            id,
            organization_id,
            created_by,
            case_number,
            title,
            description,
            status,
            created_at
        FROM cases
        WHERE organization_id IN :organization_ids
        ORDER BY created_at DESC, id DESC
    """).bindparams(
        bindparam("organization_ids", expanding=True)
    )

    with engine.connect() as connection:
        rows = connection.execute(
            statement,
            {"organization_ids": organization_ids},
        ).mappings().all()

    return {
        "total": len(rows),
        "cases": [dict(row) for row in rows],
    }


@app.post("/cases", status_code=201)
def create_case(
    data: CaseCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    memberships = get_user_organizations(current_user["id"])

    if not memberships:
        raise HTTPException(
            status_code=403,
            detail="Kamu belum tergabung dalam organisasi",
        )

    if data.organization_id is None:
        if len(memberships) > 1:
            raise HTTPException(
                status_code=400,
                detail="organization_id wajib diisi karena kamu memiliki beberapa organisasi",
            )
        organization_id = memberships[0]["organization_id"]
    else:
        organization_id = data.organization_id
        check_membership(current_user["id"], organization_id)

    case_number = (
        f"ST-{datetime.now().strftime('%Y%m%d')}-"
        f"{uuid4().hex[:8].upper()}"
    )

    try:
        with engine.begin() as connection:
            result = connection.execute(
                text("""
                    INSERT INTO cases (
                        organization_id,
                        created_by,
                        case_number,
                        title,
                        description,
                        status,
                        created_at
                    )
                    VALUES (
                        :organization_id,
                        :created_by,
                        :case_number,
                        :title,
                        :description,
                        'Open',
                        NOW()
                    )
                """),
                {
                    "organization_id": organization_id,
                    "created_by": current_user["id"],
                    "case_number": case_number,
                    "title": data.title.strip(),
                    "description": (
                        data.description.strip()
                        if data.description else None
                    ),
                },
            )

            case_id = result.lastrowid

            connection.execute(
                text("""
                    INSERT INTO audit_logs (
                        user_id,
                        organization_id,
                        action,
                        description,
                        ip_address,
                        created_at
                    )
                    VALUES (
                        :user_id,
                        :organization_id,
                        :action,
                        :description,
                        :ip_address,
                        NOW()
                    )
                """),
                {
                    "user_id": current_user["id"],
                    "organization_id": organization_id,
                    "action": "CASE_CREATED",
                    "description": f"Kasus {case_number} dibuat",
                    "ip_address": (
                        request.client.host if request.client else None
                    ),
                },
            )

        return {
            "message": "Kasus berhasil dibuat",
            "case": {
                "id": case_id,
                "case_number": case_number,
                "title": data.title.strip(),
                "description": data.description,
                "status": "Open",
                "organization_id": organization_id,
                "created_by": current_user["id"],
            },
        }

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Gagal membuat kasus. Periksa struktur database dan audit_logs.",
        )


@app.get("/cases/{case_id}")
def get_case(
    case_id: int,
    current_user: dict = Depends(get_current_user),
):
    with engine.connect() as connection:
        case = connection.execute(
            text("""
                SELECT c.*
                FROM cases c
                JOIN organization_members om
                    ON om.organization_id = c.organization_id
                WHERE c.id = :case_id
                  AND om.user_id = :user_id
            """),
            {
                "case_id": case_id,
                "user_id": current_user["id"],
            },
        ).mappings().first()

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Kasus tidak ditemukan",
        )

    return {"case": dict(case)}


@app.patch("/cases/{case_id}")
def update_case(
    case_id: int,
    data: CaseUpdate,
    current_user: dict = Depends(get_current_user),
):
    allowed_statuses = {
        "Open",
        "In Progress",
        "Closed",
    }

    if data.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Status harus Open, In Progress, atau Closed",
        )

    with engine.begin() as connection:
        case = connection.execute(
            text("""
                SELECT c.id, c.organization_id, c.case_number
                FROM cases c
                JOIN organization_members om
                    ON om.organization_id = c.organization_id
                WHERE c.id = :case_id
                  AND om.user_id = :user_id
            """),
            {
                "case_id": case_id,
                "user_id": current_user["id"],
            },
        ).mappings().first()

        if not case:
            raise HTTPException(
                status_code=404,
                detail="Kasus tidak ditemukan",
            )

        connection.execute(
            text("""
                UPDATE cases
                SET status = :status
                WHERE id = :case_id
            """),
            {
                "status": data.status,
                "case_id": case_id,
            },
        )

        connection.execute(
            text("""
                INSERT INTO audit_logs (
                    user_id,
                    organization_id,
                    action,
                    description,
                    created_at
                )
                VALUES (
                    :user_id,
                    :organization_id,
                    'CASE_UPDATED',
                    :description,
                    NOW()
                )
            """),
            {
                "user_id": current_user["id"],
                "organization_id": case["organization_id"],
                "description": (
                    f"Status kasus {case['case_number']} "
                    f"diubah menjadi {data.status}"
                ),
            },
        )

    return {
        "message": "Status kasus berhasil diperbarui",
        "case_id": case_id,
        "status": data.status,
    }
