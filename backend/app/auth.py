import os

from datetime import datetime, timedelta, timezone

from jose import jwt, JWTError
from passlib.context import CryptContext

from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel, Field

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from .database import engine


router = APIRouter(prefix="/auth", tags=["Authentication"])


pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)

security = HTTPBearer()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

TOKEN_EXPIRE = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
)

if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY belum diatur di .env")


class RegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    email: str = Field(min_length=5, max_length=150)
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str
    password: str


def create_token(user_id: int):
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRE
    )

    payload = {
        "sub": str(user_id),
        "exp": expire
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )


@router.post("/register")
def register(data: RegisterRequest):

    name = data.name.strip()
    email = data.email.strip().lower()

    if len(name) < 2:
        raise HTTPException(
            status_code=400,
            detail="Nama minimal 2 karakter"
        )

    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(
            status_code=400,
            detail="Format email tidak valid"
        )

    hashed_password = pwd_context.hash(data.password)

    try:
        # Semua proses harus berhasil dalam satu transaksi.
        with engine.begin() as connection:

            # 1. Membuat akun pengguna.
            user_result = connection.execute(
                text("""
                    INSERT INTO users (name, email, password)
                    VALUES (:name, :email, :password)
                """),
                {
                    "name": name,
                    "email": email,
                    "password": hashed_password
                }
            )

            user_id = user_result.lastrowid

            # 2. Membuat workspace organisasi.
            organization_name = f"{name} Workspace"

            organization_result = connection.execute(
                text("""
                    INSERT INTO organizations
                        (name, description)
                    VALUES
                        (:name, :description)
                """),
                {
                    "name": organization_name,
                    "description": (
                        f"Workspace SentinelTriage milik {name}"
                    )
                }
            )

            organization_id = organization_result.lastrowid

            # 3. Mendaftarkan pengguna sebagai admin.
            connection.execute(
                text("""
                    INSERT INTO organization_members
                        (organization_id, user_id, role)
                    VALUES
                        (:organization_id, :user_id, :role)
                """),
                {
                    "organization_id": organization_id,
                    "user_id": user_id,
                    "role": "admin"
                }
            )

    except IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Email sudah terdaftar atau data registrasi tidak valid"
        )

    return {
        "message": "Registrasi dan pembuatan workspace berhasil",
        "user": {
            "id": user_id,
            "name": name,
            "email": email
        },
        "organization": {
            "id": organization_id,
            "name": organization_name,
            "role": "admin"
        }
    }


@router.post("/login")
def login(data: LoginRequest):

    email = data.email.strip().lower()

    with engine.connect() as connection:
        user = connection.execute(
            text("""
                SELECT id, name, email, password
                FROM users
                WHERE email = :email
            """),
            {"email": email}
        ).mappings().first()

    if not user or not pwd_context.verify(
        data.password,
        user["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Email atau password salah"
        )

    token = create_token(user["id"])

    return {
        "message": "Login berhasil",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"]
        }
    }


@router.get("/me")
def get_profile(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = int(payload["sub"])

    except (JWTError, ValueError, KeyError):
        raise HTTPException(
            status_code=401,
            detail="Token tidak valid atau sudah kedaluwarsa"
        )

    with engine.connect() as connection:
        user = connection.execute(
            text("""
                SELECT id, name, email, created_at
                FROM users
                WHERE id = :id
            """),
            {"id": user_id}
        ).mappings().first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Pengguna tidak ditemukan"
        )

    return dict(user)
