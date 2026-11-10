
import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker

BASE_DIR = Path(__file__).resolve().parent.parent

ENV_FILE = os.getenv(
    "SENTINELTRIAGE_ENV_FILE",
    str(BASE_DIR / ".env")
)
load_dotenv(ENV_FILE)

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "sentineltriage_db")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

DB_SSL = os.getenv("DB_SSL", "false").lower() in {
    "1", "true", "yes", "on"
}

DATABASE_URL = URL.create(
    "mysql+pymysql",
    username=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT,
    database=DB_NAME,
    query={"charset": "utf8mb4"},
)

connect_args = {}

if DB_SSL:
    import certifi

    connect_args = {
        "ssl_ca": certifi.where(),
        "ssl_verify_cert": True,
        "ssl_verify_identity": True,
    }

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    echo=False,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_database_connection():
    from sqlalchemy import text

    with engine.connect() as connection:
        result = connection.execute(text("SELECT DATABASE()"))
        return result.scalar()
