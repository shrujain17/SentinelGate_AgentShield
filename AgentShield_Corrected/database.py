"""
AgentShield - Database Configuration & Session Management

Provides SQLAlchemy engine initialization, session manufacturing, declarative base,
and the FastAPI `get_db` dependency for clean session lifecycle handling.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# Canonical absolute database path anchored to the project root
PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env", override=False)
DEFAULT_DB_FILE = PROJECT_ROOT / "agentshield.db"

# In test mode, isolate test database so live database is never dropped or polluted
if os.getenv("TESTING") == "1":
    test_db_file = PROJECT_ROOT / "test_agentshield.db"
    SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{test_db_file}")
else:
    SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_FILE}")

# connect_args={"check_same_thread": False} allows multiple worker threads to interact
# with the local SQLite file safely in FastAPI.
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)

# Session factory for generating scoped database sessions per request
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# Base class for all ORM models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a database session per HTTP request and
    guarantees that the session is closed cleanly when the request finishes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
