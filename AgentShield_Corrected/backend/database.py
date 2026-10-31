"""
Backend Database Re-export (Authoritative source: database.py)
"""
from database import engine, SessionLocal, Base, get_db, SQLALCHEMY_DATABASE_URL

__all__ = ["engine", "SessionLocal", "Base", "get_db", "SQLALCHEMY_DATABASE_URL"]
