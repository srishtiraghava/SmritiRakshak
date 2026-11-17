"""
SmritiRakshak — Database Session & Engine Lifecycle
===================================================

Configures the SQLAlchemy 2.0 engine using the psycopg 3 driver,
connection pooling, and session lifecycle managers.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import DATABASE_URL


def build_engine(url: str, **kwargs: Any) -> Engine:
    """Build a configured SQLAlchemy 2.0 engine."""
    engine_kwargs = {
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
    }
    engine_kwargs.update(kwargs)
    return create_engine(url, **engine_kwargs)


# Primary application engine
engine: Engine = build_engine(DATABASE_URL)

# Thread-safe session factory
SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


@contextmanager
def get_session_context(custom_engine: Engine | None = None) -> Generator[Session, None, None]:
    """Provide a transactional database session context manager.

    Automatically commits on normal completion, rolls back on exception,
    and guarantees the connection is returned to the pool.
    """
    factory = (
        sessionmaker(bind=custom_engine, autocommit=False, autoflush=False, expire_on_commit=False)
        if custom_engine is not None
        else SessionLocal
    )
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a transactional session per request."""
    with get_session_context() as session:
        yield session
