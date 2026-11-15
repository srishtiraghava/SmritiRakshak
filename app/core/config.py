"""
SmritiRakshak — Centralized Application Configuration

All tuneable values live here so that no other module needs to
hard-code limits, thresholds or application metadata.

Values are read from environment variables (or a .env file) at
import time.  Sensible defaults are provided for every setting so
the application can start without a .env file during development.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# ── Load .env if present (project root = two levels up from this file) ──
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(_PROJECT_ROOT / ".env")


# ---------------------------------------------------------------------------
# Helper to read env vars with type conversion
# ---------------------------------------------------------------------------

def _env_int(name: str, default: int) -> int:
    """Return an environment variable as an int, or *default*."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_str(name: str, default: str) -> str:
    """Return an environment variable as a string, or *default*."""
    return os.getenv(name, default)


# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------

APP_NAME: str = _env_str("APP_NAME", "SmritiRakshak")
APP_VERSION: str = _env_str("APP_VERSION", "0.1.0")
APP_DESCRIPTION: str = (
    "AI Agent Memory Security Firewall — protects agent memory "
    "systems against persistent memory poisoning and malicious "
    "memory manipulation (OWASP ASI-06)."
)

# ---------------------------------------------------------------------------
# Memory content limits
# ---------------------------------------------------------------------------

# Maximum number of characters accepted in a single memory entry.
# Anything longer is rejected at the validation layer.
MAX_CONTENT_LENGTH: int = _env_int("MAX_CONTENT_LENGTH", 10_000)

# Minimum meaningful content length (avoids vacuous entries).
MIN_CONTENT_LENGTH: int = 1

# ---------------------------------------------------------------------------
# Risk-score thresholds  (inclusive lower bounds for each band)
#
#   0  .. THRESHOLD_FLAG - 1       → ALLOW
#   THRESHOLD_FLAG .. THRESHOLD_QUARANTINE - 1  → FLAG
#   THRESHOLD_QUARANTINE .. THRESHOLD_BLOCK - 1 → QUARANTINE
#   THRESHOLD_BLOCK .. 100         → BLOCK
# ---------------------------------------------------------------------------

THRESHOLD_FLAG: int = _env_int("THRESHOLD_FLAG", 30)
THRESHOLD_QUARANTINE: int = _env_int("THRESHOLD_QUARANTINE", 50)
THRESHOLD_BLOCK: int = _env_int("THRESHOLD_BLOCK", 80)

# Absolute bounds for the computed risk score.
RISK_SCORE_MIN: int = 0
RISK_SCORE_MAX: int = 100

# ---------------------------------------------------------------------------
# Severity levels used by detectors (ordered low → high)
# ---------------------------------------------------------------------------

SEVERITY_LOW: str = "low"
SEVERITY_MEDIUM: str = "medium"
SEVERITY_HIGH: str = "high"
SEVERITY_CRITICAL: str = "critical"

# A finding at this severity forces an immediate BLOCK regardless of
# the numerical risk score.
CRITICAL_SEVERITY: str = SEVERITY_CRITICAL
