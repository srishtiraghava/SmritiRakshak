"""
SmritiRakshak — Rule-Based Memory Threat Detector
==================================================

Scans the textual *content* of a memory entry for two categories of
threat:

  1. **Prompt injection** — attempts to override agent instructions,
     reveal hidden system prompts, or exfiltrate stored secrets.
  2. **Sensitive data** — API keys, bearer tokens, password
     assignments, private-key markers and similar credential patterns.

Design principles
─────────────────
• Each detection category is implemented as its own function that
  returns a list of ``DetectorFinding`` objects.
• ``scan_content()`` is the single public entry-point that
  orchestrates all detectors and returns the combined findings.
• Patterns are context-aware *combinations* of tokens — a word like
  "password" or "ignore" alone does NOT trigger a finding.
• Detected secrets are **redacted** before being placed in the
  ``evidence`` field.  The full secret is never returned.
• All rules are intentionally readable and documented so that
  security reviewers can audit them.

Limitations
───────────
• Rule-based detection is inherently incomplete.  Sophisticated
  prompt injections that use novel phrasing, encoding tricks or
  multi-step strategies will bypass these rules.
• The detector can produce **false positives** (benign content that
  happens to match a pattern) and **false negatives** (real attacks
  that do not match any rule).
• These rules are a first layer of defence; they are designed to be
  supplemented with ML-based detection in a later milestone.
"""

from __future__ import annotations

import re
from typing import Callable

from app.schemas.memory import DetectorFinding, Severity


# ═══════════════════════════════════════════════════════════════════
# UTILITY HELPERS
# ═══════════════════════════════════════════════════════════════════

def _redact(text: str, keep_start: int = 4, keep_end: int = 0) -> str:
    """Return a redacted version of *text* that hides the middle.

    Only the first *keep_start* and last *keep_end* characters are
    kept; everything else is replaced with ``****``.

    If the text is short enough that keeping start + end would expose
    most of it, the whole thing is replaced.
    """
    if len(text) <= keep_start + keep_end + 4:
        return "****"
    prefix = text[:keep_start] if keep_start else ""
    suffix = text[-keep_end:] if keep_end else ""
    return f"{prefix}****{suffix}"


def _safe_snippet(content: str, match: re.Match, context: int = 30) -> str:
    """Extract a short window around *match* in *content*.

    The snippet is meant to show where in the text the pattern
    appeared, without exposing a full secret.  It is truncated with
    ellipses on either side if necessary.
    """
    start = max(0, match.start() - context)
    end = min(len(content), match.end() + context)
    snippet = content[start:end]
    if start > 0:
        snippet = "…" + snippet
    if end < len(content):
        snippet = snippet + "…"
    return snippet


# ═══════════════════════════════════════════════════════════════════
# 1.  PROMPT INJECTION DETECTORS
# ═══════════════════════════════════════════════════════════════════

# Each pattern is a tuple of:
#   (compiled_regex, detector_name, severity, description, risk_points)
#
# Patterns are written to require *combined* context so that isolated
# words like "ignore" or "system" do not fire on their own.

_PROMPT_INJECTION_RULES: list[
    tuple[re.Pattern, str, Severity, str, int]
] = [
    # ── Override / ignore previous instructions ─────────────────
    (
        re.compile(
            r"(?:ignore|disregard|forget|override|bypass|skip)"
            r"\s+(?:all\s+|any\s+|the\s+|your\s+)?"
            r"(?:previous|prior|above|earlier|existing|original|old|preceding)"
            r"\s+(?:instructions?|directives?|rules?|prompts?|guidelines?|constraints?)",
            re.IGNORECASE,
        ),
        "prompt_injection_override",
        Severity.CRITICAL,
        "Attempt to override or ignore the agent's prior instructions.",
        40,
    ),
    # ── "You are now …" role hijack ─────────────────────────────
    (
        re.compile(
            r"you\s+are\s+now\s+(?:a\s+|an\s+|my\s+)?"
            r"(?:new|different|unrestricted|unfiltered|evil|jailbroken)",
            re.IGNORECASE,
        ),
        "prompt_injection_role_hijack",
        Severity.CRITICAL,
        "Attempt to reassign the agent's role or persona to bypass restrictions.",
        40,
    ),
    # ── Reveal system / hidden prompt ───────────────────────────
    (
        re.compile(
            r"(?:reveal|show|display|print|output|repeat|tell\s+me|give\s+me|leak|expose|disclose)"
            r"\s+(?:me\s+)?(?:the\s+|your\s+|all\s+|any\s+|full\s+)?"
            r"(?:system\s+(?:prompts?|messages?|instructions?)"
            r"|hidden\s+(?:prompts?|instructions?|context)"
            r"|internal\s+(?:prompts?|instructions?|rules?|configuration)"
            r"|confidential\s+(?:prompts?|instructions?|rules?|directives?)"
            r"|secret\s+(?:prompts?|instructions?|rules?))",
            re.IGNORECASE,
        ),
        "prompt_injection_reveal_prompt",
        Severity.HIGH,
        "Attempt to extract or reveal the agent's system prompt or internal instructions.",
        35,
    ),
    # ── Exfiltrate secrets / credentials via agent ──────────────
    (
        re.compile(
            r"(?:send|transmit|forward|exfiltrate|post|upload|email|output|write|log|leak|extract)"
            r"\s+"
            r"(?:(?:all|any|the|stored|saved|known|user'?s?)\s+)*"
            r"(?:api[\s_-]?keys?|credentials?|secrets?|tokens?|passwords?|private[\s_-]?keys?"
            r"|auth(?:entication)?[\s_-]?(?:tokens?|keys?|credentials?))",
            re.IGNORECASE,
        ),
        "prompt_injection_exfiltrate",
        Severity.CRITICAL,
        "Attempt to instruct the agent to exfiltrate stored credentials or secrets.",
        45,
    ),
    # ── Disable / change security behaviour ─────────────────────
    (
        re.compile(
            r"(?:disable|turn\s+off|deactivate|remove|stop|shut\s+off|eliminate)"
            r"\s+(?:all\s+|any\s+|the\s+|your\s+)?"
            r"(?:security|safety|guard|filter|content[\s_-]?filter|moderation"
            r"|restriction|safeguard|protection|scanning|checking|validation|firewall)",
            re.IGNORECASE,
        ),
        "prompt_injection_disable_security",
        Severity.HIGH,
        "Attempt to instruct the agent to disable its security controls.",
        35,
    ),
    # ── "Do not remember / log / store this" evasion ────────────
    (
        re.compile(
            r"(?:do\s+not|don'?t|never|stop)"
            r"\s+(?:log|store|record|remember|track|audit|save|persist)"
            r"\s+(?:this|my|the|any|these|those|future)"
            r".*?(?:conversation|interaction|message|request|query|action|command|instruction)",
            re.IGNORECASE,
        ),
        "prompt_injection_anti_logging",
        Severity.MEDIUM,
        "Attempt to prevent the agent from logging or auditing activity.",
        20,
    ),
]


def detect_prompt_injection(content: str) -> list[DetectorFinding]:
    """Scan *content* for prompt-injection patterns.

    Returns a list of findings.  Each finding carries safely-redacted
    evidence — the matched text is shown in context but the raw
    instruction is never hidden since it is the threat itself (as
    opposed to a secret).
    """
    findings: list[DetectorFinding] = []

    for pattern, name, severity, description, risk_points in _PROMPT_INJECTION_RULES:
        match = pattern.search(content)
        if match:
            findings.append(
                DetectorFinding(
                    detector_name=name,
                    category="prompt_injection",
                    severity=severity,
                    description=description,
                    evidence=_safe_snippet(content, match),
                    risk_points=risk_points,
                )
            )

    return findings


# ═══════════════════════════════════════════════════════════════════
# 2.  SENSITIVE DATA DETECTORS
# ═══════════════════════════════════════════════════════════════════

# Each rule is a tuple of:
#   (compiled_regex, group_index_to_redact, detector_name, severity,
#    description, risk_points)
#
# ``group_index_to_redact`` is the regex group number whose matched
# text should be redacted in the ``evidence`` field.  If ``None`` the
# whole match is redacted.

_SENSITIVE_DATA_RULES: list[
    tuple[re.Pattern, int | None, str, Severity, str, int]
] = [
    # ── Generic API-key patterns (e.g. sk-abc123…, AKIA…) ──────
    (
        re.compile(
            r"(?:^|[^a-zA-Z0-9])"                          # boundary
            r"((?:sk|pk|rk|ak)[-_][a-zA-Z0-9]{20,})"       # key itself
            r"(?:[^a-zA-Z0-9]|$)",
        ),
        1,
        "sensitive_data_api_key",
        Severity.HIGH,
        "Detected a string resembling an API key (sk-/pk-/rk-/ak- prefix with 20+ alphanumerics).",
        30,
    ),
    # ── AWS-style access key (AKIA…) ────────────────────────────
    (
        re.compile(
            r"(?:^|[^a-zA-Z0-9])"
            r"(AKIA[0-9A-Z]{16,})"
            r"(?:[^a-zA-Z0-9]|$)",
        ),
        1,
        "sensitive_data_aws_key",
        Severity.HIGH,
        "Detected a string resembling an AWS access key ID.",
        30,
    ),
    # ── Bearer token in text ────────────────────────────────────
    (
        re.compile(
            r"[Bb]earer\s+([A-Za-z0-9\-._~+/]+=*){20,}",
        ),
        1,
        "sensitive_data_bearer_token",
        Severity.HIGH,
        "Detected a Bearer token pattern.",
        30,
    ),
    # ── Password / secret assignments (key=value style) ─────────
    (
        re.compile(
            r"(?:password|passwd|pwd|secret|api_key|apikey|api[-_]?secret|access[-_]?token)"
            r"\s*[:=]\s*"
            r"['\"]?"
            r"([^\s'\"]{8,})"           # the value — at least 8 chars
            r"['\"]?",
            re.IGNORECASE,
        ),
        1,
        "sensitive_data_password_assignment",
        Severity.HIGH,
        "Detected a password or secret assignment (key = value pattern).",
        30,
    ),
    # ── Private key markers (PEM) ───────────────────────────────
    (
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+|PGP\s+)?PRIVATE\s+KEY-----",
            re.IGNORECASE,
        ),
        None,
        "sensitive_data_private_key",
        Severity.CRITICAL,
        "Detected a PEM-encoded private key header.",
        40,
    ),
    # ── GitHub / GitLab personal access tokens ──────────────────
    (
        re.compile(
            r"(?:^|[^a-zA-Z0-9])"
            r"((?:ghp|gho|ghu|ghs|ghr|glpat)[-_][a-zA-Z0-9]{30,})"
            r"(?:[^a-zA-Z0-9]|$)",
        ),
        1,
        "sensitive_data_scm_token",
        Severity.HIGH,
        "Detected a GitHub or GitLab personal access token.",
        30,
    ),
]


def detect_sensitive_data(content: str) -> list[DetectorFinding]:
    """Scan *content* for credential-like patterns.

    The ``evidence`` field in each finding contains the redacted value
    so that actual secrets are never exposed in logs or API responses.
    """
    findings: list[DetectorFinding] = []

    for pattern, group_idx, name, severity, description, risk_points in _SENSITIVE_DATA_RULES:
        match = pattern.search(content)
        if match:
            # Decide which part of the match to redact
            if group_idx is not None:
                secret_text = match.group(group_idx)
            else:
                secret_text = match.group(0)

            redacted = _redact(secret_text)

            findings.append(
                DetectorFinding(
                    detector_name=name,
                    category="sensitive_data",
                    severity=severity,
                    description=description,
                    evidence=f"Detected pattern: {redacted}",
                    risk_points=risk_points,
                )
            )

    return findings


# ═══════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

# Registry of all individual detector functions.
# Extend this list to plug in new categories.
_DETECTOR_FUNCTIONS: list[Callable[[str], list[DetectorFinding]]] = [
    detect_prompt_injection,
    detect_sensitive_data,
]


def scan_content(content: str) -> list[DetectorFinding]:
    """Run **all** registered detectors against *content*.

    Returns the combined, deduplicated list of ``DetectorFinding``
    objects.  If a detector raises an unexpected exception the error
    is caught and converted into a CRITICAL finding so that the
    pipeline **fails closed** — a broken detector must not silently
    let content through.
    """
    findings: list[DetectorFinding] = []

    for detector_fn in _DETECTOR_FUNCTIONS:
        try:
            findings.extend(detector_fn(content))
        except Exception as exc:
            # Fail closed: report the detector error as a critical finding.
            findings.append(
                DetectorFinding(
                    detector_name=f"error_in_{detector_fn.__name__}",
                    category="detector_error",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Detector '{detector_fn.__name__}' raised an "
                        f"unexpected error: {type(exc).__name__}. "
                        "Content was NOT cleared."
                    ),
                    evidence="(error during detection — content not inspected)",
                    risk_points=100,
                )
            )

    return findings
