# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Developers building AI agents that use long-term memory. They need to inspect candidate memories before storing them and understand the resulting security decisions.

## Product Purpose

SmritiRakshak ("Memory Protector") is a security layer for AI agent memory. It inspects candidate memories before storage to reduce persistent memory poisoning and unsafe retention of sensitive data. Success means risky memories are detected and handled according to policy before they enter trusted memory.

## Positioning

SmritiRakshak combines pre-storage inspection, rule-based threat detection, risk scoring, policy decisions, and physically segregated memory tiers. Its central promise is to intercept and classify candidate memories before storage.

## Operating Context

Developers integrate the FastAPI service into an AI agent's memory path. The web dashboard supports reviewing system status and telemetry, exploring memories, inspecting detected threats, reviewing quarantined memories, examining the audit trail, and simulating candidate memory text.

## Capabilities and Constraints

- Validates candidate memory input, scans for prompt-injection patterns and sensitive credential patterns, computes a weighted risk score, and applies `ALLOW`, `FLAG`, `QUARANTINE`, or `BLOCK` decisions.
- Separates trusted, pending-review, quarantined, and security-audit records.
- Detection is rule-based; there is no LLM-based secondary judge.
- The README describes transient in-memory storage, but the current backend code uses PostgreSQL-backed segregated tables for persisted memories and dashboard telemetry. Treat the README storage statement as stale pending correction.
- The README identifies missing authentication, API-key rate limiting, encryption at rest, and multi-tenant database persistence as current prototype limitations.
- Rule-based detection can miss novel or obfuscated attacks and can produce false positives.
- The project is an early-stage prototype and is not production-ready.

## Evidence on Hand

- Product behavior and threat model: `README.md`.
- API implementation: `app/api/routes/memory.py` and `app/services/memory_service.py`.
- PostgreSQL storage implementation: `app/db/models.py` and `app/db/repository.py`.
- Dashboard workflows: `frontend/src/App.tsx` and `frontend/src/pages/`.
- Do not invent customer claims, certifications, benchmarks, or testimonials. The README explicitly states that the project is independent and is not certified or endorsed by OWASP.

## Product Principles

- Inspect untrusted candidate memories before they enter trusted memory.
- Make security decisions explainable through risk scores, findings, and policy reasons.
- Keep trusted, pending, quarantined, and audit data segregated.
- Treat current detection limits and prototype status honestly.
