# SmritiRakshak — Architecture & Technical Design

This document details the architecture, design principles, module responsibilities, and data flow of **SmritiRakshak** (Milestone 1).

---

## 1. High-Level Processing Flow

SmritiRakshak acts as a security middleware firewall between external inputs (conversations, documents, tool outputs) and an AI agent's long-term memory store.

```
       Incoming Memory Entry
                 │
                 ▼
       ┌───────────────────┐
       │ 1. Input          │  Pydantic v2 validation (types, bounds,
       │    Validation     │  non-blank content, max 10,000 chars)
       └─────────┬─────────┘
                 │ (Validated payload)
                 ▼
       ┌───────────────────┐
       │ 2. Threat         │  Modular rules: prompt injection overrides,
       │    Detection      │  credential patterns, safe evidence redaction
       └─────────┬─────────┘
                 │ (List of DetectorFindings)
                 ▼
       ┌───────────────────┐
       │ 3. Risk           │  Deduplication, weight calculation,
       │    Scoring        │  bounds clamping (0–100), audit explanation
       └─────────┬─────────┘
                 │ (RiskAssessment)
                 ▼
       ┌───────────────────┐
       │ 4. Policy         │  Configurable threshold bands +
       │    Enforcement    │  Critical finding override
       └─────────┬─────────┘
                 │ (PolicyDecision)
                 ▼
 ┌───────────────┬─────────────────┬───────────────────┐
 │               │                 │                   │
 ▼ (0–29)        ▼ (30–49)         ▼ (50–79)           ▼ (80–100 or Critical)
ALLOW           FLAG              QUARANTINE          BLOCK
  │               │                 │                   │
  ▼               ▼                 ▼                   ▼
Trusted         Pending-Review    Isolated            Rejected /
Memory          Repository        Quarantine          Audit Log
Repository      (Not trusted)     (Not trusted)       (Never trusted)
```

---

## 2. Component & Module Responsibilities

| Module | Location | Core Responsibility |
|---|---|---|
| **Config** | `app/core/config.py` | Centralizes all environment variables, memory size limits (`MAX_CONTENT_LENGTH=10000`), score thresholds (`THRESHOLD_FLAG=30`, `THRESHOLD_QUARANTINE=50`, `THRESHOLD_BLOCK=80`), and severity constants. No magic numbers exist in domain code. |
| **Schemas** | `app/schemas/memory.py` | Defines immutable Pydantic v2 models: `MemoryInput`, `DetectorFinding`, `RiskAssessment`, `PolicyDecision`, and `MemoryProcessingResponse`. Enforces whitespace rejection and type constraints. |
| **Detector** | `app/security/detector.py` | Scans text using context-aware regex patterns. Identifies prompt injections (instruction overrides, role hijacks, prompt leak attempts, exfiltration instructions, safety deactivations) and sensitive credentials (API keys, AWS keys, Bearer tokens, passwords, private keys, PATs). Redacts all secrets in findings evidence. |
| **Risk Scorer** | `app/security/risk_scorer.py` | Deduplicates findings by signature `(detector_name, category, evidence)`. Computes raw points, applies configurable weights, clamps the score strictly between `0` and `100`, maps score to a `RiskLevel`, and produces an audit breakdown string. |
| **Policy Engine** | `app/security/policy_engine.py` | Applies decision thresholds (`ALLOW`, `FLAG`, `QUARANTINE`, `BLOCK`). Enforces the **Critical Severity Override**: any finding with `Severity.CRITICAL` forces `BLOCK` regardless of numeric score. Validates numeric score safety. |
| **Memory Service** | `app/services/memory_service.py` | Coordinates the full 5-step pipeline. Maintains separate in-memory repositories for each decision tier. Ensures `FLAG` and `QUARANTINE` records are never returned by trusted queries (`get_trusted_memories`). Framework-independent (pure Python). |
| **API Routes** | `app/api/routes/memory.py` | Exposes `POST /api/memories` and `GET /api/health`. Sets HTTP status codes (`201 Created` for `ALLOW`, `200 OK` for evaluated decisions, `422` on validation errors). Masks internal stack traces. |
| **Main App** | `app/main.py` | Instantiates FastAPI, registers OpenAPI metadata, configures `/docs` Swagger UI, and attaches a centralized exception safety handler. |

---

## 3. Policy Decision Thresholds

All thresholds are configurable in `app/core/config.py` (and via `.env`):

| Score Range | Decision | Meaning & Handling | Storage Destination |
|:---:|:---:|---|---|
| **0 – 29** | **ALLOW** | Safe memory entry. No significant risk detected. Assigned a memory ID. | `_trusted_repo` (Accessible to agent) |
| **30 – 49** | **FLAG** | Borderline or low-confidence risk detected (e.g. solitary token or minor warning). Marked with `flagged: true`. | `_pending_review_repo` (Not accessible to agent) |
| **50 – 79** | **QUARANTINE** | High-risk content (e.g. multiple credentials or suspicious directives). Isolated for safety. | `_quarantine_repo` (Not accessible to agent) |
| **80 – 100** | **BLOCK** | Critical security violation (or any finding with `Severity.CRITICAL`). Completely rejected. | `_blocked_repo` (Audit only; never trusted) |

### Critical Finding Override
If any detector finding carries `Severity.CRITICAL` (such as explicit instruction overrides, private key headers, or credential exfiltration commands), the policy engine immediately returns **BLOCK**, even if the calculated numerical score would otherwise fall into a lower tier.

---

## 4. Fail-Closed Security Architecture

SmritiRakshak adheres strictly to the **Fail-Closed** security principle: under no circumstances does a software fault, unhandled error, or malformed input result in untrusted content being written to trusted memory.

```
┌─────────────────────────────────┐
│ Runtime Event                   │
├─────────────────────────────────┤
│ Input Schema Validation Error   │ ──► Immediately rejected with HTTP 422. No processing.
├─────────────────────────────────┤
│ Detection Rule Exception        │ ──► Converted into a CRITICAL finding (100 risk points).
├─────────────────────────────────┤
│ Risk Scorer / Pipeline Error    │ ──► MemoryService catches exception, returns BLOCK verdict
│                                 │     (risk_score=100, risk_level=CRITICAL), writes 0 entries.
├─────────────────────────────────┤
│ Unhandled Route / HTTP Error    │ ──► FastAPI exception handler returns HTTP 500 with a generic
│                                 │     error message. No stack traces or secrets are exposed.
└─────────────────────────────────┘
```

---

## 5. Memory Segregation & Storage Model (Milestone 1)

In Milestone 1, persistence is handled using **segregated in-memory repositories** inside `MemoryService`:
- `_trusted_repo: dict[str, StoredMemory]`
- `_pending_review_repo: dict[str, StoredMemory]`
- `_quarantine_repo: dict[str, StoredMemory]`
- `_blocked_repo: dict[str, StoredMemory]`

### Segregation Guarantee
The retrieval helper `get_trusted_memories(user_id)` strictly queries `_trusted_repo`. Flagged, quarantined, and blocked memories reside in isolated dictionaries and cannot be returned by trusted context queries.

> **Note on Persistence**: Storage in Milestone 1 is in-memory and transient for prototyping. Database persistence (e.g., PostgreSQL, SQLite, or vector memory stores) is slated for future milestones.
