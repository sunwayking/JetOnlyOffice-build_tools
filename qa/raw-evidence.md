# Immutable QA evidence

Raw evidence is append-only and lives under `evidence/raw/<run-id>/<gate-id>/`. Each gate result records the path, byte size, mode, media type and SHA-256 of every raw input. Processed gate results and the final `release-evidence.json` bind those inputs by canonical JSON digest.

- A run ID identifies one first attempt. A retry always creates a new run ID.
- Blocking failures, including `INFRA_INCOMPLETE`, cannot be quarantined or replaced by a later pass.
- Raw screenshots, traces, logs and device facts are never edited after hashing.
- Evidence paths are normalized repository-relative paths; `latest`, traversal segments and mutable aliases are forbidden.
- Evidence excludes document contents and direct user identifiers. Test corpora use dedicated non-user data.
- Wall-clock timestamps may be captured in raw logs. Contract results use integer Unix seconds and integer metrics so canonicalization is deterministic.
