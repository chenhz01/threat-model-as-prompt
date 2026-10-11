# Changelog

All notable changes to this project are documented here.

## v0.1.1 — 2026-10-11 (round 2: self-review iteration)

### Improved (Pareto round 2, ≥20% on completeness dimension)
- Self-test suite 15 → 18 cases (+20%): added `edge/non-dict-root`, `edge/unicode-project-names` (unicode roundtrip + SHA stability), `edge/duplicate-asset-names-flagged`.
- Warning channel made explicit in v0.1.1 review: empty `boundaries` now emits a warning (not an error, not silence) — scanners get told the spec lacked boundary context.
- README round 2: added rubric-washing / hash-false-confidence second-order effects; expanded why-not-X to 4 rows with scanner-proprietary policy row.

### Verified
- `python self_test.py` → 18/18 PASS. Render determinism verified by SHA equality across two independent spec copies; rubric sensitivity verified by SHA change on one-word edit.

## v0.1.0 — 2026-10-11 (initial draft)

### Added
- Spec `tmap/1`: assets (trust levels), boundaries, 4-level severity rubric (verbatim embedding), out_of_scope, optional reporting.
- Validator with error/warning split and actionable messages (semver check, unique asset names, all severity levels required).
- Deterministic prompt renderer with fixed sections (ROLE/ASSETS/TRUST BOUNDARIES/SEVERITY RUBRIC/OUT OF SCOPE/OUTPUT CONTRACT/GUARDRAILS) + `prompt_sha` pinning (sha16).
- CLI: `validate` (exit 1 invalid), `render [--out]`, `template`; exit codes 3/4 for missing/corrupt files.
- Self-test suite (functional / error-path / extreme-edge) and initial docs.
