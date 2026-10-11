# Alignment Audit (Rules 85-100 / 16 items) — threat-model-as-prompt

Audit date: 2026-10-11 · Auditor: R11 construction worker W4 · Iteration: 2 rounds

| # | Check | Status | Evidence |
|---|-------|--------|----------|
| 1 | 85 Safety/Ethics section | PASS | Security-adjacent repo; guardrails embedded in every rendered prompt (no exploitation, no exfil); README Limits covers rubric-gaming; not a payload/offense tool |
| 2 | 86 Privacy de-identification | PASS | grep `(sk-\|ghp_\|api[_-]?key)` → 0 hits; template uses `example.invalid`; no real names; LICENSE = "zhengming contributors" |
| 3 | 87 Copyright boundary | PASS | Inspired by oss-scanner's "threat model as prompt" concept only; spec/renderer/tests are original; zero >50-char fragments from source |
| 4 | 88 Fact-check labeling | PASS | A2 marked `[estimated]` (cross-scanner benchmark not run); no unverified performance claims |
| 5 | 89 Confidence grading | PASS | A1/A2 Medium, A3/A4 High with rationale; ≥2 explicit labels |
| 6 | 90 PLAN B built in | PASS | README "Minimal Fallback": manual rubric paste; spec is plain JSON |
| 7 | 91 Timeout presets | PASS | Quickstart: ~5 s per step, staged template → validate → render → self-test |
| 8 | 92 Rule conflict arbitration | PASS | "Design Trade-offs": determinism > project-authority > scanner freedom > brevity |
| 9 | 93 Version changelog | PASS | CHANGELOG v0.1.0 → v0.1.1 with per-item iteration trail |
| 10 | 94 Exemption instructions | N/A | Session-governance rule; static repo exempt |
| 11 | 95 External knowledge cutoff | PASS | Header "As of 2026-10-11"; no time-sensitive external claims |
| 12 | 96 Assumptions explicit | PASS | `[Core Assumptions]` A1-A4 (4 ≥ 3) |
| 13 | 97 Logic-check trio | PASS | self_test 18/18 PASS: functional 6 + error-path 7 (missing severity level, bad trust, empty assets, render-rejects-invalid, corrupt JSON exit 4, missing file exit 3, invalid spec exit 1) + extreme 5 (empty object, non-dict root, 500 assets, unicode, duplicates) |
| 14 | 98 Socratic FAQ | PASS | FAQ "When NOT to use this?" — 4 anti-use cases incl. rubric-as-suppression |
| 15 | 99 Pareto improvement | PASS | CHANGELOG v0.1.1: suite 15→18 (+20%), boundary-warning channel added, second-order effects expanded |
| 16 | 100 Minimal entry ≤60 words | PASS | First paragraph 59 words (counted), decision sentence "this pins the grading; it will not" |

Second-order effects (rule 16 addendum): PASS — README "Limits & Second-order Effects" covers rubric-washing, hash false confidence, out-of-scope moral hazard.
