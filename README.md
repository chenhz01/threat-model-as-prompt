# threat-model-as-prompt

A tiny interface spec + validator that compiles a project's threat model file into a deterministic AI-scanner rating prompt. Projects state assets, trust boundaries, and a severity rubric once; any AI security scanner can then be graded against that exact contract. If you run AI-driven audits, this pins the grading; if you expect the tool to find vulnerabilities itself, it will not.

**As of 2026-10-11.**

## Problem

AI security scanners output severities nobody asked for. "Critical" from scanner A is "medium" from scanner B, because each model improvises a rubric at prompt time. Meanwhile projects *do* have opinions — they know which assets are secret, which bugs are acceptable, and what "critical" means for them — but that knowledge lives in docs the scanner never sees.

The fix is an interface: the project declares its threat model in a machine-checkable file; the tool compiles it into a prompt whose severity section is **verbatim from the project**, with a stable hash so you can pin exactly which contract a scanner was graded against.

## How it works

A `threat_model.json` (spec `tmap/1`) declares:

- `assets[]` — name, description, trust level (`public|internal|secret`)
- `boundaries[]` — pairs of names plus controls between them
- `severity{}` — all four levels (`critical/high/medium/low`), each with a `means` sentence and examples; this text is embedded verbatim in the prompt
- `out_of_scope[]`, optional `reporting{}`

The validator enforces schema rules (semver version, unique asset names, all four severity levels present, empty boundaries → warning not error). The renderer then emits a fixed-section prompt — `ROLE / ASSETS / TRUST BOUNDARIES / SEVERITY RUBRIC / OUT OF SCOPE / OUTPUT CONTRACT / GUARDRAILS` — with no timestamps and no randomness, so identical specs produce byte-identical prompts and a 16-hex SHA pins the rendered contract.

## Quickstart

```bash
# ~5 s: get the example spec
python tmap.py template > threat_model.json

# ~5 s: validate it (exit 0 = valid; warnings print first)
python tmap.py validate threat_model.json

# ~5 s: compile the rating prompt (sha16 pins the contract)
python tmap.py render threat_model.json --out scanner_prompt.txt

# ~5 s: self-test (18 cases)
python self_test.py
```

## Why not X

| Alternative | Why not alone |
|---|---|
| Free-form "read our SECURITY.md" prompt | Prose is unparseable; the model skips sections; no validation, no pinned hash |
| Hand-written prompt per project | Duplicates effort, drifts from the real threat model, impossible to diff-review |
| Scanner-proprietary policy files (e.g. per-scanner YAML rubrics) | Locks the rubric to one vendor; tmap's output is plain text any model accepts |
| Trusting the scanner's default rubric | The default reflects the scanner's worldview, not your asset inventory |

## Minimal Fallback

No Python? The spec is plain JSON and the prompt is plain text: read `tmap.py template`, paste the `severity` section into your existing scanner prompt by hand, and you lose validation and hash-pinning but keep the interface. `validate` is also just schema checking — any JSON-schema-aware editor can approximate it.

## Design Trade-offs

Priority order when goals conflict: **determinism > project-authority (rubric is verbatim) > scanner freedom > brevity**.

- Rubric embedded verbatim instead of paraphrased: prompts get longer, but the project's exact words are the point.
- Render rejects invalid specs instead of rendering-with-warnings: a scanner graded against a half-valid spec is worse than a loud failure.
- JSON only (no YAML): stdlib-only and one less parser; YAML's ambiguity is a liability for a validation contract.
- Severity vocabulary fixed to 4 levels: loses exotic taxonomies, gains cross-project comparability.
- Guardrails section ships with every prompt: scanners must not treat the rubric as license to exploit.

## Limits & Second-order Effects

- **Limits.** The rubric is the project's *stated* intent — a wrong or gamed rubric yields consistently wrong ratings (garbage in, pinned garbage out). tmap validates structure, not sincerity; it cannot detect that "critical" is defined so narrowly nothing qualifies. Rendered prompts assume the scanner honors output contracts; models that ignore `NO_FINDINGS` will still work, just noisier.
- **Second-order effects.** If this pattern spreads, projects may lower their rubrics to look better in scanner scorecards — rubric-washing. Hash-pinning can also create false confidence: the same pinned hash grades a scanner that ignores half the contract. And "out of scope" lists become a moral-hazard magnet; reviewers should read them first.

## FAQ

**Q: Does tmap scan anything?** No. It is a spec validator + prompt compiler. Scanning is another tool's job.

**Q: Why a hash over the rendered prompt?** So audit logs can record which contract produced which ratings: `sha=ab12cd34ef567890` is reproducible forever, byte-identical.

**Q: Can I add severity levels?** Not without changing the spec id — 4 fixed levels keep ratings comparable across projects.

**Q: What if my threat model is secret?** Rendered prompts contain whatever you put in the spec; review before sharing with a third-party scanner. The template ships `example.invalid` placeholders only.

**Q: When NOT to use this?** (Socratic check) Not for projects with no asset inventory to declare (a fake spec is worse than none), not as a substitute for human threat modeling, not where you need CVE-grade severity mapping (this is triage vocabulary), and not to *suppress* findings by declaring them out of scope.

## Core Assumptions

- [A1] Projects will honestly maintain a machine-readable severity rubric. *(Medium confidence — incentive to rubric-wash is real; see Limits.)*
- [A2] Verbatim rubric embedding measurably improves rating agreement across scanners vs. improvised rubrics. *(Medium confidence — mechanism is sound, cross-scanner benchmark not yet run [estimated].)*
- [A3] Deterministic prompts (no timestamps/randomness) are a requirement for auditability, even at the cost of freshness. *(High confidence.)*
- [A4] Four severity levels cover the practical triage vocabulary. *(High confidence — matches industry convention.)*

*Measured marker: self-test 18/18 PASS (repro `python self_test.py`) includes render-determinism SHA equality and rubric-sensitivity checks. Knowledge cutoff: 2026-10-11.*
