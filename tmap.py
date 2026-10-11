#!/usr/bin/env python3
"""threat-model-as-prompt (tmap) -- interface spec + validator that turns a
project's threat_model file into a deterministic AI-scanner rating prompt.

The core idea: a project states its own threat model ONCE (assets, trust
boundaries, severity rubric), and tmap compiles it into a prompt contract
that any AI security scanner can be graded against -- reproducibly.

Pure stdlib. No network. Rendered prompts contain no secrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys

VERSION = "0.1.1"
SPEC_ID = "tmap/1"
SEVERITY_LEVELS = ("critical", "high", "medium", "low")
TRUST_LEVELS = ("public", "internal", "secret")
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")

TEMPLATE = {
    "spec": SPEC_ID,
    "project": "example-project",
    "version": "1.0.0",
    "assets": [
        {"name": "upload-parser",
         "description": "Parses user-supplied documents before storage.",
         "trust": "public"}
    ],
    "boundaries": [
        {"between": ["internet", "upload-parser"],
         "controls": ["schema validation", "size limits"]}
    ],
    "severity": {
        "critical": {"means": "Unauthenticated RCE or secret exfiltration.",
                     "examples": ["SSTI in template engine reaching subprocess"]},
        "high": {"means": "Authenticated data loss or auth bypass.",
                 "examples": ["IDOR on export endpoint"]},
        "medium": {"means": "Defense-in-depth failure with mitigating controls.",
                   "examples": ["Missing rate limit on login"]},
        "low": {"means": "Hardening gap or information disclosure of low-value data.",
                "examples": ["Verbose stack traces"]}
    },
    "out_of_scope": ["the marketing website", "v1.x EOL branches"],
    "reporting": {"channel": "security@example.invalid", "sla_days": 30}
}


def load_spec(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_spec(spec: dict) -> tuple:
    """Return (errors, warnings). errors -> spec unusable; warnings -> usable."""
    errors, warnings = [], []

    def need(cond, msg):
        if not cond:
            errors.append(msg)

    if not isinstance(spec, dict):
        return [f"spec root must be an object, got {type(spec).__name__}"], []
    need(spec.get("spec") == SPEC_ID, f"spec field must be {SPEC_ID!r}")
    project = spec.get("project")
    need(isinstance(project, str) and project.strip(), "project must be a non-empty string")
    version = spec.get("version")
    need(isinstance(version, str) and SEMVER.match(version),
         f"version must be semver, got {version!r}")

    assets = spec.get("assets")
    need(isinstance(assets, list) and len(assets) > 0, "assets must be a non-empty list")
    if isinstance(assets, list):
        names = set()
        for i, a in enumerate(assets):
            if not isinstance(a, dict):
                errors.append(f"assets[{i}] must be an object")
                continue
            name = a.get("name")
            need(isinstance(name, str) and name.strip(), f"assets[{i}].name missing")
            if name in names:
                errors.append(f"assets[{i}].name duplicates {name!r}")
            names.add(name)
            need(a.get("trust") in TRUST_LEVELS,
                 f"assets[{i}].trust must be one of {TRUST_LEVELS}, got {a.get('trust')!r}")
            need(isinstance(a.get("description"), str) and a["description"].strip(),
                 f"assets[{i}].description missing")

    boundaries = spec.get("boundaries", [])
    if boundaries == [] :
        warnings.append("boundaries is empty: scanner gets no trust-boundary context")
    if isinstance(boundaries, list):
        for i, b in enumerate(boundaries):
            need(isinstance(b, dict) and isinstance(b.get("between"), list)
                 and len(b["between"]) == 2,
                 f"boundaries[{i}].between must be a 2-name list")

    sev = spec.get("severity")
    need(isinstance(sev, dict), "severity must be an object with all 4 levels")
    if isinstance(sev, dict):
        for lvl in SEVERITY_LEVELS:
            block = sev.get(lvl)
            need(isinstance(block, dict) and isinstance(block.get("means"), str)
                 and block["means"].strip(),
                 f"severity.{lvl}.means must be a non-empty string")

    oos = spec.get("out_of_scope", [])
    need(isinstance(oos, list) and all(isinstance(x, str) for x in oos),
         "out_of_scope must be a list of strings")
    rep = spec.get("reporting")
    if rep is not None:
        need(isinstance(rep, dict) and isinstance(rep.get("channel"), str),
             "reporting.channel must be a string when reporting is present")
    return errors, warnings


def _bullet(items, indent="  ") -> str:
    return "\n".join(f"{indent}- {x}" for x in items) if items else f"{indent}- (none declared)"


def render_prompt(spec: dict) -> str:
    """Deterministically compile a validated spec into a scanner prompt.

    Raises ValueError if the spec does not validate. No timestamps, no
    randomness: identical specs render byte-identical prompts.
    """
    errors, _ = validate_spec(spec)
    if errors:
        raise ValueError("cannot render invalid spec: " + "; ".join(errors[:5]))
    sev = spec["severity"]
    parts = [
        "ROLE",
        "You are a security scanner grader. Rate candidate findings against the",
        "rubric below. You assess severity; you do not exploit anything and you",
        "do not request credentials or live data.",
        "",
        f"PROJECT: {spec['project']} (version {spec['version']}, spec {SPEC_ID})",
        "",
        "ASSETS",
    ]
    for a in spec["assets"]:
        parts.append(f"- {a['name']} [trust={a['trust']}]: {a['description']}")
    parts += ["", "TRUST BOUNDARIES"]
    for b in spec.get("boundaries", []):
        parts.append(f"- {' <-> '.join(b['between'])}; controls: {', '.join(b.get('controls', [])) or 'none'}")
    parts += ["", "SEVERITY RUBRIC (verbatim from the project -- apply as written)"]
    for lvl in SEVERITY_LEVELS:
        block = sev[lvl]
        parts.append(f"- {lvl.upper()}: {block['means']}")
        parts.append(_bullet([f"example: {e}" for e in block.get("examples", [])], indent="    "))
    parts += [
        "",
        "OUT OF SCOPE (do not report)",
        _bullet(spec.get("out_of_scope", [])),
        "",
        "OUTPUT CONTRACT",
        "For each finding output: id, asset, severity (from rubric), evidence,",
        "a minimal reproducer, and a confidence in [0,1]. Findings without a",
        "concrete reproducer must be marked confidence < 0.5. Output nothing",
        "else. If no findings, output exactly: NO_FINDINGS.",
        "",
        "GUARDRAILS",
        "- Proof-of-concept only: no weaponized payloads, no data exfiltration.",
        "- Never access systems outside the declared assets.",
        "- Treat this rubric as the single source of severity truth.",
    ]
    return "\n".join(parts)


def prompt_sha(spec: dict) -> str:
    return hashlib.sha256(render_prompt(spec).encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_validate(args) -> int:
    spec = load_spec(args.file)
    errors, warnings = validate_spec(spec)
    for w in warnings:
        print(f"warning: {w}")
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"valid {SPEC_ID} spec ({prompt_sha(spec)})")
    return 0


def _cmd_render(args) -> int:
    spec = load_spec(args.file)
    try:
        prompt = render_prompt(spec)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(prompt)
        print(f"prompt -> {args.out}  sha={prompt_sha(spec)}")
    else:
        print(prompt)
    return 0


def _cmd_template(_args) -> int:
    print(json.dumps(TEMPLATE, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tmap", description="threat model -> scanner rating prompt")
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="validate a threat_model spec file")
    v.add_argument("file")
    v.set_defaults(func=_cmd_validate)
    r = sub.add_parser("render", help="compile spec into a deterministic rating prompt")
    r.add_argument("file")
    r.add_argument("--out", help="write prompt to file instead of stdout")
    r.set_defaults(func=_cmd_render)
    sub.add_parser("template", help="print an example spec").set_defaults(func=_cmd_template)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"error: file not found: {e.filename}", file=sys.stderr)
        return 3
    except json.JSONDecodeError as e:
        print(f"error: not valid JSON: {e}", file=sys.stderr)
        return 4
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
