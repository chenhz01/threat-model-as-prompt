#!/usr/bin/env python3
"""Self-test for threat-model-as-prompt: functional / error-path / extreme-edge."""
import copy
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tmap  # noqa: E402

RESULTS = []
CASES = []


def case(name):
    def deco(fn):
        def wrapper():
            try:
                fn()
                RESULTS.append((name, "PASS", ""))
            except AssertionError as e:
                RESULTS.append((name, "FAIL", str(e)))
            except Exception as e:  # noqa: BLE001
                RESULTS.append((name, "FAIL", f"{type(e).__name__}: {e}"))
        CASES.append(wrapper)
        return wrapper
    return deco


def spec_file(blob):
    td = tempfile.mkdtemp()
    p = os.path.join(td, "threat_model.json")
    json.dump(blob, open(p, "w", encoding="utf-8"))
    return p


# ---------------- functional ----------------

@case("func/template-validates-clean")
def _():
    errors, warnings = tmap.validate_spec(copy.deepcopy(tmap.TEMPLATE))
    assert errors == [], errors
    assert warnings == [], warnings


@case("func/render-deterministic-same-sha")
def _():
    s1 = tmap.prompt_sha(tmap.TEMPLATE)
    s2 = tmap.prompt_sha(copy.deepcopy(tmap.TEMPLATE))
    assert s1 == s2, (s1, s2)


@case("func/render-changes-with-rubric")
def _():
    spec = copy.deepcopy(tmap.TEMPLATE)
    sha_before = tmap.prompt_sha(spec)
    spec["severity"]["critical"]["means"] += " Or worse."
    assert tmap.prompt_sha(spec) != sha_before


@case("func/render-contains-contract-sections")
def _():
    p = tmap.render_prompt(tmap.TEMPLATE)
    for section in ("ROLE", "ASSETS", "SEVERITY RUBRIC", "OUTPUT CONTRACT", "GUARDRAILS", "NO_FINDINGS"):
        assert section in p, section
    assert "critical" in p.lower()


@case("func/validate-warns-empty-boundaries")
def _():
    spec = copy.deepcopy(tmap.TEMPLATE)
    spec["boundaries"] = []
    errors, warnings = tmap.validate_spec(spec)
    assert errors == [] and any("boundaries" in w for w in warnings)


@case("func/cli-validate-render")
def _():
    p = spec_file(tmap.TEMPLATE)
    rc = subprocess.run([sys.executable, "tmap.py", "validate", p], capture_output=True, cwd=HERE)
    assert rc.returncode == 0, rc.stderr
    out = os.path.join(os.path.dirname(p), "prompt.txt")
    rc2 = subprocess.run([sys.executable, "tmap.py", "render", p, "--out", out],
                         capture_output=True, cwd=HERE)
    assert rc2.returncode == 0, rc2.stderr
    assert "OUTPUT CONTRACT" in open(out, encoding="utf-8").read()


# ---------------- error paths ----------------

@case("err/missing-severity-level")
def _():
    spec = copy.deepcopy(tmap.TEMPLATE)
    del spec["severity"]["low"]
    errors, _ = tmap.validate_spec(spec)
    assert any("severity.low" in e for e in errors), errors


@case("err/bad-trust-level")
def _():
    spec = copy.deepcopy(tmap.TEMPLATE)
    spec["assets"][0]["trust"] = "top-secret-ish"
    errors, _ = tmap.validate_spec(spec)
    assert any("trust" in e for e in errors)


@case("err/empty-assets")
def _():
    spec = copy.deepcopy(tmap.TEMPLATE)
    spec["assets"] = []
    errors, _ = tmap.validate_spec(spec)
    assert any("assets" in e for e in errors)


@case("err/render-rejects-invalid-spec")
def _():
    try:
        tmap.render_prompt({"spec": "tmap/1"})
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


@case("err/cli-corrupt-json-exit-4")
def _():
    td = tempfile.mkdtemp()
    p = os.path.join(td, "bad.json")
    open(p, "w").write("{ oops")
    rc = subprocess.run([sys.executable, "tmap.py", "validate", p], capture_output=True, cwd=HERE)
    assert rc.returncode == 4, rc.returncode


@case("err/cli-missing-file-exit-3")
def _():
    rc = subprocess.run([sys.executable, "tmap.py", "validate", "ghost.json"],
                        capture_output=True, cwd=HERE)
    assert rc.returncode == 3, rc.returncode


@case("err/cli-invalid-spec-exit-1")
def _():
    spec = copy.deepcopy(tmap.TEMPLATE)
    spec["version"] = "not-semver"
    rc = subprocess.run([sys.executable, "tmap.py", "validate", spec_file(spec)],
                        capture_output=True, cwd=HERE)
    assert rc.returncode == 1, rc.returncode


# ---------------- extreme edges ----------------

@case("edge/empty-json-object")
def _():
    errors, _ = tmap.validate_spec({})
    assert len(errors) >= 4, errors


@case("edge/non-dict-root")
def _():
    errors, _ = tmap.validate_spec([1, 2, 3])
    assert errors and "object" in errors[0]


@case("edge/huge-spec-500-assets")
def _():
    spec = copy.deepcopy(tmap.TEMPLATE)
    spec["assets"] = [{"name": f"asset-{i}", "description": "d" * 50, "trust": "internal"}
                      for i in range(500)]
    errors, _ = tmap.validate_spec(spec)
    assert errors == []
    p = tmap.render_prompt(spec)
    assert "asset-499" in p


@case("edge/unicode-project-names")
def _():
    spec = copy.deepcopy(tmap.TEMPLATE)
    spec["project"] = "工程-emoji-🚀"
    p = tmap.render_prompt(spec)
    assert "🚀" in p
    tmap.prompt_sha(spec)  # sha stable over unicode


@case("edge/duplicate-asset-names-flagged")
def _():
    spec = copy.deepcopy(tmap.TEMPLATE)
    spec["assets"].append(dict(spec["assets"][0]))
    errors, _ = tmap.validate_spec(spec)
    assert any("duplicates" in e for e in errors), errors


def main() -> int:
    for fn in CASES:
        fn()
    width = max(len(n) for n, _, _ in RESULTS)
    for name, status, msg in RESULTS:
        print(f"{name:<{width}}  {status}" + (f"  ({msg})" if msg else ""))
    passed = sum(1 for _, s, _ in RESULTS if s == "PASS")
    print(f"\n{passed}/{len(RESULTS)} passed")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
