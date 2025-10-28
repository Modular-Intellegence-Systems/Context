#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / ".agents" / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import ctx_lint  # type: ignore  # noqa: E402


def load_expected(path: Path) -> Dict[str, str]:
    if not path.exists():
        raise RuntimeError(f"missing expected outcome: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def lint_context(path: Path) -> Dict[str, str]:
    try:
        doc, canonical = ctx_lint.parse_document(path)
    except ctx_lint.LintError as err:  # type: ignore[attr-defined]
        return {"status": "error", "message": str(err)}
    digest = ctx_lint.compute_digest(canonical)
    profile = getattr(doc, "header_profile", "unknown")
    return {"status": "ok", "profile": profile, "digest": digest}


def compare(actual: Dict[str, str], expected: Dict[str, str]) -> List[str]:
    issues: List[str] = []
    if actual.get("status") != expected.get("status"):
        issues.append(f"status {actual.get('status')} != {expected.get('status')}")
        return issues
    if actual["status"] == "ok":
        if "profile" in expected and actual.get("profile") != expected.get("profile"):
            issues.append(
                f"profile {actual.get('profile')} != {expected.get('profile')}"
            )
        if "digest" in expected:
            if actual.get("digest") != expected.get("digest"):
                issues.append(
                    f"digest {actual.get('digest')} != {expected.get('digest')}"
                )
    else:
        if "message" in expected and actual.get("message") != expected.get("message"):
            issues.append(
                f"message {actual.get('message')} != {expected.get('message')}"
            )
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate CONTEXT goldens")
    parser.add_argument(
        "--contexts-dir",
        type=Path,
        default=ROOT / "tests" / "context",
        help="Directory with golden .context files",
    )
    parser.add_argument(
        "--outcomes-dir",
        type=Path,
        default=ROOT / "tests" / "outcomes",
        help="Directory with expected JSON outcomes",
    )
    args = parser.parse_args()

    contexts = sorted(args.contexts_dir.glob("*.context"))
    if not contexts:
        print("No context files found", file=sys.stderr)
        return 1

    failures: List[str] = []
    for ctx_path in contexts:
        expected_path = args.outcomes_dir / f"{ctx_path.stem}.json"
        expected = load_expected(expected_path)
        actual = lint_context(ctx_path)
        issues = compare(actual, expected)
        if issues:
            formatted = "; ".join(issues)
            failures.append(f"{ctx_path.name}: {formatted}")
        else:
            print(f"[OK] {ctx_path.name}")

    if failures:
        print("\nFailures:", file=sys.stderr)
        for line in failures:
            print(f" - {line}", file=sys.stderr)
        return 1

    return 0


if __name__ == "main":
    raise SystemExit("Run this module as a script")

if __name__ == '__main__':
    sys.exit(main())
