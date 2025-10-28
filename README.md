# CONTEXT/1.2 Workspace

This repository hosts the working implementation of the CONTEXT/1.2 format and linting tooling. It includes the normative specification, canonical examples, automated golden tests, and CI configuration to guarantee deterministic handling of capsules and relations.

## Contents

- `docs/context_spec_1_2.md` – normative specification (@CONTEXT/1.2 + CTX-CANON/3).
- `docs/testing.md` – instructions for running and extending the golden test suite.
- `.agents/tools/ctx_lint.py` – reference parser/linter used in all validations.
- `tests/context/` + `tests/outcomes/` – golden `.context` files with expected results (positive & negative scenarios).
- `.github/workflows/goldens.yml` – GitHub Actions workflow running the golden suite on each push/PR.

## Getting Started

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # if such file exists; else ensure python>=3.11
python tests/run_goldens.py
```

The command must exit with status `0`. Any discrepancy between actual and expected outcomes indicates a regression in the format or tooling.

## Adding New Test Cases

1. Create a `.context` file under `tests/context/`.
2. Run `python tests/run_goldens.py` to obtain the digest or error metadata.
3. Add the expected outcome in `tests/outcomes/<name>.json`.
4. Commit the new files alongside any required changes in `ctx_lint.py` or docs.

## CI Enforcement

The GitHub Actions workflow `goldens.yml` executes the golden suite automatically. Pull requests failing this check must be fixed before merging. This ensures that every change preserves canon determinism and lint diagnostics.

## Contributing

- Extend the specification via `docs/context_spec_1_2.md` (include Annex references when adding new constructs).
- Update the golden suite whenever specification changes introduce new behaviour.
- Keep the documentation (spec, testing guide, AGENTS index) consistent with code changes.

## Status

The current golden suite covers: resolver metadata, chunk payloads, TTL policies, confidence models, signatures (rotation and quorum), safe-hints, negative error scenarios (TAB, attachment hash mismatch, external relation without resolver), and JSON round-trip placeholder. Remaining matrix items (pack/unpack, tag validation, external descriptor verification) are slated for future iterations.
