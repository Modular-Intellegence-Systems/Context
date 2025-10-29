# CONTEXT/1.2 Workspace

> Deterministic capsule format for Flagship agents: a shared language between the Reasoning Core, Memory Brain, and Tooling Mesh.

![CI - Golden Suite](https://github.com/Modular-Intellegence-Systems/Context/actions/workflows/goldens.yml/badge.svg) ![Spec - CTX/1.2](https://img.shields.io/badge/spec-CTX--1.2-blue)

**Goal.** Guarantee that every `.context` capsule conforms to the specification and passes the golden suite before entering Modular Intellegence Systems production pipelines.

## Repository Map

| Path | Purpose |
| --- | --- |
| `docs/context_spec_1_2.md` | Authoritative CONTEXT/1.2 specification with CTX-CANON/3 annexes. |
| `docs/testing.md` | Guide for running and extending the golden suites. |
| `.agents/tools/ctx_lint.py` | Reference parser/linter used across all validations. |
| `tests/context/` | Positive and negative `.context` scenarios. |
| `tests/outcomes/` | Expected outputs for the golden suite. |
| `.github/workflows/goldens.yml` | CI workflow that executes the full golden suite on every push/PR. |

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # ensure python>=3.11 if the file is absent
python tests/run_goldens.py
```

The command must exit with status `0`. Any divergence between actual and expected output marks a regression and blocks merge.

## Golden Suite and CI
- `goldens.yml` runs on every push and pull request.
- Always run `python tests/run_goldens.py` locally before publishing commits.
- Specification changes must ship with updated golden cases and documentation.

## Adding New Scenarios
1. Create a `.context` capsule in `tests/context/` with a descriptive name.
2. Execute `python tests/run_goldens.py` to produce the digest or error metadata.
3. Store the expected output under `tests/outcomes/<name>.json`.
4. Update `docs/context_spec_1_2.md` and `docs/testing.md` if behavior changed.
5. Open a pull request with the execution trace, references to ADRs when relevant, and proof of a green CI run.

## Status and Next Steps
- Covered: resolver metadata, chunk payloads, TTL, confidence models, signature rotation and quorum, safe hints, TAB errors, attachment hash mismatch, external relation validation, JSON round-trip placeholder.
- In progress: pack/unpack flow, tag validation, external descriptors, public registry.
- Quarterly target: broaden negative scenarios and formalize the converter audit protocol.

## Contributing
- Follow `AGENTS.md` and the Flagship bar: zero mocks, coverage >=85 percent, cyclomatic complexity <=10.
- Each pull request includes a design brief plus evidence (test logs, ADR links).
- Use organization GitHub Discussions for questions and design clarifications.

## Support
- Issues are the preferred channel for requests or improvements.
- Contact: magraytlinov@gmail.com - core team replies within one business day.
- Context is pinned on the Modular Intellegence Systems overview as the entry point into the modular ecosystem.
