# CONTEXT Test Suite

## Golden Runner

Execute all deterministic checks:

```
python tests/run_goldens.py
```

The runner iterates over `tests/context/*.context`, invokes `ctx_lint.parse_document`, computes the canonical digest (CTX-CANON/3), and compares the result with `tests/outcomes/<name>.json`. Any deviation (status/profile/digest mismatch) causes a non-zero exit code.

### Continuous Integration

GitHub Actions workflow `.github/workflows/goldens.yml` executes the same command on every push and pull-request targeting `main`. Pipelines MUST remain green before merging changes.

## Negative scenarios

Files such as `tests/context/CAN-TAB.context`, `tests/context/ATT-HASH-MISMATCH.context`, and `tests/context/REL-EXTERNAL.context` intentionally trigger lint failures. Their outcomes reflect the canonical error messages the runner expects.

## Extending the matrix

1. Add a `.context` file under `tests/context/`.
2. Run `python tests/run_goldens.py` to verify behaviour.
3. Capture the produced digest/status and store it in `tests/outcomes/<name>.json`.
4. Commit both files together with any required tooling updates.
