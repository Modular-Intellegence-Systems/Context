# CONTEXT Test Suite

## Golden Runner

Execute all deterministic checks:

```
python tests/run_goldens.py
```

The runner iterates over `tests/context/*.context`, invokes `ctx_lint.parse_document`, computes the canonical digest (CTX-CANON/3), and compares the result with `tests/outcomes/<name>.json`. Any deviation (status/profile/digest mismatch) causes a non-zero exit code.

### Continuous Integration

GitHub Actions workflow `.github/workflows/goldens.yml` executes the same command on every push and pull-request targeting `main`. Pipelines MUST remain green before merging changes.

### Current Coverage

| Context file | Outcome | Purpose |
| --- | --- | --- |
| `ATT-HASH-MISMATCH.context` | error | Attachment descriptor hash mismatch. |
| `CAN-TAB.context` | error | TAB characters rejected outside payload/literal. |
| `CF-NORM.context` | ok | Multiple `policy.cf` entries with `cf.src`. |
| `CH-REASSEMBLE.context` | ok | Chunked payload (`^chunk:`) validation. |
| `ENC-PRIVACY.context` | ok | Encrypted capsule envelope `enc.*`. |
| `ERR-RETRIABLE.context` | ok | Structured `err.*` metadata. |
| `JSON-ROUNDTRIP.context` | ok | Baseline for JSON/JSON-LD projection tests. |
| `REL-EXTERNAL.context` | error | External relation without resolver metadata. |
| `REL-EXTERNAL-OK.context` | ok | External relation with `[resolution]`/`[repo]`. |
| `RES-DOC.context` | ok | Resolver workflow + attachments. |
| `SAFE-UNTRUSTED.context` | ok | `safe.hint=untrusted` handling. |
| `SIG-2OF3.context` | ok | `sig.policy=k-of-n` quorum validation. |
| `SIG-ROTATE-EPOCH.context` | ok | Multi-signature with epoch rotation and TSA token. |
| `TR-BRANCH.context` | ok | Branch/merge trace invariants. |
| `TTL-EXPIRED.context` | ok | TTL policy annotation (`policy.ttl`). |

## Negative scenarios

Files such as `tests/context/CAN-TAB.context`, `tests/context/ATT-HASH-MISMATCH.context`, and `tests/context/REL-EXTERNAL.context` intentionally trigger lint failures. Their outcomes reflect the canonical error messages the runner expects.

## Extending the matrix

1. Add a `.context` file under `tests/context/`.
2. Run `python tests/run_goldens.py` to verify behaviour.
3. Capture the produced digest/status and store it in `tests/outcomes/<name>.json`.
4. Commit both files together with any required tooling updates.
