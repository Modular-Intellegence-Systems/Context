# Tools Inventory

- `log_metrics.py` — parses Codex jsonl logs to extract tokens, runtime (seconds), and memory usage (RSS KB). Usage: `python .agents/tools/log_metrics.py <path-glob>`.
- `tests/run_goldens.py` — validates CONTEXT goldens (`tests/context/*.context` vs `tests/outcomes/*.json`); run via `python tests/run_goldens.py`.
