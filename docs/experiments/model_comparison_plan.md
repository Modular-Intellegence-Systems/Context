# Model Comparison Plan

## Objective
Evaluate three generations of OpenAI models on the Aquila ingestion benchmark:
1. gpt-5-codex (current flagship with deterministic execution via Codex CLI)
2. gpt-5-nano (lightweight modern variant via native API)
3. gpt-3.5-turbo-0125 (legacy problematic model representative of earlier reliability issues)

## Datasets
- Primary: `experiments/contexts/scale/variant_?_scale.context` (86 capsules).
- Prompt templates: `experiments/prompts/scale/variant_?_scale_prompt.txt` producing JSON patch requirement.

## Metrics
- Completion correctness: exact patch lines + justification referencing `telemetry-burst` and `firmware-v3.18`.
- Token usage: prompt/completion/total tokens (from API usage or Codex logs).
- Runtime: measured via `/usr/bin/time` for Codex; wall-clock using script timestamps for API models.
- Failure mode classification (timeouts, 4xx errors, hallucinations).

## Execution Strategy
- gpt-5-codex: use `experiments/scripts/run_codex_with_metrics.sh`.
- gpt-5-nano: extend `run_openai_chat.py` with `--model gpt-5-nano` (temperature default) and parse JSON content.
- gpt-3.5-turbo-0125: same API path as nanos, expect higher error/hallucination rate.
- Each run repeated twice to confirm determinism; log outputs under `experiments/results/model_comparison/`.

## Deliverables
- `docs/experiments/model_comparison_results.md` summarising metrics table and qualitative observations.
- JSON summary file for automated consumption.
- `.agents/context/DCTX/experiments/*` entries documenting new findings.

## Timeline
- Setup & scripts: ~40 min.
- Execution & validation: ~60 min.
- Documentation & context updates: ~30 min.
