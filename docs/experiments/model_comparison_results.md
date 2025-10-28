# Model Comparison: gpt-5-codex vs gpt-5-nano vs gpt-3.5-turbo-0125

## Summary Table (Variant A — 86 capsules)
| Model | Prompt Tokens | Completion Tokens | Total Tokens | Runtime | Outcome |
|-------|---------------|-------------------|--------------|---------|---------|
| gpt-5-codex | 12 047 (tokens from Codex log) | — | — | 16.83 s | Correct patch + justification. |
| gpt-5-nano-2025-08-07 | 5 344 | 256 (reasoning only) | 5 600 | n/a (API) | **Failure**: response empty, finish_reason `length`. |
| gpt-3.5-turbo-0125 | 5 328 | 100 | 5 428 | n/a (API) | Correct JSON patch with justification. |

## Additional Variants
- gpt-5-codex metrics for B/C: see `experiments/results/scale/metrics_summary.txt` (tokens 11 775 / 11 163).
- gpt-3.5-turbo-0125 produced valid patches for B/C with total tokens 5 665 / 5 000.
- gpt-5-nano attempts with higher `max_completion_tokens` (2000, 1000, 256) yielded only reasoning tokens and empty `content`.

## Observations
1. gpt-5-nano currently unsuitable for long structured outputs: model expends allowance on hidden reasoning and returns no final message even with JSON response_format.
2. gpt-3.5-turbo, despite legacy status, succeeds with concise completions but justification quality is shorter and less specific.
3. gpt-5-codex remains deterministic with highest token cost but quickest successful execution pipeline.

## Artifacts
- gpt-5-codex logs: `experiments/results/scale/variant_*_scale_codex.jsonl`.
- gpt-5-nano attempts: `experiments/results/model_comparison/variant_a_gpt5_nano*.json` (failures documented).
- gpt-3.5 outputs: `experiments/results/model_comparison/variant_*_gpt35_turbo.json`.
- Consolidated metrics: `experiments/results/model_comparison/summary.json`.
