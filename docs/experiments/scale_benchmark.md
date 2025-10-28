# DCTX Scale Benchmark (86 Capsules)

## Dataset
- 86 capsules derived from Aquila incident telemetry with mixed priorities.
- Variants: `variant_a_scale` (canonical DCTX), `variant_b_scale` (DCTX-Compact), `variant_c_scale` (Hybrid Outline).
- Variant C теперь включает блок `[relations]` с причинно-следственными связями (см. docs/hybrid_outline_spec.md).
- Context files stored in `experiments/contexts/scale/`.

## gpt-5-codex Results (temperature 0)
| Variant | Tokens | real s | RSS KB | Outcome |
|---------|--------|--------|--------|---------|
| A | 12 047 | 16.83 | 53 128 | Correct patch + justification citing telemetry-burst & firmware-v3.18. |
| B | 11 775 | 10.20 | 53 116 | Correct result; compact form shows best runtime on large corpus. |
| C | 11 188 | 11.77 | 53 688 | Correct; hybrid outline remains close in cost with balanced runtime. |

## o4-mini API Results (max_completion_tokens=2000)
| Variant | Prompt Tokens | Completion Tokens | Total Tokens | Outcome |
|---------|---------------|-------------------|--------------|---------|
| A | 5 344 | 1 009 | 6 353 | Correct JSON with required patch/justification. |
| B | 5 583 | 682 | 6 265 | Correct JSON; shortest completion among variants. |
| C | 4 915 | 825 | 5 740 | Correct JSON; lowest prompt cost. |

## Model Availability Notes
- Codex CLI still rejects `gpt-4.2` and `o4-mini` with HTTP 400 (`model is not supported when using Codex with a ChatGPT account`).
- Direct OpenAI API now lists `o4-mini` but still omits `gpt-4.2`; chat completion with `gpt-4.2` returns `model_not_found`.
- Successful `o4-mini` API runs stored as JSON responses (`experiments/results/scale/variant_*_scale_o4mini_api.json`).
- Codex failure logs preserved under `experiments/results/scale/variant_*_scale_gpt4_2.jsonl` and `..._o4mini.jsonl`.
- **Policy:** использование любых вариантов `gpt-4.2` запрещено в тестовом контуре; скрипты автоматически прекращают запуск с этой моделью.

## Metrics Extraction
- Use `.agents/tools/log_metrics.py` to summarise logs (example output in `experiments/results/scale/metrics_summary.txt`).
- Script parses tokens, runtime, memory, and flags unsupported-model errors automatically.
- Wrapper `experiments/scripts/run_codex_with_metrics.sh` запускает codex exec и автоматически добавляет секцию stderr с `real=`/`mem=`.

## Next Steps
1. Validate `log_metrics.py` on historical small-context runs for consistency.
2. Investigate alternative access paths for `gpt-4.2` / `o4-mini` (non-Codex API) or document limitation officially.
3. Extend benchmark with additional noise capsules (e.g., conflicting metrics per region) to test context prioritisation.
