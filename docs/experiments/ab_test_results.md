# DCTX Context Variant Evaluation Results (2025-10-28)

## Scenario Recap
- Incident: Aquila ingestion throughput drops tied to firmware-v3.18 deployment.
- Required output: three exact configuration lines plus justification citing `telemetry-burst` and `firmware-v3.18`.
- Solver: `codex exec` using `gpt-5-codex` with approval policy `never`.

## Variant Outcomes
| Variant | Format Notes | Patch Correct? | Justification Valid? | Tokens (baseline) | real s | RSS KB | Observations |
|---------|--------------|----------------|----------------------|-------------------|--------|--------|--------------|
| A | Canonical DCTX with ordered capsules | Yes | Yes (references both terms) | 7010 | 20.36 | 53416 | Noise capsules ignored; runtime measured on rerun showed stable latencies. |
| B | DCTX-Compact with bundled metadata | Yes | Yes (non-null values) | 7072 | 13.66 | 53376 | Bundle syntax parsed correctly; fastest among DCTX encodings. |
| C | Hybrid Outline sections | Yes | Yes | 6405 | 8.71 | 53352 | Lowest token cost and shortest runtime overall. |

## Temperature 0.7 Robustness
| Variant | Tokens | real s | RSS KB | Outcome |
|---------|--------|--------|--------|---------|
| A | 7650 | 21.90 | 53160 | Correct patch; justification satisfied despite higher sampling.
| B | 7005 | 15.08 | 53156 | Correct result; minor token drop from baseline due to sampling variance.
| C | 5577 | 9.62 | 53164 | Correct; Hybrid format stayed most token-efficient.

## Contradictory Noise Trial
| Variant | Tokens | real s | RSS KB | Outcome |
|---------|--------|--------|--------|---------|
| A | 7647 | 18.35 | 53608 | Ignored `status=unverified/unsupported` capsules and returned correct patch.
| B | 7210 | 16.12 | 52688 | Bundled noise marked unsupported did not mislead the model.
| C | 6418 | 17.91 | 53352 | Extra sections increased runtime but final answer remained correct.

## Findings
- Все запуски (baseline, температура 0.7, шум) выдают идентичный патч и корректную ссылку на `telemetry-burst` и `firmware-v3.18`.
- Формат C consistently uses ~12–15% fewer токенов, но требует больше инструкционной структуры.
- Дополнительный шум с `status=unverified/unsupported` не сбивает модель, однако заметно увеличивает время ответа для варианта C.

## Next Questions
1. Протестировать увеличенные корпусные файлы (≥50 капсул) для оценки масштабируемости.
2. Сравнить результаты с другими моделями (например, gpt-4.2, o4-mini).
3. Автоматизировать сбор метрик токенов/времени в отдельный скрипт.

## Artifacts
- Контексты: `experiments/contexts/variant_a.context`, `variant_b.context`, `variant_c.context`.
- Контексты с шумом: `experiments/contexts/variant_a_noise.context`, `variant_b_noise.context`, `variant_c_noise.context`.
- Промпты: `experiments/prompts/variant_a_prompt.txt`, `variant_b_prompt.txt`, `variant_c_prompt.txt` и соответствующие `*_noise_prompt.txt`.
- Запуски: `experiments/results/variant_*_codex*.jsonl` (включая `temp07` и `noise`).
- Извлечённые ответы: `experiments/results/variant_*_codex*_extracted.json`.
