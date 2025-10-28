# DCTX Context Format A/B Testing Plan

## Objective
Evaluate how effectively large language models solve a complex troubleshooting task when provided with different context encodings derived from the same knowledge base. The task should be unsolvable without the provided context.

## Task Definition
- **Scenario**: Diagnose and remediate throughput drops in the "Aquila" event ingestion pipeline after a silent rollout of firmware v3.18 on edge collectors.
- **Required Answer**: The model must produce the exact configuration patch:
  ```
  analytics.streams.ingest.stage3.window.max_skew_ms=1200
  analytics.streams.ingest.stage3.watermark.offset_ms=350
  analytics.streams.replicator.quorum.min_nodes=5
  ```
  Plus a brief justification (<40 words) that references the `telemetry-burst` anomaly and the `firmware-v3.18` release note.
- **Impossible Without Context**: None of the above values are deducible from the user prompt alone; they exist only inside the context payloads.

## Evaluation Metrics
1. **Correctness** – exact config keys and values, justification references required terms.
2. **Extraction Robustness** – whether the model ignores high-volume noise capsules.
3. **Latency Tokens** – prompt token count per variant.
4. **Error Patterns** – capture deviations (wrong numbers, missing keys, hallucinated fixes).

## Variants
- **Variant A**: Canonical DCTX capsules with explicit metadata ordering.
- **Variant B**: DCTX-Compact (collapsed headers, shared metadata bundles) to test higher density.
- **Variant C**: Hybrid Outline (section tags + inline tables) for comparison against a semi-structured format.

## Noise Strategy
- Insert outdated remediation suggestions with lower priority (`pr=8-9`).
- Add telemetry dumps and irrelevant metrics at different timestamps.
- Include a misleading capsule referencing `window.max_skew_ms=2200` flagged as deprecated via attribute `+ status=deprecated`.

## Execution Steps
1. Generate the three context files under `experiments/contexts/`.
2. Prepare Codex prompts that inject each context variant and pose the remediation question.
3. Run `codex exec` for each variant, capture raw JSON outputs.
4. Summarise findings in `.agents/context/DCTX/evals/`.

## Timeline
- Context authoring: ~45 minutes.
- Test execution: ~30 minutes.
- Reporting: ~20 minutes.
