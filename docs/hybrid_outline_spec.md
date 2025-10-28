# Hybrid Outline Format (Variant C) — Relations Extension

## Recap
Hybrid Outline stores capsules as INI-like sections where each block encapsulates metadata and payload lines. Section headers follow `[type index]` and fields use simple `key=value` syntax.

## New Section: Relations
- Optional block appended near document end:
  ```
  [relations]
  rel=<from_id>|<relation>|<to_id>
  ```
- `from_id` / `to_id` correspond to `section_id` values inside capsule sections (e.g., `section_id=analysis_83`).
- Allowed relation verbs (extensible): `triggers`, `recommends`, `supported_by`, `enforced_by`, `contradicts`, `mitigates`.
- Keep the relation list sparse and ordered by causal flow (upstream → downstream).

## Section IDs
- Any capsule participating in relations MUST declare `section_id=<identifier>` directly under metadata fields.
- Identifiers use lowercase snake-case; indices may be appended (e.g., `metric_81`).

## Example Snippet
```
[analysis 83]
section_id=analysis_83
...

[relations]
rel=metric_81|triggers|analysis_83
rel=analysis_83|recommends|guide_84
rel=guide_84|supported_by|release_note_85
rel=guide_84|enforced_by|decision_86
rel=playbook_82|contradicts|analysis_83
```

## Guidance
1. Document only actionable links; omit obvious or redundant edges to save tokens.
2. When multiple relations share the same source, group them consecutively.
3. Update prompts to mention “relations block encodes causal links; use it when reasoning about dependencies.”

These rules are applied to both the baseline `variant_c.context` and the 86-capsule scale dataset.
