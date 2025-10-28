# DCTX Format Specification (v1.0 Draft)

## 1. Overview
DCTX (Deterministic Context eXchange) is a plain-text, canonical serialization designed for storing and reusing knowledge capsules inside AI systems. The format emphasises determinism, semantic fidelity, and token efficiency so language models can reliably load the same context without wasting prompt budget.

## 2. Design Goals
1. **Deterministic reproduction** – identical logical data always produces byte-identical output.
2. **Token economy** – common tokens are short, whitespace is minimised, and optional elements default to omission.
3. **Semantic precision** – metadata keeps provenance, priority, and validity intervals explicit.
4. **Incremental diffability** – capsule boundaries and stable ordering simplify merging and version control.
5. **Forward compatibility** – rigid core with extension points that do not break existing parsers.

## 3. Document Layout
A DCTX document is composed of ordered blocks:

1. **Magic header**: single line `@DCTX/1` signalling the schema major version.
2. **Document metadata block**: zero or more lines describing the document itself.
3. **Capsule block sequence**: one or more knowledge capsules.
4. **Digest footer** (recommended): one line cryptographic hash of the canonical body.

Whitespace rules: only `\n` line endings, no trailing spaces, no blank lines except the single separator described below.

### 3.1 Document Metadata Block
Metadata lines begin with `#` and follow the pattern `# <key>=<value>`. Keys are required to be lowercase ASCII. Canonical order sorts keys lexicographically. Reserved keys:

- `id` – stable document identifier (ULID or UUID).
- `created` – ISO 8601 timestamp in UTC.
- `agent` – authoring system identifier.
- `locale` – BCP 47 language tag for human-facing text.
- `schema` – semantic schema identifier for capsules if specialised.

Custom keys must be prefixed with `x-`.

### 3.2 Capsule Blocks
Each capsule captures a coherent unit of knowledge. Capsules must appear in non-decreasing `ts` order.

A capsule consists of three logical sections without blank lines between them:

1. **Capsule header** – single line starting with `*`:
   ```
   * id=<capsule-id> ts=<iso8601> ty=<type> pr=<priority> src=<source>
   ```
   Field order is fixed. Omit `pr` or `src` entirely if unknown. Allowed priorities: `0` (highest) to `9` (lowest).
2. **Attribute lines** – optional lines for structured metadata, each beginning with `+` and sorted by key:
   ```
   + key=value
   ```
   Keys use lowercase ASCII; values follow the encoding rules in §4.4. Recommended reserved keys include `span` (validity interval), `tags` (comma-separated, alphabetically sorted), `ref` (cross-document reference), `sig` (cryptographic signature).
3. **Content block** – one or more lines containing the payload, each starting with `>`:
   ```
   > text segment
   > continued segment
   ```
   The payload is semantically opaque to DCTX but must already be canonicalised (e.g., trimmed, normalised Unicode NFC, line length ≤ 300 characters). Multi-line content remains part of the single capsule. Back-to-back capsules are separated by exactly one newline.

Capsule termination is implicit: the next capsule header `*`, digest line `=` or end-of-file closes the current capsule.

### 3.3 Digest Footer
Optional integrity line beginning with `=`:
```
= sha256:<hex>
```
The digest covers all bytes from the magic header through the newline before the digest line. Producers must compute it over the canonical form; consumers MAY verify if present.

## 4. Encoding Rules

### 4.1 Character Set
- ASCII only (0x20–0x7E) to avoid multi-token surprises.
- Use literal `\n` (LF) for newlines; no CR characters.

### 4.2 Whitespace
- Single space separates tokens within header lines.
- No leading or trailing spaces elsewhere.
- Attribute values must not contain unescaped double spaces; collapse sequences unless semantically significant.

### 4.3 Identifiers
- `id` fields use base32 crockford ULIDs (`7`-bit uppercase) for lexical sorting while embedding timestamps.
- `ts` values use extended ISO 8601 with `Z` suffix (`YYYY-MM-DDTHH:MM:SSZ`).
- `src` adopts URI compact forms (e.g., `doc:research-notes`).

### 4.4 Value Escaping
Values are tokenised to minimise special characters. Escape rules:
- Escape literal spaces at the start or end with `\_` (underscore indicates escaped space).
- Escape literal `=` as `\=` and `,` as `\,` within values.
- Represent newline inside values with `\n`; actual newlines are forbidden in value fields.
- Use `\>` at the start of a content line to represent a literal leading `>`.

### 4.5 Ordering Guarantees
- Document metadata: keys ascending.
- Capsules: sorted by `ts`, tie-breaking with `id`.
- Attribute lines: keys ascending.
- `tags` lists: comma-separated, no spaces, ASCII sorted.

### 4.6 Deterministic Normalisation Pipeline
Producers MUST apply the following steps before serialisation:
1. Canonicalise Unicode to NFC and strip control characters.
2. Trim external whitespace; collapse internal runs to single spaces except in code blocks stored as content (handled before stage 1).
3. Sort structures per §4.5.
4. Validate that mandatory fields (`id`, `ts`, `ty`) exist.
5. Compute digest if requested.

Consumers MAY assume the serialisation adheres to this pipeline and should reject capsules that violate ordering or escaping rules.

## 5. Token Economy Features
1. **Symbol budget** – single-character sigils (`@`, `#`, `*`, `+`, `>`, `=`) reduce the need for verbose keywords.
2. **Short field names** – `ts`, `ty`, `pr`, `src` stay within one or two subword tokens in common LLM BPE vocabularies.
3. **Comma-less lists** – omit spaces in comma-separated values to minimise token splits.
4. **Predictable patterns** – consistent prefixes help LLMs compress attention weights and recall structures efficiently.
5. **Optional sections** – writers omit unused metadata instead of serialising empty scaffolding.

## 6. Extension Mechanism
- New sigils MUST start with `~` followed by a single uppercase letter (e.g., `~E event` block) and be registered in a shared catalogue.
- Attribute keys with namespace prefixes (`x-`, `exp-`) are reserved for experimentation.
- Consumers MUST ignore unknown `+` keys and `~` blocks while preserving order.

## 7. Operational Guidance
- Store each capsule as an atomic knowledge statement (fact, rule, summary) to keep retrieval granular.
- When updating content, reuse the same capsule `id` and append a new capsule with `ty=revision` referencing the prior `ref=<id>`.
- Use the digest footer in distributed environments to detect tampering.
- For embedding stores, pair each capsule with a vector index keyed by `id`; DCTX transports the human-readable payload.

## 8. Reference Example
```
@DCTX/1
# agent=context-service
# created=2025-10-28T12:04:05Z
# id=01J37QJ8K8F2P8C08TG51F5Q5Q
* id=01J37QJ8K8G8W0HCFT5RJQ4A0M ts=2025-10-28T12:05:00Z ty=summary pr=4 src=note:manual
+ tags=context,format
> DCTX фиксирует знания как капсулы с каноническими полями и минимальной пунктуацией.
* id=01J37QJ8K8G8W0HCFT5RJQ4A0N ts=2025-10-28T12:05:30Z ty=guideline pr=5 src=spec:dctx
+ span=2025-10-28T12:05:30Z/2026-10-28T12:05:30Z
+ tags=context,maintenance
> Перед сохранением применяй нормализацию NFC и сортировку ключей.
= sha256:1b5c3fa7e9b4a8f9df0c6461f6a2fb0906be1cadaf7a4fcdb0d8f871dc1f6a2a
```

## 9. Next Steps
- Finalise field catalogue for common `ty` values (e.g., `summary`, `fact`, `prompt`, `plan`).
- Build reference parser/serializer with canonical checks.
- Define test corpus ensuring round-trip determinism.
