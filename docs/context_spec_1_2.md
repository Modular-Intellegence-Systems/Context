# CONTEXT/1.2 + CTX-CANON/3 Specification

## 0. Goals (non-negotiable)

* **Determinism**: identical meaning → identical canonical byte stream.
* **Universality / Extensibility**: the format defines only the container and rules; semantics / ontologies live outside; extensions via namespaces.
* **Token efficiency**: short keys, `feed` profile for direct LLM consumption.
* **Atomicity**: one capsule holds one unit of meaning (fact, skill, rule, inference, trace step, resource, code, noise).
* **Explicit relations**: strictly typed triples.
* **Traceable reasoning**: steps are structural nodes, no free-form chain-of-thought.
* **Append-only evolution**: updates via new capsules + relations.
* **Global addressing**: identifiers survive corpus merges.
* **Security**: digest + optional multi-signatures, no footer comments.

## 1. Versioning & Profiles

First line (magic):

```
@CONTEXT/1.2 profile=<human|feed> canon=CTX-CANON/3
```

Profiles:

- `human`: human-readable.
- `feed`: ultra-compact for direct LLM ingestion.

Compatibility: 1.2 shares the core ideas with 1.0/1.1; new features (namespaces, global refs, signatures) live behind explicit constructs.

## 2. Namespaces (NS)

Optional but required when using prefixed identifiers. Section `[ns]`:

```
[ns]
ctx=ctx:
ops=ops:
bio=https://example.org/bio#
```

Rules:

- Prefix = `^[a-z][a-z0-9_]{0,15}$`.
- Value = URI/URN/opaque identifier.
- Relations, types, ops **must** use QNames (`ctx.supports`, `ops.call`). Bare words are prohibited.

### 2.1 Namespace governance

Governance rules are expressed explicitly:

```
[ns-governance]
ctx.status=locked                  ; `ctx` vocabulary is immutable
collision.policy=reject            ; reject|alias
alias.pred.1=ctx.supports->ex.supports
pred.deprecated-since.ctx.clarifies=1.4
```

- `ctx.status=locked` freezes the base namespace; new predicates/types MUST use vendor prefixes.
- `collision.policy=reject` blocks conflicting declarations. When set to `alias`, aliases MUST be listed via `alias.pred.N=a->b`, applied before canonicalisation; cycles are errors.
- `pred.deprecated-since.<QName>=<semver>` records the earliest minor version where a predicate is discouraged; tools MAY warn when reading documents with equal or newer schema versions.
- Governance entries participate in the canonical digest and SHOULD be present in multi-team registries.

## 3. Global addressing

### 3.1 Identifiers

- **Document ID** (`doc` in `[meta]`): ULID (26 chars, Crockford base32, lowercase).
- **Capsule ID** (`cid`): `^[a-z0-9_]{3,32}$` (unique within document).
- **Global reference (GREF)**:
  - By document: `@<doc>#<cid>`.
  - By content hash: `@sha256:<64hex>` (canonical capsule hash).

### 3.2 Usage

Capsule references can be local (`cid`) or global (`@doc#cid`, `@sha256:...`).

### 3.3 Resolution workflow

All producers **MUST** declare how GREFs are resolved:

1. `[meta]` **SHALL** include `resolver.scheme=<ctx|https|did|ipfs|vendor|file>` describing the primary discovery protocol. Optional `resolver.policy=<text>` documents custom rules (e.g. cache TTL, auth scope).
2. Optional `[repo <id>]` sections enumerate repositories. Each entry MUST contain `uri=<absolute-uri>` and MAY supply `priority=<0-9>` (default `5`). Repositories are queried in ascending `priority`, then lexicographic `<id>`.
3. Resolution order is deterministic: (a) local document (match by `cid`), (b) declared repositories, (c) well-known resolver for the selected scheme (see Annex R), (d) direct `@sha256` verification when payload is supplied inline.
4. Failures emit canonical resolver codes: `R404` (missing), `R409` (conflict), `R422` (digest mismatch), `R503` (resolver unavailable). Implementations MUST surface these codes via lint diagnostics and MAY propagate them into `err` fields of trace capsules.
5. Consumers MUST treat unresolved references as errors; silent fallback to best-effort is prohibited.

*Acceptance criterion:* a corpus containing (a) an external `@doc#cid` resolvable through `[repo]`, and (b) a `@sha256` reference with matching payload, passes lint. Corrupting the repository URI MUST trigger `R404`.

## 4. Entities

### 4.1 Capsule blocks `[cap <cid>]`

Mandatory keys:

| Key  | Meaning                | Format                                                                                                                                              |
|------|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `t`  | type                   | `ctx.K`, `ctx.S`, `ctx.R`, `ctx.I`, `ctx.E`, `ctx.P`, `ctx.L`, `ctx.C`, `ctx.N`, `ctx.T` or `ns.Type`.                                               |
| `p`  | priority               | `0..9`.                                                                                                                                             |
| `cf` | confidence             | `0.000..1.000` (exactly three decimals).                                                                                                            |
| `ts` | timestamp              | RFC3339 (with Z or offset).                                                                                                                         |
| `ttl`| review horizon         | ISO8601 duration (`P30D`, `P1Y2M`, ...).                                                                                                             |
| `src`| provenance             | Escaped string (URI/URN/opaque).                                                                                                                    |
| `lang`| language              | BCP47 tag (`en`, `en-US`, `ru`).                                                                                                                     |
| `tags`| tags                  | CSV, items `[a-z0-9._-]+`, sorted & unique.                                                                                                         |
| `note`| remark                | Repeatable short string (≤ 256 UTF-8 chars).                                                                                                        |
| `d`  | payload                | Inline string (`d=value`) **or** block `d@<mime><<EOF ... EOF`.                                                                                    |

Optional structural keys:

- `cf.src=<policy-id>` — links to `[policy.cf]` (defaults to document-wide `policy.cf[0]`).
- `ts.event`, `ts.ingest`, `ts.logical` — multi-clock timestamps; when absent, `ts` populates all three.
- `dir`, `script` — text direction and script (see §H-05).
- `kind=ctx.event|ctx.state` — distinguishes events from states.
- `safe.hint=trusted|untrusted` — guidance for downstream LLM ingestion (see §H-08).
- `index.*`, `provenance.*`, `code.*`, `license.*` — described in §H.

#### Trace capsules (`t=ctx.T`)

Additional keys:

- `op` – QName (default set `ctx.retrieve`, `ctx.deduce`, `ctx.compute`, `ctx.decide`, `ctx.validate`, `ctx.plan`, `ctx.execute`, `ctx.summarize`, `ctx.branch`, `ctx.merge`).
- `in` – CSV of inputs (each entry: `cid` / `@doc#cid` / `@sha256:...` / literal `L"..."`).
- `out` – CSV of outputs (`cid` / global ref).
- `cost.kind` – QName (`ctx.tokens`, `ctx.ms`, or extension).
- `cost.val` – number with up to 6 decimals.
- `err` – error code (string) if failure.
- `enc.*` — optional encryption envelope (see §B-07) and mutually exclusive with `d`/`d@`.

Literals inside `L"..."` support escapes: `\", \\, \n, \t, \|, \=`.

### 4.2 Trace blocks `[trace <chain>]`

```
goal=<cid|GREF>
head=<cid>
halt=<cid>        ; optional
status=<QName>    ; e.g. ctx.ok, ctx.fail, ctx.partial
ts=<RFC3339>
tags=<csv>
parent=<chain_id> ; optional
```

Ordering of `ctx.T` steps is defined via relations `ctx.applied_by` (see below).

**Invariants:**

- The directed graph of trace steps with edges `ctx.applied_by` MUST remain acyclic.
- `ctx.branch` steps MUST emit ≥2 outgoing `ctx.applied_by`; `ctx.merge` steps MUST consume ≥2 inputs and all contributing step IDs shall be present in `in`.
- Every `out` identifier MUST resolve to an existing capsule (local `cid` or valid GREF).
- Sub-traces inherit scope from `parent`; absence of `parent` denotes root traces.
- Traces terminate at `halt` or any node with zero outgoing `ctx.applied_by` edges.

### 4.3 Relations `[rel]`

One per line:

```
r=<subj>|<pred>|<obj>[|w=<0..1>][|ts=<RFC3339>]
```

- `subj`/`obj` – `cid` or `GREF`.
- `pred` – QName (prefix from `[ns]`).
- `w` – optional weight.

Reserved predicates `ctx.*`:
`ctx.clarifies, ctx.supports, ctx.contradicts, ctx.derived_from, ctx.applied_by, ctx.depends_on, ctx.duplicates, ctx.supersedes, ctx.retracts, ctx.cites`

Extensions use custom namespaces (`ex.aligned_with`, ...).

### 4.4 Attachments (optional)

Descriptor in `[meta]` or separate `[att]` entries:

```
att=<name>|mime=<mime>|sha256=<64hex>|bytes=<uint>|uri=<URI>
```

Fields `sha256` and `bytes` are mandatory; omitting either is a lint blocker. Capsule payload may reference attachment via `d=^att:<name>` (in `feed`) or `d@...` for inlined data.
The descriptor line **is part of the canonical byte stream**. Implementations MUST verify that dereferenced bytes match both `sha256` and `bytes`. Optional `sig.alg`, `sig.key`, `sig.base64` fields MAY sign individual attachments. When both inline payload and attachment exist, the inline payload is authoritative for digest computation; attachment integrity MUST still be checked before use.

### 4.5 Encrypted payloads

Capsules MAY protect sensitive content via an encryption envelope which replaces `d`/`d@`:

```
enc.alg=aes-256-gcm
enc.keyref=did:key:z...
enc.iv=base64url(...)
enc.tag=base64url(...)
enc.ct=^block:application/octet-stream:<len>
privacy.class=pii|psi|none
```

- `enc.*` keys are mutually exclusive with `d`/`d@`.
- Consumers MUST verify authentication tags and MUST discard ciphertext when key material is unavailable (cryptographic deletion).
- `privacy.class` declares legal sensitivity; downstream policies MAY reject classes outside approved sets.

## 5. Metadata `[meta]`

```
[meta]
doc=<ULID>
author=<string>
date=<RFC3339>
schema=CONTEXT
version=1.2
units=ctx.tokens
lang=<BCP47 default>
policy.cf=<text>
policy.ttl=<text>
resolver.scheme=<ctx|https|did|ipfs|vendor|file>
resolver.policy=<text>
sig.policy=k-of-n
sig.k=2
```

`policy.*` describe how to treat `cf`, `ttl`. `resolver.*` fields define the primary discovery mechanism for resolving external capsules (see §3.3). `sig.policy` and `sig.k` configure multi-signature quorum thresholds (see §7).

### 5.1 Repository sections `[repo <id>]`

Each optional repository section MUST look as follows:

```
[repo <id>]
uri=<absolute-uri>
priority=<0-9>        ; optional, default 5
auth=<opaque token>    ; optional scheme-specific material
```

Identifiers obey `^[a-z0-9._-]{3,32}$`. Repositories are canonicalised by ascending `priority`, then lexicographically by `<id>`. Missing `priority` implies `5`. Implementations SHALL iterate repositories exactly in that order when resolving GREFs.

### 5.2 Confidence calibration `[policy.cf]`

Confidence metadata becomes machine-readable:

```
[policy.cf]
id=cf.platt.v1
kind=probability              ; probability|score
model=ctx.platt               ; ctx.platt|ctx.isotonic|ns.Custom
params=a=-1.37;b=3.02         ; optional model parameters
domain=[0,1]
monotone=true
mapping=global                ; global|per-tag|per-type
```

- Documents MAY include multiple `policy.cf` sections; capsules reference them via `cf.src=<id>`.
- Consumers MUST perform deterministic monotonic normalisation when aggregating corpora with different policies (e.g. re-scaling to a shared spline defined in Annex CF).

### 5.3 Review horizon `[policy.ttl]`

```
[policy.ttl]
id=ttl.v1
states=fresh,grace,stale,expired
grace=P14D
stale=P90D
expired.action=exclude        ; include|exclude|demote
```

- `ttl` on capsules references this policy; once state=`expired`, consumers MUST apply the declared action.
- Lint SHALL warn when `ts` implies state `stale` or `expired` at validation time.

## 6. Canonicalisation CTX-CANON/3

1. UTF-8, Unicode NFC.
2. LF line endings, file terminates with a single LF.
3. No tabs outside block payloads (`d@...`) and literals (`L"..."`); trailing spaces stripped everywhere.
4. Forbidden code points:
   - All Unicode categories Cc/Cf **except** `LF (U+000A)`; `TAB (U+0009)` is permitted only within block payloads or literals.
   - Surrogate halves (`U+D800–U+DFFF`) and stray `BOM (U+FEFF)` anywhere after the first byte.
   - Zero-width characters (`U+200B`, `U+200C`, `U+200D`, `U+2060`).
   - `NBSP (U+00A0)` allowed only within block payloads or literals when semantically required.
   - Non-BMP code points MUST be valid Unicode scalar values encoded in UTF-8.
5. Comments (`#`, `;`) allowed outside `[footer]`; removed in canon; MUST NOT carry semantics.
6. Section order: `[ns]?`, `[meta]`, `[repo ...]*` (lexicographic `<id>`), `[cap ...]*` (lexicographic `cid`), `[trace ...]*`, `[rel]`, `[footer]`.
7. Capsule key order: `t, p, cf, cf.src, ts, ts.event, ts.ingest, ts.logical, ttl, src, lang, dir, script, kind, tags, note*, in, out, op, cost.kind, cost.val, err, enc.alg, enc.keyref, enc.iv, enc.tag, enc.ct, privacy.class, d`.
8. Tags sorted & unique.
9. Escapes for single-line values: `\ → \\`, `| → \|`, `= → \=`.
10. Literals `L"..."`: allow `\", \\, \n, \t, \|, \=`.
11. Numbers: decimal point, no exponent; `cf` three decimals; `cost.val` up to six.
12. Digest input: canonical content from start to line `digest-base16=` (exclusive).
13. `digest-base16` – lowercase, 64 hex chars.
14. ULID lowercase 26 chars.
15. Attachment descriptors participate in digest calculation exactly as written; referenced binary bytes remain external but MUST match the declared `sha256` and `bytes` values.
16. When multiple timestamp fields exist, canonical consumers order reasoning steps by `ts.logical`, then `ts.event`, then `ts.ingest`, finally by `cid`.

## 7. Footer `[footer]`

```
[footer]
digest=sha256
digest-base16=<64hex>
sig.count=<N>
sig.1.alg=ed25519
sig.1.key=<key-id>
sig.1.epoch=<int>
sig.1.ts=<RFC3339>
sig.1.base64=<base64url>
...
```

`sig.count` optional (default 0). No comments allowed in footer.

Multi-signature rules:

- Signatures are indexed `1..N`; indices need not be contiguous but MUST be unique.
- `sig.policy=k-of-n` with `sig.k` from `[meta]` defines the acceptance quorum; validators ensure at least `k` signatures verify against declared keys.
- `sig.<i>.epoch` increments on key rotation; older documents remain valid when verified against historical public keys.
- `sig.<i>.ts` SHOULD reflect signing time and MAY be anchored via RFC3161 TSA evidence (Annex SIG).

## 8. Feed profile

Header identical with `profile=feed`.

Capsule line:

```
c|<cid>|<t>|p=<0-9>|cf=<0.000-1.000>|ts=<RFC3339>|ttl=<ISO8601>|lang=<BCP47>|tags=<csv>|src=<s>[|n=<note>]*[|in=<items>][|out=<refs>][|op=<QName>][|cost.kind=<QName>][|cost.val=<num>][|err=<code>]|d=<inline|^block:<mime>:<len>|^att:<name>>
```

Block data: next line holds `<len>` bytes. No comments/blank lines permitted.

Relations & traces use compact forms `r|...`, `t|...`.

Recommended selection order for feeding LLMs: high-priority `ctx.S/ctx.R`, followed by `ctx.K/ctx.I`, required `ctx.T`, finishing with `ctx.E/ctx.L`; exclude `ctx.N` and `cf<0.5` unless needed.

## 9. Evolution rules

- Update: new capsule + `ctx.supersedes` relation.
- Retraction: new capsule + `ctx.retracts`.
- Merge: unite sets; `cid` collisions forbidden; cross-document references via GREF (`@doc#cid`).
- Selection precedence: non-retracted > superseding > superseded.

### 9.1 Versioning metadata `[versioning]`

```
[versioning]
semver.major.breaks.canon=true
minor.adds.keys=true
minor.adds.predicates=true
minor.cannot.change.canon=true
patch.docs.only=true
sunset.ctx.predicates=P36M
```

- CTX-CANON/3 is immutable; any change to canonical ordering requires a MAJOR release.
- MINOR releases MAY introduce new keys/predicates via namespaces but MUST remain backward compatible with existing documents.
- PATCH releases are editorial only.
- `sunset.ctx.predicates` defines the minimum support window for deprecated core predicates.

## 10. Lint gates (normative)

1. Header exactly `@CONTEXT/1.2 ...`.
2. `[meta].doc` valid ULID; `[footer].digest-base16` 64 hex lower.
3. `[meta].resolver.scheme` present and within allowed domain; `[repo]` sections (if any) have unique IDs and ordered priorities.
4. All `cid` unique; regex compliant.
5. All QNames have declared prefixes.
6. All refs resolve (`cid` or GREF); weight/time valid; unresolved refs emit canonical resolver codes.
7. Tags sorted & unique.
8. `ts`, `ttl`, `cf`, `cost.*` obey syntax.
9. For each `ctx.T`, outputs exist (or GREF to known doc).
10. Trace graph DAG under `ctx.applied_by`.
11. Attachment descriptors include `sha256`+`bytes`; dereferenced payloads match both values.
12. Multi-signature policy satisfied: at least `sig.k` valid signatures and non-decreasing epochs.
13. Canonical dump reproduces digest.
14. `[footer]` contains only `digest`, `sig.count`, `sig.*` keys.
15. Capsules using `enc.*` omit `d`/`d@`; ciphertext length matches declared `enc.ct` wrapper.

## 11. Example (human)

```
@CONTEXT/1.2 profile=human canon=CTX-CANON/3
[ns]
ctx=ctx:
ops=ops:

[meta]
doc=01jdz5y5zn7p5qv2v9eq5gf6sn
author=spec-team
date=2025-10-28T17:05:00Z
schema=CONTEXT
version=1.2
units=ctx.tokens
lang=en

[cap k_lr_plateau]
t=ctx.K
p=7
cf=0.920
ts=2025-10-28T17:06:00Z
ttl=P180D
src=paper:adamw
lang=en
tags=ml,optimization,training
d=Lowering learning rate after plateau reduces validation loss by 3-7%.

[cap s_rag_proc]
t=ctx.S
p=8
cf=0.900
ts=2025-10-28T17:06:10Z
ttl=P90D
src=ops:rag
lang=en
tags=procedure,rag
note=Procedure suitable for multi-hop QA.
d@text/markdown<<MD
1. Formulate intent.
2. Retrieve top-k (k=6, λ=0.3).
3. Compress to 4-6 bullets.
4. Synthesize with attribution.
MD

[cap i_token_saving]
t=ctx.I
p=9
cf=0.830
ts=2025-10-28T17:06:20Z
ttl=P60D
src=exp:ab-42
lang=en
tags=insight,latency,token_budget
d=Explicit capsules and relations save ~20% tokens on multi-hop tasks.

[cap t_step1]
t=ctx.T
p=7
cf=0.900
ts=2025-10-28T17:06:25Z
ttl=P30D
src=ops:rag
lang=en
.tags=trace
op=ctx.retrieve
in=s_rag_proc
out=t_step2
cost.kind=ctx.tokens
cost.val=512

[cap t_step2]
t=ctx.T
p=7
cf=0.880
ts=2025-10-28T17:06:27Z
ttl=P30D
src=ops:rag
lang=en
.tags=trace
op=ctx.deduce
in=k_lr_plateau,t_step1
out=i_token_saving

[trace ch_ab42]
goal=i_token_saving
head=t_step1
halt=t_step2
status=ctx.ok
ts=2025-10-28T17:06:30Z
.tags=reasoning,ab-test

[rel]
r=k_lr_plateau|ctx.supports|i_token_saving|w=0.6|ts=2025-10-28T17:06:32Z
r=s_rag_proc|ctx.clarifies|i_token_saving
r=t_step1|ctx.applied_by|t_step2
r=t_step2|ctx.derived_from|k_lr_plateau

[footer]
digest=sha256
digest-base16=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

## 12. Feed example

```
@CONTEXT/1.2 profile=feed canon=CTX-CANON/3
c|k_lr_plateau|ctx.K|p=7|cf=0.920|ts=2025-10-28T17:06:00Z|ttl=P180D|lang=en|tags=ml,optimization,training|src=paper:adamw|d=Lowering learning rate after plateau reduces validation loss by 3-7%.
c|s_rag_proc|ctx.S|p=8|cf=0.900|ts=2025-10-28T17:06:10Z|ttl=P90D|lang=en|tags=procedure,rag|src=ops:rag|n=Procedure suitable for multi-hop QA.|d=^block:text/markdown:109
1. Formulate intent.
2. Retrieve top-k (k=6, λ=0.3).
3. Compress to 4-6 bullets.
4. Synthesize with attribution.
c|i_token_saving|ctx.I|p=9|cf=0.830|ts=2025-10-28T17:06:20Z|ttl=P60D|lang=en|tags=insight,latency,token_budget|src=exp:ab-42|d=Explicit capsules and relations save ~20% tokens on multi-hop tasks.
c|t_step1|ctx.T|p=7|cf=0.900|ts=2025-10-28T17:06:25Z|ttl=P30D|lang=en|tags=trace|src=ops:rag|op=ctx.retrieve|in=s_rag_proc|out=t_step2|cost.kind=ctx.tokens|cost.val=512
ec|t_step2|ctx.T|p=7|cf=0.880|ts=2025-10-28T17:06:27Z|ttl=P30D|lang=en|tags=trace|src=ops:rag|op=ctx.deduce|in=k_lr_plateau,t_step1|out=i_token_saving
r|k_lr_plateau|ctx.supports|i_token_saving|w=0.6|ts=2025-10-28T17:06:32Z
r|s_rag_proc|ctx.clarifies|i_token_saving
r|t_step1|ctx.applied_by|t_step2
r|t_step2|ctx.derived_from|k_lr_plateau
```

---

This specification defines the format only; treatment policies, ontologies, toolchains, and provenance semantics remain under the control of consuming systems.

## 13. Extended normative appendices (High priority)

### 13.1 JSONL / JSON-LD projection

- Canonical JSONL projection emits one record per capsule/relation/trace using the following schema:
  - `{"rec":"cap","doc":"<ULID>","cid":"<id>","t":"<QName>","p":int,"cf":float,"ts":{"event":...,"ingest":...,"logical":...},"lang":"...","tags":[...],"d":<string|object|ref>,"enc":{...}?,"provenance":{...}?}`
  - `{"rec":"rel","doc":"<ULID>","subj":"<cid|GREF>","pred":"<QName>","obj":"<cid|GREF>","w":float?,"ts":"<RFC3339>?"}`
  - `{"rec":"trace","doc":"<ULID>","id":"<chain_id>","goal":"<ref>","head":"<cid>","halt":"<cid>?","parent":"<chain_id>?","status":"<QName>","tags":[...]}`
- JSON-LD documents MUST include `@context` reusing prefixes from `[ns]`; core predicates map to PROV-O where applicable (`ctx.derived_from → prov:wasDerivedFrom`, etc.).
- Round-trip requirement: `context → jsonld → context` MUST preserve canonical bytes (ordering may differ but digest recomputed matches).

### 13.2 Code capsules (`t=ctx.C`)

- Mandatory metadata: `code.lang`, `code.ver`, `code.env`, multiple `code.dep=<ecosystem:spec>`, optional `exec.entry`.
- The combination MUST be sufficient to reproduce the artefact environment without inspecting payload contents.

### 13.3 Error taxonomy

- Trace or capsule-level errors use structured keys: `err.class=io|net|tool|llm|auth|data|unknown`, `err.code=<TOKEN>`, `err.retriable=true|false`, `err.cause=L"..."`, `err.at=<cid>`.
- Lint enforces known classes; vendor-specific values use prefixed QNames.

### 13.4 Chunked payload streaming

- `d=^chunk:<mime>:<total_bytes>:<index>:<len>:<sha256>` (feed profile). Each chunk line is immediately followed by a block of `<len>` bytes.
- Chunks MUST start at `index=0` and increase by 1. Concatenated bytes MUST hash to `<sha256>` and equal `<total_bytes>` length.
- Mixing `^chunk` and other payload types for a single capsule is forbidden.

### 13.5 Internationalisation

- Capsules MAY declare `dir=rtl|ltr|auto` and `script=<ISO15924>`; defaults derive from `lang`.
- Consumers MUST respect `dir` when rendering aggregated prompts.

### 13.6 Indexing hints

- `index.hint=none|light|full`, `index.fields=<csv>`, `index.weight=<0..1>` guide deterministic selection of fields for retrieval systems.

### 13.7 Tag ontologies

- `tags.schema=<URI>` and `tags.ns=<prefix>` allow validation against controlled vocabularies; validators SHALL flag unknown tags when a schema is supplied.

### 13.8 LLM safety hints

- `safe.hint=trusted|untrusted`; `safe.hint=untrusted` instructs consumers to sandbox or sanitise payloads. The optional MIME `text/safe-markdown` asserts that markdown is sanitised according to Annex SAFE.

## 14. Operational guidance (Medium priority)

### 14.1 Offline packaging

- `.contextpack` archives contain `manifest.context`, optional `att/<name>` payloads, and optional `SIGNATURES`. Archive signatures (outside the spec) SHOULD cover all entries.

### 14.2 Size recommendations

- Guidelines (lint-level warnings): ≤100k capsules/document, ≤256 KiB per payload (`^chunk` beyond), ≤2M relations, `note` ≤256 characters.

### 14.3 Units and numbers

- `units` accepts `ctx.tokens|ctx.ms|ctx.bytes|ctx.usd|<QName>`; numeric fields remain decimal without exponent.

### 14.4 Duplicate semantics

- `ctx.duplicates` stored once with lexical ordering `min(subj,obj) → max(subj,obj)`; mirrored edges are errors.

### 14.5 Provenance

- Structured provenance keys: `provenance.agent=human|llm|tool`, `provenance.model=<id>`, `provenance.temp=<float>`, `provenance.seed=<int>`.

### 14.6 Licensing

- `license.id`, `license.uri`, `license.notes` document downstream rights; consumers MAY filter by license id.

### 14.7 External relations

- Cross-document `rel` entries require verified descriptors (digest + signature) of the external document; otherwise lint emits `REL_EXTERNAL_DANGLING`.

### 14.8 Contextpack provenance

- Packaging metadata SHOULD include `pack.created=<RFC3339>` and `pack.author=<text>`; these values do not affect canonical digest but MUST be signed at archive level.

---

## 15. Acceptance test matrix

Reference artefacts ("golden files") SHALL be produced for each scenario below. Validators MUST demonstrate pass/fail outcomes exactly as specified.

| ID | Purpose | Expected outcome |
|----|---------|------------------|
| RES-DOC | `@doc#cid` via `[repo]` | Resolves successfully |
| RES-SHA | `@sha256:` reference | Resolve hit or `RESOLVE_NOT_FOUND` |
| RES-ERR | Broken repo URI | Lint error `RESOLVE_NOT_FOUND` |
| ATT-HASH-MISMATCH | Attachment bytes tampered | Lint error `ATTACHMENT_HASH_MISMATCH` |
| CAN-TAB | TAB outside payload | Lint error with position |
| CAN-ZWJ | Zero-width char usage | Lint error with U+ code |
| CAN-NBSP | NBSP misuse | Lint error |
| NS-COLLISION-REJECT | Prefix conflict, policy=reject | Lint error |
| NS-ALIAS | Alias rewrite | Canonical output normalised |
| CF-NORM-AGG | Two corpora, different `policy.cf` | Aggregated scores monotonic |
| TTL-EXPIRED-EXCLUDE | Capsule beyond expiry | Consumer excludes per policy |
| TR-BRANCH | Trace with branch/merge | DAG verified |
| TR-SUBTRACE | Parent/child traces | Invariants satisfied |
| ENC-NO-D | Capsule with `enc.*` but no `d` | Lint OK |
| SEM-MINOR-COMPAT | 1.2 doc read under 1.3 | Canon preserved |
| SIG-ROTATE-EPOCH | Multiple signatures w/ epoch | Quorum satisfied |
| SIG-2OF3 | k-of-n policy | Exactly k signatures required |
| TS-ORDER-LOGICAL | Mixed clocks | Sorting deterministic |
| JSON-ROUNDTRIP | JSON-LD round-trip | Digest equality |
| CH-REASSEMBLE | Chunked payload | Reconstructed hash matches |
| SAFE-UNTRUSTED | `safe.hint=untrusted` | Consumer sandbox enforced |

Future revisions SHALL attach file names (e.g. `tests/RES-DOC.context`) and computed digests for reproducibility.

### 15.1 Automation

A reference validator (`tests/run_goldens.py`) executes the full matrix:

```
python tests/run_goldens.py
```

The script parses each `tests/context/*.context`, computes the canonical digest via `ctx_lint.parse_document`, and compares the result with the expected JSON stored in `tests/outcomes/<name>.json`. CI pipelines MUST invoke this runner and fail the build on any mismatch (unexpected digest/profile/status).

---

## 16. Annexes (normative)

### Annex R — Resolver discovery (`wellknown.domain`)

1. If `resolver.scheme=ctx`, clients MUST attempt HTTPS GET on:
   - `https://<ULID>.context.wellknown.io/manifest.context`
   - `https://<ULID>.context.wellknown.io/signatures.json`
   Responses MUST be served with `Content-Type: text/plain` (for manifest) and `application/json` (for signatures).
2. DNS SRV record `_context._tcp.<ULID>.context.wellknown.io` MAY advertise alternate ports/hosts.
3. The manifest served MUST match the canonical bytes of the referenced document; clients verify `digest-base16` and signatures before trusting embedded capsules.
4. Failures to connect/time out MUST surface as `R503`; HTTP 404 → `R404`; digest mismatch → `R422`.
5. Vendors MAY register alternative `wellknown.domain` values; domains MUST be globally unique and listed in governance documentation.

### Annex SIG — Signature verification and TSA binding

1. Default algorithm `ed25519` verifies over the canonical byte stream up to (but excluding) `digest-base16=`. The signed payload is the UTF-8 canonical string.
2. When `sig.<i>.epoch` increases, previous public keys MUST remain resolvable for archival validation (e.g. via DID document history).
3. Optional TSA evidence is encoded as:
   - `sig.<i>.tsa.alg=rfc3161-sha256`
   - `sig.<i>.tsa.base64=<BASE64>` (DER-encoded timestamp token)
   Validators verify the TSA token against the same digest.
4. Quorum check: at least `sig.k` signatures validate; the remaining signatures MAY be present but are ignored beyond quorum.
5. Signatures MUST be ordered by increasing index; duplicates invalidate the footer.

### Annex CF — Confidence normalisation

1. When aggregating corpora with different `policy.cf`, consumers project each distribution onto `Q = {0.0, 0.1, …, 1.0}` quantiles.
2. Each corpus provides (or approximates) cumulative mapping `F^{-1}(q)` via the declared model (e.g. Platt scaling parameters or isotonic bin table). Missing mappings MUST be estimated via monotone interpolation.
3. Normalised confidence `cf_norm` is computed as:
   - `cf_norm = spline_interpolate(F_source(cf_raw), F_target^{-1})`, where splines are linear between adjacent quantile knots.
4. Consumers SHOULD persist the applied policy pair `<policy-source, policy-target>` to ensure auditability.
