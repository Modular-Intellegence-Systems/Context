#!/usr/bin/env python3
"""Lint and canonicalize CONTEXT/1.2 files (CTX-CANON/3)."""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

HEADER_RE = re.compile(r"^@CONTEXT/1\.2 profile=(human|feed) canon=CTX-CANON/3$")
ULID_RE = re.compile(r"^[0-9a-hjkmnp-tv-z]{26}$")
CID_RE = re.compile(r"^[a-z0-9_]{3,32}$")
QNAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,15}\.[A-Za-z0-9_]+$")
RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
ISO8601_DUR_RE = re.compile(r"^P(?!$)(?:\d+Y)?(?:\d+M)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?$")
CF_RE = re.compile(r"^(?:0\.\d{3}|1\.000)$")
COST_VAL_RE = re.compile(r"^-?\d+(?:\.\d{1,6})?$")
WEIGHT_RE = re.compile(r"^(?:0(?:\.\d+)?|1(?:\.0+)?)$")
LANG_RE = re.compile(r"^[a-zA-Z]{2,3}(?:-[A-Za-z0-9]{2,8})*$")
TAG_RE = re.compile(r"^[a-z0-9._-]+$")
REF_DOC_RE = re.compile(r"^@([0-9a-hjkmnp-tv-z]{26})#([a-z0-9_]{3,32})$")
REF_HASH_RE = re.compile(r"^@sha256:[0-9a-f]{64}$")
LITERAL_RE = re.compile(r'^L".*"$')
ZW_FORBIDDEN = {"\u200b", "\u200c", "\u200d"}
DEFAULT_FEED_NAMESPACES = {'ctx': 'ctx:'}


class LintError(Exception):
    """Raised when the document violates the CONTEXT/1.2 specification."""


@dataclass
class InlinePayload:
    value: str


@dataclass
class BlockPayload:
    mime: str
    delimiter: str
    text: str


@dataclass
class AttachmentPayload:
    name: str


Payload = Union[InlinePayload, BlockPayload, AttachmentPayload, None]


@dataclass
class Attachment:
    name: str
    mime: str
    size_bytes: int
    sha256: str
    uri: Optional[str]
    sig_alg: Optional[str]
    sig_key: Optional[str]
    sig_base64: Optional[str]


@dataclass
class ResolutionConfig:
    order: List[str]
    schemes: List[str]
    wellknown: Optional[str]
    timeout_ms: Optional[int]


@dataclass
class RepoEntry:
    idx: int
    repo_id: str
    uri: str
    priority: int
    auth: Optional[str]


@dataclass
class PolicyCf:
    policy_id: str
    kind: str
    model: str
    params: Dict[str, str]
    domain: str
    monotone: bool
    mapping: str


@dataclass
class PolicyTtl:
    policy_id: str
    states: List[str]
    grace: Optional[str]
    stale: Optional[str]
    expired_action: Optional[str]


@dataclass
class NamespaceGovernance:
    status: Dict[str, str]
    collision_policy: str
    aliases: Dict[str, str]
    deprecations: Dict[str, str]


@dataclass
class VersioningRules:
    data: Dict[str, str]


@dataclass
class InputItem:
    kind: str  # 'ref' or 'literal'
    value: str

    def to_canonical(self) -> str:
        if self.kind == "ref":
            return self.value
        escaped = (
            self.value.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\t", "\\t")
            .replace("|", "\\|")
            .replace("=", "\\=")
        )
        return f'L"{escaped}"'


@dataclass
class Capsule:
    cid: str
    t: str
    p: int
    cf: str
    ts: str
    ttl: str
    src: str
    lang: str
    tags: List[str]
    notes: List[str]
    inputs: List[InputItem]
    outputs: List[str]
    op: Optional[str]
    cost_kind: Optional[str]
    cost_val: Optional[str]
    err: Optional[str]
    payload: Payload
    cf_src: Optional[str] = None
    ts_event: Optional[str] = None
    ts_ingest: Optional[str] = None
    ts_logical: Optional[str] = None
    dir: Optional[str] = None
    script: Optional[str] = None
    kind: Optional[str] = None
    safe_hint: Optional[str] = None
    index_hint: Optional[str] = None
    index_fields: Optional[List[str]] = None
    index_weight: Optional[str] = None
    provenance: Dict[str, str] = field(default_factory=dict)
    code: Dict[str, List[str]] = field(default_factory=dict)
    license: Dict[str, str] = field(default_factory=dict)
    enc: Dict[str, str] = field(default_factory=dict)
    privacy_class: Optional[str] = None
    extras: Dict[str, str] = field(default_factory=dict)


@dataclass
class Trace:
    tid: str
    goal: str
    head: str
    halt: Optional[str]
    status: str
    ts: str
    tags: List[str]


@dataclass
class Relation:
    subj: str
    pred: str
    obj: str
    weight: Optional[str]
    ts: Optional[str]


@dataclass
class Signature:
    index: int
    alg: str
    key: str
    base64: str
    epoch: Optional[int] = None
    ts: Optional[str] = None
    tsa_alg: Optional[str] = None
    tsa_base64: Optional[str] = None


@dataclass
class Footer:
    digest: str
    signatures: List[Signature]
    sig_count: Optional[int] = None


@dataclass
class HumanDocument:
    header_profile: str
    namespaces: Dict[str, str]
    ns_governance: Optional[NamespaceGovernance]
    meta: Dict[str, str]
    resolution: Optional[ResolutionConfig]
    repos: List[RepoEntry]
    policies_cf: Dict[str, PolicyCf]
    policies_ttl: Dict[str, PolicyTtl]
    attachments: Dict[str, Attachment]
    versioning: Optional[VersioningRules]
    capsules: Dict[str, Capsule]
    traces: Dict[str, Trace]
    relations: List[Relation]
    footer: Footer


@dataclass
class FeedCapsule:
    cid: str
    t: str
    p: int
    cf: str
    ts: str
    ttl: str
    lang: str
    tags: List[str]
    src: str
    notes: List[str]
    inputs: List[InputItem]
    outputs: List[str]
    op: Optional[str]
    cost_kind: Optional[str]
    cost_val: Optional[str]
    err: Optional[str]
    payload: Payload
    cf_src: Optional[str] = None
    ts_event: Optional[str] = None
    ts_ingest: Optional[str] = None
    ts_logical: Optional[str] = None
    dir: Optional[str] = None
    script: Optional[str] = None
    kind: Optional[str] = None
    safe_hint: Optional[str] = None
    index_hint: Optional[str] = None
    index_fields: Optional[List[str]] = None
    index_weight: Optional[str] = None
    provenance: Dict[str, str] = field(default_factory=dict)
    code: Dict[str, List[str]] = field(default_factory=dict)
    license: Dict[str, str] = field(default_factory=dict)
    enc: Dict[str, str] = field(default_factory=dict)
    privacy_class: Optional[str] = None


@dataclass
class FeedTrace:
    tid: str
    goal: str
    head: str
    halt: Optional[str]
    status: str
    ts: str
    tags: List[str]


@dataclass
class FeedDocument:
    header_profile: str
    capsules: Dict[str, FeedCapsule]
    relations: List[Relation]
    traces: Dict[str, FeedTrace]


Document = Union[HumanDocument, FeedDocument]


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise LintError(message)


def check_qname(qname: str, namespaces: Optional[Dict[str, str]], context: str) -> None:
    ensure(QNAME_RE.match(qname) is not None, f"{context}: invalid QName {qname}")
    if namespaces is not None:
        prefix = qname.split('.', 1)[0]
        ensure(prefix in namespaces, f"{context}: unknown namespace prefix {prefix}")


def validate_clean_text(value: str, context: str) -> None:
    for ch in value:
        if ord(ch) < 0x20 and ch not in "\t\n\r":
            raise LintError(f"{context}: control character U+{ord(ch):04X} is not allowed")
        if ch in ZW_FORBIDDEN:
            raise LintError(f"{context}: zero-width characters are not allowed")


def split_kv(line: str) -> Tuple[str, str]:
    if '=' not in line:
        raise LintError(f"invalid key-value line: {line}")
    key, value = line.split('=', 1)
    return key.strip(), value.strip()


def unescape_value(raw: str) -> str:
    result = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == '\\':
            i += 1
            ensure(i < len(raw), "dangling escape")
            esc = raw[i]
            if esc in {'\\', '|', '='}:
                result.append(esc)
            else:
                raise LintError(f"unsupported escape \\{esc}")
        else:
            result.append(ch)
        i += 1
    value = ''.join(result)
    validate_clean_text(value, "value")
    return value


def parse_literal(token: str) -> str:
    ensure(LITERAL_RE.match(token) is not None, f"invalid literal {token}")
    body = token[2:-1]
    result = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == '\\':
            i += 1
            ensure(i < len(body), "dangling literal escape")
            esc = body[i]
            if esc == '\\':
                result.append('\\')
            elif esc == '"':
                result.append('"')
            elif esc == 'n':
                result.append('\n')
            elif esc == 't':
                result.append('\t')
            elif esc in {'|', '='}:
                result.append(esc)
            else:
                raise LintError(f"unsupported literal escape \\{esc}")
        else:
            result.append(ch)
        i += 1
    value = ''.join(result)
    validate_clean_text(value, "literal")
    return value


def format_literal(value: str) -> str:
    escaped = (
        value.replace('\\', '\\\\')
        .replace('"', '\\"')
        .replace('\n', '\\n')
        .replace('\t', '\\t')
        .replace('|', '\\|')
        .replace('=', '\\=')
    )
    return f'L"{escaped}"'


def parse_ref(token: str) -> str:
    if CID_RE.match(token):
        return token
    if REF_DOC_RE.match(token) or REF_HASH_RE.match(token):
        return token
    raise LintError(f"invalid reference {token}")


def parse_input_csv(raw: str) -> List[InputItem]:
    if not raw:
        return []
    items: List[str] = []
    current: List[str] = []
    in_literal = False
    escape = False
    for ch in raw:
        if in_literal:
            current.append(ch)
            if escape:
                escape = False
                continue
            if ch == '\\':
                escape = True
            elif ch == '"':
                in_literal = False
        else:
            if ch == ',':
                token = ''.join(current)
                items.append(token)
                current = []
            else:
                current.append(ch)
                if len(current) == 2 and current[0] == 'L' and current[1] == '"':
                    in_literal = True
    token = ''.join(current)
    if token:
        items.append(token)
    parsed_items: List[InputItem] = []
    for token in items:
        token = token.strip()
        if not token:
            continue
        if token.startswith('L"'):
            parsed_items.append(InputItem('literal', parse_literal(token)))
        else:
            parsed_items.append(InputItem('ref', parse_ref(token)))
    return parsed_items


def parse_ref_csv(raw: str) -> List[str]:
    if not raw:
        return []
    items = []
    for token in raw.split(','):
        token = token.strip()
        if not token:
            continue
        items.append(parse_ref(token))
    return items


def canonical_tags(raw: str, context: str) -> List[str]:
    tags = [] if not raw else raw.split(',')
    cleaned: List[str] = []
    for tag in tags:
        tag = tag.strip()
        if not tag:
            continue
        ensure(TAG_RE.match(tag) is not None, f"{context}: invalid tag {tag}")
        cleaned.append(tag)
    ensure(cleaned == sorted(cleaned), f"{context}: tags must be sorted lexicographically")
    ensure(len(cleaned) == len(set(cleaned)), f"{context}: duplicate tags are not allowed")
    return cleaned


def parse_human_document(path: Path, lines: List[str]) -> HumanDocument:
    sections: List[Tuple[str, List[str]]] = []
    current_name: Optional[str] = None
    current_body: List[str] = []
    for raw_line in lines[1:]:
        line = raw_line
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith(';'):
            continue
        if stripped == '' and current_name is None:
            continue
        if stripped.startswith('[') and stripped.endswith(']') and not line.startswith('d@'):
            if current_name is not None:
                sections.append((current_name, current_body))
            current_name = stripped[1:-1].strip()
            current_body = []
        else:
            if current_name is None and stripped:
                raise LintError(f"unexpected content before first section: {line}")
            current_body.append(line)
    if current_name is not None:
        sections.append((current_name, current_body))

    namespaces: Dict[str, str] = {}
    ns_governance: Optional[NamespaceGovernance] = None
    meta: Dict[str, str] = {}
    resolution: Optional[ResolutionConfig] = None
    repos: List[RepoEntry] = []
    policies_cf: Dict[str, PolicyCf] = {}
    policies_ttl: Dict[str, PolicyTtl] = {}
    attachments: Dict[str, Attachment] = {}
    versioning: Optional[VersioningRules] = None
    capsules: Dict[str, Capsule] = {}
    traces: Dict[str, Trace] = {}
    relations: Optional[List[Relation]] = None
    footer: Optional[Footer] = None

    for name, body in sections:
        lower = name.lower()
        if lower == 'ns':
            ensure(not namespaces, "[ns] section duplicated")
            namespaces = parse_namespaces(body)
        elif lower == 'ns-governance':
            ensure(ns_governance is None, "[ns-governance] duplicated")
            ns_governance = parse_ns_governance(body)
        elif lower == 'meta':
            ensure(not meta, "[meta] section duplicated")
            meta = parse_meta(body)
        elif lower == 'resolution':
            ensure(resolution is None, "[resolution] duplicated")
            resolution = parse_resolution_section(body)
        elif name.startswith('repo '):
            repo_entry = parse_repo_section(name, body, len(repos) + 1)
            repos.append(repo_entry)
        elif lower == 'repo':
            repos.extend(parse_repo_block(body))
        elif lower == 'policy.cf':
            policy = parse_policy_cf_section(body)
            ensure(policy.policy_id not in policies_cf, f"duplicate policy.cf id {policy.policy_id}")
            policies_cf[policy.policy_id] = policy
        elif lower == 'policy.ttl':
            policy = parse_policy_ttl_section(body)
            ensure(policy.policy_id not in policies_ttl, f"duplicate policy.ttl id {policy.policy_id}")
            policies_ttl[policy.policy_id] = policy
        elif name.startswith('att '):
            attachment = parse_attachment_section(name, body)
            ensure(attachment.name not in attachments, f"duplicate attachment {attachment.name}")
            attachments[attachment.name] = attachment
        elif lower == 'versioning':
            ensure(versioning is None, "[versioning] duplicated")
            versioning = parse_versioning_section(body)
        elif name.startswith('cap '):
            cid = name.split(' ', 1)[1].strip()
            ensure(cid not in capsules, f"duplicate capsule id {cid}")
            capsule = parse_capsule(cid, body, namespaces)
            capsules[cid] = capsule
        elif name.startswith('trace '):
            tid = name.split(' ', 1)[1].strip()
            ensure(tid not in traces, f"duplicate trace id {tid}")
            traces[tid] = parse_trace(tid, body, namespaces)
        elif lower == 'rel':
            ensure(relations is None, "[rel] section duplicated")
            relations = parse_relations(body, namespaces)
        elif lower == 'footer':
            ensure(footer is None, "[footer] section duplicated")
            footer = parse_footer(body)
        else:
            raise LintError(f"unknown section [{name}]")

    ensure(namespaces, "missing [ns] section")
    ensure(meta, "missing [meta] section")
    ensure(relations is not None, "missing [rel] section")
    ensure(footer is not None, "missing [footer] section")

    validate_human_document(
        namespaces,
        ns_governance,
        meta,
        resolution,
        repos,
        policies_cf,
        policies_ttl,
        attachments,
        versioning,
        capsules,
        traces,
        relations or [],
        footer,
    )
    return HumanDocument(
        header_profile=lines[0].split()[1].split('=')[1],
        namespaces=namespaces,
        ns_governance=ns_governance,
        meta=meta,
        resolution=resolution,
        repos=repos,
        policies_cf=policies_cf,
        policies_ttl=policies_ttl,
        attachments=attachments,
        versioning=versioning,
        capsules=capsules,
        traces=traces,
        relations=relations or [],
        footer=footer,
    )


def parse_namespaces(body: List[str]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        ensure(re.match(r"^[a-z][a-z0-9_]{0,15}$", key) is not None, f"invalid namespace prefix {key}")
        ensure(key not in mapping, f"namespace prefix {key} duplicated")
        mapping[key] = value
    ensure('ctx' in mapping, "namespace prefix 'ctx' must be defined")
    return mapping


def parse_ns_governance(body: List[str]) -> NamespaceGovernance:
    statuses: Dict[str, str] = {}
    aliases: Dict[str, str] = {}
    deprecations: Dict[str, str] = {}
    collision_policy = 'reject'
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        if key.endswith('.status'):
            prefix = key[:-7]
            statuses[prefix] = value
        elif key == 'collision.policy':
            ensure(value in {'reject', 'alias'}, "unknown collision policy")
            collision_policy = value
        elif key.startswith('alias.pred.'):
            parts = value.split('->')
            ensure(len(parts) == 2, "alias must use a->b")
            src, dst = parts[0].strip(), parts[1].strip()
            aliases[src] = dst
        elif key.startswith('pred.deprecated-since.'):
            pred = key.split('.', 2)[2]
            deprecations[pred] = value
        else:
            raise LintError(f"unknown ns-governance key {key}")
    return NamespaceGovernance(status=statuses, collision_policy=collision_policy, aliases=aliases, deprecations=deprecations)


def parse_resolution_section(body: List[str]) -> ResolutionConfig:
    order: Optional[List[str]] = None
    schemes: Optional[List[str]] = None
    wellknown: Optional[str] = None
    timeout_ms: Optional[int] = None
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        if key == 'resolver.order':
            order = [item.strip() for item in value.split(',') if item.strip()]
            ensure(all(item in {'cache','repo','wellknown'} for item in order), "resolver.order contains invalid entry")
        elif key == 'resolver.schemes':
            schemes = [item.strip() for item in value.split(',') if item.strip()]
            for scheme in schemes:
                ensure(scheme in {'ctx','https','did','ipfs','vendor','file'}, f"unsupported resolver scheme {scheme}")
        elif key == 'wellknown.domain':
            wellknown = value
        elif key == 'timeout.ms':
            ensure(value.isdigit(), "timeout.ms must be integer")
            timeout_ms = int(value)
        else:
            raise LintError(f"unknown resolution key {key}")
    ensure(order is not None, "resolution must define resolver.order")
    ensure(schemes is not None, "resolution must define resolver.schemes")
    return ResolutionConfig(order=order, schemes=schemes, wellknown=wellknown, timeout_ms=timeout_ms)


def parse_repo_section(name: str, body: List[str], default_idx: int) -> RepoEntry:
    repo_id = name.split(' ', 1)[1].strip()
    fields: Dict[str, str] = {}
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        fields[key] = value
    ensure('uri' in fields, f"repo {repo_id} missing uri")
    priority = int(fields.get('priority', '5')) if fields.get('priority', '5').isdigit() else None
    ensure(priority is not None, f"repo {repo_id} priority must be integer")
    auth = fields.get('auth')
    return RepoEntry(idx=default_idx, repo_id=repo_id, uri=fields['uri'], priority=priority, auth=auth)


def parse_repo_block(body: List[str]) -> List[RepoEntry]:
    entries: Dict[int, Dict[str, str]] = {}
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        ensure(key.startswith('repo.'), "repo block requires repo.N.* keys")
        remainder = key[5:]
        idx_str, attr = remainder.split('.', 1)
        ensure(idx_str.isdigit(), "repo index must be digit")
        idx = int(idx_str)
        entries.setdefault(idx, {})[attr] = value
    result: List[RepoEntry] = []
    for idx in sorted(entries.keys()):
        data = entries[idx]
        ensure('id' in data and 'uri' in data, f"repo.{idx} requires id and uri")
        priority = int(data.get('priority', '5')) if data.get('priority', '5').isdigit() else None
        ensure(priority is not None, f"repo.{idx} priority must be integer")
        result.append(RepoEntry(idx=idx, repo_id=data['id'], uri=data['uri'], priority=priority, auth=data.get('auth')))
    return result


def parse_policy_cf_section(body: List[str]) -> PolicyCf:
    data: Dict[str, str] = {}
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        data[key] = value
    ensure('id' in data, "policy.cf missing id")
    ensure('kind' in data, "policy.cf missing kind")
    ensure(data['kind'] in {'probability', 'score'}, "policy.cf kind must be probability|score")
    ensure('model' in data, "policy.cf missing model")
    params: Dict[str, str] = {}
    if 'params' in data and data['params']:
        for assignment in data['params'].split(';'):
            assignment = assignment.strip()
            if not assignment:
                continue
            ensure('=' in assignment, "policy.cf params must be key=value")
            k, v = assignment.split('=', 1)
            params[k.strip()] = v.strip()
    monotone = data.get('monotone', 'true').lower() == 'true'
    mapping = data.get('mapping', 'global')
    return PolicyCf(
        policy_id=data['id'],
        kind=data['kind'],
        model=data['model'],
        params=params,
        domain=data.get('domain', '[0,1]'),
        monotone=monotone,
        mapping=mapping,
    )


def parse_policy_ttl_section(body: List[str]) -> PolicyTtl:
    data: Dict[str, str] = {}
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        data[key] = value
    ensure('id' in data, "policy.ttl missing id")
    states = [item.strip() for item in data.get('states', '').split(',') if item.strip()]
    ensure(states, "policy.ttl requires states")
    return PolicyTtl(
        policy_id=data['id'],
        states=states,
        grace=data.get('grace'),
        stale=data.get('stale'),
        expired_action=data.get('expired.action'),
    )


def parse_attachment_section(name: str, body: List[str]) -> Attachment:
    attachment_name = name.split(' ', 1)[1].strip()
    fields: Dict[str, str] = {}
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        fields[key] = value
    for required in ('mime', 'bytes', 'sha256'):
        ensure(required in fields, f"attachment {attachment_name} missing {required}")
    ensure(len(fields['sha256']) == 64 and re.fullmatch(r"[0-9a-f]{64}", fields['sha256']) is not None, f"attachment {attachment_name} invalid sha256")
    ensure(fields['bytes'].isdigit(), f"attachment {attachment_name} bytes must be integer")
    sig_alg = fields.get('sig.alg')
    sig_key = fields.get('sig.key')
    sig_base64 = fields.get('sig.base64')
    if sig_alg or sig_key or sig_base64:
        ensure(sig_alg and sig_key and sig_base64, f"attachment {attachment_name} signature requires alg/key/base64")
    return Attachment(
        name=attachment_name,
        mime=fields['mime'],
        size_bytes=int(fields['bytes']),
        sha256=fields['sha256'],
        uri=fields.get('uri'),
        sig_alg=sig_alg,
        sig_key=sig_key,
        sig_base64=sig_base64,
    )


def parse_versioning_section(body: List[str]) -> VersioningRules:
    data: Dict[str, str] = {}
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        data[key] = value
    return VersioningRules(data=data)


def parse_meta(body: List[str]) -> Dict[str, str]:
    meta: Dict[str, str] = {}
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        meta[key] = unescape_value(value)
    required = ['doc', 'author', 'date', 'schema', 'version', 'units', 'lang']
    for key in required:
        ensure(key in meta, f"meta missing {key}")
    ensure(ULID_RE.match(meta['doc']) is not None, "meta doc must be ULID (lowercase)")
    ensure(meta['schema'] == 'CONTEXT', "meta schema must be CONTEXT")
    ensure(meta['version'] == '1.2', "meta version must be 1.2")
    ensure(RFC3339_RE.match(meta['date']) is not None, "meta date must be RFC3339")
    ensure(LANG_RE.match(meta['lang']) is not None, "meta lang must be BCP47")
    ensure(QNAME_RE.match(meta['units']) is not None, "meta units must be QName")
    if 'resolver.scheme' in meta:
        ensure(meta['resolver.scheme'] in {'ctx','https','did','ipfs','vendor','file'}, "unsupported resolver.scheme")
    if 'timeout.ms' in meta:
        ensure(meta['timeout.ms'].isdigit(), "timeout.ms must be integer")
    if 'sig.k' in meta:
        ensure(meta.get('sig.policy') == 'k-of-n', "sig.k requires sig.policy=k-of-n")
        ensure(meta['sig.k'].isdigit(), "sig.k must be integer")
    return meta


def parse_capsule(cid: str, body: List[str], namespaces: Dict[str, str]) -> Capsule:
    ensure(CID_RE.match(cid) is not None, f"invalid capsule id {cid}")
    fields: Dict[str, List[str]] = {}
    payload: Optional[Payload] = None
    i = 0
    while i < len(body):
        line = body[i]
        stripped = line.strip()
        if not stripped:
            i += 1
            continue
        if stripped.startswith('d@') and '<<' in stripped:
            ensure(payload is None, f"capsule {cid} has multiple payloads")
            header = stripped[2:]
            mime, delim = header.split('<<', 1)
            mime = mime.strip()
            delim = delim.strip()
            ensure(mime, f"capsule {cid}: mime type required for block payload")
            i += 1
            payload_lines: List[str] = []
            while i < len(body):
                candidate = body[i]
                if candidate.strip() == delim:
                    break
                payload_lines.append(candidate)
                i += 1
            else:
                raise LintError(f"capsule {cid}: unterminated block payload")
            text = '\n'.join(payload_lines)
            if payload_lines:
                text += '\n'
            payload = BlockPayload(mime, delim, text)
            i += 1
        else:
            key, value = split_kv(stripped)
            fields.setdefault(key, []).append(value)
            i += 1

    required = ['t', 'p', 'cf', 'ts', 'ttl', 'src', 'lang', 'tags']
    for key in required:
        ensure(key in fields, f"capsule {cid} missing {key}")

    t_value = fields['t'][0]
    check_qname(t_value, namespaces, f"capsule {cid}: type")
    ensure(fields['p'][0].isdigit(), f"capsule {cid}: invalid priority {fields['p'][0]}")
    p_int = int(fields['p'][0])
    ensure(0 <= p_int <= 9, f"capsule {cid}: priority must be 0..9")
    cf_val = fields['cf'][0]
    ensure(CF_RE.match(cf_val) is not None, f"capsule {cid}: cf must be 0.xxx with 3 decimals")
    cf_src = fields.get('cf.src', [None])[0]
    ts_primary = fields['ts'][0]
    ensure(RFC3339_RE.match(ts_primary) is not None, f"capsule {cid}: ts must be RFC3339")
    ts_event = fields.get('ts.event', [None])[0]
    if ts_event:
        ensure(RFC3339_RE.match(ts_event) is not None, f"capsule {cid}: ts.event invalid")
    ts_ingest = fields.get('ts.ingest', [None])[0]
    if ts_ingest:
        ensure(RFC3339_RE.match(ts_ingest) is not None, f"capsule {cid}: ts.ingest invalid")
    ts_logical = fields.get('ts.logical', [None])[0]
    if ts_logical:
        ensure(RFC3339_RE.match(ts_logical) is not None, f"capsule {cid}: ts.logical invalid")
    ttl_val = fields['ttl'][0]
    ensure(ISO8601_DUR_RE.match(ttl_val) is not None, f"capsule {cid}: ttl must be ISO8601 duration")
    src_val = unescape_value(fields['src'][0])
    lang_val = fields['lang'][0]
    ensure(LANG_RE.match(lang_val) is not None, f"capsule {cid}: lang must be BCP47")
    dir_val = fields.get('dir', [None])[0]
    if dir_val:
        ensure(dir_val in {'rtl','ltr','auto'}, f"capsule {cid}: dir must be rtl|ltr|auto")
    script_val = fields.get('script', [None])[0]
    if script_val:
        ensure(re.fullmatch(r"[A-Za-z]{4}", script_val) is not None, f"capsule {cid}: script must be ISO15924 code")
    kind_val = fields.get('kind', [None])[0]
    if kind_val:
        ensure(kind_val in {'ctx.event','ctx.state'}, f"capsule {cid}: kind must be ctx.event|ctx.state")
    tags = canonical_tags(fields['tags'][0], f"capsule {cid}")
    notes = [unescape_value(val) for val in fields.get('note', [])]
    inputs = parse_input_csv(fields.get('in', [''])[0] if 'in' in fields else '')
    outputs = parse_ref_csv(fields.get('out', [''])[0] if 'out' in fields else '')
    op = fields.get('op', [None])[0]
    if op is not None:
        check_qname(op, namespaces, f"capsule {cid}: op")
    cost_kind = fields.get('cost.kind', [None])[0]
    if cost_kind is not None:
        check_qname(cost_kind, namespaces, f"capsule {cid}: cost.kind")
    cost_val = fields.get('cost.val', [None])[0]
    if cost_val is not None:
        ensure(COST_VAL_RE.match(cost_val) is not None, f"capsule {cid}: cost.val invalid")
    if (cost_kind is None) != (cost_val is None):
        raise LintError(f"capsule {cid}: cost.kind and cost.val must appear together")
    err_raw = fields.get('err', [None])[0]
    err_value = unescape_value(err_raw) if err_raw is not None else None
    safe_hint = fields.get('safe.hint', [None])[0]
    if safe_hint:
        ensure(safe_hint in {'trusted','untrusted'}, f"capsule {cid}: safe.hint invalid")
    index_hint = fields.get('index.hint', [None])[0]
    if index_hint:
        ensure(index_hint in {'none','light','full'}, f"capsule {cid}: index.hint invalid")
    index_fields_raw = fields.get('index.fields', [None])[0]
    index_fields = None
    if index_fields_raw:
        index_fields = [item.strip() for item in index_fields_raw.split(',') if item.strip()]
    index_weight = fields.get('index.weight', [None])[0]
    if index_weight:
        ensure(re.fullmatch(r"0(?:\.\d+)?|1(?:\.0+)?", index_weight) is not None, f"capsule {cid}: index.weight invalid")
    provenance: Dict[str, str] = {}
    for key in list(fields.keys()):
        if key.startswith('provenance.'):
            provenance[key.split('.',1)[1]] = fields[key][0]
    code: Dict[str, List[str]] = {}
    for key in list(fields.keys()):
        if key.startswith('code.'):
            val_list = [unescape_value(v) for v in fields[key]]
            code[key.split('.',1)[1]] = val_list
    license_info: Dict[str, str] = {}
    for key in list(fields.keys()):
        if key.startswith('license.'):
            license_info[key.split('.',1)[1]] = unescape_value(fields[key][0])
    enc_map: Dict[str, str] = {}
    for key in list(fields.keys()):
        if key.startswith('enc.'):
            enc_map[key.split('.',1)[1]] = fields[key][0]
    privacy_class = fields.get('privacy.class', [None])[0]
    if privacy_class:
        ensure(privacy_class in {'pii','psi','none'}, f"capsule {cid}: privacy.class invalid")

    if enc_map:
        ensure('d' not in fields and payload is None, f"capsule {cid}: enc.* cannot be combined with d")
    if payload is None and 'd' in fields:
        ensure(len(fields['d']) == 1, f"capsule {cid}: d must appear once")
        inline_value = fields['d'][0]
        if inline_value.startswith('^att:'):
            payload = AttachmentPayload(name=inline_value[len('^att:'):])
        else:
            payload = InlinePayload(unescape_value(inline_value))

    allowed_keys = {
        't','p','cf','cf.src','ts','ts.event','ts.ingest','ts.logical','ttl','src','lang','dir','script','kind','tags','note','in','out','op','cost.kind','cost.val','err','d','safe.hint','index.hint','index.fields','index.weight','privacy.class'
    }
    dynamic_prefixes = ('x.', 'provenance.', 'code.', 'license.', 'enc.')
    for key in fields.keys():
        if key.startswith(dynamic_prefixes):
            continue
        if key in allowed_keys:
            continue
        raise LintError(f"capsule {cid}: unsupported key {key}")

    if t_value == 'ctx.T':
        ensure(inputs, f"capsule {cid}: trace capsule requires inputs")
        ensure(outputs, f"capsule {cid}: trace capsule requires outputs")
        ensure(op is not None, f"capsule {cid}: trace capsule requires op")

    payload = payload or None

    return Capsule(
        cid=cid,
        t=t_value,
        p=p_int,
        cf=cf_val,
        cf_src=cf_src,
        ts=ts_primary,
        ts_event=ts_event,
        ts_ingest=ts_ingest,
        ts_logical=ts_logical,
        ttl=ttl_val,
        src=src_val,
        lang=lang_val,
        dir=dir_val,
        script=script_val,
        kind=kind_val,
        tags=tags,
        notes=notes,
        inputs=inputs,
        outputs=outputs,
        op=op,
        cost_kind=cost_kind,
        cost_val=cost_val,
        err=err_value,
        safe_hint=safe_hint,
        index_hint=index_hint,
        index_fields=index_fields,
        index_weight=index_weight,
        provenance=provenance,
        code=code,
        license=license_info,
        enc=enc_map,
        privacy_class=privacy_class,
        payload=payload,
    )


def parse_trace(tid: str, body: List[str], namespaces: Dict[str, str]) -> Trace:
    ensure(CID_RE.match(tid) is not None, f"invalid trace id {tid}")
    fields: Dict[str, str] = {}
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        key, value = split_kv(stripped)
        fields[key] = value
    required = ['goal', 'head', 'status', 'ts', 'tags']
    for key in required:
        ensure(key in fields, f"trace {tid} missing {key}")
    goal = fields['goal']
    head = fields['head']
    halt = fields.get('halt')
    status = fields['status']
    check_qname(status, namespaces, f"trace {tid}: status")
    ensure(RFC3339_RE.match(fields['ts']) is not None, f"trace {tid}: ts must be RFC3339")
    tags = canonical_tags(fields['tags'], f"trace {tid}")
    goal_ref = parse_ref(goal)
    head_ref = parse_ref(head)
    halt_ref = parse_ref(halt) if halt else None
    return Trace(tid=tid, goal=goal_ref, head=head_ref, halt=halt_ref, status=status, ts=fields['ts'], tags=tags)


def parse_relations(body: List[str], namespaces: Dict[str, str]) -> List[Relation]:
    rels: List[Relation] = []
    for line in body:
        stripped = line.strip()
        if not stripped:
            continue
        ensure(stripped.startswith('r='), "relation line must start with r=")
        payload = stripped[2:]
        parts = payload.split('|')
        ensure(len(parts) >= 3, "relation requires subj|pred|obj")
        subj = parse_ref(parts[0])
        pred = parts[1]
        check_qname(pred, namespaces, f"relation predicate {pred}")
        obj = parse_ref(parts[2])
        weight = None
        ts = None
        for suffix in parts[3:]:
            if suffix.startswith('w='):
                weight = suffix[2:]
                ensure(WEIGHT_RE.match(weight) is not None, "invalid relation weight")
            elif suffix.startswith('ts='):
                ts = suffix[3:]
                ensure(RFC3339_RE.match(ts) is not None, "invalid relation ts")
            else:
                raise LintError(f"unknown relation suffix {suffix}")
        rels.append(Relation(subj, pred, obj, weight, ts))
    rels.sort(key=lambda r: (r.subj, r.pred, r.obj, r.weight or '', r.ts or ''))
    return rels


def parse_footer(body: List[str]) -> Footer:
    digest: Optional[str] = None
    signatures: List[Signature] = []
    sig_buffers: Dict[int, Dict[str, str]] = {}
    sig_count: Optional[int] = None
    for line in body:
        stripped = line.strip()
        ensure(not stripped.startswith('#') and not stripped.startswith(';'), "footer must not contain comments")
        if not stripped:
            continue
        key, value = split_kv(stripped)
        if key == 'digest':
            ensure(value == 'sha256', "only sha256 digest supported")
        elif key == 'digest-base16':
            ensure(re.fullmatch(r"[0-9a-f]{64}", value) is not None, "invalid digest hex")
            digest = value
        elif key == 'sig.count':
            ensure(value.isdigit(), "sig.count must be integer")
            sig_count = int(value)
            ensure(0 <= sig_count <= 8, "sig.count must be between 0 and 8")
        elif key.startswith('sig.'):
            prefix, rest = key.split('.', 1)
            idx_str, attr = rest.split('.', 1)
            ensure(idx_str.isdigit(), f"invalid signature index {idx_str}")
            idx = int(idx_str)
            sig_buffers.setdefault(idx, {})[attr] = value
        else:
            raise LintError(f"unknown footer key {key}")
    ensure(digest is not None, "missing digest-base16 in footer")
    for idx, data in sorted(sig_buffers.items()):
        for required in ('alg', 'key', 'base64'):
            ensure(required in data, f"signature {idx} missing {required}")
        epoch = None
        if 'epoch' in data:
            ensure(data['epoch'].isdigit(), f"signature {idx}: epoch must be integer")
            epoch = int(data['epoch'])
        ts = data.get('ts')
        if ts:
            ensure(RFC3339_RE.match(ts) is not None, f"signature {idx}: ts must be RFC3339")
        sig = Signature(index=idx, alg=data['alg'], key=data['key'], base64=data['base64'], epoch=epoch, ts=ts, tsa_alg=data.get('tsa.alg'), tsa_base64=data.get('tsa.base64'))
        if sig.tsa_alg or sig.tsa_base64:
            ensure(sig.tsa_alg and sig.tsa_base64, f"signature {idx}: tsa requires alg/base64")
        signatures.append(sig)
    if sig_count is not None:
        ensure(sig_count == len(signatures), "sig.count mismatch with actual signatures")
    return Footer(digest=digest, signatures=signatures, sig_count=sig_count)


def validate_human_document(
    namespaces: Dict[str, str],
    ns_governance: Optional[NamespaceGovernance],
    meta: Dict[str, str],
    resolution: Optional[ResolutionConfig],
    repos: List[RepoEntry],
    policies_cf: Dict[str, PolicyCf],
    policies_ttl: Dict[str, PolicyTtl],
    attachments: Dict[str, Attachment],
    versioning: Optional[VersioningRules],
    capsules: Dict[str, Capsule],
    traces: Dict[str, Trace],
    relations: List[Relation],
    footer: Footer,
) -> None:
    ensure(capsules, "document must contain at least one capsule")

    if ns_governance:
        for ns, status in ns_governance.status.items():
            ensure(ns in namespaces, f"governance references unknown namespace {ns}")
            ensure(status in {'locked','experimental','draft'}, f"namespace {ns} has invalid status {status}")
        if ns_governance.collision_policy == 'alias':
            for src, dst in ns_governance.aliases.items():
                check_qname(src, namespaces, "alias source")
                check_qname(dst, namespaces, "alias target")
        for pred, since in ns_governance.deprecations.items():
            check_qname(pred, namespaces, "deprecated predicate")

    if resolution and 'resolver.scheme' in meta:
        ensure(meta['resolver.scheme'] in resolution.schemes, "meta resolver.scheme not listed in [resolution]")

    if repos:
        seen_ids = set()
        for entry in repos:
            ensure(entry.repo_id not in seen_ids, f"duplicate repo id {entry.repo_id}")
            seen_ids.add(entry.repo_id)

    cid_set = set(capsules.keys())
    for trace in traces.values():
        if trace.goal in cid_set:
            pass
        elif REF_DOC_RE.match(trace.goal) or REF_HASH_RE.match(trace.goal):
            pass
        else:
            raise LintError(f"trace {trace.tid}: goal references unknown capsule {trace.goal}")
        ensure(trace.head in cid_set, f"trace {trace.tid}: head must reference local capsule")
        if trace.halt is not None:
            ensure(trace.halt in cid_set, f"trace {trace.tid}: halt must reference local capsule")

    for capsule in capsules.values():
        if capsule.cf_src:
            ensure(capsule.cf_src in policies_cf or capsule.cf_src in meta.get('policy.cf', ''), f"capsule {capsule.cid}: unknown cf.src {capsule.cf_src}")
        if capsule.payload and isinstance(capsule.payload, AttachmentPayload):
            ensure(capsule.payload.name in attachments, f"capsule {capsule.cid}: attachment {capsule.payload.name} missing")
        if capsule.enc:
            ensure({'alg','keyref','iv','tag','ct'}.issubset(set(capsule.enc.keys())), f"capsule {capsule.cid}: incomplete enc.*")
        for item in capsule.inputs:
            if item.kind == 'ref' and CID_RE.match(item.value):
                ensure(item.value in cid_set, f"capsule {capsule.cid}: input {item.value} missing")
        for ref in capsule.outputs:
            if CID_RE.match(ref):
                ensure(ref in cid_set, f"capsule {capsule.cid}: output {ref} missing")

    for rel in relations:
        if CID_RE.match(rel.subj):
            ensure(rel.subj in cid_set, f"relation subject {rel.subj} missing")
        if CID_RE.match(rel.obj):
            ensure(rel.obj in cid_set, f"relation object {rel.obj} missing")


def build_canonical_human(doc: HumanDocument) -> str:
    lines: List[str] = []
    lines.append("@CONTEXT/1.2 profile=human canon=CTX-CANON/3")
    if doc.namespaces:
        lines.append('[ns]')
        for prefix in sorted(doc.namespaces):
            lines.append(f"{prefix}={doc.namespaces[prefix]}")
        lines.append('')
    if doc.ns_governance:
        lines.append('[ns-governance]')
        for ns, status in sorted(doc.ns_governance.status.items()):
            lines.append(f"{ns}.status={status}")
        lines.append(f"collision.policy={doc.ns_governance.collision_policy}")
        for src in sorted(doc.ns_governance.aliases):
            lines.append(f"alias.pred.{src}={src}->{doc.ns_governance.aliases[src]}")
        for pred in sorted(doc.ns_governance.deprecations):
            lines.append(f"pred.deprecated-since.{pred}={doc.ns_governance.deprecations[pred]}")
        lines.append('')
    lines.append('[meta]')
    for key in ['doc','author','date','schema','version','units','lang']:
        lines.append(f"{key}={escape_value(doc.meta[key])}")
    extra_meta_keys = sorted(k for k in doc.meta.keys() if k not in {'doc','author','date','schema','version','units','lang'})
    for key in extra_meta_keys:
        lines.append(f"{key}={escape_value(doc.meta[key])}")
    lines.append('')
    if doc.resolution:
        lines.append('[resolution]')
        lines.append(f"resolver.order={','.join(doc.resolution.order)}")
        lines.append(f"resolver.schemes={','.join(doc.resolution.schemes)}")
        if doc.resolution.wellknown:
            lines.append(f"wellknown.domain={escape_value(doc.resolution.wellknown)}")
        if doc.resolution.timeout_ms is not None:
            lines.append(f"timeout.ms={doc.resolution.timeout_ms}")
        lines.append('')
    if doc.repos:
        for entry in sorted(doc.repos, key=lambda r: (r.priority, r.repo_id)):
            lines.append(f"[repo {entry.repo_id}]")
            lines.append(f"uri={escape_value(entry.uri)}")
            if entry.priority != 5:
                lines.append(f"priority={entry.priority}")
            if entry.auth:
                lines.append(f"auth={escape_value(entry.auth)}")
            lines.append('')
    if doc.policies_cf:
        for policy_id in sorted(doc.policies_cf):
            policy = doc.policies_cf[policy_id]
            lines.append(f"[policy.cf {policy.policy_id}]")
            lines.append(f"id={policy.policy_id}")
            lines.append(f"kind={policy.kind}")
            lines.append(f"model={policy.model}")
            if policy.params:
                params_str = ';'.join(f"{k}={v}" for k, v in sorted(policy.params.items()))
                lines.append(f"params={params_str}")
            lines.append(f"domain={policy.domain}")
            lines.append(f"monotone={'true' if policy.monotone else 'false'}")
            lines.append(f"mapping={policy.mapping}")
            lines.append('')
    if doc.policies_ttl:
        for policy_id in sorted(doc.policies_ttl):
            policy = doc.policies_ttl[policy_id]
            lines.append(f"[policy.ttl {policy.policy_id}]")
            lines.append(f"id={policy.policy_id}")
            lines.append(f"states={','.join(policy.states)}")
            if policy.grace:
                lines.append(f"grace={policy.grace}")
            if policy.stale:
                lines.append(f"stale={policy.stale}")
            if policy.expired_action:
                lines.append(f"expired.action={policy.expired_action}")
            lines.append('')
    if doc.attachments:
        for name in sorted(doc.attachments):
            att = doc.attachments[name]
            lines.append(f"[att {att.name}]")
            lines.append(f"mime={escape_value(att.mime)}")
            lines.append(f"bytes={att.size_bytes}")
            lines.append(f"sha256={att.sha256}")
            if att.uri:
                lines.append(f"uri={escape_value(att.uri)}")
            if att.sig_alg:
                lines.append(f"sig.alg={att.sig_alg}")
                lines.append(f"sig.key={escape_value(att.sig_key)}")
                lines.append(f"sig.base64={att.sig_base64}")
            lines.append('')
    if doc.versioning:
        lines.append('[versioning]')
        for key in sorted(doc.versioning.data):
            lines.append(f"{key}={doc.versioning.data[key]}")
        lines.append('')
    for cid in sorted(doc.capsules.keys()):
        cap = doc.capsules[cid]
        lines.append(f"[cap {cid}]")
        lines.append(f"t={cap.t}")
        lines.append(f"p={cap.p}")
        lines.append(f"cf={cap.cf}")
        if cap.cf_src:
            lines.append(f"cf.src={cap.cf_src}")
        lines.append(f"ts={cap.ts}")
        if cap.ts_event:
            lines.append(f"ts.event={cap.ts_event}")
        if cap.ts_ingest:
            lines.append(f"ts.ingest={cap.ts_ingest}")
        if cap.ts_logical:
            lines.append(f"ts.logical={cap.ts_logical}")
        lines.append(f"ttl={cap.ttl}")
        lines.append(f"src={escape_value(cap.src)}")
        lines.append(f"lang={cap.lang}")
        if cap.dir:
            lines.append(f"dir={cap.dir}")
        if cap.script:
            lines.append(f"script={cap.script}")
        if cap.kind:
            lines.append(f"kind={cap.kind}")
        lines.append(f"tags={','.join(cap.tags)}")
        for note in cap.notes:
            lines.append(f"note={escape_value(note)}")
        if cap.inputs:
            lines.append(f"in={','.join(item.to_canonical() for item in cap.inputs)}")
        if cap.outputs:
            lines.append(f"out={','.join(cap.outputs)}")
        if cap.op:
            lines.append(f"op={cap.op}")
        if cap.cost_kind and cap.cost_val:
            lines.append(f"cost.kind={cap.cost_kind}")
            lines.append(f"cost.val={cap.cost_val}")
        if cap.err:
            lines.append(f"err={escape_value(cap.err)}")
        if cap.safe_hint:
            lines.append(f"safe.hint={cap.safe_hint}")
        if cap.index_hint:
            lines.append(f"index.hint={cap.index_hint}")
        if cap.index_fields:
            lines.append(f"index.fields={','.join(cap.index_fields)}")
        if cap.index_weight:
            lines.append(f"index.weight={cap.index_weight}")
        for key in sorted(cap.provenance.keys()):
            lines.append(f"provenance.{key}={escape_value(cap.provenance[key])}")
        for key in sorted(cap.code.keys()):
            values = cap.code[key]
            for val in values:
                lines.append(f"code.{key}={escape_value(val)}")
        for key in sorted(cap.license.keys()):
            lines.append(f"license.{key}={escape_value(cap.license[key])}")
        if cap.enc:
            for key in ['alg','keyref','iv','tag','ct']:
                if key in cap.enc:
                    lines.append(f"enc.{key}={cap.enc[key]}")
        if cap.privacy_class:
            lines.append(f"privacy.class={cap.privacy_class}")
        if isinstance(cap.payload, InlinePayload):
            lines.append(f"d={escape_value(cap.payload.value)}")
        elif isinstance(cap.payload, BlockPayload):
            lines.append(f"d@{cap.payload.mime}<<{cap.payload.delimiter}")
            for payload_line in cap.payload.text.splitlines():
                lines.append(payload_line)
            lines.append(cap.payload.delimiter)
        elif isinstance(cap.payload, AttachmentPayload):
            lines.append(f"d=^att:{cap.payload.name}")
        lines.append('')
    for tid in sorted(doc.traces.keys()):
        trace = doc.traces[tid]
        lines.append(f"[trace {tid}]")
        lines.append(f"goal={trace.goal}")
        lines.append(f"head={trace.head}")
        if trace.halt:
            lines.append(f"halt={trace.halt}")
        lines.append(f"status={trace.status}")
        lines.append(f"ts={trace.ts}")
        lines.append(f"tags={','.join(trace.tags)}")
        lines.append('')
    lines.append('[rel]')
    for rel in doc.relations:
        parts = [rel.subj, rel.pred, rel.obj]
        if rel.weight is not None:
            parts.append(f"w={rel.weight}")
        if rel.ts is not None:
            parts.append(f"ts={rel.ts}")
        lines.append('r=' + '|'.join(parts))
    lines.append('')
    lines.append('[footer]')
    lines.append('digest=sha256')
    lines.append(f"digest-base16={doc.footer.digest}")
    if doc.footer.sig_count is not None:
        lines.append(f"sig.count={doc.footer.sig_count}")
    for sig in doc.footer.signatures:
        lines.append(f"sig.{sig.index}.alg={sig.alg}")
        lines.append(f"sig.{sig.index}.key={escape_value(sig.key)}")
        if sig.epoch is not None:
            lines.append(f"sig.{sig.index}.epoch={sig.epoch}")
        if sig.ts is not None:
            lines.append(f"sig.{sig.index}.ts={sig.ts}")
        lines.append(f"sig.{sig.index}.base64={sig.base64}")
        if sig.tsa_alg and sig.tsa_base64:
            lines.append(f"sig.{sig.index}.tsa.alg={sig.tsa_alg}")
            lines.append(f"sig.{sig.index}.tsa.base64={sig.tsa_base64}")
    return '\n'.join(lines) + '\n'


def escape_value(value: str) -> str:
    return value.replace('\\', '\\\\').replace('|', '\\|').replace('=', '\\=')


def parse_feed_document(path: Path, lines: List[str], raw_lines: List[str]) -> FeedDocument:
    capsules: Dict[str, FeedCapsule] = {}
    relations: List[Relation] = []
    traces: Dict[str, FeedTrace] = {}
    i = 1
    while i < len(raw_lines):
        line = raw_lines[i]
        stripped = line.strip('\n')
        if not stripped:
            i += 1
            continue
        if stripped.startswith('c|'):
            capsule, next_index = parse_feed_capsule(raw_lines, i)
            ensure(capsule.cid not in capsules, f"duplicate capsule id {capsule.cid}")
            capsules[capsule.cid] = capsule
            i = next_index
            continue
        if stripped.startswith('r|'):
            relations.append(parse_feed_relation(stripped))
            i += 1
            continue
        if stripped.startswith('t|'):
            trace = parse_feed_trace(stripped)
            ensure(trace.tid not in traces, f"duplicate trace id {trace.tid}")
            traces[trace.tid] = trace
            i += 1
            continue
        raise LintError(f"unexpected line: {stripped}")
    validate_feed_document(capsules, relations, traces)
    return FeedDocument(lines[0].split()[1].split('=')[1], capsules, relations, traces)


def parse_feed_capsule(lines: List[str], index: int) -> Tuple[FeedCapsule, int]:
    header = lines[index].rstrip('\n')
    parts = header.split('|')
    ensure(len(parts) >= 3, "feed capsule requires c|cid|type|")
    ensure(parts[0] == 'c', "capsule line must start with c|")
    cid = parts[1]
    ensure(CID_RE.match(cid) is not None, f"invalid capsule id {cid}")
    t_value = parts[2]
    check_qname(t_value, DEFAULT_FEED_NAMESPACES, f"capsule {cid}: type")
    field_data: Dict[str, List[str]] = {}
    for token in parts[3:]:
        ensure('=' in token, f"capsule {cid}: malformed token {token}")
        key, value = token.split('=', 1)
        field_data.setdefault(key, []).append(value)
    required = ['p','cf','ts','ttl','lang','tags','src','d']
    for key in required:
        ensure(key in field_data, f"capsule {cid} missing {key}")
    ensure(len(field_data['d']) == 1, f"capsule {cid}: duplicate d entries")
    p_val = field_data['p'][0]
    ensure(p_val.isdigit(), f"capsule {cid}: invalid priority {p_val}")
    p_int = int(p_val)
    ensure(0 <= p_int <= 9, f"capsule {cid}: priority must be 0..9")
    cf_val = field_data['cf'][0]
    ensure(CF_RE.match(cf_val) is not None, f"capsule {cid}: cf invalid")
    ts_val = field_data['ts'][0]
    ensure(RFC3339_RE.match(ts_val) is not None, f"capsule {cid}: ts invalid")
    ttl_val = field_data['ttl'][0]
    ensure(ISO8601_DUR_RE.match(ttl_val) is not None, f"capsule {cid}: ttl invalid")
    lang_val = field_data['lang'][0]
    ensure(LANG_RE.match(lang_val) is not None, f"capsule {cid}: lang invalid")
    tags = canonical_tags(field_data['tags'][0], f"capsule {cid}")
    src_val = unescape_value(field_data['src'][0])
    notes = [unescape_value(val) for val in field_data.get('n', [])]
    inputs = parse_input_csv(field_data.get('in', [''])[0] if 'in' in field_data else '')
    outputs = parse_ref_csv(field_data.get('out', [''])[0] if 'out' in field_data else '')
    op = field_data.get('op', [None])[0]
    if op:
        check_qname(op, DEFAULT_FEED_NAMESPACES, f"capsule {cid}: op")
    cost_kind = field_data.get('cost.kind', [None])[0]
    cost_val = field_data.get('cost.val', [None])[0]
    if cost_kind or cost_val:
        ensure(cost_kind and cost_val, f"capsule {cid}: cost.kind and cost.val must appear together")
        check_qname(cost_kind, DEFAULT_FEED_NAMESPACES, f"capsule {cid}: cost.kind")
        ensure(COST_VAL_RE.match(cost_val) is not None, f"capsule {cid}: cost.val invalid")
    err_raw = field_data.get('err', [None])[0]
    err = unescape_value(err_raw) if err_raw is not None else None
    cf_src = field_data.get('cf.src', [None])[0]
    ts_event = field_data.get('ts.event', [None])[0]
    if ts_event:
        ensure(RFC3339_RE.match(ts_event) is not None, f"capsule {cid}: ts.event invalid")
    ts_ingest = field_data.get('ts.ingest', [None])[0]
    if ts_ingest:
        ensure(RFC3339_RE.match(ts_ingest) is not None, f"capsule {cid}: ts.ingest invalid")
    ts_logical = field_data.get('ts.logical', [None])[0]
    if ts_logical:
        ensure(RFC3339_RE.match(ts_logical) is not None, f"capsule {cid}: ts.logical invalid")
    dir_val = field_data.get('dir', [None])[0]
    if dir_val:
        ensure(dir_val in {'rtl','ltr','auto'}, f"capsule {cid}: dir invalid")
    script_val = field_data.get('script', [None])[0]
    if script_val:
        ensure(re.fullmatch(r"[A-Za-z]{4}", script_val) is not None, f"capsule {cid}: script invalid")
    kind_val = field_data.get('kind', [None])[0]
    if kind_val:
        ensure(kind_val in {'ctx.event','ctx.state'}, f"capsule {cid}: kind invalid")
    safe_hint = field_data.get('safe.hint', [None])[0]
    if safe_hint:
        ensure(safe_hint in {'trusted','untrusted'}, f"capsule {cid}: safe.hint invalid")
    index_hint = field_data.get('index.hint', [None])[0]
    if index_hint:
        ensure(index_hint in {'none','light','full'}, f"capsule {cid}: index.hint invalid")
    index_fields = None
    if 'index.fields' in field_data:
        index_fields = [item.strip() for item in field_data['index.fields'][0].split(',') if item.strip()]
    index_weight = field_data.get('index.weight', [None])[0]
    if index_weight:
        ensure(re.fullmatch(r"0(?:\.\d+)?|1(?:\.0+)?", index_weight) is not None, f"capsule {cid}: index.weight invalid")
    provenance: Dict[str, str] = {}
    for key, values in field_data.items():
        if key.startswith('provenance.'):
            provenance[key.split('.',1)[1]] = unescape_value(values[0])
    code: Dict[str, List[str]] = {}
    for key, values in field_data.items():
        if key.startswith('code.'):
            code.setdefault(key.split('.',1)[1], []).extend(unescape_value(v) for v in values)
    license_info: Dict[str, str] = {
        key.split('.',1)[1]: unescape_value(values[0])
        for key, values in field_data.items()
        if key.startswith('license.')
    }
    privacy_class = field_data.get('privacy.class', [None])[0]
    if privacy_class:
        ensure(privacy_class in {'pii','psi','none'}, f"capsule {cid}: privacy.class invalid")
    enc_map: Dict[str, str] = {}
    payload_token = field_data['d'][0]
    payload: Payload
    next_index = index + 1
    if payload_token.startswith('^block:'):
        _, rest = payload_token.split(':', 1)
        mime, length_str = rest.rsplit(':', 1)
        ensure(length_str.isdigit(), f"capsule {cid}: block length must be integer")
        byte_len = int(length_str)
        content_parts: List[str] = []
        consumed = 0
        while next_index < len(lines):
            candidate = lines[next_index]
            stripped_candidate = candidate.strip('\n')
            if stripped_candidate.startswith(('c|','r|','t|')) and consumed >= byte_len:
                break
            content_parts.append(candidate)
            consumed += len(candidate.encode('utf-8'))
            next_index += 1
            if consumed >= byte_len:
                break
        ensure(consumed == byte_len, f"capsule {cid}: block payload length mismatch (expected {byte_len}, got {consumed})")
        payload = BlockPayload(mime=mime, delimiter='', text=''.join(content_parts))
    elif payload_token.startswith('^att:'):
        payload = AttachmentPayload(name=payload_token[len('^att:'):])
    else:
        payload = InlinePayload(unescape_value(payload_token))
    if t_value == 'ctx.T':
        ensure(inputs, f"capsule {cid}: trace capsule requires inputs")
        ensure(outputs, f"capsule {cid}: trace capsule requires outputs")
        ensure(op is not None, f"capsule {cid}: trace capsule requires op")
    return FeedCapsule(
        cid=cid,
        t=t_value,
        p=p_int,
        cf=cf_val,
        cf_src=cf_src,
        ts=ts_val,
        ts_event=ts_event,
        ts_ingest=ts_ingest,
        ts_logical=ts_logical,
        ttl=ttl_val,
        lang=lang_val,
        dir=dir_val,
        script=script_val,
        kind=kind_val,
        tags=tags,
        src=src_val,
        notes=notes,
        inputs=inputs,
        outputs=outputs,
        op=op,
        cost_kind=cost_kind,
        cost_val=cost_val,
        err=err,
        safe_hint=safe_hint,
        index_hint=index_hint,
        index_fields=index_fields,
        index_weight=index_weight,
        provenance=provenance,
        code=code,
        license=license_info,
        enc=enc_map,
        privacy_class=privacy_class,
        payload=payload,
    ), next_index


def parse_feed_relation(line: str) -> Relation:
    parts = line.split('|')
    ensure(len(parts) >= 4 and parts[0] == 'r', "relation line must start with r|")
    subj = parse_ref(parts[1])
    pred = parts[2]
    check_qname(pred, DEFAULT_FEED_NAMESPACES, f"relation predicate {pred}")
    obj = parse_ref(parts[3])
    weight = None
    ts = None
    for token in parts[4:]:
        if token.startswith('w='):
            weight = token[2:]
            ensure(WEIGHT_RE.match(weight) is not None, "invalid relation weight")
        elif token.startswith('ts='):
            ts = token[3:]
            ensure(RFC3339_RE.match(ts) is not None, "invalid relation ts")
        else:
            raise LintError(f"unknown relation suffix {token}")
    return Relation(subj=subj, pred=pred, obj=obj, weight=weight, ts=ts)


def parse_feed_trace(line: str) -> FeedTrace:
    parts = line.split('|')
    ensure(len(parts) >= 2 and parts[0] == 't', "trace line must start with t|")
    tid = parts[1]
    ensure(CID_RE.match(tid) is not None, f"invalid trace id {tid}")
    fields: Dict[str, str] = {}
    for token in parts[2:]:
        ensure('=' in token, f"trace token malformed: {token}")
        key, value = token.split('=', 1)
        fields[key] = value
    required = ['goal','head','status','ts','tags']
    for key in required:
        ensure(key in fields, f"trace {tid} missing {key}")
    goal = parse_ref(fields['goal'])
    head = parse_ref(fields['head'])
    halt = parse_ref(fields['halt']) if 'halt' in fields else None
    status = fields['status']
    check_qname(status, DEFAULT_FEED_NAMESPACES, f"trace {tid}: status")
    ts = fields['ts']
    ensure(RFC3339_RE.match(ts) is not None, f"trace {tid}: ts invalid")
    tags = canonical_tags(fields['tags'], f"trace {tid}")
    return FeedTrace(tid=tid, goal=goal, head=head, halt=halt, status=status, ts=ts, tags=tags)


def validate_feed_document(capsules: Dict[str, FeedCapsule], relations: List[Relation], traces: Dict[str, FeedTrace]) -> None:
    ensure(capsules, "feed document must contain capsules")
    cid_set = set(capsules.keys())
    for cap in capsules.values():
        for item in cap.inputs:
            if item.kind == 'ref' and CID_RE.match(item.value):
                ensure(item.value in cid_set, f"capsule {cap.cid}: input {item.value} missing")
        for ref in cap.outputs:
            if CID_RE.match(ref):
                ensure(ref in cid_set, f"capsule {cap.cid}: output {ref} missing")
        if isinstance(cap.payload, BlockPayload):
            byte_len = len(cap.payload.text.encode('utf-8'))
            ensure(byte_len > 0, f"capsule {cap.cid}: block payload must not be empty")
    for rel in relations:
        if CID_RE.match(rel.subj):
            ensure(rel.subj in cid_set, f"relation subject {rel.subj} missing")
        if CID_RE.match(rel.obj):
            ensure(rel.obj in cid_set, f"relation object {rel.obj} missing")
    for trace in traces.values():
        if trace.goal in cid_set:
            pass
        elif REF_DOC_RE.match(trace.goal) or REF_HASH_RE.match(trace.goal):
            pass
        else:
            raise LintError(f"trace {trace.tid}: goal {trace.goal} missing")
        ensure(trace.head in cid_set, f"trace {trace.tid}: head missing")
        if trace.halt is not None:
            ensure(trace.halt in cid_set, f"trace {trace.tid}: halt missing")


def build_canonical_feed(doc: FeedDocument) -> str:
    lines: List[str] = []
    lines.append("@CONTEXT/1.2 profile=feed canon=CTX-CANON/3")
    for cid in sorted(doc.capsules.keys()):
        cap = doc.capsules[cid]
        parts = [
            'c',
            cid,
            cap.t,
            f"p={cap.p}",
            f"cf={cap.cf}",
            f"ts={cap.ts}",
            f"ttl={cap.ttl}",
            f"lang={cap.lang}",
            f"tags={','.join(cap.tags)}",
            f"src={escape_value(cap.src)}",
        ]
        if cap.cf_src:
            parts.append(f"cf.src={cap.cf_src}")
        if cap.ts_event:
            parts.append(f"ts.event={cap.ts_event}")
        if cap.ts_ingest:
            parts.append(f"ts.ingest={cap.ts_ingest}")
        if cap.ts_logical:
            parts.append(f"ts.logical={cap.ts_logical}")
        if cap.dir:
            parts.append(f"dir={cap.dir}")
        if cap.script:
            parts.append(f"script={cap.script}")
        if cap.kind:
            parts.append(f"kind={cap.kind}")
        for note in cap.notes:
            parts.append(f"n={escape_value(note)}")
        if cap.inputs:
            parts.append(f"in={','.join(item.to_canonical() for item in cap.inputs)}")
        if cap.outputs:
            parts.append(f"out={','.join(cap.outputs)}")
        if cap.op:
            parts.append(f"op={cap.op}")
        if cap.cost_kind and cap.cost_val:
            parts.append(f"cost.kind={cap.cost_kind}")
            parts.append(f"cost.val={cap.cost_val}")
        if cap.err:
            parts.append(f"err={escape_value(cap.err)}")
        if cap.safe_hint:
            parts.append(f"safe.hint={cap.safe_hint}")
        if cap.index_hint:
            parts.append(f"index.hint={cap.index_hint}")
        if cap.index_fields:
            parts.append(f"index.fields={','.join(cap.index_fields)}")
        if cap.index_weight:
            parts.append(f"index.weight={cap.index_weight}")
        for key in sorted(cap.provenance.keys()):
            parts.append(f"provenance.{key}={escape_value(cap.provenance[key])}")
        for key in sorted(cap.code.keys()):
            for val in cap.code[key]:
                parts.append(f"code.{key}={escape_value(val)}")
        for key in sorted(cap.license.keys()):
            parts.append(f"license.{key}={escape_value(cap.license[key])}")
        if cap.privacy_class:
            parts.append(f"privacy.class={cap.privacy_class}")
        if cap.enc:
            for key in ['alg','keyref','iv','tag','ct']:
                if key in cap.enc:
                    parts.append(f"enc.{key}={cap.enc[key]}")
        if isinstance(cap.payload, InlinePayload):
            parts.append(f"d={escape_value(cap.payload.value)}")
            lines.append('|'.join(parts))
        elif isinstance(cap.payload, BlockPayload):
            byte_len = len(cap.payload.text.encode('utf-8'))
            parts.append(f"d=^block:{cap.payload.mime}:{byte_len}")
            lines.append('|'.join(parts))
            block_lines = cap.payload.text.splitlines()
            if block_lines:
                lines.extend(block_lines)
            else:
                lines.append('')
        elif isinstance(cap.payload, AttachmentPayload):
            parts.append(f"d=^att:{cap.payload.name}")
            lines.append('|'.join(parts))
    for rel in sorted(doc.relations, key=lambda r: (r.subj, r.pred, r.obj, r.weight or '', r.ts or '')):
        parts = ['r', rel.subj, rel.pred, rel.obj]
        if rel.weight is not None:
            parts.append(f"w={rel.weight}")
        if rel.ts is not None:
            parts.append(f"ts={rel.ts}")
        lines.append('|'.join(parts))
    for tid in sorted(doc.traces.keys()):
        trace = doc.traces[tid]
        parts = [
            't',
            tid,
            f"goal={trace.goal}",
            f"head={trace.head}",
            f"status={trace.status}",
            f"ts={trace.ts}",
            f"tags={','.join(trace.tags)}",
        ]
        if trace.halt:
            parts.append(f"halt={trace.halt}")
        lines.append('|'.join(parts))
    return '\n'.join(lines) + '\n'


def compute_digest(canonical: str) -> str:
    lines = canonical.split('\n')
    digest_lines: List[str] = []
    for line in lines:
        if line.startswith('digest-base16='):
            break
        digest_lines.append(line)
    digest_input = '\n'.join(digest_lines) + '\n'
    return sha256(digest_input.encode('utf-8')).hexdigest()


def parse_document(path: Path) -> Tuple[Document, str]:
    text = path.read_text(encoding='utf-8')
    ensure(text.endswith('\n'), "file must end with LF newline")
    ensure('\r' not in text, "CR characters are not allowed")
    ensure('\t' not in text, "TAB characters are not allowed")
    for forbidden in ZW_FORBIDDEN:
        ensure(forbidden not in text, "zero-width characters are not allowed globally")
    lines_plain = text.split('\n')
    if lines_plain and lines_plain[-1] == '':
        lines_plain = lines_plain[:-1]
    ensure(lines_plain, "empty file")
    header = lines_plain[0]
    match = HEADER_RE.match(header)
    ensure(match is not None, "invalid header")
    profile = match.group(1)
    raw_lines = text.splitlines(True)
    if profile == 'human':
        doc = parse_human_document(path, lines_plain)
        canonical = build_canonical_human(doc)
        digest = compute_digest(canonical)
        ensure(digest == doc.footer.digest, f"digest mismatch: expected {doc.footer.digest}, got {digest}")
        return doc, canonical
    doc = parse_feed_document(path, lines_plain, raw_lines)
    canonical = build_canonical_feed(doc)
    return doc, canonical


def lint_path(path: Path, write: bool) -> Dict[str, str]:
    doc, canonical = parse_document(path)
    if write:
        path.write_text(canonical, encoding='utf-8')
    return {
        "file": str(path),
        "status": "ok",
        "profile": doc.header_profile,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files', nargs='+', help='CONTEXT/1.2 documents to lint')
    parser.add_argument('--json', action='store_true', help='emit JSON summary')
    parser.add_argument('--write', action='store_true', help='rewrite files in canonical form')
    args = parser.parse_args(argv)

    results: List[Dict[str, str]] = []
    ok = True
    for file in args.files:
        path = Path(file)
        try:
            res = lint_path(path, args.write)
            results.append(res)
        except LintError as err:
            ok = False
            results.append({"file": str(path), "status": "error", "message": str(err)})
        except Exception as err:  # unexpected failure
            ok = False
            results.append({"file": str(path), "status": "error", "message": f"unexpected: {err}"})

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for res in results:
            if res['status'] == 'ok':
                print(f"[OK] {res['file']} (profile={res['profile']})")
            else:
                print(f"[ERR] {res['file']}: {res['message']}")
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
