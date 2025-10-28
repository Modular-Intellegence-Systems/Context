#!/usr/bin/env python3
"""Extract token/time/memory metrics from Codex jsonl logs."""
import argparse
import json
import re
from pathlib import Path
from typing import Optional, List

TOKEN_RE = re.compile(r"tokens used:\s*([0-9\s]+)")
REAL_RE = re.compile(r"real=([0-9]+\.[0-9]+)")
MEM_RE = re.compile(r"mem=([0-9]+)")
JSON_RE = re.compile(r"\{\"patch_lines\".*")


def parse_file(path: Path) -> dict:
    text = path.read_text(errors="ignore")
    tokens_match = TOKEN_RE.findall(text)
    real_match = REAL_RE.findall(text)
    mem_match = MEM_RE.findall(text)
    json_payload: Optional[dict] = None
    for line in text.splitlines():
        if line.strip().startswith('{"patch_lines"'):
            try:
                json_payload = json.loads(JSON_RE.match(line).group(0))
            except Exception:
                json_payload = None
            break
    status = "ok" if json_payload else "missing-answer"
    error = None
    if "ERROR:" in text:
        status = "error"
        error = ";".join(sorted(set(re.findall(r"ERROR: ([^\n]+)", text))))
    def _clean_int(match_list):
        if not match_list:
            return None
        digits = re.sub(r"[^0-9]", "", match_list[-1])
        return int(digits) if digits else None

    return {
        "file": str(path),
        "tokens": _clean_int(tokens_match),
        "real_s": float(real_match[-1]) if real_match else None,
        "mem_kb": int(mem_match[-1]) if mem_match else None,
        "status": status,
        "error": error,
    }


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('paths', nargs='+', help='Paths or glob patterns to jsonl logs.')
    parser.add_argument('--json', action='store_true', help='Emit JSON array instead of table.')
    args = parser.parse_args(argv)

    files: List[Path] = []
    for pattern in args.paths:
        p = Path(pattern)
        if p.exists():
            if p.is_dir():
                files.extend(sorted(p.glob('**/*.jsonl')))
            else:
                files.append(p)
        else:
            files.extend(sorted(Path().glob(pattern)))
    if not files:
        parser.error('No files matched input patterns.')

    rows = [parse_file(path) for path in files]
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    header = f"{'file':70}  {'tokens':>8}  {'real_s':>8}  {'mem_kb':>8}  status"
    print(header)
    print('-' * len(header))
    for row in rows:
        print(f"{row['file'][:70]:70}  {row['tokens'] if row['tokens'] is not None else '-':>8}  "
              f"{row['real_s'] if row['real_s'] is not None else '-':>8}  {row['mem_kb'] if row['mem_kb'] is not None else '-':>8}  {row['status']}")
        if row.get('error'):
            print(f"{'':70}  error: {row['error']}")


if __name__ == '__main__':
    main()
