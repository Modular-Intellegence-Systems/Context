#!/usr/bin/env bash
# Run codex exec with a prompt file, capture stdout/stderr, and append runtime metrics.
set -euo pipefail
if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <prompt_file> <output_log> [model]" >&2
  exit 1
fi
PROMPT_FILE=$1
OUTPUT_LOG=$2
MODEL=${3:-gpt-5-codex}
if [[ ! -f $PROMPT_FILE ]]; then
  echo "Prompt file not found: $PROMPT_FILE" >&2
  exit 2
fi
if [[ "$MODEL" == gpt-4.2* ]]; then
  echo "Model '$MODEL' is disallowed (gpt-4.2 family is unsupported)." >&2
  exit 3
fi
TMP_STDOUT=$(mktemp)
TMP_STDERR=$(mktemp)
trap 'rm -f "$TMP_STDOUT" "$TMP_STDERR"' EXIT
/usr/bin/time -f 'real=%e\nmem=%M' \
  codex exec --skip-git-repo-check -m "$MODEL" - < "$PROMPT_FILE" \
  >"$TMP_STDOUT" 2>"$TMP_STDERR"
cat "$TMP_STDOUT" > "$OUTPUT_LOG"
if [[ -s $TMP_STDERR ]]; then
  {
    echo "\n--- stderr ---"
    cat "$TMP_STDERR"
  } >> "$OUTPUT_LOG"
fi
