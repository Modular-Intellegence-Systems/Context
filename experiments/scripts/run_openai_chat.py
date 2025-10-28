#!/usr/bin/env python3
"""Invoke OpenAI chat completions for a given prompt file and save structured output."""
import argparse
import json
import os
import sys
from pathlib import Path

import requests

API_URL = "https://api.openai.com/v1/chat/completions"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prompt_file", help="Path to prompt text file")
    parser.add_argument("output_file", help="Where to write JSONL-style response")
    parser.add_argument("model", help="OpenAI model id")
    parser.add_argument("--max-completion-tokens", type=int, default=1200,
                        help="max tokens for completions (default 1200)")
    parser.add_argument("--temperature", type=float, default=None,
                        help="Optional sampling temperature (omit to use model default)")
    args = parser.parse_args()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("OPENAI_API_KEY is required", file=sys.stderr)
        return 2

    if args.model.startswith("gpt-4.2"):
        print("Model 'gpt-4.2' is explicitly disallowed (unsupported).", file=sys.stderr)
        return 3

    prompt_path = Path(args.prompt_file)
    if not prompt_path.is_file():
        print(f"Prompt file not found: {prompt_path}", file=sys.stderr)
        return 2
    content = prompt_path.read_text(encoding="utf-8")

    payload = {
        "model": args.model,
        "messages": [
            {"role": "user", "content": content}
        ],
        "max_completion_tokens": args.max_completion_tokens,
    }
    if args.temperature is not None:
        payload["temperature"] = args.temperature

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    response = requests.post(API_URL, headers=headers, data=json.dumps(payload), timeout=180)
    output = {
        "status_code": response.status_code,
        "payload": response.json() if response.headers.get('Content-Type','').startswith('application/json') else response.text,
    }

    Path(args.output_file).write_text(json.dumps(output, indent=2), encoding="utf-8")

    if response.status_code != 200:
        print(f"Request failed: {response.status_code}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
