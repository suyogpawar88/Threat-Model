#!/usr/bin/env python3
"""
Token-minimization helper for appsec-threat-modeler.

Connector tools (Jira descriptions, Jenkins console logs, ServiceNow records,
repo files) can return large payloads. Rather than pasting all of that
directly into the main Claude session's context, pipe it through this script
first: it makes a single, cheap call to the Anthropic API to compress the
payload down to the facts that matter for threat modeling, using a
cost-efficient model by default.

This is the mechanism behind "uses Claude Sonnet to minimize token usage" --
Sonnet is the default MODEL_NAME because it is materially cheaper than Opus
while still reliable at extractive summarization. Point MODEL_NAME at any
other available Claude model to change that tradeoff.

Usage:
  python3 summarize.py --focus "auth flow, data stores, external calls" < big_payload.txt
  echo '{"raw": "..."}' | python3 summarize.py --focus "..." --max-words 250

Required env var:
  ANTHROPIC_API_KEY

Optional env var:
  MODEL_NAME   defaults to "claude-sonnet-5". Set to any other available
               Claude model string (e.g. "claude-haiku-4-5-20251001" for even
               lower cost, or "claude-opus-4-8" for higher-fidelity summaries
               on especially dense material) to override.
"""
import os
import sys
import argparse

DEFAULT_MODEL = "claude-sonnet-5"
SYSTEM_PROMPT = (
    "You compress raw engineering artifacts (ticket text, build logs, config "
    "files, incident records) into a short, dense brief for a security threat "
    "modeling exercise. Preserve every fact relevant to: system components, "
    "data flows, trust boundaries, authentication/authorization logic, "
    "external integrations, secrets/credentials handling, and known "
    "incidents or failures. Drop boilerplate, timestamps, formatting noise, "
    "and anything not relevant to security analysis. Output plain prose, no "
    "preamble."
)


def summarize(raw_text: str, focus: str = "", max_words: int = 300) -> str:
    try:
        import anthropic
    except ImportError:
        raise RuntimeError(
            "The 'anthropic' package is required for summarize.py. "
            "Install with: pip install anthropic --break-system-packages"
        )

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set; cannot call the summarization model.")

    model = os.environ.get("MODEL_NAME", DEFAULT_MODEL)
    client = anthropic.Anthropic(api_key=api_key)

    focus_line = f"\n\nPay special attention to: {focus}" if focus else ""
    user_prompt = (
        f"Summarize the following in at most {max_words} words for a security "
        f"threat-modeling brief.{focus_line}\n\n---\n{raw_text}"
    )

    resp = client.messages.create(
        model=model,
        max_tokens=max(512, max_words * 4),
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return "".join(block.text for block in resp.content if getattr(block, "type", "") == "text").strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--focus", default="", help="What to prioritize when compressing (e.g. 'auth flow, external calls')")
    parser.add_argument("--max-words", type=int, default=300)
    parser.add_argument("--input-file", default="-", help="Path to read from, or '-' for stdin (default)")
    args = parser.parse_args()

    raw = sys.stdin.read() if args.input_file == "-" else open(args.input_file, "r", encoding="utf-8", errors="replace").read()
    if not raw.strip():
        print("", end="")
        return

    print(summarize(raw, focus=args.focus, max_words=args.max_words))


if __name__ == "__main__":
    main()
