#!/usr/bin/env python3
"""Update or append one KEY=\"value\" line in the repo .env file."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT_DIR / ".env"


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} KEY VALUE", file=sys.stderr)
        return 1

    key = sys.argv[1].strip()
    value = sys.argv[2]
    if not key:
        print("KEY must not be empty", file=sys.stderr)
        return 1

    prefix = f"{key}="
    new_line = f'{key}="{value}"'
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    updated = False
    output: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            output.append(line)
            continue
        if stripped.startswith(prefix):
            output.append(new_line)
            updated = True
        else:
            output.append(line)

    if not updated:
        if output and output[-1].strip():
            output.append("")
        output.append(new_line)

    ENV_FILE.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
