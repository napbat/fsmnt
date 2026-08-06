#!/usr/bin/env python3
"""Fail if any file passed as an argument exceeds MAX_LINES lines.

Used by the `max-file-lines` hook in .pre-commit-config.yaml.
"""

import sys

MAX_LINES = 1000


def main() -> int:
    status = 0
    for path in sys.argv[1:]:
        with open(path, "rb") as f:
            lines = sum(1 for _ in f)
        if lines > MAX_LINES:
            print(f"{path}: {lines} lines (max {MAX_LINES})")
            status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
