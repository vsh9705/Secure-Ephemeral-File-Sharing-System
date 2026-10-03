#!/usr/bin/env python3
"""Combine selected JSON/JSONL evidence files into one timestamped report."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def read_evidence(path: Path):
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return json.loads(path.read_text())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, help="Evidence .json or .jsonl file; repeat for each source.")
    parser.add_argument("--output", required=True, help="Report .json file to create.")
    args = parser.parse_args()
    evidence = []
    for raw_path in args.input:
        path = Path(raw_path)
        evidence.append({"source": str(path), "data": read_evidence(path)})
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "methodology": "Observed evidence only. No generic pass/fail conclusion is calculated.",
        "evidence": evidence,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(output)


if __name__ == "__main__":
    main()
