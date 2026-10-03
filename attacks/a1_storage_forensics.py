#!/usr/bin/env python3
"""Offline storage-compromise evidence collection; it sends no HTTP traffic."""

from __future__ import annotations

import argparse
import hashlib
import math
from pathlib import Path

from lib import create_result_dir, save_result


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [data.count(bytes([value])) for value in range(256)]
    return round(-sum((count / len(data)) * math.log2(count / len(data)) for count in counts if count), 4)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="Directory copied by the storage attacker.")
    parser.add_argument("--marker-file", required=True, help="A known plaintext test file to search for.")
    parser.add_argument("--max-file-mb", type=int, default=100, help="Skip files larger than this.")
    parser.add_argument("--exclude-dir", action="append", default=["node_modules", ".git"], help="Directory name to skip; repeatable.")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    marker = Path(args.marker_file).read_bytes()
    if not root.is_dir() or not marker:
        raise SystemExit("--root must exist and --marker-file must be a non-empty file.")
    limit = args.max_file_mb * 1024 * 1024
    records = []
    for path in sorted(
        item for item in root.rglob("*")
        if item.is_file() and not any(part in args.exclude_dir for part in item.relative_to(root).parts)
    ):
        size = path.stat().st_size
        if size > limit:
            records.append({"path": str(path), "size": size, "skipped": "larger than max-file-mb"})
            continue
        content = path.read_bytes()
        records.append(
            {
                "path": str(path),
                "size": size,
                "sha256": hashlib.sha256(content).hexdigest(),
                "contains_known_plaintext": marker in content,
                "first_64_bytes_hex": content[:64].hex(),
                "sample_entropy_bits_per_byte": entropy(content[: min(len(content), 65536)]),
                "is_sqlite_database": content.startswith(b"SQLite format 3"),
            }
        )
    result_dir = create_result_dir("a1_storage_forensics")
    save_result(result_dir, "result.json", {"root": str(root), "marker_sha256": hashlib.sha256(marker).hexdigest(), "files": records})
    print(f"Scanned {len(records)} files. Evidence: {result_dir / 'result.json'}")
    print("Inspect contains_known_plaintext and SQLite/WAL/blob records. This tool reports observations; it does not decide pass/fail.")


if __name__ == "__main__":
    main()
