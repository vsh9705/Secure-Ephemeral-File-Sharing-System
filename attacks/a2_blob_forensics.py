#!/usr/bin/env python3
"""Analyse one stolen blob without assuming the application's encryption scheme."""

from __future__ import annotations

import argparse
import hashlib
import math
from pathlib import Path

from lib import create_result_dir, save_result


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    histogram = [data.count(bytes([i])) for i in range(256)]
    return round(-sum((n / len(data)) * math.log2(n / len(data)) for n in histogram if n), 4)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob", required=True, help="Path to a stolen server-side blob.")
    parser.add_argument("--known-plaintext-file", required=True, help="Original known plaintext test file.")
    args = parser.parse_args()
    blob = Path(args.blob).read_bytes()
    plaintext = Path(args.known_plaintext_file).read_bytes()
    magic = {
        "pdf": b"%PDF-",
        "png": b"\x89PNG\r\n\x1a\n",
        "zip": b"PK\x03\x04",
        "jpeg": b"\xff\xd8\xff",
    }
    result = {
        "blob": str(Path(args.blob).resolve()),
        "blob_size": len(blob),
        "blob_sha256": hashlib.sha256(blob).hexdigest(),
        "blob_entropy_bits_per_byte": entropy(blob[: min(len(blob), 65536)]),
        "known_plaintext_size": len(plaintext),
        "known_plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "known_plaintext_found_as_substring": plaintext in blob,
        "known_file_magic_found": [name for name, value in magic.items() if value in blob],
        "first_128_bytes_hex": blob[:128].hex(),
    }
    result_dir = create_result_dir("a2_blob_forensics")
    save_result(result_dir, "result.json", result)
    print(f"Blob evidence: {result_dir / 'result.json'}")
    print(f"Known plaintext found verbatim: {result['known_plaintext_found_as_substring']}")
    print(f"Sample entropy: {result['blob_entropy_bits_per_byte']} bits/byte")
    print("Interpret the factual evidence with the target's documented blob format; no cipher is assumed by this tool.")


if __name__ == "__main__":
    main()
