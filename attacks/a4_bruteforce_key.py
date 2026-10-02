#!/usr/bin/env python3
"""A4: Online guessing attack against the 256-bit key-hash verifier."""

import hashlib
import secrets
import sys
import time

from common import base_parser, create_fixture, download, print_verdict, require_backend


def main() -> int:
    parser = base_parser(__doc__)
    parser.add_argument("--attempts", type=int, default=12, help="Guesses to submit (default exceeds 10/min limit)")
    args = parser.parse_args()
    require_backend(args.base_url)
    fixture = create_fixture(args.base_url, label="a4-key-guessing")
    results = []
    started = time.perf_counter()
    for _ in range(args.attempts):
        # Guess a raw 256-bit key, then submit its SHA-256 value as a real client would.
        guessed_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        response = download(args.base_url, fixture.file_id, guessed_hash)
        results.append(response.status_code)
    elapsed = time.perf_counter() - started

    print(f"Submitted {args.attempts} independent 256-bit key guesses in {elapsed:.2f}s")
    print(f"Status codes: {results}")
    print(f"Successful guesses: {results.count(200)}")
    print(f"Rate-limit responses (429): {results.count(429)}")
    return print_verdict(
        results.count(200) == 0 and (args.attempts < 11 or 429 in results),
        "no random key guess authenticated; the online rate limit throttled guesses after ten attempts.",
    )


if __name__ == "__main__":
    sys.exit(main())
