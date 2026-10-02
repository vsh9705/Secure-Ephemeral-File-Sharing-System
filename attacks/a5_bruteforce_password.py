#!/usr/bin/env python3
"""A5: Online dictionary attack against a password-protected share."""

import sys
import time

from common import base_parser, create_fixture, download, print_verdict, require_backend

GUESSES = [
    "password", "123456", "qwerty", "letmein", "admin", "welcome",
    "password123", "iloveyou", "abc123", "monkey", "dragon", "football",
]


def main() -> int:
    parser = base_parser(__doc__)
    parser.add_argument("--attempts", type=int, default=len(GUESSES), help="Number of dictionary entries to try")
    args = parser.parse_args()
    require_backend(args.base_url)
    password = "correct-password-not-in-dictionary"
    fixture = create_fixture(args.base_url, password=password, label="a5-password-guessing")
    guesses = GUESSES[:args.attempts]
    statuses = []
    started = time.perf_counter()
    for guess in guesses:
        response = download(args.base_url, fixture.file_id, fixture.key_hash, guess)
        statuses.append(response.status_code)
    elapsed = time.perf_counter() - started

    print(f"Submitted {len(guesses)} wrong dictionary passwords in {elapsed:.2f}s")
    print(f"Status codes: {statuses}")
    print(f"Successful guesses: {statuses.count(200)}")
    print(f"Rate-limit responses (429): {statuses.count(429)}")
    return print_verdict(
        statuses.count(200) == 0 and (len(guesses) < 11 or 429 in statuses),
        "the dictionary did not unlock the share and the online rate limit throttled repeated attempts.",
    )


if __name__ == "__main__":
    sys.exit(main())
