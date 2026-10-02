#!/usr/bin/env python3
"""A3: Race concurrent consumers against a one-time download link."""

import concurrent.futures
import sys

from common import base_parser, create_fixture, download, print_verdict, require_backend, response_text


def main() -> int:
    parser = base_parser(__doc__)
    parser.add_argument("--workers", type=int, default=2, choices=range(2, 11), help="Concurrent consumers")
    args = parser.parse_args()
    require_backend(args.base_url)
    fixture = create_fixture(args.base_url, password="replay-password", label="a3-replay")

    def attempt():
        response = download(args.base_url, fixture.file_id, fixture.key_hash, fixture.password)
        return response.status_code, response_text(response)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        results = list(executor.map(lambda _: attempt(), range(args.workers)))

    statuses = [status for status, _ in results]
    successes = statuses.count(200)
    print(f"Concurrent request status codes: {statuses}")
    for status, body in results:
        if status != 200:
            print(f"Rejected response ({status}): {body}")
            break
    return print_verdict(
        successes == 1,
        "exactly one concurrent consumer received the ciphertext; every other consumer was rejected.",
    )


if __name__ == "__main__":
    sys.exit(main())
