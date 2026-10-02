#!/usr/bin/env python3
"""A6: Attempt to download a link after its TTL has expired."""

import sys
import time

from common import base_parser, create_fixture, download, print_verdict, require_backend, response_text


def main() -> int:
    parser = base_parser(__doc__)
    parser.add_argument("--ttl", type=int, default=2, help="Short TTL used for the test")
    args = parser.parse_args()
    require_backend(args.base_url)
    fixture = create_fixture(args.base_url, ttl_seconds=args.ttl, label="a6-ttl")
    print(f"Created fixture {fixture.file_id} with TTL={args.ttl}s. Waiting for expiry...")
    time.sleep(args.ttl + 1)
    response = download(args.base_url, fixture.file_id, fixture.key_hash)
    print(f"Post-expiry response: {response.status_code} {response_text(response)}")
    return print_verdict(
        response.status_code == 404,
        "the download route itself rejects an expired record; it does not rely only on the cron sweep.",
    )


if __name__ == "__main__":
    sys.exit(main())
