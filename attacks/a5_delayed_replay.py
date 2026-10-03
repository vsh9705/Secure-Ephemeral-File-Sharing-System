#!/usr/bin/env python3
"""Wait for a target TTL or revocation window, then replay one authorised request."""

from __future__ import annotations

import argparse
import time

from lib import assert_authorisation, create_result_dir, execute, load_json, require_authorisation, save_result, validate_request


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, help="Captured valid request to send after the wait.")
    parser.add_argument("--wait-seconds", type=float, required=True, help="How long to wait before replaying.")
    parser.add_argument("--timeout", type=float, default=15)
    require_authorisation(parser)
    args = parser.parse_args()
    if not 0 <= args.wait_seconds <= 86400:
        raise SystemExit("--wait-seconds must be between 0 and 86400.")
    template = load_json(args.request)
    validate_request(template)
    assert_authorisation(args, template["url"])
    print(f"Waiting {args.wait_seconds} seconds before the replay. Do not change the target resource during this wait.")
    time.sleep(args.wait_seconds)
    observation = execute(template, timeout=args.timeout)
    result_dir = create_result_dir("a5_delayed_replay")
    save_result(result_dir, "result.json", {"request_template": template, "wait_seconds": args.wait_seconds, "observation": observation})
    print(f"Delayed replay evidence: {result_dir / 'result.json'}")
    print(observation)
    print("Compare this actual response with a separately captured pre-expiry response. The tool records evidence and does not assume expiry semantics.")


if __name__ == "__main__":
    main()
