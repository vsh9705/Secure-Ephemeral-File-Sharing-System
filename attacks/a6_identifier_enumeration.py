#!/usr/bin/env python3
"""Probe authorised candidate identifiers and show whether responses are distinguishable."""

from __future__ import annotations

import argparse
import hashlib

from lib import assert_authorisation, cluster, create_result_dir, execute, load_json, read_lines, require_authorisation, save_result, validate_request


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, help="Request template with {{ID}} in URL, body, or headers.")
    parser.add_argument("--identifiers", required=True, help="Authorised candidate IDs, one per line.")
    parser.add_argument("--max-attempts", type=int, default=20)
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--timeout", type=float, default=15)
    require_authorisation(parser)
    args = parser.parse_args()
    if not 1 <= args.max_attempts <= 100 or args.delay < 0:
        raise SystemExit("--max-attempts must be 1..100 and --delay cannot be negative.")
    template = load_json(args.request)
    validate_request(template)
    assert_authorisation(args, template["url"])
    if "{{ID}}" not in str(template):
        raise SystemExit("Template has no {{ID}} placeholder.")
    identifiers = read_lines(args.identifiers, args.max_attempts)
    observations = []
    for identifier in identifiers:
        observation = execute(template, {"ID": identifier}, args.timeout)
        observation["identifier_sha256"] = hashlib.sha256(identifier.encode()).hexdigest()
        observations.append(observation)
        __import__("time").sleep(args.delay)
    result_dir = create_result_dir("a6_identifier_enumeration")
    result = {"request_template": template, "attempt_count": len(identifiers), "observations": observations, "response_clusters": cluster(observations)}
    save_result(result_dir, "result.json", result)
    print(f"Identifier-enumeration evidence: {result_dir / 'result.json'}")
    print(f"Response clusters: {len(result['response_clusters'])}")
    print("Compare clusters for authorised known-valid IDs and random IDs. Different status, size, digest, or timing is concrete enumeration evidence.")


if __name__ == "__main__":
    main()
