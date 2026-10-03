#!/usr/bin/env python3
"""Replay exactly the same authorised HTTP request concurrently and record what happened."""

from __future__ import annotations

import argparse

from lib import (
    assert_authorisation,
    cluster,
    create_result_dir,
    load_json,
    print_observation,
    require_authorisation,
    run_parallel,
    save_result,
    validate_request,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, help="JSON request template captured from an authorised test.")
    parser.add_argument("--workers", type=int, default=5, help="Number of identical simultaneous requests.")
    parser.add_argument("--timeout", type=float, default=15)
    require_authorisation(parser)
    args = parser.parse_args()
    template = load_json(args.request)
    validate_request(template)
    assert_authorisation(args, template["url"])
    if not 2 <= args.workers <= 20:
        raise SystemExit("--workers must be between 2 and 20.")
    observations = run_parallel(template, [{} for _ in range(args.workers)], args.workers, args.timeout)
    result_dir = create_result_dir("a3_replay_race")
    result = {"request_template": template, "workers": args.workers, "observations": observations, "response_clusters": cluster(observations)}
    save_result(result_dir, "result.json", result)
    print_observation(result_dir, "Replay-race observations:", observations)
    print(f"Distinct response clusters: {len(result['response_clusters'])}. Inspect result.json; the tool makes no target-specific success claim.")


if __name__ == "__main__":
    main()
