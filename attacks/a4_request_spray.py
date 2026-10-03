#!/usr/bin/env python3
"""Send an authorised wordlist through a request placeholder and detect response anomalies."""

from __future__ import annotations

import argparse

from lib import (
    assert_authorisation,
    cluster,
    create_result_dir,
    execute,
    load_json,
    print_observation,
    read_lines,
    require_authorisation,
    save_result,
    validate_request,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, help="JSON request template containing {{GUESS}}.")
    parser.add_argument("--wordlist", required=True, help="One authorised candidate per line.")
    parser.add_argument("--max-attempts", type=int, default=20, help="Safety cap; maximum 100.")
    parser.add_argument("--delay", type=float, default=0.25, help="Seconds between attempts.")
    parser.add_argument("--timeout", type=float, default=15)
    require_authorisation(parser)
    args = parser.parse_args()
    if not 1 <= args.max_attempts <= 100 or args.delay < 0:
        raise SystemExit("--max-attempts must be 1..100 and --delay cannot be negative.")
    template = load_json(args.request)
    validate_request(template)
    assert_authorisation(args, template["url"])
    if "{{GUESS}}" not in str(template):
        raise SystemExit("Template has no {{GUESS}} placeholder.")
    guesses = read_lines(args.wordlist, args.max_attempts)
    if not guesses:
        raise SystemExit("Wordlist had no usable values.")
    observations = []
    for index, guess in enumerate(guesses):
        observation = execute(template, {"GUESS": guess}, args.timeout)
        observation["candidate_index"] = index
        observation["candidate_sha256"] = __import__("hashlib").sha256(guess.encode()).hexdigest()
        observations.append(observation)
        if index < len(guesses) - 1:
            __import__("time").sleep(args.delay)
    result_dir = create_result_dir("a4_request_spray")
    result = {"request_template": template, "attempt_count": len(guesses), "observations": observations, "response_clusters": cluster(observations)}
    save_result(result_dir, "result.json", result)
    print_observation(result_dir, "Spray observations:", observations)
    print("Candidate values are represented only by SHA-256 in result.json. Different status/body clusters are concrete anomalies for review, not automatic proof of authentication.")


if __name__ == "__main__":
    main()
