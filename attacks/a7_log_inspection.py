#!/usr/bin/env python3
"""A7: Verify that URL fragments never enter a server request log."""

import sys
import time
import uuid
from pathlib import Path

import requests

from common import api_url, base_parser, print_verdict, require_backend


def main() -> int:
    parser = base_parser(__doc__)
    parser.add_argument(
        "--log-path",
        default=str(Path(__file__).resolve().parents[1] / "backend" / "server.log"),
        help="Log file created when starting node server.js with output redirection",
    )
    args = parser.parse_args()
    log_path = Path(args.log_path)
    if not log_path.exists():
        raise SystemExit(
            f"Log file not found: {log_path}\n"
            "Start the backend as documented in attacks/README.md, then run this script."
        )
    require_backend(args.base_url)
    marker = f"fragment-secret-{uuid.uuid4()}"
    log_offset = log_path.stat().st_size

    # HTTP clients must strip fragments before sending a request. The server
    # receives only /health even though the local URL contains the marker.
    response = requests.get(api_url(args.base_url, f"/health#{marker}"), timeout=15)
    if response.status_code != 200:
        raise RuntimeError(f"Health request failed: {response.status_code} {response.text}")
    time.sleep(0.2)
    new_log_text = log_path.read_text(errors="replace")[log_offset:]
    marker_absent = marker not in new_log_text
    route_logged = "GET /health" in new_log_text
    print(f"Request URL used locally: {api_url(args.base_url, f'/health#{marker}')}")
    print(f"Fragment marker appears in new server logs: {not marker_absent}")
    print(f"Server logged the requested route: {route_logged}")
    return print_verdict(
        marker_absent and route_logged,
        "the URL fragment was stripped before the HTTP request and did not reach the server log.",
    )


if __name__ == "__main__":
    sys.exit(main())
