#!/usr/bin/env python3
"""Controlled client for the A8 mitmproxy addon; it sends one test upload via port 8080."""

import base64
import hashlib
import sys

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import base_parser, print_verdict

PLAINTEXT = b"MITM-PLAINTEXT-SENTINEL-DO-NOT-TRANSMIT"
RAW_KEY = b"\x00" * 32
PASSWORD = "mitm-password-sentinel"


def main() -> int:
    parser = base_parser(__doc__)
    parser.add_argument("--proxy-url", default="http://127.0.0.1:8080", help="mitmproxy listener")
    args = parser.parse_args()
    nonce = b"\x01" * 12
    encrypted_blob = nonce + AESGCM(RAW_KEY).encrypt(nonce, PLAINTEXT, None)
    payload = {
        "encrypted_blob": base64.b64encode(encrypted_blob).decode("ascii"),
        "key_hash": hashlib.sha256(RAW_KEY).hexdigest(),
        "password": PASSWORD,
        "ttl_seconds": 60,
        "original_name": "a8-mitm.txt",
        "mime_type": "text/plain",
    }
    session = requests.Session()
    session.trust_env = False
    response = session.post(
        f"{args.base_url.rstrip('/')}/upload",
        json=payload,
        proxies={"http": args.proxy_url},
        timeout=15,
    )
    print(f"Proxied upload response: {response.status_code} {response.text}")
    return print_verdict(response.status_code == 200, "the controlled upload passed through mitmproxy.")


if __name__ == "__main__":
    sys.exit(main())
