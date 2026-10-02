"""Shared helpers for controlled attacks against a local ephemeral.share server.

These helpers create real AES-GCM ciphertext, so the tests exercise the same
server contract used by the browser application.  They never target hosts
other than the explicitly supplied local test server.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import time
import uuid
from dataclasses import dataclass

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DEFAULT_BASE_URL = "http://localhost:3001"
TIMEOUT_SECONDS = 15


@dataclass
class Fixture:
    file_id: str
    plaintext: bytes
    key: bytes
    key_hash: str
    encrypted_blob: bytes
    password: str | None


def base_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Backend address (default: {DEFAULT_BASE_URL})",
    )
    return parser


def api_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}{path}"


def require_backend(base_url: str) -> None:
    try:
        response = requests.get(api_url(base_url, "/health"), timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.RequestException as error:
        raise SystemExit(
            f"Cannot reach {base_url}. Start the backend first: cd backend && node server.js\n{error}"
        ) from error


def create_fixture(
    base_url: str,
    *,
    password: str | None = None,
    ttl_seconds: int = 60,
    label: str = "attack",
) -> Fixture:
    """Upload a unique, genuinely encrypted test file and return local secrets."""
    marker = f"{label}-plaintext-marker-{uuid.uuid4()}".encode()
    plaintext = marker + b"\nThis content must never be recoverable from server storage.\n"
    key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    encrypted_blob = nonce + AESGCM(key).encrypt(nonce, plaintext, None)
    key_hash = hashlib.sha256(key).hexdigest()
    payload = {
        "encrypted_blob": base64.b64encode(encrypted_blob).decode("ascii"),
        "key_hash": key_hash,
        "ttl_seconds": ttl_seconds,
        "original_name": f"{label}.txt",
        "mime_type": "text/plain",
    }
    if password is not None:
        payload["password"] = password

    response = requests.post(api_url(base_url, "/upload"), json=payload, timeout=TIMEOUT_SECONDS)
    if response.status_code != 200:
        raise RuntimeError(f"Fixture upload failed ({response.status_code}): {response.text}")
    return Fixture(
        file_id=response.json()["file_id"],
        plaintext=plaintext,
        key=key,
        key_hash=key_hash,
        encrypted_blob=encrypted_blob,
        password=password,
    )


def download(base_url: str, file_id: str, key_hash: str, password: str | None = None) -> requests.Response:
    payload: dict[str, str] = {"key_hash": key_hash}
    if password is not None:
        payload["password"] = password
    return requests.post(
        api_url(base_url, f"/download/{file_id}"), json=payload, timeout=TIMEOUT_SECONDS
    )


def response_text(response: requests.Response) -> str:
    try:
        return json.dumps(response.json())
    except ValueError:
        return response.text


def print_verdict(passed: bool, summary: str) -> int:
    verdict = "PASS" if passed else "FAIL"
    print(f"\nVERDICT: {verdict} — {summary}")
    return 0 if passed else 1


def wait_until(timestamp: float) -> None:
    while time.time() < timestamp:
        time.sleep(0.1)
