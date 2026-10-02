#!/usr/bin/env python3
"""A2: Simulate theft of an encrypted blob from the server's uploads directory."""

import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import base_parser, create_fixture, print_verdict, require_backend


def main() -> int:
    parser = base_parser(__doc__)
    parser.add_argument(
        "--uploads-dir",
        default=str(Path(__file__).resolve().parents[1] / "backend" / "uploads"),
        help="Directory from which the attacker stole the .bin file",
    )
    args = parser.parse_args()
    require_backend(args.base_url)
    fixture = create_fixture(args.base_url, label="a2-blob-exfil")
    stolen_blob = (Path(args.uploads_dir) / f"{fixture.file_id}.bin").read_bytes()

    plaintext_absent = fixture.plaintext not in stolen_blob
    try:
        attacker_key = AESGCM.generate_key(bit_length=256)
        AESGCM(attacker_key).decrypt(stolen_blob[:12], stolen_blob[12:], None)
        wrong_key_rejected = False
    except InvalidTag:
        wrong_key_rejected = True

    print(f"Stolen blob size: {len(stolen_blob)} bytes")
    print(f"Known plaintext bytes absent from stolen blob: {plaintext_absent}")
    print(f"AES-GCM rejects decryption with an attacker key: {wrong_key_rejected}")
    return print_verdict(
        stolen_blob == fixture.encrypted_blob and plaintext_absent and wrong_key_rejected,
        "a stolen blob is ciphertext and cannot be authenticated/decrypted with a different 256-bit key.",
    )


if __name__ == "__main__":
    sys.exit(main())
