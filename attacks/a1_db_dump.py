#!/usr/bin/env python3
"""A1: Simulate an attacker who obtains a copy of the SQLite database."""

import sqlite3
import sys
from pathlib import Path

from common import base_parser, create_fixture, print_verdict, require_backend


def main() -> int:
    parser = base_parser(__doc__)
    parser.add_argument(
        "--db-path",
        default=str(Path(__file__).resolve().parents[1] / "backend" / "fileshare.db"),
        help="Path to the copied SQLite database",
    )
    args = parser.parse_args()
    require_backend(args.base_url)
    fixture = create_fixture(args.base_url, password="db-dump-password", label="a1-db-dump")

    with sqlite3.connect(args.db_path) as connection:
        columns = [row[1] for row in connection.execute("PRAGMA table_info(files)")]
        row = connection.execute(
            "SELECT id, key_hash, password_hash, blob_path FROM files WHERE id = ?", (fixture.file_id,)
        ).fetchone()
        dump_text = "\n".join(
            str(value)
            for database_row in connection.execute("SELECT * FROM files").fetchall()
            for value in database_row
        )

    no_raw_key_column = "raw_key" not in columns and "key" not in columns
    password_is_argon2_hash = bool(row and row[2] and str(row[2]).startswith("$argon2id$"))
    plaintext_absent = fixture.plaintext.decode() not in dump_text
    print(f"Captured database row for fixture: {row[0] if row else 'MISSING'}")
    print(f"Schema has no raw-key column: {no_raw_key_column}")
    print(f"Password is stored as Argon2id: {password_is_argon2_hash}")
    print(f"Known plaintext marker absent from DB: {plaintext_absent}")
    return print_verdict(
        bool(row) and no_raw_key_column and password_is_argon2_hash and plaintext_absent,
        "a database dump exposes metadata and hashes, but not this fixture's plaintext or raw key.",
    )


if __name__ == "__main__":
    sys.exit(main())
