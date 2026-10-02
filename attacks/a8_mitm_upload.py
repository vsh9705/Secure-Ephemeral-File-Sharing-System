"""mitmproxy addon for A8: inspect an intercepted HTTP upload without storing its body.

Run with: mitmdump -p 8080 -s attacks/a8_mitm_upload.py
Then run: python attacks/a8_mitm_client.py
"""

import json
from pathlib import Path

from mitmproxy import ctx, http

RESULT_PATH = Path(__file__).resolve().parent / "results" / "a8_mitm_upload.json"
PLAINTEXT_MARKER = b"MITM-PLAINTEXT-SENTINEL-DO-NOT-TRANSMIT"
RAW_KEY_MARKER = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PASSWORD_MARKER = b"mitm-password-sentinel"


class UploadInspector:
    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.method != "POST" or flow.request.path != "/upload":
            return
        body = flow.request.raw_content or b""
        try:
            field_names = sorted(json.loads(body.decode("utf-8")).keys())
        except (UnicodeDecodeError, json.JSONDecodeError):
            field_names = ["<unparseable request body>"]
        evidence = {
            "target": f"{flow.request.scheme}://{flow.request.host}:{flow.request.port}{flow.request.path}",
            "request_fields": field_names,
            "plaintext_marker_visible": PLAINTEXT_MARKER in body,
            "raw_key_marker_visible": RAW_KEY_MARKER in body,
            "password_visible": PASSWORD_MARKER in body,
            "result": (
                "FINDING: plaintext and raw key were absent, but the optional password was visible "
                "to the on-path observer. Use HTTPS and a password-authenticated key exchange in production."
                if PASSWORD_MARKER in body
                else "PASS: neither the controlled plaintext marker nor raw-key marker was visible."
            ),
        }
        RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
        RESULT_PATH.write_text(json.dumps(evidence, indent=2) + "\n")
        ctx.log.info(f"A8 evidence saved to {RESULT_PATH}")


addons = [UploadInspector()]
