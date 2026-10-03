"""mitmproxy addon: alter one JSON string field in matching authorised test traffic.

Example:
mitmdump -p 8080 -s attacks/a8_mitm_tamper.py --set url_regex=/upload --set json_field=encrypted_blob --set evidence_dir=attacks/results/tamper
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from mitmproxy import ctx, http


def mutate(value: str) -> str:
    if not value:
        return value
    first = value[0]
    replacement = "A" if first != "A" else "B"
    return replacement + value[1:]


class Tamper:
    def load(self, loader):
        loader.add_option("evidence_dir", str, "attacks/results/tamper", "Directory for JSON evidence.")
        loader.add_option("url_regex", str, ".*", "Only tamper matching URLs.")
        loader.add_option("json_field", str, "", "String JSON field to alter.")

    def request(self, flow: http.HTTPFlow) -> None:
        if not re.search(ctx.options.url_regex, flow.request.pretty_url):
            return
        if not ctx.options.json_field:
            return
        try:
            payload = json.loads((flow.request.raw_content or b"").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        field = ctx.options.json_field
        if not isinstance(payload, dict) or not isinstance(payload.get(field), str):
            return
        original_length = len(payload[field])
        payload[field] = mutate(payload[field])
        flow.request.content = json.dumps(payload, separators=(",", ":")).encode()
        flow.metadata["tampered"] = {"field": field, "original_length": original_length}
        ctx.log.warn(f"tampered field {field} in {flow.request.pretty_url}")

    def response(self, flow: http.HTTPFlow) -> None:
        details = flow.metadata.get("tampered")
        if not details:
            return
        directory = Path(ctx.options.evidence_dir)
        directory.mkdir(parents=True, exist_ok=True)
        record = {
            "url": flow.request.pretty_url,
            "tampered_field": details["field"],
            "original_field_length": details["original_length"],
            "server_response_status": flow.response.status_code,
            "server_response_body_preview": (flow.response.raw_content or b"")[:300].decode("utf-8", errors="replace"),
        }
        with (directory / "tampered_flows.jsonl").open("a", encoding="utf-8") as output:
            output.write(json.dumps(record, sort_keys=True) + "\n")
        ctx.log.info(f"tampered flow response status: {flow.response.status_code}")


addons = [Tamper()]
