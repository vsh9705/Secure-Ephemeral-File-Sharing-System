"""mitmproxy addon: record factual evidence from matching HTTP flows.

Example:
mitmdump -p 8080 -s attacks/a7_mitm_capture.py --set evidence_dir=attacks/results/proxy --set url_regex=/upload
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from mitmproxy import ctx, http


class Capture:
    def load(self, loader):
        loader.add_option("evidence_dir", str, "attacks/results/proxy", "Directory for JSONL evidence.")
        loader.add_option("url_regex", str, ".*", "Only record flows whose URL matches this regular expression.")
        loader.add_option("marker", str, "", "Optional controlled marker to search for in request and response bodies.")
        loader.add_option("record_bodies", bool, False, "Store raw bodies. Use only with disposable test data.")

    def response(self, flow: http.HTTPFlow) -> None:
        if not re.search(ctx.options.url_regex, flow.request.pretty_url):
            return
        request_body = flow.request.raw_content or b""
        response_body = flow.response.raw_content or b""
        marker = ctx.options.marker.encode() if ctx.options.marker else b""
        fields = []
        try:
            decoded = json.loads(request_body.decode("utf-8"))
            if isinstance(decoded, dict):
                fields = sorted(decoded.keys())
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
        sensitive_names = [name for name in fields if re.search(r"pass|secret|token|key|auth", name, re.I)]
        record = {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": dict(flow.request.headers),
            "request_content_length": len(request_body),
            "request_sha256": hashlib.sha256(request_body).hexdigest(),
            "request_json_fields": fields,
            "request_sensitive_field_names": sensitive_names,
            "response_status": flow.response.status_code,
            "response_headers": dict(flow.response.headers),
            "response_content_length": len(response_body),
            "response_sha256": hashlib.sha256(response_body).hexdigest(),
            "marker_in_request": bool(marker and marker in request_body),
            "marker_in_response": bool(marker and marker in response_body),
        }
        if ctx.options.record_bodies:
            record["request_body_utf8"] = request_body.decode("utf-8", errors="replace")
            record["response_body_utf8"] = response_body.decode("utf-8", errors="replace")
        directory = Path(ctx.options.evidence_dir)
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "flows.jsonl").open("a", encoding="utf-8") as output:
            output.write(json.dumps(record, sort_keys=True) + "\n")
        ctx.log.info(f"captured {flow.request.method} {flow.request.pretty_url} -> {flow.response.status_code}")


addons = [Capture()]
