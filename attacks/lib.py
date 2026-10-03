"""Common utilities for configurable, authorised HTTP attack simulations."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

RESULTS_ROOT = Path(__file__).resolve().parent / "results"


def require_authorisation(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="Required acknowledgement that you own or are authorised to test the target.",
    )


def assert_authorisation(args: argparse.Namespace, url: str | None = None) -> None:
    if not args.i_own_this_target:
        raise SystemExit("Refusing to send attack traffic. Re-run with --i-own-this-target.")
    if url:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise SystemExit(f"Request URL must be absolute HTTP(S): {url}")


def load_json(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"Could not read JSON file {path}: {error}") from error
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must contain one JSON object.")
    return data


def render(value, variables: dict[str, str]):
    if isinstance(value, str):
        for name, replacement in variables.items():
            value = value.replace("{{" + name + "}}", replacement)
        return value
    if isinstance(value, list):
        return [render(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: render(item, variables) for key, item in value.items()}
    return value


def validate_request(template: dict) -> None:
    if template.get("method", "GET").upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
        raise SystemExit("Unsupported HTTP method in request template.")
    url = template.get("url")
    if not isinstance(url, str):
        raise SystemExit("Request template needs an absolute string field named url.")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SystemExit("Request template url must begin with http:// or https://.")


def execute(template: dict, variables: dict[str, str] | None = None, timeout: float = 15) -> dict:
    variables = variables or {}
    request = render(copy.deepcopy(template), variables)
    validate_request(request)
    method = request.get("method", "GET").upper()
    headers = request.get("headers", {})
    request_kwargs = {"headers": headers, "timeout": timeout, "allow_redirects": False}
    if "json" in request:
        request_kwargs["json"] = request["json"]
    elif "body" in request:
        request_kwargs["data"] = request["body"].encode() if isinstance(request["body"], str) else request["body"]
    started = time.perf_counter()
    try:
        response = requests.request(method, request["url"], **request_kwargs)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        content = response.content
        return {
            "ok": True,
            "method": method,
            "url": request["url"],
            "status": response.status_code,
            "elapsed_ms": elapsed_ms,
            "content_type": response.headers.get("content-type", ""),
            "content_length": len(content),
            "body_sha256": hashlib.sha256(content).hexdigest(),
            "body_preview": content[:300].decode("utf-8", errors="replace"),
            "response_headers": dict(response.headers),
        }
    except requests.RequestException as error:
        return {
            "ok": False,
            "method": method,
            "url": request["url"],
            "error": str(error),
        }


def create_result_dir(attack_name: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = RESULTS_ROOT / f"{stamp}_{attack_name}"
    path.mkdir(parents=True, exist_ok=False)
    return path


def save_result(result_dir: Path, name: str, value) -> Path:
    path = result_dir / name
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    return path


def print_observation(result_dir: Path, headline: str, observations: list[dict]) -> None:
    print(headline)
    for item in observations:
        if item.get("ok"):
            print(
                f"  status={item['status']} time={item['elapsed_ms']}ms "
                f"bytes={item['content_length']} digest={item['body_sha256'][:12]}"
            )
        else:
            print(f"  request error: {item['error']}")
    print(f"Raw evidence: {result_dir / 'result.json'}")


def cluster(observations: list[dict]) -> list[dict]:
    groups: dict[tuple, list[int]] = {}
    for index, item in enumerate(observations):
        key = (
            item.get("ok"),
            item.get("status"),
            item.get("content_length"),
            item.get("body_sha256"),
        )
        groups.setdefault(key, []).append(index)
    return [
        {
            "count": len(indices),
            "request_indexes": indices,
            "signature": {
                "ok": signature[0],
                "status": signature[1],
                "content_length": signature[2],
                "body_sha256": signature[3],
            },
        }
        for signature, indices in groups.items()
    ]


def run_parallel(template: dict, variables: list[dict[str, str]], workers: int, timeout: float) -> list[dict]:
    results: list[dict | None] = [None] * len(variables)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(execute, template, variables[index], timeout): index
            for index in range(len(variables))
        }
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return [result for result in results if result is not None]


def read_lines(path: str, maximum: int) -> list[str]:
    values = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            values.append(line)
        if len(values) >= maximum:
            break
    return values
