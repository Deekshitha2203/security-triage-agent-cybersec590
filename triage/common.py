"""Safe persistence, source hashing, and bounded HTTP without third-party packages."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
CVE = "CVE-2024-21762"
SECRET_ENV = ("LITELLM_TOKEN", "DUKE_AI_GATEWAY_API_KEY", "TRIAGE_MODEL_API_KEY", "OLLAMA_API_KEY", "OPENAI_API_KEY", "RECORDED_FUTURE_API_KEY")


class SafeError(Exception):
    """Only application-defined messages; never include remote exception bodies."""


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data: bytes):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def load_local_env():
    """Read only known config names from an ignored .env; never evaluate its content."""
    path = ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in SECRET_ENV + ("TRIAGE_MODEL",):
            os.environ.setdefault(key, value.strip().strip('"').strip("'"))


def redact(value):
    """Remove configured secrets and common credential patterns recursively."""
    if isinstance(value, dict):
        return {k: "[REDACTED]" if re.search(r"authorization|api[_-]?key|token|password|secret", k, re.I)
                and k not in {"max_output_tokens", "max_tokens", "prompt_tokens", "completion_tokens", "total_tokens"}
                else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if not isinstance(value, str):
        return value
    for key in SECRET_ENV:
        secret = os.environ.get(key)
        if secret:
            value = value.replace(secret, "[REDACTED]")
    value = re.sub(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
    return re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "[REDACTED]", value)


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(redact(obj), indent=2, ensure_ascii=False) + "\n")
    temp.replace(path)


def write_text(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact(content), encoding="utf-8")


class Budget:
    def __init__(self, config):
        self.config = config
        self.deadline = time.monotonic() + config["run_timeout_seconds"]
        self.executions = 0
        self.model_turns = 0

    def remaining(self):
        return self.deadline - time.monotonic()

    def timeout(self, seconds):
        if self.remaining() <= 0:
            raise SafeError("run_deadline_exhausted")
        return min(seconds, self.remaining())

    def use_tool(self):
        self.timeout(1)
        if self.executions >= self.config["max_tool_executions"]:
            raise SafeError("tool_budget_exhausted")
        self.executions += 1

    def use_model(self):
        self.timeout(1)
        if self.model_turns >= self.config["max_model_turns"]:
            raise SafeError("model_budget_exhausted")
        self.model_turns += 1


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SafeError("redirect_refused")


def http(url, timeout, payload=None, credential=None, max_bytes=8_000_000):
    headers = {"User-Agent": "Northbridge-Course-Triage/1.0", "Accept": "application/json, text/html"}
    if credential:
        headers["Authorization"] = "Bearer " + credential
    body = None if payload is None else json.dumps(redact(payload)).encode()
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = Request(url, data=body, headers=headers)
    try:
        with build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise SafeError("response_size_exceeded")
            return data
    except HTTPError as exc:
        raise SafeError("http_status_" + str(exc.code)) from None
    except (URLError, TimeoutError, OSError):
        raise SafeError("network_unavailable_or_timeout") from None
    except SafeError:
        raise
    except Exception:
        raise SafeError("invalid_http_response") from None
