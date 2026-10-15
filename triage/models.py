"""Duke native tool-call adapter and explicitly scripted offline test provider."""
from __future__ import annotations

import json
import os

from .common import SafeError, CVE, http

DUKE_BASE = "https://litellm.oit.duke.edu/v1"


class DukeModel:
    mode = "live_model"

    def __init__(self, config):
        self.config = config
        self.name = os.environ.get("TRIAGE_MODEL") or config["model"]
        self.credential = os.environ.get("LITELLM_TOKEN") or os.environ.get("DUKE_AI_GATEWAY_API_KEY")
        if not self.credential:
            raise SafeError("duke_credential_missing; run python3 -m triage configure locally or set LITELLM_TOKEN")
        self.metadata = {"provider": "Duke AI Gateway", "model": self.name, "endpoint": DUKE_BASE,
                         "mode": self.mode, "temperature": config["temperature"]}

    def chat(self, messages, tools, timeout, final=False):
        payload = {"model": self.name, "messages": messages, "stream": False,
                   "temperature": self.config["temperature"], "max_tokens": self.config["max_output_tokens"]}
        if final:
            payload["response_format"] = {"type": "json_object"}
        else:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        try:
            response = json.loads(http(DUKE_BASE + "/chat/completions", timeout, payload, self.credential))
            message = response["choices"][0]["message"]
            message = {k: v for k, v in message.items() if k in {"role", "content", "tool_calls"}}
            if message.get("role") != "assistant":
                raise SafeError("invalid_model_message_role")
            if response.get("choices", [{}])[0].get("finish_reason") == "length":
                raise SafeError("model_output_truncated")
            self.metadata["reported_model"] = response.get("model")
            return message, response.get("usage", {})
        except (ValueError, KeyError, TypeError, IndexError):
            raise SafeError("invalid_model_response") from None


class ReplayModel:
    """Never presented as a real LLM. Supports reproducible workflow integration tests."""
    mode = "scripted_replay"

    def __init__(self, config, invalid_first=False):
        self.invalid_first = invalid_first
        self.sent_invalid = False
        self.metadata = {"provider": "Scripted test fixture", "model": "replay-v1", "mode": self.mode}

    def chat(self, messages, tools, timeout, final=False):
        if final:
            packet = json.loads(messages[-1]["content"])
            d = packet["decision"]
            content = {"policy_rule": d["policy_rule"], "rating": d["rating"], "priority": d["priority"],
                       "claim_ids": list(packet["claims"]), "action_ids": list(packet["actions"])}
            return {"role": "assistant", "content": json.dumps(content)}, {}
        if self.invalid_first and not self.sent_invalid:
            self.sent_invalid = True
            return {"role": "assistant", "content": None, "tool_calls": [{"id": "replay-invalid", "type": "function",
                     "function": {"name": "run_shell", "arguments": json.dumps({"command": "refused-test-command"})}}]}, {}
        attempted = set()
        for message in messages:
            if message.get("role") == "assistant":
                for call in message.get("tool_calls", []):
                    function = call["function"]
                    args = json.loads(function["arguments"]) if isinstance(function["arguments"], str) else function["arguments"]
                    attempted.add((function["name"], args.get("source")))
        snapshot = tools[0]["function"]["parameters"]["properties"]["snapshot_id"]["enum"][0]
        queries = [("lookup_environment", {"asset_id": "N02", "snapshot_id": snapshot}),
                   ("lookup_vulnerability", {"cve_id": CVE, "source": "cna"}),
                   ("lookup_vulnerability", {"cve_id": CVE, "source": "cert"}),
                   ("lookup_kev", {"cve_id": CVE})]
        for i, (name, args) in enumerate(queries):
            if (name, args.get("source")) not in attempted:
                call = {"id": f"replay-call-{i}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}
                return {"role": "assistant", "content": None, "tool_calls": [call]}, {}
        return {"role": "assistant", "content": "Evidence gathering complete."}, {}
