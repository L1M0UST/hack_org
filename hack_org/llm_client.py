"""OpenAI-compatible LLM client and prompt rendering helpers."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml
from jsonschema import ValidationError

from .llm_protocol import load_schema, validate_payload
from .errors import ModelAuthError, ModelConnectionError, ModelResponseFormatError
from .env_utils import load_env_file


@dataclass
class PromptConfig:
    """Paths for one LLM task definition."""

    system: Path
    user_template: Path
    schema: Path


@dataclass
class LLMConfig:
    """OpenAI-compatible provider configuration."""

    base_url: str
    api_key_env: str
    model: str
    temperature: float
    timeout_seconds: float
    max_retries: int
    response_format: str
    prompts: dict[str, PromptConfig]


def load_llm_config(path: Path) -> LLMConfig:
    """Load LLM configuration from YAML."""

    data = yaml.safe_load(path.read_text(encoding="utf-8"))["llm"]
    prompts = {
        name: PromptConfig(
            system=Path(item["system"]),
            user_template=Path(item["user_template"]),
            schema=Path(item["schema"]),
        )
        for name, item in data["prompts"].items()
    }
    return LLMConfig(
        base_url=str(data["base_url"]).rstrip("/"),
        api_key_env=str(data["api_key_env"]),
        model=str(data["model"]),
        temperature=float(data.get("temperature", 0.1)),
        timeout_seconds=float(data.get("timeout_seconds", 120)),
        max_retries=int(data.get("max_retries", 3)),
        response_format=str(data.get("response_format", "json_schema")),
        prompts=prompts,
    )


class OpenAICompatibleClient:
    """Minimal OpenAI-compatible chat-completions client for structured tasks."""

    def __init__(self, config: LLMConfig, env_path: Path | None = None) -> None:
        if env_path:
            load_env_file(env_path)
        api_key = os.environ.get(config.api_key_env)
        if not api_key:
            raise RuntimeError(f"Missing API key env var: {config.api_key_env}")
        self.config = config
        self.api_key = api_key

    def run_task(self, task_type: str, variables: dict[str, Any], repo_root: Path) -> dict[str, Any]:
        """Render prompts, call the model, parse JSON, and validate the response."""

        prompt_cfg = self.config.prompts[task_type]
        system_prompt = (repo_root / prompt_cfg.system).read_text(encoding="utf-8")
        user_template = (repo_root / prompt_cfg.user_template).read_text(encoding="utf-8")
        user_prompt = render_template(user_template, variables)
        schema_path = repo_root / prompt_cfg.schema
        schema = load_schema(schema_path)
        schema_prompt = (
            "\n\nAUTHORITATIVE JSON SCHEMA\n"
            "The final answer must validate against this exact schema. "
            "Do not invent singular/plural variants, renamed fields, or extra keys.\n"
            f"{json.dumps(schema, ensure_ascii=False, indent=2)}"
        )
        messages = [
            {"role": "system", "content": system_prompt + schema_prompt},
            {"role": "user", "content": user_prompt},
        ]
        last_error: Exception | None = None
        content = ""
        for attempt in range(1, self.config.max_retries + 1):
            try:
                content = self._chat_completion(task_type, schema, messages)
                result = json.loads(content)
                validate_payload(schema_path, result)
                return result
            except (json.JSONDecodeError, ValidationError) as exc:
                last_error = exc
                if attempt >= self.config.max_retries:
                    break
                if isinstance(exc, ValidationError):
                    messages = [
                        *messages,
                        {"role": "assistant", "content": content},
                        {
                            "role": "user",
                            "content": (
                                "Your previous JSON failed validation. Return a corrected JSON object only. "
                                f"Validation error: {exc.message}"
                            ),
                        },
                    ]
                time.sleep(min(2 ** (attempt - 1), 4))
        raise ModelResponseFormatError(str(last_error)) from last_error

    def _chat_completion(self, task_type: str, schema: dict[str, Any], messages: list[dict[str, str]]) -> str:
        """Call one OpenAI-compatible chat completion request."""

        payload = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "messages": messages,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": task_type,
                    "schema": schema,
                    "strict": True,
                },
            },
        }
        try:
            response = httpx.post(
                f"{self.config.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.config.timeout_seconds,
                trust_env=False,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in {401, 403}:
                raise ModelAuthError(str(exc)) from exc
            raise ModelConnectionError(str(exc)) from exc
        except httpx.RequestError as exc:
            raise ModelConnectionError(str(exc)) from exc
        return response.json()["choices"][0]["message"]["content"]


def render_template(template: str, variables: dict[str, Any]) -> str:
    """Render a tiny JSON-oriented placeholder template."""

    rendered = template
    for key, value in variables.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", json.dumps(value, ensure_ascii=False, indent=2))
    return rendered
