from __future__ import annotations

import re
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _env_file() -> Path:
    p = Path(__file__).resolve().parents[3] / ".env"
    return p if p.exists() else Path(".env")


MODEL_ALLOWLIST = re.compile(r"^(anthropic|openai|google|meta-llama|mistralai)/.+$")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_env_file()),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    openrouter_api_key: str = ""
    openrouter_http_referer: str = ""
    openrouter_x_title: str = ""

    rtapi_api_key: str = "rtapi-dev-key-change-me"
    rtapi_judge_model: str = "anthropic/claude-haiku-4-5"
    rtapi_attacker_model: str = "anthropic/claude-sonnet-4-6"

    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    def validate_model_id(self, model_id: str) -> str:
        if MODEL_ALLOWLIST.match(model_id):
            return model_id
        raise ValueError(
            f"Model ID '{model_id}' does not match allowlist pattern "
            r"^(anthropic|openai|google|meta-llama|mistralai)/.+"
        )


settings = Settings()
