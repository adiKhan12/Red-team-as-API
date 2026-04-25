from __future__ import annotations

from typing import Any

import httpx

from redteam_api.adapters.base import TargetAdapter


class OpenAIChatAdapter(TargetAdapter):
    def __init__(self, base_url: str, api_key: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key

    async def send(self, user_message: str, context: Any | None = None) -> str:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        messages = [{"role": "user", "content": user_message}]

        payload = {
            "model": "default",
            "messages": messages,
            "max_tokens": 512,
            "temperature": 0.0,
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{self._base_url}/chat/completions",
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
