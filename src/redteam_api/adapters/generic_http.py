from __future__ import annotations

import re
from typing import Any

import httpx
from jsonpath_ng import parse as jsonpath_parse
from jsonpath_ng.exceptions import JsonPathParserError

from redteam_api.adapters.base import TargetAdapter
from redteam_api.core.models import TargetAuth


class GenericHTTPAdapter(TargetAdapter):
    def __init__(
        self,
        base_url: str,
        request_template: dict[str, Any],
        response_path: str,
        auth: TargetAuth | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._template = request_template
        self._response_path = response_path
        self._auth = auth

    def _interpolate(self, template: dict[str, Any], user_message: str) -> dict[str, Any]:
        import json

        raw = json.dumps(template)
        raw = raw.replace("{{user_message}}", user_message.replace('"', '\\"'))
        return json.loads(raw)

    def _extract(self, data: dict[str, Any]) -> str:
        try:
            expr = jsonpath_parse(self._response_path)
            matches = [m.value for m in expr.find(data)]
            if matches:
                return str(matches[0])
        except (JsonPathParserError, TypeError):
            pass
        return json.dumps(data)

    async def send(self, user_message: str, context: Any | None = None) -> str:
        headers: dict[str, str] = {}
        if self._auth and self._auth.token:
            headers["Authorization"] = f"Bearer {self._auth.token}"

        body = self._interpolate(self._template, user_message)

        method = body.pop("_method", "POST").upper()
        path = body.pop("_path", "/")
        url = f"{self._base_url}{path}"

        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"

        async with httpx.AsyncClient(timeout=60.0) as client:
            if method == "GET":
                response = await client.get(url, headers=headers, params=body)
            else:
                response = await client.request(method, url, json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
            return self._extract(data)
