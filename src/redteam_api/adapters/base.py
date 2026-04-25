from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class TargetAdapter(ABC):
    @abstractmethod
    async def send(self, user_message: str, context: Any | None = None) -> str:
        ...
