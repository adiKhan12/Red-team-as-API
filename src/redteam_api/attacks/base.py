from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from redteam_api.core.models import AttackAttempt, FindingCategory, ScanContext, ScanModels


class AttackModule(ABC):
    category: FindingCategory

    @abstractmethod
    async def generate_attempts(
        self,
        context: ScanContext,
        max_attempts: int,
        models: ScanModels | None = None,
    ) -> list[AttackAttempt]:
        ...

    @abstractmethod
    async def judge_response(
        self,
        attempt: AttackAttempt,
        context: ScanContext,
        models: ScanModels | None = None,
    ) -> dict[str, Any]:
        ...
