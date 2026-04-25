from __future__ import annotations

import asyncio
import importlib
import json
import traceback
from datetime import datetime, timezone

from redteam_api.adapters.base import TargetAdapter
from redteam_api.attacks.base import AttackModule
from redteam_api.core.models import (
    AttackAttempt,
    Finding,
    FindingCategory,
    ScanBudget,
    ScanContext,
    ScanCreateRequest,
    ScanCreatedResponse,
    ScanModels,
    ScanStatus,
    Severity,
    TargetType,
    _gen_id,
)
from redteam_api.core.storage import Storage

ATTACK_MODULE_MAP: dict[FindingCategory, str] = {
    FindingCategory.DIRECT_PROMPT_INJECTION: "redteam_api.attacks.direct_prompt_injection",
    FindingCategory.SYSTEM_PROMPT_EXTRACTION: "redteam_api.attacks.system_prompt_extraction",
    FindingCategory.JAILBREAK_PERSONA_SWITCH: "redteam_api.attacks.jailbreak_persona_switch",
    FindingCategory.INDIRECT_PROMPT_INJECTION: "redteam_api.attacks.indirect_prompt_injection",
    FindingCategory.OUTPUT_HANDLING_UNSAFE_CONTENT: "redteam_api.attacks.output_handling",
}


class Orchestrator:
    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    async def enqueue(self, request: ScanCreateRequest) -> ScanCreatedResponse:
        scan_id = _gen_id("scn")
        attempts_total = len(request.categories) * request.budget.max_attempts_per_category
        created_at = datetime.now(timezone.utc).isoformat()

        await self._storage.insert_scan(
            scan_id=scan_id,
            request_json=json.dumps(request.model_dump(), default=str),
            attempts_total=attempts_total,
            created_at=created_at,
        )

        asyncio.create_task(self._run_scan(scan_id, request))

        return ScanCreatedResponse(scan_id=scan_id)

    async def _run_scan(self, scan_id: str, request: ScanCreateRequest) -> None:
        await self._storage.update_scan_status(scan_id, ScanStatus.RUNNING)

        try:
            adapter = await self._build_adapter(request)

            async with asyncio.TaskGroup() as tg:
                for category in request.categories:
                    module = self._load_module(category)
                    if module is None:
                        continue
                    tg.create_task(
                        self._run_category(
                            scan_id=scan_id,
                            category=category,
                            module=module,
                            adapter=adapter,
                            budget=request.budget,
                            context=request.context,
                            models=request.models,
                        )
                    )

            await self._storage.update_scan_status(scan_id, ScanStatus.COMPLETE)
        except Exception:
            traceback.print_exc()
            await self._storage.update_scan_status(scan_id, ScanStatus.FAILED)

    async def _run_category(
        self,
        scan_id: str,
        category: FindingCategory,
        module: AttackModule,
        adapter: TargetAdapter,
        budget: ScanBudget,
        context: ScanContext,
        models: ScanModels | None,
    ) -> None:
        attempts = await module.generate_attempts(context, budget.max_attempts_per_category, models)

        run_count = 0
        for attempt in attempts:
            attempt.scan_id = scan_id

            try:
                target_response = await adapter.send(attempt.attacker_prompt, context)
                attempt.target_response = target_response or ""
            except Exception:
                attempt.target_response = "[ERROR: target unreachable]"
                run_count += 1
                continue

            try:
                judge_result = await module.judge_response(attempt, context, models)
            except Exception:
                judge_result = {
                    "success": False,
                    "severity": "P5",
                    "confidence": 0.0,
                    "rationale": "Judge call failed",
                }

            attempt.judge_result = judge_result
            run_count += 1

            await self._storage.insert_attempt(attempt)

            if judge_result and judge_result.get("success"):
                finding = Finding(
                    scan_id=scan_id,
                    category=attempt.category,
                    severity=Severity(judge_result.get("severity", "P3")),
                    confidence=float(judge_result.get("confidence", 0.5)),
                    attacker_prompt=attempt.attacker_prompt,
                    target_response=attempt.target_response or "",
                    judge_rationale=str(judge_result.get("rationale", "")),
                )
                await self._storage.insert_finding(finding)

        await self._storage.update_scan_status(scan_id, ScanStatus.RUNNING, attempts_run=run_count)

    def _load_module(self, category: FindingCategory) -> AttackModule | None:
        module_name = ATTACK_MODULE_MAP.get(category)
        if module_name is None:
            return None

        try:
            mod = importlib.import_module(module_name)
            return getattr(mod, "module")
        except (ImportError, AttributeError):
            return None

    async def _build_adapter(self, request: ScanCreateRequest) -> TargetAdapter:
        if request.target.type == TargetType.OPENAI_CHAT:
            from redteam_api.adapters.openai_chat import OpenAIChatAdapter

            return OpenAIChatAdapter(
                base_url=request.target.url,
                api_key=request.target.auth.token if request.target.auth else "",
            )
        else:
            from redteam_api.adapters.generic_http import GenericHTTPAdapter

            return GenericHTTPAdapter(
                base_url=request.target.url,
                request_template=request.target.request_template or {},
                response_path=request.target.response_path,
                auth=request.target.auth,
            )


_ORCHESTRATOR: Orchestrator | None = None


def get_orchestrator(storage: Storage) -> Orchestrator:
    global _ORCHESTRATOR
    if _ORCHESTRATOR is None:
        _ORCHESTRATOR = Orchestrator(storage)
    return _ORCHESTRATOR
