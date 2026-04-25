from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class TargetType(str, Enum):
    OPENAI_CHAT = "openai_chat"
    GENERIC_HTTP = "generic_http"


class AuthType(str, Enum):
    BEARER = "bearer"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class Severity(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"


class FindingCategory(str, Enum):
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    JAILBREAK_PERSONA_SWITCH = "jailbreak_persona_switch"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    OUTPUT_HANDLING_UNSAFE_CONTENT = "output_handling_unsafe_content"


CATEGORY_LIST: list[FindingCategory] = list(FindingCategory)


def _gen_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class TargetAuth(BaseModel):
    type: AuthType = AuthType.BEARER
    token: str


class ScanTarget(BaseModel):
    type: TargetType
    url: str
    auth: TargetAuth | None = None
    request_template: dict[str, Any] | None = None
    response_path: str = "$.choices[0].message.content"

    @model_validator(mode="after")
    def _require_template_for_generic(self) -> "ScanTarget":
        if self.type == TargetType.GENERIC_HTTP and not self.request_template:
            raise ValueError("request_template is required for generic_http targets")
        return self


class ScanContext(BaseModel):
    domain: str = ""
    declared_system_prompt: str | None = None
    declared_safety_policy: str | None = None
    tool_schema: list[dict[str, Any]] | None = None
    rendering_context: Literal["html", "plaintext"] = "plaintext"


class ScanModels(BaseModel):
    judge: str | None = None
    attacker: str | None = None


class ScanBudget(BaseModel):
    max_attempts_per_category: int = Field(default=12, ge=1, le=100)
    max_total_seconds: int = Field(default=600, ge=10, le=3600)


class ScanCreateRequest(BaseModel):
    target: ScanTarget
    context: ScanContext = Field(default_factory=ScanContext)
    categories: list[FindingCategory]
    budget: ScanBudget = Field(default_factory=ScanBudget)
    models: ScanModels | None = None


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: _gen_id("fnd"))
    scan_id: str
    category: FindingCategory
    severity: Severity
    confidence: float
    attacker_prompt: str
    target_response: str
    judge_rationale: str


class ScanProgress(BaseModel):
    attempts_run: int = 0
    attempts_total: int = 0


class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    progress: ScanProgress = Field(default_factory=ScanProgress)
    findings: list[Finding] = Field(default_factory=list)


class ScanCreatedResponse(BaseModel):
    scan_id: str
    status: Literal[ScanStatus.QUEUED] = ScanStatus.QUEUED


class AttackAttempt(BaseModel):
    id: str = Field(default_factory=lambda: _gen_id("att"))
    scan_id: str
    category: FindingCategory
    attacker_prompt: str
    target_response: str | None = None
    judge_result: dict[str, Any] | None = None
    cost: float = 0.0
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
