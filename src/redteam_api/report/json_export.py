from __future__ import annotations

import json

from redteam_api.core.models import Finding, ScanStatus


def render_json_report(
    scan_id: str,
    status: ScanStatus,
    findings: list[Finding],
    attempts: list[object],
    scan_row: dict[str, object] | None = None,
) -> str:
    payload = {
        "scan_id": scan_id,
        "status": status.value,
        "cost_total": float(scan_row.get("cost_total", 0)) if scan_row else 0.0,
        "findings": [
            {
                "id": f.id,
                "category": f.category.value,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "attacker_prompt": f.attacker_prompt,
                "target_response": f.target_response,
                "judge_rationale": f.judge_rationale,
            }
            for f in findings
        ],
        "attempts": [
            {
                "id": getattr(a, "id", ""),
                "category": getattr(a, "category", ""),
                "attacker_prompt": getattr(a, "attacker_prompt", ""),
                "target_response": getattr(a, "target_response", ""),
                "judge_result": getattr(a, "judge_result", None),
                "cost": getattr(a, "cost", 0.0),
            }
            for a in attempts
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)
