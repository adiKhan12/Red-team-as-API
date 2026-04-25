from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from redteam_api.api.auth import require_api_key
from redteam_api.core.models import (
    CATEGORY_LIST,
    ScanCreateRequest,
    ScanCreatedResponse,
    ScanResponse,
)
from redteam_api.core.storage import Storage

router = APIRouter()


def get_storage(request: Request) -> Storage:
    return request.app.state.storage


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/v1/scans", status_code=202)
async def create_scan(
    request: ScanCreateRequest,
    storage: Storage = Depends(get_storage),
    _auth: None = Depends(require_api_key),
) -> ScanCreatedResponse:
    if not request.categories:
        raise HTTPException(422, "At least one attack category is required")
    from redteam_api.core.orchestrator import get_orchestrator

    orch = get_orchestrator(storage)
    return await orch.enqueue(request)


@router.get("/v1/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    storage: Storage = Depends(get_storage),
    _auth: None = Depends(require_api_key),
) -> ScanResponse:
    row = await storage.get_scan(scan_id)
    if row is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    from redteam_api.core.models import ScanProgress, ScanStatus

    findings = await storage.get_findings(scan_id)

    return ScanResponse(
        scan_id=str(row["scan_id"]),
        status=ScanStatus(row["status"]),
        progress=ScanProgress(
            attempts_run=int(row["attempts_run"]),
            attempts_total=int(row["attempts_total"]),
        ),
        findings=findings,
    )


@router.get("/v1/scans/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    request: Request,
    storage: Storage = Depends(get_storage),
    _auth: None = Depends(require_api_key),
) -> Response:
    row = await storage.get_scan(scan_id)
    if row is None:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    from redteam_api.core.models import ScanStatus

    status = ScanStatus(row["status"])
    findings = await storage.get_findings(scan_id)
    attempts = await storage.get_attempts(scan_id)

    from redteam_api.report.markdown import render_markdown_report
    from redteam_api.report.json_export import render_json_report

    accept = request.headers.get("accept", "text/markdown")

    if "application/json" in accept:
        body = render_json_report(scan_id, status, findings, attempts, row)
        return Response(content=body, media_type="application/json")

    body = render_markdown_report(scan_id, status, findings, attempts, row)
    return Response(content=body, media_type="text/markdown; charset=utf-8")
