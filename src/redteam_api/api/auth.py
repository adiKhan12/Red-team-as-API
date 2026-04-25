from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from redteam_api.core.config import settings

_auth_scheme = HTTPBearer(auto_error=False)


async def require_api_key(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_auth_scheme),
) -> None:
    if not settings.rtapi_api_key:
        return
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    if credentials.credentials != settings.rtapi_api_key:
        raise HTTPException(status_code=403, detail="Invalid API key")
