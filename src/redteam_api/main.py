from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from redteam_api.api.routes import router
from redteam_api.core.storage import Storage


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    storage = Storage()
    await storage.init()
    app.state.storage = storage
    yield


app = FastAPI(
    title="Red Team API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
