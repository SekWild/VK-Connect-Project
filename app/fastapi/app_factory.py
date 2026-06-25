from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.fastapi.background_tasks import (
    start_vk_refresh_background_worker,
    stop_vk_refresh_background_worker,
)
from app.fastapi.routers.health_router import router as health_router
from app.fastapi.routers.vk_oauth_router import router as vk_oauth_router
from VK.callback_service import router as vk_callback_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Управляет запуском и остановкой фоновых задач FastAPI."""
    del app
    await start_vk_refresh_background_worker()
    try:
        yield
    finally:
        await stop_vk_refresh_background_worker()


def create_app() -> FastAPI:
    """Создает FastAPI-приложение VK Connect Project."""
    app = FastAPI(title="VK Connect Project", lifespan=lifespan)

    app.include_router(health_router)
    app.include_router(vk_oauth_router)
    app.include_router(vk_callback_router)

    return app
