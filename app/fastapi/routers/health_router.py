from __future__ import annotations

from fastapi import APIRouter


router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Возвращает безопасный статус FastAPI-сервера."""
    return {
        "status": "ok",
        "service": "vk-connect",
        "module": "fastapi",
        "message": "VK Connect FastAPI server is running",
    }
