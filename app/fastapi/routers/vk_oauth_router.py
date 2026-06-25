from __future__ import annotations

from fastapi import APIRouter, HTTPException
from starlette.concurrency import run_in_threadpool

from VK.oauth_service import OAuthConfig, OAuthService


router = APIRouter(
    prefix="/auth/vk",
    tags=["VK OAuth"],
)


@router.get("/start")
async def start_vk_oauth() -> dict[str, str]:
    """Создает данные для старта VK OAuth и возвращает authorization URL."""
    try:
        config = OAuthConfig.fill_data()
        service = OAuthService(config)
        authorization_data = await run_in_threadpool(
            service.create_authorization_data
        )

        state = authorization_data.get("state", "")
        oauth_url = authorization_data.get("oauth_url", "")
        if not state or not oauth_url:
            raise RuntimeError("OAuth service вернул неполные данные.")

        return {
            "state": state,
            "oauth_url": oauth_url,
            "message": "Open oauth_url in browser to start VK authorization",
        }
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Не удалось создать VK OAuth URL.",
        ) from exc
