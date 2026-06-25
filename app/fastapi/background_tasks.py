from __future__ import annotations

import asyncio
import logging
import re
from contextlib import suppress

from VK.access_token_service import AccessTokenConfig, AccessTokenService
from VK.queue_refresh_service import (
    QUEUE_REBUILD_INTERVAL_SECONDS,
    REFRESH_BATCH_SIZE,
    REFRESH_DUE_CHECK_INTERVAL_SECONDS,
    QueueRefreshService,
)
from VK.refresh_token_service import RefreshTokenConfig, RefreshTokenService


logger = logging.getLogger(__name__)

SENSITIVE_FIELD_NAMES = (
    "access_token",
    "refresh_token",
    "authorization_code",
    "auth_code",
    "code_verifier",
    "client_secret",
    "device_id",
    "id_token",
    "code",
)
SENSITIVE_FIELD_PATTERN = "|".join(SENSITIVE_FIELD_NAMES)
_refresh_worker_stop_event: asyncio.Event | None = None
_refresh_worker_tasks: list[asyncio.Task[None]] = []


def _sanitize_error_message(message: str) -> str:
    """Консервативно скрывает чувствительные значения из текста ошибки."""
    sanitized = str(message)
    sanitized = re.sub(
        rf"""(?ix)
        (["'](?:{SENSITIVE_FIELD_PATTERN})["']\s*:\s*["'])
        [^"']*
        (["'])
        """,
        r"\1[REDACTED]\2",
        sanitized,
    )
    sanitized = re.sub(
        rf"(?i)\b({SENSITIVE_FIELD_PATTERN})\s*=\s*([^&,\s]+)",
        r"\1=[REDACTED]",
        sanitized,
    )
    sanitized = re.sub(
        rf"(?i)\b({SENSITIVE_FIELD_PATTERN})\s*:\s*([^\s,}}]+)",
        r"\1: [REDACTED]",
        sanitized,
    )
    sanitized = re.sub(
        rf"(?i)\b({SENSITIVE_FIELD_PATTERN})\s+([A-Za-z0-9._~+/=-]{{6,}})",
        r"\1 [REDACTED]",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)(Authorization\s*:\s*)?Bearer\s+[^\s,;]+",
        "Bearer [REDACTED]",
        sanitized,
    )
    sanitized = re.sub(
        r"(?i)\bvk[12]\.[A-Za-z0-9._~+/=-]+",
        "[REDACTED]",
        sanitized,
    )
    return sanitized


async def exchange_vk_callback_code_in_background(
    state: str,
    code: str,
    device_id: str = "",
    user_id: str = "",
) -> None:
    """Безопасно обменивает VK authorization code на token data в фоне."""
    if not state or not code:
        logger.warning(
            "VK token exchange не запущен: отсутствует state или authorization code."
        )
        return

    try:
        config = AccessTokenConfig.from_env()
        service = AccessTokenService(config)
        await service.process_callback_code(
            state=state,
            code=code,
            user_id=user_id,
            device_id=device_id.strip(),
        )
    except Exception as exc:
        safe_error_message = _sanitize_error_message(str(exc))
        logger.error(
            "VK token exchange завершился ошибкой: "
            "state=%s, device_id_present=%s, error_type=%s, error=%s.",
            state,
            bool(device_id),
            type(exc).__name__,
            safe_error_message,
        )
        return

    logger.info(
        "VK token exchange успешно завершен: state=%s, device_id_present=%s.",
        state,
        bool(device_id),
    )


async def start_vk_refresh_background_worker() -> None:
    """Запускает автоматический VK refresh worker внутри FastAPI process."""
    global _refresh_worker_stop_event, _refresh_worker_tasks

    active_tasks = [task for task in _refresh_worker_tasks if not task.done()]
    if active_tasks:
        logger.info("VK refresh background worker уже запущен.")
        return

    _refresh_worker_stop_event = asyncio.Event()
    _refresh_worker_tasks = [
        asyncio.create_task(
            _refresh_queue_loop(_refresh_worker_stop_event),
            name="vk-refresh-queue-loop",
        ),
        asyncio.create_task(
            _due_refresh_loop(_refresh_worker_stop_event),
            name="vk-due-refresh-loop",
        ),
    ]
    logger.info("VK refresh background worker запущен.")


async def stop_vk_refresh_background_worker() -> None:
    """Останавливает автоматический VK refresh worker."""
    global _refresh_worker_stop_event, _refresh_worker_tasks

    if _refresh_worker_stop_event is None:
        return

    _refresh_worker_stop_event.set()
    for task in _refresh_worker_tasks:
        task.cancel()

    for task in _refresh_worker_tasks:
        with suppress(asyncio.CancelledError):
            await task

    _refresh_worker_stop_event = None
    _refresh_worker_tasks = []
    logger.info("VK refresh background worker остановлен.")


async def _refresh_queue_loop(stop_event: asyncio.Event) -> None:
    """Периодически пересобирает refresh queue."""
    while not stop_event.is_set():
        try:
            result = await asyncio.to_thread(_rebuild_refresh_queue_once)
            logger.info(
                "VK refresh queue rebuilt: planned=%s, emergency=%s, skipped=%s.",
                result.planned_count,
                result.emergency_count,
                result.skipped_count,
            )
        except Exception as exc:
            logger.error(
                "VK refresh queue rebuild failed: error_type=%s, error=%s.",
                type(exc).__name__,
                _sanitize_error_message(str(exc)),
            )

        if await _wait_for_stop(stop_event, QUEUE_REBUILD_INTERVAL_SECONDS):
            break


async def _due_refresh_loop(stop_event: asyncio.Event) -> None:
    """Периодически выполняет refresh для due token rows."""
    while not stop_event.is_set():
        try:
            token_ids = await asyncio.to_thread(_get_due_refresh_token_ids)
        except Exception as exc:
            logger.error(
                "VK due refresh lookup failed: error_type=%s, error=%s.",
                type(exc).__name__,
                _sanitize_error_message(str(exc)),
            )
            if await _wait_for_stop(stop_event, REFRESH_DUE_CHECK_INTERVAL_SECONDS):
                break
            continue

        if token_ids:
            await _refresh_due_tokens(token_ids)

        if await _wait_for_stop(stop_event, REFRESH_DUE_CHECK_INTERVAL_SECONDS):
            break


def _rebuild_refresh_queue_once():
    """Создает planner и пересобирает queue в worker thread."""
    return QueueRefreshService().rebuild_refresh_queue()


def _get_due_refresh_token_ids() -> list[int]:
    """Возвращает due token IDs в worker thread."""
    return QueueRefreshService().get_due_token_ids(limit=REFRESH_BATCH_SIZE)


async def _refresh_due_tokens(token_ids: list[int]) -> None:
    """Выполняет refresh для найденных due token IDs."""
    try:
        config = RefreshTokenConfig.from_env()
    except Exception as exc:
        logger.error(
            "VK refresh config load failed: error_type=%s, error=%s.",
            type(exc).__name__,
            _sanitize_error_message(str(exc)),
        )
        return

    refresh_service = RefreshTokenService(config=config)
    for token_id in token_ids:
        try:
            result = await refresh_service.refresh_token_by_token_id(token_id)
        except Exception as exc:
            logger.error(
                "VK token refresh failed unexpectedly: token_id=%s, "
                "error_type=%s, error=%s.",
                token_id,
                type(exc).__name__,
                _sanitize_error_message(str(exc)),
            )
            continue

        logger.info(
            "VK token refresh finished: token_id=%s, link_id=%s, "
            "refreshed=%s, status=%s.",
            result.token_id,
            result.link_id,
            result.refreshed,
            result.status,
        )


async def _wait_for_stop(stop_event: asyncio.Event, timeout_seconds: int) -> bool:
    """Ждет остановку worker или истечение таймера."""
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=timeout_seconds)
    except TimeoutError:
        return False
    return True
