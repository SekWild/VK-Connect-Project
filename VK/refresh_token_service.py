from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from os import getenv
from typing import Any

import httpx
from dotenv import load_dotenv

from app.sql_save_service import (
    REFRESH_STATUS_ERROR,
    REFRESH_STATUS_REAUTH_REQUIRED,
    SQLSaveService,
)


DEFAULT_HTTP_TIMEOUT_SECONDS = 10.0
REFRESH_LOCK_SECONDS = 180
TRANSIENT_BACKOFF_MAX_SECONDS = 300
TRANSIENT_BACKOFF_STEP_SECONDS = 60


class RefreshPermanentError(RuntimeError):
    """Постоянная ошибка refresh, требующая повторной авторизации."""


class RefreshTransientError(RuntimeError):
    """Временная ошибка refresh, которую можно повторить позже."""


@dataclass(frozen=True)
class RefreshTokenConfig:
    """Конфигурация refresh token flow."""

    client_id: str
    client_secret: str
    oauth_token_url: str
    http_timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS

    @classmethod
    def from_env(cls) -> "RefreshTokenConfig":
        """Загружает настройки refresh token flow из переменных окружения."""
        load_dotenv()

        required_variables = {
            "VK_CLIENT_ID": getenv("VK_CLIENT_ID"),
            "VK_CLIENT_SECRET": getenv("VK_CLIENT_SECRET"),
            "VK_OAUTH_TOKEN_URL": getenv("VK_OAUTH_TOKEN_URL"),
        }
        missing_variables = [
            name for name, value in required_variables.items() if not value
        ]
        if missing_variables:
            missing_names = ", ".join(missing_variables)
            raise ValueError(
                f"Не заданы обязательные переменные окружения: {missing_names}"
            )

        return cls(
            client_id=required_variables["VK_CLIENT_ID"] or "",
            client_secret=required_variables["VK_CLIENT_SECRET"] or "",
            oauth_token_url=required_variables["VK_OAUTH_TOKEN_URL"] or "",
            http_timeout_seconds=cls._read_http_timeout(),
        )

    @staticmethod
    def _read_http_timeout() -> float:
        """Возвращает HTTP timeout из окружения или дефолт."""
        raw_timeout = getenv("HTTP_TIMEOUT_SECONDS")
        if not raw_timeout:
            return DEFAULT_HTTP_TIMEOUT_SECONDS

        try:
            timeout = float(raw_timeout)
        except ValueError as exc:
            raise ValueError(
                "Переменная окружения HTTP_TIMEOUT_SECONDS должна быть числом."
            ) from exc

        if timeout <= 0:
            raise ValueError(
                "Переменная окружения HTTP_TIMEOUT_SECONDS должна быть больше нуля."
            )
        return timeout


@dataclass(frozen=True)
class RefreshTokenResult:
    """Безопасный результат refresh без token values."""

    token_id: int
    link_id: int | None
    refreshed: bool
    status: str
    message: str


@dataclass(frozen=True)
class ParsedRefreshResponse:
    """Разобранный успешный ответ VK refresh token endpoint."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int | None
    expires_at: datetime | None
    scope: str
    id_token: str


class RefreshTokenService:
    """Исполнитель refresh для одной VK token row."""

    def __init__(
        self,
        config: RefreshTokenConfig | None = None,
        sql_storage: SQLSaveService | None = None,
    ) -> None:
        self.config = config or RefreshTokenConfig.from_env()
        self.sql_storage = sql_storage or SQLSaveService()

    async def refresh_token_by_link_id(self, link_id: int) -> RefreshTokenResult:
        """Выполняет refresh по link ID."""
        token_id = self.sql_storage.get_token_id_by_link_id(link_id)
        if token_id is None:
            return RefreshTokenResult(
                token_id=0,
                link_id=link_id,
                refreshed=False,
                status="not_found",
                message="Token row for link was not found.",
            )
        return await self.refresh_token_by_token_id(token_id)

    async def refresh_token_by_token_id(self, token_id: int) -> RefreshTokenResult:
        """Выполняет refresh одного token row по token ID."""
        now = datetime.now(UTC)
        lock_until = now + timedelta(seconds=REFRESH_LOCK_SECONDS)
        lock_acquired = self.sql_storage.acquire_refresh_lock(
            token_id=token_id,
            lock_until=lock_until,
        )
        if not lock_acquired:
            return RefreshTokenResult(
                token_id=token_id,
                link_id=None,
                refreshed=False,
                status="locked_or_not_due",
                message="Refresh lock was not acquired.",
            )

        token_data = self.sql_storage.get_token_for_refresh_by_token_id(token_id)
        if token_data is None:
            return RefreshTokenResult(
                token_id=token_id,
                link_id=None,
                refreshed=False,
                status="not_found",
                message="Token row was not found after lock acquisition.",
            )

        link_id = int(token_data["link_id"])
        refresh_token = str(token_data.get("refresh_token") or "")
        device_id = str(token_data.get("device_id") or "").strip()
        if not refresh_token:
            self.sql_storage.mark_token_reauth_required(
                token_id=token_id,
                safe_error="Missing refresh token.",
            )
            return RefreshTokenResult(
                token_id=token_id,
                link_id=link_id,
                refreshed=False,
                status=REFRESH_STATUS_REAUTH_REQUIRED,
                message="Refresh token is missing; reauthorization is required.",
            )

        if not device_id:
            self.sql_storage.mark_token_reauth_required(
                token_id=token_id,
                safe_error="Missing device_id for VK ID refresh flow.",
            )
            return RefreshTokenResult(
                token_id=token_id,
                link_id=link_id,
                refreshed=False,
                status=REFRESH_STATUS_REAUTH_REQUIRED,
                message="Missing device_id for VK ID refresh flow.",
            )

        try:
            response_data = await self._request_refresh_token(
                refresh_token=refresh_token,
                device_id=device_id,
            )
            parsed_response = self._parse_refresh_response(response_data)
        except RefreshPermanentError as exc:
            safe_error = self._sanitize_vk_error_text(str(exc))
            self.sql_storage.update_token_refresh_failure(
                token_id=token_id,
                refresh_status=REFRESH_STATUS_REAUTH_REQUIRED,
                safe_error=safe_error,
                next_refresh_at=None,
                mark_link_reauth_required=True,
            )
            return RefreshTokenResult(
                token_id=token_id,
                link_id=link_id,
                refreshed=False,
                status=REFRESH_STATUS_REAUTH_REQUIRED,
                message=safe_error,
            )
        except RefreshTransientError as exc:
            safe_error = self._sanitize_vk_error_text(str(exc))
            attempts = int(token_data.get("refresh_attempts") or 0) + 1
            backoff_seconds = min(
                TRANSIENT_BACKOFF_MAX_SECONDS,
                TRANSIENT_BACKOFF_STEP_SECONDS * attempts,
            )
            self.sql_storage.update_token_refresh_failure(
                token_id=token_id,
                refresh_status=REFRESH_STATUS_ERROR,
                safe_error=safe_error,
                next_refresh_at=datetime.now(UTC)
                + timedelta(seconds=backoff_seconds),
            )
            return RefreshTokenResult(
                token_id=token_id,
                link_id=link_id,
                refreshed=False,
                status=REFRESH_STATUS_ERROR,
                message=safe_error,
            )

        self.sql_storage.update_token_refresh_success(
            token_id=token_id,
            access_token=parsed_response.access_token,
            refresh_token=parsed_response.refresh_token,
            token_type=parsed_response.token_type,
            expires_in=parsed_response.expires_in,
            expires_at=parsed_response.expires_at,
            scope=parsed_response.scope,
            id_token=parsed_response.id_token,
        )
        return RefreshTokenResult(
            token_id=token_id,
            link_id=link_id,
            refreshed=True,
            status="refreshed",
            message="VK token was refreshed successfully.",
        )

    async def _request_refresh_token(
        self,
        *,
        refresh_token: str,
        device_id: str,
    ) -> dict[str, Any]:
        """Отправляет refresh request в VK token endpoint."""
        request_data = {
            "grant_type": "refresh_token",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "refresh_token": refresh_token,
            "device_id": device_id,
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.config.http_timeout_seconds
            ) as client:
                response = await client.post(
                    self.config.oauth_token_url,
                    data=request_data,
                )
        except httpx.HTTPError as exc:
            raise RefreshTransientError(
                "HTTP request to VK token endpoint failed."
            ) from exc

        response_data: Any
        try:
            response_data = response.json()
        except ValueError as exc:
            raise RefreshTransientError(
                "VK token endpoint returned non-JSON response."
            ) from exc

        if response.status_code == 429 or response.status_code >= 500:
            raise RefreshTransientError(
                self._extract_safe_error_text(response_data)
            )

        if response.status_code >= 400:
            safe_error = self._extract_safe_error_text(response_data)
            if self._is_permanent_error(response_data):
                raise RefreshPermanentError(safe_error)
            raise RefreshTransientError(safe_error)

        if isinstance(response_data, dict) and "error" in response_data:
            safe_error = self._extract_safe_error_text(response_data)
            if self._is_permanent_error(response_data):
                raise RefreshPermanentError(safe_error)
            raise RefreshTransientError(safe_error)

        if not isinstance(response_data, dict):
            raise RefreshTransientError("VK token endpoint returned invalid JSON.")
        return response_data

    def _parse_refresh_response(
        self,
        response_data: dict[str, Any],
    ) -> ParsedRefreshResponse:
        """Преобразует успешный VK response в безопасную структуру."""
        access_token = response_data.get("access_token")
        if not access_token or not isinstance(access_token, str):
            raise RefreshTransientError("VK refresh response has no access_token.")

        expires_in = self._parse_optional_int(response_data.get("expires_in"))
        expires_at = self._calculate_expires_at(expires_in)
        return ParsedRefreshResponse(
            access_token=access_token,
            refresh_token=self._optional_string(
                response_data.get("refresh_token")
            ),
            token_type=self._optional_string(response_data.get("token_type")),
            expires_in=expires_in,
            expires_at=expires_at,
            scope=self._parse_scope(response_data.get("scope")),
            id_token=self._optional_string(response_data.get("id_token")),
        )

    @staticmethod
    def _calculate_expires_at(expires_in: int | None) -> datetime | None:
        """Вычисляет expires_at по expires_in."""
        if expires_in is None:
            return None
        return datetime.now(UTC) + timedelta(seconds=expires_in)

    @staticmethod
    def _parse_optional_int(value: Any) -> int | None:
        """Преобразует значение в int, если оно задано."""
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise RefreshTransientError(
                "Field expires_in in VK refresh response is invalid."
            ) from exc

    @staticmethod
    def _optional_string(value: Any) -> str:
        """Преобразует значение в строку или пустую строку."""
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        return str(value)

    @staticmethod
    def _parse_scope(value: Any) -> str:
        """Преобразует scope из ответа VK в строку."""
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return " ".join(str(scope) for scope in value)
        return str(value)

    @staticmethod
    def _extract_safe_error_text(response_data: Any) -> str:
        """Возвращает безопасное описание VK error без token values."""
        if not isinstance(response_data, dict):
            return "Unknown VK refresh error."

        error = response_data.get("error")
        error_description = response_data.get("error_description")
        if isinstance(error_description, str) and error_description:
            return RefreshTokenService._sanitize_vk_error_text(error_description)

        if isinstance(error, str) and error:
            return RefreshTokenService._sanitize_vk_error_text(error)

        if isinstance(error, dict):
            error_code = error.get("error_code")
            if error_code is not None:
                return f"VK refresh error code {error_code}."
            return "VK refresh error."

        return "Unknown VK refresh error."

    @staticmethod
    def _is_permanent_error(response_data: Any) -> bool:
        """Определяет ошибки, после которых нужна повторная авторизация."""
        if not isinstance(response_data, dict):
            return False

        raw_error = response_data.get("error")
        raw_description = response_data.get("error_description")
        error_text = " ".join(
            str(part).lower()
            for part in (raw_error, raw_description)
            if part
        )
        permanent_markers = (
            "invalid_grant",
            "invalid_token",
            "invalid refresh",
            "device_id is invalid",
            "invalid device",
            "invalid_device",
            "device id is invalid",
            "expired",
            "revoked",
            "reauthor",
        )
        return any(marker in error_text for marker in permanent_markers)

    @staticmethod
    def _sanitize_vk_error_text(message: str) -> str:
        """Скрывает token-like значения из safe diagnostic text."""
        sanitized = str(message)
        sensitive_fields = (
            "access_token|refresh_token|authorization_code|auth_code|"
            "code_verifier|client_secret|device_id|code|id_token"
        )
        sanitized = re.sub(
            rf"""(?ix)
            (["'](?:{sensitive_fields})["']\s*:\s*["'])
            [^"']*
            (["'])
            """,
            r"\1[REDACTED]\2",
            sanitized,
        )
        sanitized = re.sub(
            rf"(?i)\b({sensitive_fields})\s*=\s*([^&,\s]+)",
            r"\1=[REDACTED]",
            sanitized,
        )
        sanitized = re.sub(
            rf"(?i)\b({sensitive_fields})\s+([A-Za-z0-9._~+/=-]{{6,}})",
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
        return sanitized[:500]
