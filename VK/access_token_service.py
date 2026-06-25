from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv
from filelock import FileLock

from app.sql_save_service import SQLSaveService


PROVIDER = "vk"
STATUS_ACTIVE = "active"
STATUS_ERROR = "error"
STATUS_TOKEN_RECEIVED = "token_received"
STATUS_USED = "used"
SKIP_AUTH_CODE_STATUSES = {STATUS_TOKEN_RECEIVED, STATUS_USED, STATUS_ERROR}
SKIP_OAUTH_STATE_STATUSES = {STATUS_USED, STATUS_ERROR}


@dataclass(frozen=True)
class AccessTokenConfig:
    """Конфигурация обмена authorization code на VK token data."""

    client_id: str
    client_secret: str
    redirect_uri: str
    oauth_token_url: str
    auth_code_storage_path: str
    oauth_state_storage_path: str
    http_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> "AccessTokenConfig":
        """Загружает настройки token exchange из переменных окружения."""
        load_dotenv()

        required_variables = {
            "VK_CLIENT_ID": os.getenv("VK_CLIENT_ID"),
            "VK_CLIENT_SECRET": os.getenv("VK_CLIENT_SECRET"),
            "VK_REDIRECT_URI": os.getenv("VK_REDIRECT_URI"),
            "VK_OAUTH_TOKEN_URL": os.getenv("VK_OAUTH_TOKEN_URL"),
            "AUTH_CODE_STORAGE_JSON_PATH": os.getenv("AUTH_CODE_STORAGE_JSON_PATH"),
            "OAUTH_STATE_STORAGE_JSON_PATH": os.getenv("OAUTH_STATE_STORAGE_JSON_PATH"),
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
            redirect_uri=required_variables["VK_REDIRECT_URI"] or "",
            oauth_token_url=required_variables["VK_OAUTH_TOKEN_URL"] or "",
            auth_code_storage_path=required_variables["AUTH_CODE_STORAGE_JSON_PATH"]
            or "",
            oauth_state_storage_path=required_variables[
                "OAUTH_STATE_STORAGE_JSON_PATH"
            ]
            or "",
            http_timeout_seconds=cls._read_http_timeout_seconds(),
        )

    @staticmethod
    def _read_http_timeout_seconds() -> float:
        """Читает HTTP timeout или возвращает значение по умолчанию."""
        raw_timeout = os.getenv("HTTP_TIMEOUT_SECONDS")
        if not raw_timeout:
            return 30.0

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
class AuthCodeDocument:
    """Документ authorization code, готовый к обмену на токены."""

    state: str
    auth_code: str
    user_id: str = ""
    device_id: str = ""
    provider: str = PROVIDER
    status: str = ""


@dataclass(frozen=True)
class OAuthStateDocument:
    """Документ OAuth state с PKCE code_verifier."""

    state: str
    code_verifier: str
    code_challenge: str = ""
    code_challenge_method: str = "S256"
    provider: str = PROVIDER
    user_id: str = ""
    status: str = ""


@dataclass(frozen=True)
class VKTokenData:
    """Token data, полученная от VK token endpoint."""

    access_token: str
    refresh_token: str | None = None
    token_type: str | None = None
    expires_in: int | None = None
    expires_at: str | None = None
    scope: str | None = None
    vk_user_id: str | None = None
    id_token: str | None = None


@dataclass(frozen=True)
class AccessTokenProcessResult:
    """Безопасный результат обработки одного auth-code документа."""

    state: str
    success: bool
    status: str
    vk_user_id: str | None = None
    message: str = ""


class JsonStoragePathResolver:
    """Преобразует путь JSON-хранилища в абсолютный путь."""

    @staticmethod
    def resolve(storage_path: str) -> Path:
        """Возвращает абсолютный путь к JSON-хранилищу."""
        path = Path(storage_path)
        if path.is_absolute():
            return path
        return Path(__file__).resolve().parent.parent / path


class _JsonStorage:
    """Базовая безопасная работа с JSON-хранилищем."""

    storage_key: str

    def __init__(self, storage_path: str) -> None:
        self.storage_path = JsonStoragePathResolver.resolve(storage_path)
        self.lock = FileLock(str(self.storage_path) + ".lock")

    def _default_data(self) -> dict[str, list[Any]]:
        """Возвращает структуру JSON-хранилища по умолчанию."""
        return {self.storage_key: []}

    def _read_data(self) -> dict[str, Any]:
        """Безопасно читает JSON-хранилище и проверяет структуру."""
        if not self.storage_path.exists():
            return self._default_data()

        raw_content = self.storage_path.read_text(encoding="utf-8")
        if not raw_content.strip():
            return self._default_data()

        try:
            data = json.loads(raw_content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"JSON-хранилище повреждено: {self.storage_path}"
            ) from exc

        if not isinstance(data, dict):
            raise RuntimeError(
                f"JSON-хранилище должно содержать объект верхнего уровня: "
                f"{self.storage_path}"
            )

        if self.storage_key not in data:
            data[self.storage_key] = []

        if not isinstance(data[self.storage_key], list):
            raise RuntimeError(
                f"Поле '{self.storage_key}' должно быть списком: "
                f"{self.storage_path}"
            )

        return data

    def _write_data(self, data: dict[str, Any]) -> None:
        """Атомарно записывает JSON-хранилище через временный файл."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.storage_path.with_name(f"{self.storage_path.name}.tmp")
        tmp_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp_path, self.storage_path)

    @staticmethod
    def _find_document(documents: list[Any], state: str) -> dict[str, Any] | None:
        """Ищет документ по state."""
        for document in documents:
            if isinstance(document, dict) and document.get("state") == state:
                return document
        return None


class AuthCodeStorage(_JsonStorage):
    """Хранилище authorization code, полученных callback-сервисом."""

    storage_key = "auth_codes"

    def get_ready_auth_code_documents(self) -> list[AuthCodeDocument]:
        """Возвращает auth-code документы, готовые к обмену на токены."""
        with self.lock:
            data = self._read_data()
            documents: list[AuthCodeDocument] = []
            for document in data[self.storage_key]:
                if not isinstance(document, dict):
                    continue

                state = str(document.get("state") or "")
                auth_code = str(document.get("auth_code") or "")
                provider = str(document.get("provider") or PROVIDER)
                status = str(document.get("status") or "")
                if not state or not auth_code:
                    continue
                if provider != PROVIDER:
                    continue
                if status in SKIP_AUTH_CODE_STATUSES:
                    continue

                documents.append(
                    AuthCodeDocument(
                        state=state,
                        auth_code=auth_code,
                        user_id=str(document.get("user_id") or ""),
                        device_id=str(document.get("device_id") or ""),
                        provider=provider,
                        status=status,
                    )
                )
            return documents

    def mark_token_received(self, state: str) -> None:
        """Помечает auth-code документ как обменянный на токены."""
        with self.lock:
            data = self._read_data()
            document = self._find_document(data[self.storage_key], state)
            if not document:
                raise RuntimeError("Документ auth_code с указанным state не найден.")

            document["status"] = STATUS_TOKEN_RECEIVED
            document["updated_at"] = _utc_now_iso()
            self._write_data(data)

    def delete_by_state(self, state: str) -> None:
        """Удаляет auth-code документ по state, если он существует."""
        with self.lock:
            data = self._read_data()
            documents = data[self.storage_key]
            filtered_documents = [
                document
                for document in documents
                if not (isinstance(document, dict) and document.get("state") == state)
            ]

            if len(filtered_documents) == len(documents):
                return

            data[self.storage_key] = filtered_documents
            self._write_data(data)

    def mark_error(self, state: str) -> None:
        """Помечает auth-code документ как ошибочный."""
        with self.lock:
            data = self._read_data()
            document = self._find_document(data[self.storage_key], state)
            if not document:
                return
            if document.get("status") in {STATUS_TOKEN_RECEIVED, STATUS_USED}:
                return

            document["status"] = STATUS_ERROR
            document["updated_at"] = _utc_now_iso()
            self._write_data(data)


class OAuthStateStorage(_JsonStorage):
    """Хранилище OAuth state и PKCE данных."""

    storage_key = "oauth_states"

    def get_state_document(self, state: str) -> OAuthStateDocument:
        """Возвращает OAuth state документ с code_verifier."""
        with self.lock:
            data = self._read_data()
            document = self._find_document(data[self.storage_key], state)
            if not document:
                raise RuntimeError("OAuth state с указанным state не найден.")

            provider = str(document.get("provider") or PROVIDER)
            if provider != PROVIDER:
                raise RuntimeError("OAuth state принадлежит другому провайдеру.")

            status = str(document.get("status") or "")
            if status in SKIP_OAUTH_STATE_STATUSES:
                raise RuntimeError("OAuth state уже использован или помечен ошибкой.")

            code_verifier = str(document.get("code_verifier") or "")
            if not code_verifier:
                raise RuntimeError("В OAuth state отсутствует code_verifier.")

            return OAuthStateDocument(
                state=str(document.get("state") or ""),
                code_verifier=code_verifier,
                code_challenge=str(document.get("code_challenge") or ""),
                code_challenge_method=str(
                    document.get("code_challenge_method") or "S256"
                ),
                provider=provider,
                user_id=str(document.get("user_id") or ""),
                status=status,
            )

    def mark_used(self, state: str) -> None:
        """Помечает OAuth state как использованный."""
        with self.lock:
            data = self._read_data()
            document = self._find_document(data[self.storage_key], state)
            if not document:
                raise RuntimeError("OAuth state с указанным state не найден.")

            document["status"] = STATUS_USED
            document["updated_at"] = _utc_now_iso()
            self._write_data(data)

    def delete_by_state(self, state: str) -> None:
        """Удаляет OAuth state документ по state, если он существует."""
        with self.lock:
            data = self._read_data()
            documents = data[self.storage_key]
            filtered_documents = [
                document
                for document in documents
                if not (isinstance(document, dict) and document.get("state") == state)
            ]

            if len(filtered_documents) == len(documents):
                return

            data[self.storage_key] = filtered_documents
            self._write_data(data)

    def mark_error(self, state: str) -> None:
        """Помечает OAuth state как ошибочный."""
        with self.lock:
            data = self._read_data()
            document = self._find_document(data[self.storage_key], state)
            if not document:
                return
            if document.get("status") == STATUS_USED:
                return

            document["status"] = STATUS_ERROR
            document["updated_at"] = _utc_now_iso()
            self._write_data(data)


class AccessTokenStorage(_JsonStorage):
    """Хранилище VK token data."""

    storage_key = "access_tokens"

    def has_active_token_for_state(self, state: str) -> bool:
        """Проверяет, есть ли активный token-документ для state."""
        with self.lock:
            data = self._read_data()
            document = self._find_document(data[self.storage_key], state)
            return bool(document and document.get("status") == STATUS_ACTIVE)

    def save_token_data(
        self,
        state: str,
        token_data: VKTokenData,
        user_id: str = "",
    ) -> None:
        """Сохраняет или обновляет VK token data по state."""
        with self.lock:
            data = self._read_data()
            documents = data[self.storage_key]
            document = self._find_document(documents, state)
            now = _utc_now_iso()
            token_fields = {
                "provider": PROVIDER,
                "vk_user_id": token_data.vk_user_id or "",
                "access_token": token_data.access_token,
                "refresh_token": token_data.refresh_token or "",
                "token_type": token_data.token_type or "",
                "expires_in": token_data.expires_in or 0,
                "expires_at": token_data.expires_at or "",
                "scope": token_data.scope or "",
                "id_token": token_data.id_token or "",
                "user_id": user_id,
                "updated_at": now,
                "status": STATUS_ACTIVE,
            }

            if document:
                document.update(token_fields)
            else:
                document = {
                    "state": state,
                    "created_at": now,
                    **token_fields,
                }
                documents.append(document)

            self._write_data(data)


class AccessTokenService:
    """Сервис обмена VK authorization code на token data."""

    def __init__(self, config: AccessTokenConfig) -> None:
        self.config = config
        self.auth_code_storage = AuthCodeStorage(config.auth_code_storage_path)
        self.oauth_state_storage = OAuthStateStorage(config.oauth_state_storage_path)
        self.sql_storage = SQLSaveService()

    async def process_ready_auth_codes(self) -> list[AccessTokenProcessResult]:
        """Обрабатывает все готовые auth-code документы."""
        auth_code_documents = self.auth_code_storage.get_ready_auth_code_documents()
        results: list[AccessTokenProcessResult] = []

        for document in auth_code_documents:
            if self.sql_storage.has_active_token_for_state(document.state):
                self.auth_code_storage.delete_by_state(document.state)
                self.oauth_state_storage.delete_by_state(document.state)
                results.append(
                    AccessTokenProcessResult(
                        state=document.state,
                        success=True,
                        status="skipped_active_token_exists",
                        message="Активный token-документ уже существует.",
                    )
                )
                continue

            try:
                token_data = await self.process_callback_code(
                    state=document.state,
                    code=document.auth_code,
                    user_id=document.user_id,
                    device_id=document.device_id,
                )
            except RuntimeError as exc:
                self._mark_processing_error(document.state)
                results.append(
                    AccessTokenProcessResult(
                        state=document.state,
                        success=False,
                        status=STATUS_ERROR,
                        message=str(exc),
                    )
                )
                continue

            results.append(
                AccessTokenProcessResult(
                    state=document.state,
                    success=True,
                    status=STATUS_TOKEN_RECEIVED,
                    vk_user_id=token_data.vk_user_id,
                    message="Token data сохранена.",
                )
            )

        return results

    def _mark_processing_error(self, state: str) -> None:
        """Best-effort пометка ошибки без остановки пакетной обработки."""
        try:
            self.auth_code_storage.mark_error(state)
        except RuntimeError:
            pass

        try:
            self.oauth_state_storage.mark_error(state)
        except RuntimeError:
            pass

    async def process_callback_code(
        self,
        state: str,
        code: str,
        user_id: str = "",
        device_id: str = "",
    ) -> VKTokenData:
        """Обменивает один authorization code на VK token data."""
        if not state:
            raise RuntimeError("State не может быть пустым.")
        if not code:
            raise RuntimeError("Authorization code не может быть пустым.")

        if self.sql_storage.has_active_token_for_state(state):
            raise RuntimeError("Активный token-документ для этого state уже существует.")

        oauth_state_document = self.oauth_state_storage.get_state_document(state)
        normalized_device_id = device_id.strip()
        token_data = await self.exchange_code_for_tokens(
            code=code,
            code_verifier=oauth_state_document.code_verifier,
            device_id=normalized_device_id,
        )
        self.sql_storage.save_vk_token_data(
            state=state,
            provider=PROVIDER,
            vk_user_id=token_data.vk_user_id or "",
            user_id=user_id or oauth_state_document.user_id,
            access_token=token_data.access_token,
            refresh_token=token_data.refresh_token or "",
            token_type=token_data.token_type or "",
            expires_in=token_data.expires_in,
            expires_at=token_data.expires_at or "",
            scope=token_data.scope or "",
            id_token=token_data.id_token or "",
            device_id=normalized_device_id,
            status=STATUS_ACTIVE,
        )
        self.auth_code_storage.delete_by_state(state)
        self.oauth_state_storage.delete_by_state(state)
        return token_data

    async def exchange_code_for_tokens(
        self,
        code: str,
        code_verifier: str,
        device_id: str = "",
    ) -> VKTokenData:
        """Отправляет authorization code и code_verifier в VK token endpoint."""
        request_data = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "redirect_uri": self.config.redirect_uri,
            "code": code,
            "code_verifier": code_verifier,
        }
        normalized_device_id = device_id.strip()
        if normalized_device_id:
            request_data["device_id"] = normalized_device_id

        response_data = await self._post_json(
            url=self.config.oauth_token_url,
            data=request_data,
        )
        return self._parse_token_response(response_data)

    async def _post_json(self, url: str, data: dict[str, str]) -> dict[str, Any]:
        """Выполняет POST-запрос и безопасно разбирает JSON-ответ."""
        try:
            async with httpx.AsyncClient(
                timeout=self.config.http_timeout_seconds
            ) as client:
                response = await client.post(url, data=data)
        except httpx.HTTPError as exc:
            raise RuntimeError("Ошибка HTTP-запроса к VK token endpoint.") from exc

        try:
            response_data = response.json()
        except ValueError as exc:
            raise RuntimeError("VK token endpoint вернул ответ не в формате JSON.") from exc

        if response.status_code >= 400:
            error_text = self._extract_safe_error_text(response_data)
            raise RuntimeError(f"VK token endpoint вернул HTTP ошибку: {error_text}")

        self._raise_for_vk_error_response(response_data)
        return response_data

    def _parse_token_response(self, response_data: dict[str, Any]) -> VKTokenData:
        """Преобразует JSON-ответ VK в VKTokenData."""
        access_token = response_data.get("access_token")
        if not access_token or not isinstance(access_token, str):
            raise RuntimeError("VK token response не содержит access_token.")

        expires_in = self._parse_optional_int(response_data.get("expires_in"))
        expires_at = _calculate_expires_at(expires_in)

        return VKTokenData(
            access_token=access_token,
            refresh_token=self._optional_string(response_data.get("refresh_token")),
            token_type=self._optional_string(response_data.get("token_type")),
            expires_in=expires_in,
            expires_at=expires_at,
            scope=self._parse_scope(response_data.get("scope")),
            vk_user_id=self._parse_vk_user_id(response_data),
            id_token=self._optional_string(response_data.get("id_token")),
        )

    def _raise_for_vk_error_response(self, response_data: dict[str, Any]) -> None:
        """Проверяет VK error response без раскрытия чувствительных данных."""
        if "error" not in response_data:
            return

        error_text = self._extract_safe_error_text(response_data)
        raise RuntimeError(f"VK token endpoint вернул ошибку: {error_text}")

    @staticmethod
    def _extract_safe_error_text(response_data: Any) -> str:
        """Возвращает безопасное описание ошибки без token data."""
        if not isinstance(response_data, dict):
            return "неизвестная ошибка"

        error = response_data.get("error")
        error_description = response_data.get("error_description")
        if isinstance(error_description, str) and error_description:
            return AccessTokenService._sanitize_vk_error_text(error_description)

        if isinstance(error, str):
            return error
        if isinstance(error, dict):
            error_code = error.get("error_code")
            if error_code is not None:
                return f"код ошибки {error_code}"
            return "ошибка VK"
        return "неизвестная ошибка"

    @staticmethod
    def _sanitize_vk_error_text(message: str) -> str:
        """Скрывает token-like значения из безопасных полей VK error."""
        sanitized = str(message)
        sensitive_fields = (
            "access_token|refresh_token|authorization_code|auth_code|"
            "code_verifier|client_secret|device_id|code"
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
        return sanitized

    @staticmethod
    def _parse_optional_int(value: Any) -> int | None:
        """Преобразует значение в int, если оно задано."""
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("Поле expires_in в VK token response некорректно.") from exc

    @staticmethod
    def _optional_string(value: Any) -> str | None:
        """Преобразует значение в строку или None."""
        if value is None:
            return None
        return str(value)

    @staticmethod
    def _parse_scope(value: Any) -> str | None:
        """Преобразует scope из VK token response в строку."""
        if value is None:
            return None
        if isinstance(value, list):
            return " ".join(str(scope) for scope in value)
        return str(value)

    @staticmethod
    def _parse_vk_user_id(response_data: dict[str, Any]) -> str | None:
        """Извлекает VK user id из возможных полей ответа."""
        for key in ("vk_user_id", "user_id", "id"):
            value = response_data.get(key)
            if value is not None and value != "":
                return str(value)
        return None


def _utc_now_iso() -> str:
    """Возвращает текущее время в ISO UTC формате."""
    return datetime.now(UTC).isoformat()


def _calculate_expires_at(expires_in: int | None) -> str | None:
    """Вычисляет expires_at на основе expires_in."""
    if expires_in is None:
        return None
    return (datetime.now(UTC) + timedelta(seconds=expires_in)).isoformat()


async def _run_dev_processing() -> None:
    """Запускает безопасную dev-обработку готовых auth-code документов."""
    config = AccessTokenConfig.from_env()
    service = AccessTokenService(config)
    results = await service.process_ready_auth_codes()

    if not results:
        print("No new auth codes to process")
        return

    print(f"Processed auth codes: {len(results)}")
    for result in results:
        print(f"State: {result.state}")
        if result.vk_user_id:
            print(f"VK user id: {result.vk_user_id}")
    print("Token data saved to access_token_storage.json")


if __name__ == "__main__":
    asyncio.run(_run_dev_processing())
