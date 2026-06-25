from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import APIRouter, BackgroundTasks, Query
from filelock import FileLock
from starlette.concurrency import run_in_threadpool
from starlette.responses import RedirectResponse

from app.fastapi.background_tasks import exchange_vk_callback_code_in_background


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROVIDER = "vk"
CALLBACK_RECEIVED_STATUS = "callback_received"
ERROR_STATUS = "error"
INVALID_OAUTH_STATE_STATUSES = {"used", "error"}


@dataclass(frozen=True)
class VKCallbackConfig:
    """Конфигурация для обработки VK callback."""

    frontend_success_url: str
    frontend_error_url: str
    auth_code_storage_path: str
    oauth_state_storage_path: str

    @classmethod
    def from_env(cls) -> "VKCallbackConfig":
        """Загружает настройки callback-обработчика из переменных окружения."""
        load_dotenv()

        required_variables = {
            "FRONTEND_VK_SUCCESS_URL": os.getenv("FRONTEND_VK_SUCCESS_URL"),
            "FRONTEND_VK_ERROR_URL": os.getenv("FRONTEND_VK_ERROR_URL"),
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
            frontend_success_url=required_variables["FRONTEND_VK_SUCCESS_URL"] or "",
            frontend_error_url=required_variables["FRONTEND_VK_ERROR_URL"] or "",
            auth_code_storage_path=required_variables["AUTH_CODE_STORAGE_JSON_PATH"]
            or "",
            oauth_state_storage_path=required_variables[
                "OAUTH_STATE_STORAGE_JSON_PATH"
            ]
            or "",
        )


@dataclass(frozen=True)
class VKCallbackData:
    """Данные, полученные от VK callback."""

    code: str
    state: str
    device_id: str = ""
    error: str = ""
    error_description: str = ""


class JsonStorage:
    """Базовая логика безопасной работы с JSON-хранилищем."""

    storage_key: str

    def __init__(self, storage_path: str | Path) -> None:
        self.storage_path = self._resolve_storage_path(storage_path)
        self.lock = FileLock(str(self.storage_path) + ".lock")

    @staticmethod
    def _resolve_storage_path(storage_path: str | Path) -> Path:
        """Возвращает абсолютный путь к JSON-хранилищу."""
        path = Path(storage_path)
        if path.is_absolute():
            return path
        return PROJECT_ROOT / path

    def _default_data(self) -> dict[str, list[Any]]:
        """Возвращает структуру JSON-хранилища по умолчанию."""
        return {self.storage_key: []}

    def _read_data(self) -> dict[str, Any]:
        """Безопасно читает JSON-хранилище и проверяет его структуру."""
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

    def _find_document(self, documents: list[Any], state: str) -> dict[str, Any] | None:
        """Ищет документ по state."""
        for document in documents:
            if isinstance(document, dict) and document.get("state") == state:
                return document
        return None


class OAuthStateStorage(JsonStorage):
    """Хранилище OAuth state для проверки callback."""

    storage_key = "oauth_states"

    def state_exists(self, state: str) -> bool:
        """Проверяет, что state существует и может принять callback."""
        with self.lock:
            data = self._read_data()
            document = self._find_document(data[self.storage_key], state)
            return self._is_valid_state_document(document)

    def mark_callback_received(self, state: str) -> None:
        """Помечает OAuth state как получивший callback."""
        with self.lock:
            data = self._read_data()
            document = self._find_document(data[self.storage_key], state)
            if not self._is_valid_state_document(document):
                raise RuntimeError("OAuth state не найден или недействителен.")

            document["status"] = CALLBACK_RECEIVED_STATUS
            document["updated_at"] = _utc_now_iso()
            self._write_data(data)

    def mark_error(self, state: str) -> None:
        """Помечает OAuth state как ошибочный, если такой state найден."""
        with self.lock:
            data = self._read_data()
            document = self._find_document(data[self.storage_key], state)
            if not document or document.get("provider") != PROVIDER:
                return
            if document.get("status") == "used":
                return

            document["status"] = ERROR_STATUS
            document["updated_at"] = _utc_now_iso()
            self._write_data(data)

    def _is_valid_state_document(self, document: dict[str, Any] | None) -> bool:
        """Проверяет документ OAuth state на пригодность для callback."""
        if not document:
            return False
        if document.get("provider") != PROVIDER:
            return False
        if document.get("status") in INVALID_OAUTH_STATE_STATUSES:
            return False
        if self._is_expired(document.get("expires_at")):
            return False
        return True

    @staticmethod
    def _is_expired(expires_at: Any) -> bool:
        """Проверяет истечение срока действия state, если expires_at задан."""
        if not expires_at:
            return False
        if not isinstance(expires_at, str):
            return True

        try:
            normalized_value = expires_at.replace("Z", "+00:00")
            expires_at_datetime = datetime.fromisoformat(normalized_value)
        except ValueError:
            return True

        if expires_at_datetime.tzinfo is None:
            expires_at_datetime = expires_at_datetime.replace(tzinfo=UTC)

        return expires_at_datetime <= datetime.now(UTC)


class AuthCodeStorage(JsonStorage):
    """Хранилище authorization code, полученного от VK callback."""

    storage_key = "auth_codes"

    def attach_auth_code(
        self,
        state: str,
        code: str,
        device_id: str = "",
    ) -> None:
        """Сохраняет authorization code в документе по state."""
        with self.lock:
            data = self._read_data()
            document = self._find_document(data[self.storage_key], state)
            if not document:
                raise RuntimeError("Документ auth_code с указанным state не найден.")

            provider = document.get("provider")
            if provider and provider != PROVIDER:
                raise RuntimeError("Документ auth_code принадлежит другому провайдеру.")

            if document.get("auth_code"):
                raise RuntimeError("Authorization code уже сохранен для этого state.")

            document["auth_code"] = code
            document["device_id"] = device_id.strip()
            document["status"] = CALLBACK_RECEIVED_STATUS
            document["updated_at"] = _utc_now_iso()
            self._write_data(data)


class VKCallbackHandler:
    """Обработчик VK callback без обмена code на токены."""

    def __init__(self, config: VKCallbackConfig) -> None:
        self.config = config
        self.oauth_state_storage = OAuthStateStorage(
            self.config.oauth_state_storage_path
        )
        self.auth_code_storage = AuthCodeStorage(self.config.auth_code_storage_path)

    def handle_callback(self,
        code: str | None,
        state: str | None,
        error: str | None = None,
        error_description: str | None = None,
        device_id: str | None = None,
    ) -> str:
        """Обрабатывает VK callback и возвращает URL для редиректа пользователя."""
        callback_data = VKCallbackData(
            code=code or "",
            state=state or "",
            device_id=(device_id or "").strip(),
            error=error or "",
            error_description=error_description or "",
        )

        if callback_data.error:
            self._mark_error_if_state_present(callback_data.state)
            return self.config.frontend_error_url

        if not callback_data.code or not callback_data.state:
            return self.config.frontend_error_url

        try:
            if not self.oauth_state_storage.state_exists(callback_data.state):
                return self.config.frontend_error_url

            self.auth_code_storage.attach_auth_code(
                state=callback_data.state,
                code=callback_data.code,
                device_id=callback_data.device_id,
            )
            self.oauth_state_storage.mark_callback_received(callback_data.state)
        except RuntimeError:
            return self.config.frontend_error_url

        return self.config.frontend_success_url

    def _mark_error_if_state_present(self, state: str) -> None:
        """Помечает state ошибочным без раскрытия деталей VK error."""
        if not state:
            return

        try:
            self.oauth_state_storage.mark_error(state)
        except RuntimeError:
            return


router = APIRouter(
    prefix="/auth/vk",
    tags=["VK OAuth"],
)


@router.get("/callback")
async def vk_callback(
    background_tasks: BackgroundTasks,
    code: str | None = Query(default=None),
    state: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
) -> RedirectResponse:
    """Принимает VK callback и перенаправляет пользователя на frontend."""
    config = VKCallbackConfig.from_env()
    callback_handler = VKCallbackHandler(config)
    frontend_redirect_url = await run_in_threadpool(
        callback_handler.handle_callback,
        code=code,
        state=state,
        error=error,
        error_description=error_description,
        device_id=device_id,
    )

    if (
        frontend_redirect_url == config.frontend_success_url
        and code
        and state
    ):
        background_tasks.add_task(
            exchange_vk_callback_code_in_background,
            state=state,
            code=code,
            device_id=(device_id or "").strip(),
        )

    return RedirectResponse(
        url=frontend_redirect_url,
        status_code=302,
    )


def _utc_now_iso() -> str:
    """Возвращает текущее время в ISO UTC формате."""
    return datetime.now(UTC).isoformat()
