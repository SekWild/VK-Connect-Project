from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from filelock import FileLock


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROVIDER = "vk"
REMOTE_REVOKE_STATUS = "skipped_not_implemented"


def _resolve_storage_path(storage_path: str) -> Path:
    """Преобразует путь JSON-хранилища в абсолютный путь."""
    path = Path(storage_path)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


@dataclass(frozen=True)
class VKUnlinkConfig:
    """Конфигурация локального отключения VK-аккаунта."""

    access_token_storage_path: Path
    auth_code_storage_path: Path | None = None
    oauth_state_storage_path: Path | None = None

    @classmethod
    def from_env(cls) -> "VKUnlinkConfig":
        """Загружает пути хранилищ из переменных окружения."""
        load_dotenv()

        access_token_storage_path = os.getenv("ACCESS_TOKEN_STORAGE_JSON_PATH")
        if not access_token_storage_path:
            raise ValueError(
                "Не задана обязательная переменная окружения "
                "ACCESS_TOKEN_STORAGE_JSON_PATH."
            )

        auth_code_storage_path = os.getenv("AUTH_CODE_STORAGE_JSON_PATH")
        oauth_state_storage_path = os.getenv("OAUTH_STATE_STORAGE_JSON_PATH")

        return cls(
            access_token_storage_path=_resolve_storage_path(
                access_token_storage_path
            ),
            auth_code_storage_path=(
                _resolve_storage_path(auth_code_storage_path)
                if auth_code_storage_path
                else None
            ),
            oauth_state_storage_path=(
                _resolve_storage_path(oauth_state_storage_path)
                if oauth_state_storage_path
                else None
            ),
        )


@dataclass(frozen=True)
class VKUnlinkResult:
    """Безопасный результат локального отключения VK-аккаунта."""

    unlinked: bool
    matched_count: int
    deleted_count: int
    provider: str
    identifier_type: str
    identifier_value: str
    states_cleaned: list[str]
    temporary_documents_cleaned: bool
    remote_revoke_status: str
    message: str


class _JsonStorage:
    """Базовая безопасная работа с JSON-хранилищем."""

    storage_key: str

    def __init__(self, storage_path: Path) -> None:
        self.storage_path = storage_path
        self.lock = FileLock(str(self.storage_path) + ".lock")

    def _default_data(self) -> dict[str, list[Any]]:
        """Возвращает структуру JSON-хранилища по умолчанию."""
        return {self.storage_key: []}

    def _read_data(self) -> dict[str, Any]:
        """Безопасно читает JSON и проверяет структуру хранилища."""
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
                "JSON-хранилище должно содержать объект верхнего уровня: "
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
        """Атомарно записывает JSON через временный файл."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.storage_path.with_name(f"{self.storage_path.name}.tmp")
        tmp_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp_path, self.storage_path)


class AccessTokenStorage(_JsonStorage):
    """Хранилище token-документов для локального отключения VK."""

    storage_key = "access_tokens"

    def delete_by_identifier(
        self,
        identifier_type: str,
        identifier_value: str,
    ) -> tuple[int, int, list[str]]:
        """Удаляет только VK-документы с совпадающим идентификатором."""
        with self.lock:
            data = self._read_data()
            documents = data[self.storage_key]
            remaining_documents: list[Any] = []
            matched_count = 0
            states: list[str] = []

            for document in documents:
                if self._matches_identifier(
                    document,
                    identifier_type=identifier_type,
                    identifier_value=identifier_value,
                ):
                    matched_count += 1
                    state = str(document.get("state") or "")
                    if state and state not in states:
                        states.append(state)
                    continue

                remaining_documents.append(document)

            if matched_count:
                data[self.storage_key] = remaining_documents
                self._write_data(data)

            return matched_count, matched_count, states

    @staticmethod
    def _matches_identifier(
        document: Any,
        identifier_type: str,
        identifier_value: str,
    ) -> bool:
        """Проверяет provider и выбранный безопасный идентификатор."""
        if not isinstance(document, dict):
            return False
        if document.get("provider") != PROVIDER:
            return False
        return str(document.get(identifier_type) or "") == identifier_value


class TemporaryOAuthStorage(_JsonStorage):
    """Хранилище временных OAuth-документов для очистки по state."""

    def __init__(self, storage_path: Path, storage_key: str) -> None:
        self.storage_key = storage_key
        super().__init__(storage_path)

    def delete_by_states(self, states: list[str]) -> set[str]:
        """Удаляет временные VK-документы с совпадающими state."""
        if not states:
            return set()

        state_set = set(states)
        with self.lock:
            data = self._read_data()
            documents = data[self.storage_key]
            remaining_documents: list[Any] = []
            cleaned_states: set[str] = set()

            for document in documents:
                if self._matches_state(document, state_set):
                    cleaned_states.add(str(document.get("state")))
                    continue

                remaining_documents.append(document)

            if cleaned_states:
                data[self.storage_key] = remaining_documents
                self._write_data(data)

            return cleaned_states

    @staticmethod
    def _matches_state(document: Any, states: set[str]) -> bool:
        """Проверяет state и не затрагивает документы другого provider."""
        if not isinstance(document, dict):
            return False

        state = document.get("state")
        if state not in states:
            return False

        provider = document.get("provider")
        return provider in (None, "", PROVIDER)


class VKUnlinkService:
    """Backend-only сервис локального отключения VK-аккаунта."""

    def __init__(self, config: VKUnlinkConfig) -> None:
        self.config = config
        self.access_token_storage = AccessTokenStorage(
            config.access_token_storage_path
        )
        self.auth_code_storage = (
            TemporaryOAuthStorage(
                config.auth_code_storage_path,
                storage_key="auth_codes",
            )
            if config.auth_code_storage_path
            else None
        )
        self.oauth_state_storage = (
            TemporaryOAuthStorage(
                config.oauth_state_storage_path,
                storage_key="oauth_states",
            )
            if config.oauth_state_storage_path
            else None
        )

    def unlink_by_user_id(self, user_id: str) -> VKUnlinkResult:
        """Удаляет локальную VK-привязку по внутреннему user_id."""
        return self._unlink(
            identifier_type="user_id",
            identifier_value=self._validate_identifier(user_id, "user_id"),
        )

    def unlink_by_vk_user_id(self, vk_user_id: str) -> VKUnlinkResult:
        """Удаляет локальную VK-привязку по vk_user_id."""
        return self._unlink(
            identifier_type="vk_user_id",
            identifier_value=self._validate_identifier(
                vk_user_id,
                "vk_user_id",
            ),
        )

    def unlink_by_state(self, state: str) -> VKUnlinkResult:
        """Удаляет локальную VK-привязку по OAuth state."""
        return self._unlink(
            identifier_type="state",
            identifier_value=self._validate_identifier(state, "state"),
        )

    def _unlink(
        self,
        identifier_type: str,
        identifier_value: str,
    ) -> VKUnlinkResult:
        """Выполняет удаление token-документов и временную очистку."""
        matched_count, deleted_count, states = (
            self.access_token_storage.delete_by_identifier(
                identifier_type=identifier_type,
                identifier_value=identifier_value,
            )
        )

        if not matched_count:
            return VKUnlinkResult(
                unlinked=False,
                matched_count=0,
                deleted_count=0,
                provider=PROVIDER,
                identifier_type=identifier_type,
                identifier_value=identifier_value,
                states_cleaned=[],
                temporary_documents_cleaned=False,
                remote_revoke_status=REMOTE_REVOKE_STATUS,
                message="Активная или локальная привязка VK не найдена.",
            )

        cleaned_states: set[str] = set()
        for storage in (self.auth_code_storage, self.oauth_state_storage):
            if storage is not None:
                cleaned_states.update(storage.delete_by_states(states))

        return VKUnlinkResult(
            unlinked=True,
            matched_count=matched_count,
            deleted_count=deleted_count,
            provider=PROVIDER,
            identifier_type=identifier_type,
            identifier_value=identifier_value,
            states_cleaned=sorted(cleaned_states),
            temporary_documents_cleaned=bool(cleaned_states),
            remote_revoke_status=REMOTE_REVOKE_STATUS,
            message="Локальная привязка VK успешно удалена.",
        )

    @staticmethod
    def _validate_identifier(identifier_value: str, identifier_type: str) -> str:
        """Проверяет, что безопасный идентификатор не пуст."""
        normalized_value = identifier_value.strip()
        if not normalized_value:
            raise ValueError(
                f"Идентификатор {identifier_type} не может быть пустым."
            )
        return normalized_value


def _parse_args() -> argparse.Namespace:
    """Разбирает аргументы безопасного dev CLI."""
    parser = argparse.ArgumentParser(
        description="Локальное отключение VK-аккаунта без remote revoke."
    )
    identifiers = parser.add_mutually_exclusive_group(required=True)
    identifiers.add_argument("--user-id")
    identifiers.add_argument("--vk-user-id")
    identifiers.add_argument("--state")
    return parser.parse_args()


def _run_cli() -> int:
    """Запускает безопасное локальное отключение через CLI."""
    args = _parse_args()

    try:
        config = VKUnlinkConfig.from_env()
        service = VKUnlinkService(config)

        if args.user_id is not None:
            result = service.unlink_by_user_id(args.user_id)
        elif args.vk_user_id is not None:
            result = service.unlink_by_vk_user_id(args.vk_user_id)
        else:
            result = service.unlink_by_state(args.state or "")
    except (RuntimeError, ValueError) as exc:
        print(f"Ошибка локального отключения VK: {exc}")
        return 1

    print("Результат локального отключения VK:")
    print(f"unlinked: {str(result.unlinked).lower()}")
    print(f"matched_count: {result.matched_count}")
    print(f"deleted_count: {result.deleted_count}")
    print(f"provider: {result.provider}")
    print(f"identifier_type: {result.identifier_type}")
    print(f"identifier_value: {result.identifier_value}")
    print(f"states_cleaned: {', '.join(result.states_cleaned) or 'none'}")
    print(
        "temporary_documents_cleaned: "
        f"{str(result.temporary_documents_cleaned).lower()}"
    )
    print(f"remote_revoke_status: {result.remote_revoke_status}")
    print(f"message: {result.message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_run_cli())
