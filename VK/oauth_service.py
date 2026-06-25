from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from dotenv import load_dotenv
from filelock import FileLock


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CODE_CHALLENGE_METHOD = "S256"
PROVIDER = "vk"
OAUTH_STATE_TTL_MINUTES = 10


@dataclass(frozen=True)
class OAuthConfig:
    """Конфигурация для старта VK OAuth."""

    client_id: str
    redirect_uri: str
    scopes: list[str]
    oauth_authorize_url: str
    auth_code_storage_path: str
    oauth_state_storage_path: str

    @classmethod
    def fill_data(cls) -> "OAuthConfig":
        """Загружает настройки VK OAuth из переменных окружения."""
        load_dotenv()

        required_variables = {
            "VK_CLIENT_ID": os.getenv("VK_CLIENT_ID"),
            "VK_REDIRECT_URI": os.getenv("VK_REDIRECT_URI"),
            "VK_SCOPES": os.getenv("VK_SCOPES"),
            "VK_OAUTH_AUTHORIZE_URL": os.getenv("VK_OAUTH_AUTHORIZE_URL"),
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

        scopes = cls._parse_scopes(required_variables["VK_SCOPES"] or "")
        if not scopes:
            raise ValueError("Переменная окружения VK_SCOPES не содержит scopes.")

        return cls(
            client_id=required_variables["VK_CLIENT_ID"] or "",
            redirect_uri=required_variables["VK_REDIRECT_URI"] or "",
            scopes=scopes,
            oauth_authorize_url=required_variables["VK_OAUTH_AUTHORIZE_URL"] or "",
            auth_code_storage_path=required_variables["AUTH_CODE_STORAGE_JSON_PATH"]
            or "",
            oauth_state_storage_path=required_variables[
                "OAUTH_STATE_STORAGE_JSON_PATH"
            ]
            or "",
        )

    @staticmethod
    def _parse_scopes(raw_scopes: str) -> list[str]:
        """Разбирает scopes, разделенные пробелами или запятыми."""
        return [scope for scope in re.split(r"[\s,]+", raw_scopes.strip()) if scope]


@dataclass(frozen=True)
class OAuthStateDocument:
    """Документ OAuth state и PKCE для JSON-хранилища."""

    state: str
    code_verifier: str
    code_challenge: str
    code_challenge_method: str
    provider: str
    user_id: str
    created_at: str
    expires_at: str
    status: str


@dataclass(frozen=True)
class AuthCodeDocument:
    """Документ начального состояния authorization code."""

    state: str
    auth_code: str
    provider: str
    user_id: str
    created_at: str
    status: str


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

    def _state_exists(self, documents: list[Any], state: str) -> bool:
        """Проверяет, есть ли документ с таким state."""
        return any(
            isinstance(document, dict) and document.get("state") == state
            for document in documents
        )


class OAuthStateStorage(JsonStorage):
    """Хранилище OAuth state и PKCE-параметров."""

    storage_key = "oauth_states"

    def add_oauth_state(
        self,
        state: str,
        code_verifier: str,
        code_challenge: str,
        user_id: str = "",
    ) -> None:
        """Добавляет новый OAuth state с PKCE-данными."""
        with self.lock:
            data = self._read_data()
            documents = data[self.storage_key]

            if self._state_exists(documents, state):
                raise RuntimeError("OAuth state уже существует в хранилище.")

            document = OAuthStateDocument(
                state=state,
                code_verifier=code_verifier,
                code_challenge=code_challenge,
                code_challenge_method=CODE_CHALLENGE_METHOD,
                provider=PROVIDER,
                user_id=user_id,
                created_at=_utc_now_iso(),
                expires_at=_utc_future_iso(minutes=OAUTH_STATE_TTL_MINUTES),
                status="created",
            )
            documents.append(asdict(document))
            self._write_data(data)


class AuthCodeStorage(JsonStorage):
    """Хранилище authorization code, связанного со state."""

    storage_key = "auth_codes"

    def add_state(self, state: str, user_id: str = "") -> None:
        """Создает начальную запись для будущего authorization code."""
        with self.lock:
            data = self._read_data()
            documents = data[self.storage_key]

            if self._state_exists(documents, state):
                raise RuntimeError("State уже существует в хранилище auth_code.")

            document = AuthCodeDocument(
                state=state,
                auth_code="",
                provider=PROVIDER,
                user_id=user_id,
                created_at=_utc_now_iso(),
                status="created",
            )
            documents.append(asdict(document))
            self._write_data(data)


class OAuthService:
    """Сервис для старта VK OAuth и построения authorization URL."""

    def __init__(self, config: OAuthConfig) -> None:
        self.config = config
        self.oauth_state_storage = OAuthStateStorage(
            self.config.oauth_state_storage_path
        )
        self.auth_code_storage = AuthCodeStorage(self.config.auth_code_storage_path)

    @staticmethod
    def generate_state(length: int = 32) -> str:
        """Генерирует случайный state."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_code_verifier(length: int = 64) -> str:
        """Генерирует PKCE code_verifier."""
        return secrets.token_urlsafe(length)

    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """Генерирует PKCE code_challenge методом S256."""
        digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")

    def build_oauth_url(
        self,
        state: str,
        code_challenge: str,
    ) -> str:
        """Собирает VK OAuth authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": CODE_CHALLENGE_METHOD,
        }
        query = urlencode(params)
        separator = "&" if "?" in self.config.oauth_authorize_url else "?"
        if self.config.oauth_authorize_url.endswith(("?", "&")):
            separator = ""
        return f"{self.config.oauth_authorize_url}{separator}{query}"

    def create_authorization_data(self, user_id: str = "") -> dict[str, str]:
        """Создает данные для запуска VK OAuth авторизации."""
        state = self.generate_state()
        code_verifier = self.generate_code_verifier()
        code_challenge = self.generate_code_challenge(code_verifier)

        self.oauth_state_storage.add_oauth_state(
            state=state,
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            user_id=user_id,
        )
        self.auth_code_storage.add_state(state=state, user_id=user_id)

        oauth_url = self.build_oauth_url(
            state=state,
            code_challenge=code_challenge,
        )

        return {
            "state": state,
            "oauth_url": oauth_url,
        }


def _utc_now_iso() -> str:
    """Возвращает текущее время в ISO UTC формате."""
    return datetime.now(UTC).isoformat()


def _utc_future_iso(minutes: int) -> str:
    """Возвращает будущее время в ISO UTC формате."""
    return (datetime.now(UTC) + timedelta(minutes=minutes)).isoformat()


if __name__ == "__main__":
    config = OAuthConfig.fill_data()
    service = OAuthService(config)
    authorization_data = service.create_authorization_data()
    print(authorization_data["state"])
    print(authorization_data["oauth_url"])
