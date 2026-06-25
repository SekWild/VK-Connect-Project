from __future__ import annotations

import argparse
import json
import sys
import time
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

from app.sql_save_service import SQLSaveService


DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_TIMEOUT_SECONDS = 180
DEFAULT_POLL_INTERVAL_SECONDS = 5
DEFAULT_REFRESH_TIMEOUT_SECONDS = 240
DEFAULT_REFRESH_POLL_INTERVAL_SECONDS = 5
PROJECT_ROOT = Path(__file__).resolve().parent
AUTH_CODE_STORAGE_PATH = PROJECT_ROOT / "data" / "auth_code_storage.json"
OAUTH_STATE_STORAGE_PATH = PROJECT_ROOT / "data" / "oauth_state_storage.json"
VK_USER_INFO_URL = "https://id.vk.ru/oauth2/user_info"
_SQL_STORAGE_SERVICE: SQLSaveService | None = None


@dataclass(frozen=True)
class RefreshWaitResult:
    """Безопасный результат ожидания автоматического refresh."""

    success: bool
    reason: str
    access_token_changed: bool = False
    final_status: dict[str, Any] | None = None


def parse_args() -> argparse.Namespace:
    """Разбирает CLI-аргументы dev-симулятора frontend."""
    parser = argparse.ArgumentParser(
        description="Локальный frontend-симулятор для проверки VK OAuth callback."
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Базовый URL backend/FastAPI. По умолчанию: {DEFAULT_BASE_URL}",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Таймаут ожидания callback в секундах. По умолчанию: {DEFAULT_TIMEOUT_SECONDS}",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
        help=(
            "Интервал проверки JSON-хранилищ в секундах. "
            f"По умолчанию: {DEFAULT_POLL_INTERVAL_SECONDS}"
        ),
    )
    parser.add_argument(
        "--client-id",
        default="",
        help="VK client_id для user info запроса. По умолчанию берется из oauth_url.",
    )
    parser.add_argument(
        "--skip-user-info",
        action="store_true",
        help="Завершить проверку после сохранения активного token-документа.",
    )
    parser.add_argument(
        "--skip-refresh-test",
        action="store_true",
        help="Пропустить проверку автоматического refresh access token.",
    )
    parser.add_argument(
        "--refresh-timeout",
        type=int,
        default=DEFAULT_REFRESH_TIMEOUT_SECONDS,
        help=(
            "Таймаут ожидания автоматического refresh в секундах. "
            f"По умолчанию: {DEFAULT_REFRESH_TIMEOUT_SECONDS}"
        ),
    )
    parser.add_argument(
        "--refresh-poll-interval",
        type=int,
        default=DEFAULT_REFRESH_POLL_INTERVAL_SECONDS,
        help=(
            "Интервал проверки SQL refresh status в секундах. "
            f"По умолчанию: {DEFAULT_REFRESH_POLL_INTERVAL_SECONDS}"
        ),
    )
    parser.add_argument(
        "--force-refresh-now",
        dest="force_refresh_now",
        action="store_true",
        default=True,
        help=(
            "Dev-only: поставить текущую token row в очередь refresh немедленно. "
            "Включено по умолчанию."
        ),
    )
    parser.add_argument(
        "--no-force-refresh-now",
        dest="force_refresh_now",
        action="store_false",
        help="Не ускорять refresh и ждать уже запланированный next_refresh_at.",
    )
    return parser.parse_args()


def normalize_base_url(base_url: str) -> str:
    """Нормализует базовый URL backend без завершающего слеша."""
    return base_url.rstrip("/")


def request_json(client: httpx.Client, url: str) -> dict[str, Any]:
    """Выполняет GET-запрос и безопасно возвращает JSON-объект."""
    try:
        response = client.get(url)
        response.raise_for_status()
    except httpx.ConnectError as exc:
        raise RuntimeError("Backend недоступен. Проверьте, что FastAPI запущен.") from exc
    except httpx.HTTPStatusError as exc:
        status_code = exc.response.status_code
        raise RuntimeError(f"Backend вернул HTTP {status_code} для {url}.") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError("Не удалось выполнить HTTP-запрос к backend.") from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError(f"Backend вернул не JSON для {url}.") from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"Backend вернул JSON не-объект для {url}.")
    return data


def check_backend_health(client: httpx.Client, base_url: str) -> dict[str, Any]:
    """Проверяет, что backend отвечает на /health."""
    return request_json(client, f"{base_url}/health")


def start_vk_oauth(client: httpx.Client, base_url: str) -> tuple[str, str]:
    """Запрашивает старт VK OAuth и возвращает state и oauth_url."""
    data = request_json(client, f"{base_url}/auth/vk/start")
    state = data.get("state")
    oauth_url = data.get("oauth_url")

    if not isinstance(state, str) or not state:
        raise RuntimeError("Ответ /auth/vk/start не содержит корректный state.")
    if not isinstance(oauth_url, str) or not oauth_url:
        raise RuntimeError("Ответ /auth/vk/start не содержит корректный oauth_url.")

    return state, oauth_url


def read_storage(storage_path: Path, storage_key: str) -> list[Any]:
    """Безопасно читает JSON-хранилище только для dev-проверки."""
    if not storage_path.exists():
        return []

    raw_content = storage_path.read_text(encoding="utf-8")
    if not raw_content.strip():
        return []

    try:
        data = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"JSON-хранилище повреждено: {storage_path.name}") from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"JSON-хранилище должно содержать объект: {storage_path.name}")

    documents = data.get(storage_key, [])
    if not isinstance(documents, list):
        raise RuntimeError(
            f"Поле {storage_key} должно быть списком: {storage_path.name}"
        )
    return documents


def find_document_by_state(documents: list[Any], state: str) -> dict[str, Any] | None:
    """Ищет документ по state без вывода чувствительных данных."""
    for document in documents:
        if isinstance(document, dict) and document.get("state") == state:
            return document
    return None


def get_auth_code_safe_status(state: str) -> dict[str, Any]:
    """Возвращает безопасный статус auth-code документа."""
    documents = read_storage(AUTH_CODE_STORAGE_PATH, "auth_codes")
    document = find_document_by_state(documents, state)
    return {
        "exists": document is not None,
        "auth_code_saved": bool(document and document.get("auth_code")),
        "status": document.get("status") if document else "",
    }


def get_oauth_state_safe_status(state: str) -> dict[str, Any]:
    """Возвращает безопасный статус OAuth state документа."""
    documents = read_storage(OAUTH_STATE_STORAGE_PATH, "oauth_states")
    document = find_document_by_state(documents, state)
    status = document.get("status") if document else ""
    return {
        "exists": document is not None,
        "status": status,
        "callback_received": status == "callback_received",
    }


def get_active_token_document_for_state(
    state: str,
) -> dict[str, Any] | None:
    """Возвращает активный VK token-документ для внутренней dev-проверки."""
    return get_sql_storage_service().get_active_token_for_state(state)


def get_access_token_safe_status(state: str) -> dict[str, Any]:
    """Возвращает безопасный статус token-документа без вывода токенов."""
    return get_sql_storage_service().get_token_safe_status_by_state(state)


def get_sql_storage_service() -> SQLSaveService:
    """Возвращает единый SQL storage service для dev polling."""
    global _SQL_STORAGE_SERVICE
    if _SQL_STORAGE_SERVICE is None:
        _SQL_STORAGE_SERVICE = SQLSaveService()
    return _SQL_STORAGE_SERVICE


def schedule_refresh_now_by_state(state: str) -> bool:
    """Ставит текущую token row в очередь немедленного refresh."""
    return get_sql_storage_service().schedule_refresh_now_by_state(state)


def print_safe_poll_status(
    auth_code_status: dict[str, Any],
    oauth_state_status: dict[str, Any],
    access_token_status: dict[str, Any],
) -> None:
    """Печатает только безопасную информацию о состоянии callback."""
    print(
        "Auth code storage: "
        f"exists={auth_code_status['exists']}, "
        f"auth_code_saved={auth_code_status['auth_code_saved']}, "
        f"status={auth_code_status['status'] or 'not_found'}"
    )
    print(
        "OAuth state storage: "
        f"exists={oauth_state_status['exists']}, "
        f"status={oauth_state_status['status'] or 'not_found'}, "
        f"callback_received={oauth_state_status['callback_received']}"
    )
    print(
        "SQL token storage: "
        f"exists={access_token_status['exists']}, "
        f"active_token_saved={access_token_status['active_token_saved']}, "
        f"refresh_token_present={access_token_status['refresh_token_present']}, "
        f"device_id_present={access_token_status.get('device_id_present')}, "
        f"status={access_token_status['status'] or 'not_found'}, "
        f"expires_at={access_token_status['expires_at'] or 'not_set'}, "
        f"vk_user_id={access_token_status['vk_user_id'] or 'not_set'}, "
        f"scope={access_token_status['scope'] or 'not_set'}"
    )


def print_safe_refresh_status(status: dict[str, Any]) -> None:
    """Печатает безопасный SQL refresh status без token values."""
    print(
        "Refresh status: "
        f"exists={status.get('exists')}, "
        f"active_token_saved={status.get('active_token_saved')}, "
        f"refresh_token_present={status.get('refresh_token_present')}, "
        f"device_id_present={status.get('device_id_present')}, "
        f"link_status={status.get('status') or 'not_found'}, "
        f"expires_at={status.get('expires_at') or 'not_set'}, "
        f"updated_at={status.get('updated_at') or 'not_set'}, "
        f"next_refresh_at={status.get('next_refresh_at') or 'not_set'}, "
        f"last_refresh_at={status.get('last_refresh_at') or 'not_set'}, "
        f"refresh_status={status.get('refresh_status') or 'not_set'}, "
        f"refresh_attempts={status.get('refresh_attempts')}, "
        f"refresh_lock_until={status.get('refresh_lock_until') or 'not_set'}, "
        f"last_refresh_error={status.get('last_refresh_error') or 'not_set'}"
    )


def print_initial_refresh_status(status: dict[str, Any]) -> None:
    """Печатает безопасный начальный refresh snapshot."""
    print("Initial refresh status:")
    print(f"refresh_status={status.get('refresh_status') or 'not_set'}")
    print(f"last_refresh_at={status.get('last_refresh_at') or 'not_set'}")
    print(f"next_refresh_at={status.get('next_refresh_at') or 'not_set'}")
    print(f"refresh_attempts={status.get('refresh_attempts')}")


def wait_for_access_token_refresh(
    *,
    state: str,
    initial_access_token: str,
    initial_updated_at: str,
    initial_last_refresh_at: str,
    timeout_seconds: int,
    poll_interval_seconds: int,
) -> RefreshWaitResult:
    """Ожидает, пока автоматический worker выполнит refresh текущей token row."""
    deadline = time.monotonic() + timeout_seconds
    final_status: dict[str, Any] = {}

    while time.monotonic() < deadline:
        try:
            status = get_access_token_safe_status(state)
            token_document = get_active_token_document_for_state(state)
        except Exception as exc:
            print(
                "Предупреждение: проверка SQL refresh status завершилась "
                f"ошибкой {type(exc).__name__}."
            )
            time.sleep(poll_interval_seconds)
            continue

        final_status = status
        print_safe_refresh_status(status)

        refresh_status = str(status.get("refresh_status") or "")
        last_refresh_at = str(status.get("last_refresh_at") or "")
        updated_at = str(status.get("updated_at") or "")
        refresh_lock_until = str(status.get("refresh_lock_until") or "")
        last_refresh_error = str(status.get("last_refresh_error") or "")

        if refresh_status == "reauth_required":
            reason = "Refresh failed: reauthorization is required."
            if last_refresh_error:
                reason = f"{reason} Safe error: {last_refresh_error}"
            return RefreshWaitResult(
                success=False,
                reason=reason,
                final_status=status,
            )

        if refresh_lock_until:
            print("Refresh is currently locked/running; waiting for completion.")

        if refresh_status == "error":
            print("Transient refresh error status detected; waiting for retry.")

        if token_document and status.get("active_token_saved"):
            current_access_token = str(token_document.get("access_token") or "")
            access_token_changed = (
                bool(current_access_token)
                and current_access_token != initial_access_token
            )
            last_refresh_changed = (
                bool(last_refresh_at)
                and last_refresh_at != initial_last_refresh_at
            )
            updated_at_changed = bool(updated_at) and updated_at != initial_updated_at
            success_status = refresh_status in {"idle", "queued"}

            if (
                success_status
                and last_refresh_changed
                and (updated_at_changed or last_refresh_changed)
            ):
                if access_token_changed:
                    return RefreshWaitResult(
                        success=True,
                        reason="Access token changed after automatic refresh.",
                        access_token_changed=True,
                        final_status=status,
                    )
                return RefreshWaitResult(
                    success=True,
                    reason=(
                        "Refresh flow completed, but access token value did not "
                        "change."
                    ),
                    access_token_changed=False,
                    final_status=status,
                )

        remaining_seconds = max(0, int(deadline - time.monotonic()))
        print(f"Automatic refresh is not completed yet. Seconds left: {remaining_seconds}")
        time.sleep(poll_interval_seconds)

    reason = "Automatic access token refresh was not completed before timeout."
    if final_status.get("last_refresh_error"):
        reason = f"{reason} Safe error: {final_status['last_refresh_error']}"
    return RefreshWaitResult(
        success=False,
        reason=reason,
        final_status=final_status,
    )


def wait_for_token_exchange(
    state: str,
    timeout_seconds: int,
    poll_interval_seconds: int,
) -> dict[str, Any] | None:
    """Ожидает callback, проверяя только безопасные признаки в JSON-хранилищах."""
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        try:
            auth_code_status = get_auth_code_safe_status(state)
            oauth_state_status = get_oauth_state_safe_status(state)
            access_token_status = get_access_token_safe_status(state)
            token_document = get_active_token_document_for_state(state)
        except Exception as exc:
            print(
                "Предупреждение: проверка временного/SQL storage завершилась "
                f"ошибкой {type(exc).__name__}."
            )
            time.sleep(poll_interval_seconds)
            continue

        print_safe_poll_status(
            auth_code_status,
            oauth_state_status,
            access_token_status,
        )

        if token_document:
            return token_document

        error_statuses = {
            str(auth_code_status["status"] or ""),
            str(oauth_state_status["status"] or ""),
            str(access_token_status["status"] or ""),
        }
        if "error" in error_statuses:
            print("Обнаружен безопасный error status в OAuth/token storage.")
            return None

        remaining_seconds = max(0, int(deadline - time.monotonic()))
        print(f"Callback пока не обнаружен. Осталось секунд: {remaining_seconds}")
        time.sleep(poll_interval_seconds)

    return None


def extract_client_id_from_oauth_url(oauth_url: str) -> str:
    """Извлекает публичный client_id из OAuth URL без чтения .env."""
    query = parse_qs(urlparse(oauth_url).query)
    client_id_values = query.get("client_id", [])
    if not client_id_values or not client_id_values[0]:
        raise RuntimeError("Не удалось извлечь client_id из oauth_url.")
    return client_id_values[0]


def request_vk_user_info(
    client: httpx.Client,
    access_token: str,
    client_id: str,
) -> dict[str, Any]:
    """Запрашивает VK ID user info, не выводя access token или raw response."""
    try:
        response = client.post(
            VK_USER_INFO_URL,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            },
            json={"client_id": client_id},
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"VK user info endpoint вернул HTTP {exc.response.status_code}."
        ) from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"Ошибка VK user info запроса: {type(exc).__name__}."
        ) from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("VK user info endpoint вернул ответ не в JSON.") from exc

    if not isinstance(data, dict):
        raise RuntimeError("VK user info endpoint вернул JSON не-объект.")
    return data


def extract_safe_vk_profile(user_info: dict[str, Any]) -> dict[str, Any]:
    """Извлекает только безопасные поля профиля из VK ID response."""
    nested_user = user_info.get("user")
    source = nested_user if isinstance(nested_user, dict) else user_info

    vk_user_id = source.get("user_id") or source.get("sub") or ""
    first_name = source.get("first_name") or source.get("given_name") or ""
    last_name = source.get("last_name") or source.get("family_name") or ""
    full_name = source.get("name") or " ".join(
        part for part in (str(first_name), str(last_name)) if part
    )

    if not full_name:
        raise RuntimeError("VK user info response не содержит имя пользователя.")

    return {
        "vk_user_id": str(vk_user_id),
        "first_name": str(first_name),
        "last_name": str(last_name),
        "full_name": str(full_name),
        "email_present": bool(source.get("email") or user_info.get("email")),
        "phone_present": bool(source.get("phone") or user_info.get("phone")),
    }


def print_safe_vk_profile(profile: dict[str, Any]) -> None:
    """Печатает безопасные поля VK-профиля без контактных значений."""
    print(f"VK user id: {profile['vk_user_id'] or 'not_set'}")
    print(f"First name: {profile['first_name'] or 'not_set'}")
    print(f"Last name: {profile['last_name'] or 'not_set'}")
    print(f"Full name: {profile['full_name']}")
    print(f"Email present: {str(profile['email_present']).lower()}")
    print(f"Phone present: {str(profile['phone_present']).lower()}")


def main() -> int:
    """Запускает локальную проверку VK OAuth flow до получения callback."""
    args = parse_args()
    base_url = normalize_base_url(args.base_url)

    if args.timeout <= 0:
        print("Ошибка: --timeout должен быть больше 0.")
        return 2
    if args.poll_interval <= 0:
        print("Ошибка: --poll-interval должен быть больше 0.")
        return 2
    if args.refresh_timeout <= 0:
        print("Ошибка: --refresh-timeout должен быть больше 0.")
        return 2
    if args.refresh_poll_interval <= 0:
        print("Ошибка: --refresh-poll-interval должен быть больше 0.")
        return 2

    print(f"Backend base URL: {base_url}")

    with httpx.Client(timeout=15.0) as client:
        try:
            health_data = check_backend_health(client, base_url)
            print(f"Health check status: {health_data.get('status', 'unknown')}")

            state, oauth_url = start_vk_oauth(client, base_url)
        except RuntimeError as exc:
            print(f"Ошибка: {exc}")
            return 1

    print(f"Received state: {state}")
    print(f"OAuth URL: {oauth_url}")
    try:
        client_id = args.client_id.strip() or extract_client_id_from_oauth_url(
            oauth_url
        )
    except RuntimeError as exc:
        print(f"Ошибка: {exc}")
        return 1

    print(f"VK client_id: {client_id}")
    print("Сейчас откроется страница VK authorization в браузере.")
    print("Завершите авторизацию вручную и дождитесь callback.")

    if not webbrowser.open(oauth_url):
        print("Предупреждение: не удалось автоматически открыть браузер.")
        print("Откройте OAuth URL вручную.")

    token_document = wait_for_token_exchange(
        state=state,
        timeout_seconds=args.timeout,
        poll_interval_seconds=args.poll_interval,
    )

    if not token_document:
        print(
            "Token exchange was not completed before timeout or an error status "
            "was detected. Check browser, VK redirect URL, Dev Tunnel, Docker "
            "logs, temporary JSON storage, and vk_storage.db."
        )
        return 1

    print("Token exchange completed. Access token was saved in SQL storage.")

    access_token = token_document.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        print("Ошибка: активный token-документ не содержит access token.")
        return 1

    if not args.skip_refresh_test:
        initial_status = get_access_token_safe_status(state)
        print_initial_refresh_status(initial_status)

        initial_access_token = access_token
        initial_updated_at = str(
            token_document.get("updated_at")
            or initial_status.get("updated_at")
            or ""
        )
        initial_last_refresh_at = str(
            token_document.get("last_refresh_at")
            or initial_status.get("last_refresh_at")
            or ""
        )

        if args.force_refresh_now:
            try:
                scheduled = schedule_refresh_now_by_state(state)
            except Exception as exc:
                print(
                    "Automatic access token refresh failed."
                    f"\nReason: failed to schedule refresh now: {type(exc).__name__}."
                )
                return 1

            if not scheduled:
                print(
                    "Automatic access token refresh failed."
                    "\nReason: active token row for current state was not found."
                )
                return 1
            print("Current token row was scheduled for immediate refresh.")
        else:
            print("Force refresh disabled; waiting for existing next_refresh_at.")

        refresh_result = wait_for_access_token_refresh(
            state=state,
            initial_access_token=initial_access_token,
            initial_updated_at=initial_updated_at,
            initial_last_refresh_at=initial_last_refresh_at,
            timeout_seconds=args.refresh_timeout,
            poll_interval_seconds=args.refresh_poll_interval,
        )

        if not refresh_result.success:
            print("Automatic access token refresh failed.")
            print(f"Reason: {refresh_result.reason}")
            if refresh_result.final_status:
                print("Final safe refresh status:")
                print_safe_refresh_status(refresh_result.final_status)
            return 1

        print("Automatic access token refresh completed successfully.")
        print(f"access_token_changed={str(refresh_result.access_token_changed).lower()}")
        if not refresh_result.access_token_changed:
            print(
                "Warning: refresh flow updated SQL metadata, but access token "
                "value did not change."
            )

        refreshed_token_document = get_active_token_document_for_state(state)
        if refreshed_token_document:
            token_document = refreshed_token_document
            refreshed_access_token = token_document.get("access_token")
            if isinstance(refreshed_access_token, str) and refreshed_access_token:
                access_token = refreshed_access_token
    else:
        print("Automatic access token refresh check skipped by --skip-refresh-test.")

    if args.skip_user_info:
        print("VK user info request skipped by --skip-user-info.")
        print("Full module test completed successfully.")
        return 0

    try:
        with httpx.Client(timeout=15.0) as client:
            user_info = request_vk_user_info(
                client=client,
                access_token=access_token,
                client_id=client_id,
            )
        profile = extract_safe_vk_profile(user_info)
    except RuntimeError as exc:
        print(f"Ошибка: {exc}")
        return 1

    print_safe_vk_profile(profile)
    print(
        f"VK user info request succeeded. Full name: {profile['full_name']}"
    )
    print(
        "Token exchange completed. Access token was saved in SQL storage. "
        "VK user info request succeeded."
    )
    print("Full module test completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
