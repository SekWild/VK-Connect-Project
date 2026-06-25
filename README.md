# VK Connect Project — техническое описание модуля для ревью кода

## 1. Назначение модуля

`VK Connect Project` реализует backend-controlled flow для привязки VK-аккаунта через VK OAuth / VK ID. Модуль создает OAuth `state`, использует PKCE, принимает callback от VK, обменивает authorization code на token data, сохраняет постоянную связь аккаунта и token data в SQLite и автоматически обновляет access token через refresh flow.

Frontend или `test_service.py` отвечает только за старт привязки, открытие OAuth URL и получение итогового success/error redirect. Backend отвечает за создание `state`, PKCE-данных, проверку callback, token exchange, постоянное хранение account/token data, refresh access token и изоляцию token data от frontend.

Реализованное поведение модуля:
- FastAPI-приложение предоставляет endpoints для проверки состояния сервера, старта OAuth и обработки callback.
- Сервис старта OAuth создает временные runtime-записи для OAuth state и будущего authorization code.
- Callback-сервис принимает VK query parameters, валидирует `state`, сохраняет callback data и запускает background token exchange.
- Сервис token exchange обменивает authorization code на token data и сохраняет результат через SQL-сервис хранения.
- SQL-сервис хранения сохраняет связку аккаунта, строку токенов и refresh-метаданные.
- Сервис планирования refresh рассчитывает время обновления token rows.
- Сервис выполнения refresh обновляет одну конкретную token row через VK token endpoint.
- Background worker запускается вместе с FastAPI process и выполняет циклы планирования queue и обработки due refresh.
- `test_service.py` выполняет development-интеграционную проверку ручного end-to-end сценария.

## 2. Общая архитектура модуля

```mermaid
VK Connect Project/
│
├── .venv/
│
├── app/
│   ├── api/
│   │
│   ├── docker/
│   │   ├── docker-compose.yml
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   │
│   ├── fastapi/
│   │   ├── routers/
│   │   │   ├── health_router.py
│   │   │   └── vk_oauth_router.py
│   │   │
│   │   ├── app_factory.py
│   │   └── background_tasks.py
│   │
│   └── sql_save_service.py
│
├── data/
│   ├── auth_code_storage.json
│   ├── oauth_state_storage.json
│   ├── vk_storage.db
│
├── VK/
│   ├── access_token_service.py
│   ├── callback_service.py
│   ├── oauth_service.py
│   ├── refresh_token_service.py
│   └── queue_refresh_service.py
│
├── .dockerignore
├── .env
├── main.py
└── test_service.py
```

Слои модуля:
- FastAPI-слой: `main.py`, `app/fastapi/app_factory.py`, routers и background helpers создают HTTP-интерфейс и lifecycle hooks.
- Слой старта OAuth: `VK/oauth_service.py` генерирует `state`, PKCE-данные и authorization URL.
- Callback-слой: `VK/callback_service.py` принимает redirect от VK и сохраняет данные, необходимые для token exchange.
- Слой token exchange: `VK/access_token_service.py` выполняет обмен authorization code на token data.
- Слой SQL-хранения: `app/sql_save_service.py` создает SQLite schema, сохраняет account/token data и обслуживает refresh-метаданные.
- Слой планирования refresh: `VK/queue_refresh_service.py` рассчитывает `next_refresh_at` для active token rows.
- Слой выполнения refresh: `VK/refresh_token_service.py` обновляет конкретную token row.
- Docker-слой: `app/docker/Dockerfile`, `app/docker/docker-compose.yml`, `app/docker/requirements.txt` описывают локальный container runtime для FastAPI-модуля.
- Слой development-проверки: `test_service.py` проверяет end-to-end flow в ручном dev-сценарии.

## 3. Структура файлов реализованного модуля

| Файл | Назначение | Основная ответственность | Что не делает |
|---|---|---|---|
| `main.py` | Точка входа FastAPI-приложения | Создает `app` через `create_app()` и содержит dev-запуск Uvicorn | Не содержит OAuth/token бизнес-логику |
| `test_service.py` | Development-проверка интеграционного сценария | Проверяет health, OAuth start, callback/token exchange, SQL save, refresh worker и необязательный user info | Не является production endpoint или background worker |
| `app/fastapi/app_factory.py` | Сборка FastAPI-приложение | Подключает routers и lifespan refresh worker | Не реализует OAuth, callback, token exchange или refresh logic |
| `app/fastapi/background_tasks.py` | Координация background-задач | Запускает token exchange после callback и циклы automatic refresh worker | Не хранит token data и не разбирает VK token response |
| `app/fastapi/routers/health_router.py` | Health router | Возвращает безопасный статус сервера | Не читает storage/config |
| `app/fastapi/routers/vk_oauth_router.py` | OAuth start router | Создает authorization data через `OAuthService` | Не обрабатывает callback и не обменивает code на tokens |
| `app/sql_save_service.py` | SQLAlchemy SQLite-хранилище | Хранит account links, token data, refresh metadata, locks и safe statuses | Не вызывает VK endpoints |
| `VK/oauth_service.py` | Сервис старта OAuth | Генерирует `state`, PKCE, temporary records и authorization URL | Не принимает callback и не получает tokens |
| `VK/callback_service.py` | VK callback service | Валидирует callback, сохраняет auth code и ставит background exchange task | Не выполняет token exchange |
| `VK/access_token_service.py` | Authorization-code token exchange | Читает temporary records, вызывает VK token endpoint, сохраняет SQL token data и очищает temporary records | Не планирует automatic refresh |
| `VK/queue_refresh_service.py` | Refresh queue planner | Рассчитывает refresh slots и помечает rows к обновлению | Не вызывает VK token endpoint и не меняет token values |
| `VK/refresh_token_service.py` | Исполнитель refresh | Захватывает lock, вызывает refresh grant, обновляет token row | Не решает глобальное расписание очереди |
| `app/docker/Dockerfile` | Сборка runtime image | Устанавливает dependencies, копирует runtime modules и запускает Uvicorn | Не содержит application logic |
| `app/docker/docker-compose.yml` | Локальный container runtime | Собирает service, подключает runtime configuration, публикует порт и монтирует runtime data | Не изменяет код модуля |
| `app/docker/requirements.txt` | Runtime dependencies | Содержит Python packages для FastAPI, HTTP, env loading, file locks и SQLAlchemy | Не содержит standard-library dependencies |

## 4. Основной алгоритм работы программы

1. FastAPI-приложение создается в `main.py` через `create_app()`.
2. `app/fastapi/app_factory.py` подключает health router, OAuth start router и callback router.
3. FastAPI lifespan запускает refresh background worker.
4. Frontend или `test_service.py` вызывает `GET /auth/vk/start`.
5. Backend через `OAuthService` создает OAuth `state` и PKCE data.
6. Backend создает temporary runtime records для OAuth state и будущего authorization code.
7. Backend возвращает `state` и VK authorization URL.
8. Пользователь авторизуется в VK.
9. VK redirect вызывает backend callback endpoint.
10. Backend валидирует callback `state`.
11. Backend сохраняет callback data во temporary storage.
12. Backend ставит background token exchange task.
13. Browser получает redirect на frontend success/error URL.
14. Background task вызывает `AccessTokenService` и обменивает authorization code на token data.
15. Backend сохраняет account link и token data в SQLite через `SQLSaveService`.
16. Backend удаляет temporary OAuth/auth-code records после успешного SQL save.
17. Refresh worker планирует будущий refresh active token rows.
18. Due refresh worker обновляет access tokens, когда наступает `next_refresh_at`.
19. Development test script проверяет рабочую цепочку через HTTP endpoints и безопасный SQL status.

## 5. Сервис старта OAuth — `VK/oauth_service.py`

Сервис реализует старт OAuth flow: читает обязательные configuration names, валидирует настройки, разбирает scopes, генерирует `state`, создает PKCE `code_verifier`/`code_challenge`, записывает temporary records и собирает VK authorization URL. Наружу возвращаются только безопасные authorization data: `state` и `oauth_url`.

### Константы

- `PROJECT_ROOT` нужен для преобразования относительных storage paths в пути от корня проекта.
- `CODE_CHALLENGE_METHOD = "S256"` фиксирует PKCE method.
- `PROVIDER = "vk"` используется в temporary records.
- `OAUTH_STATE_TTL_MINUTES = 10` задает срок жизни OAuth state.

### `OAuthConfig`

`OAuthConfig` — frozen dataclass конфигурации старта OAuth. Поля:
- `client_id`;
- `redirect_uri`;
- `scopes`;
- `oauth_authorize_url`;
- `auth_code_storage_path`;
- `oauth_state_storage_path`.

`OAuthConfig.fill_data()`:
- вызывает `load_dotenv()`;
- читает обязательные environment variable names для OAuth start;
- проверяет, что значения заданы;
- вызывает `_parse_scopes()`;
- возвращает `OAuthConfig`.

`OAuthConfig._parse_scopes(raw_scopes)`:
- принимает строку scopes;
- делит ее по пробелам и запятым;
- возвращает `list[str]` без пустых элементов.

### `OAuthStateDocument`

`OAuthStateDocument` — frozen dataclass временного OAuth state document. Описывает запись, которую `OAuthStateStorage` сохраняет в JSON storage:
- `state`;
- `code_verifier`;
- `code_challenge`;
- `code_challenge_method`;
- `provider`;
- `user_id`;
- `created_at`;
- `expires_at`;
- `status`.

Эта структура нужна, чтобы callback/token exchange могли проверить state и получить PKCE verifier.

### `AuthCodeDocument`

`AuthCodeDocument` — frozen dataclass placeholder auth-code document. Поля:
- `state`;
- `auth_code`;
- `provider`;
- `user_id`;
- `created_at`;
- `status`.

Документ создается до callback, чтобы callback service позже записал authorization code по тому же `state`.

### `JsonStorage`

`JsonStorage` — базовый класс для безопасной работы с temporary JSON storage.

`__init__(storage_path)`:
- принимает string/path;
- вызывает `_resolve_storage_path()`;
- создает `FileLock` рядом со storage file.

`_resolve_storage_path(storage_path)`:
- возвращает absolute `Path`;
- относительные пути строит от `PROJECT_ROOT`.

`_default_data()`:
- возвращает `{self.storage_key: []}`.

`_read_data()`:
- возвращает базовую структуру, если файл отсутствует или пуст;
- парсит JSON;
- проверяет top-level dict;
- добавляет missing storage key как empty list;
- проверяет, что storage key содержит list;
- возвращает dict.

`_write_data(data)`:
- создает parent directory;
- пишет JSON во temporary `.tmp`;
- атомарно заменяет основной файл через `os.replace()`.

`_state_exists(documents, state)`:
- проверяет наличие dict-документа с тем же `state`;
- используется для защиты от duplicate state.

### `OAuthStateStorage`

`OAuthStateStorage(JsonStorage)` обслуживает storage key `oauth_states`.

`add_oauth_state(state, code_verifier, code_challenge, user_id="")`:
- принимает generated state и PKCE values;
- под lock читает storage;
- запрещает duplicate state;
- создает `OAuthStateDocument`;
- выставляет `created_at`, `expires_at`, `status="created"`;
- добавляет документ и атомарно записывает storage.

### `AuthCodeStorage`

`AuthCodeStorage(JsonStorage)` обслуживает storage key `auth_codes`.

`add_state(state, user_id="")`:
- принимает state;
- под lock читает storage;
- запрещает duplicate state;
- создает `AuthCodeDocument` с пустым `auth_code`;
- добавляет placeholder для будущего callback.

### `OAuthService`

Центральный service для OAuth start.

`__init__(config)`:
- сохраняет `OAuthConfig`;
- создает `OAuthStateStorage`;
- создает `AuthCodeStorage`.

`generate_state(length=32)`:
- возвращает random URL-safe state через `secrets.token_urlsafe()`.

`generate_code_verifier(length=64)`:
- возвращает random URL-safe PKCE verifier.

`generate_code_challenge(code_verifier)`:
- принимает `code_verifier`;
- считает SHA-256;
- кодирует digest в base64url;
- удаляет `=`;
- возвращает PKCE challenge.

`build_oauth_url(state, code_challenge)`:
- собирает query parameters: `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`, `code_challenge_method`;
- использует `" ".join(self.config.scopes)`;
- строит URL через `urlencode`;
- учитывает, есть ли уже `?` или завершающий `?`/`&` в base authorize URL.

`create_authorization_data(user_id="")`:
- генерирует state, code verifier и code challenge;
- сохраняет OAuth state/PKCE document;
- создает auth-code placeholder;
- строит OAuth URL;
- возвращает `{"state": state, "oauth_url": oauth_url}`.

### Вспомогательные функции и script block

`_utc_now_iso()` возвращает текущий UTC timestamp в ISO-формате.

`_utc_future_iso(minutes)` возвращает будущий UTC timestamp.

`if __name__ == "__main__"` создает config/service и печатает только `state` и `oauth_url` для dev-запуска файла.

## 6. Callback-сервис — `VK/callback_service.py`

Callback-сервис принимает VK redirect, нормализует query parameters, обрабатывает error callback, проверяет `state`, сохраняет authorization code и необязательный `device_id`, меняет status временного OAuth state и возвращает frontend redirect URL. FastAPI endpoint после успешного callback добавляет background task для token exchange.

### Константы

- `PROJECT_ROOT` используется для storage path resolution.
- `PROVIDER = "vk"` фильтрует documents текущего provider.
- `CALLBACK_RECEIVED_STATUS = "callback_received"` помечает successful callback.
- `ERROR_STATUS = "error"` помечает error state.
- `INVALID_OAUTH_STATE_STATUSES = {"used", "error"}` запрещает повторное/ошибочное использование state.

### `VKCallbackConfig`

Frozen dataclass конфигурации callback handler. Поля:
- `frontend_success_url`;
- `frontend_error_url`;
- `auth_code_storage_path`;
- `oauth_state_storage_path`.

`VKCallbackConfig.from_env()`:
- вызывает `load_dotenv()`;
- читает обязательные callback/storage variable names;
- валидирует наличие значений;
- возвращает config.

### `VKCallbackData`

Frozen dataclass normalized callback input:
- `code`;
- `state`;
- `device_id`;
- `error`;
- `error_description`.

Нужен, чтобы handler работал с нормализованными строками вместо `None`.

### `JsonStorage`

Base helper для JSON storage.

`__init__(storage_path)` приводит путь к рабочему виду и создает `FileLock`.

`_resolve_storage_path(storage_path)` возвращает absolute path.

`_default_data()` возвращает `{storage_key: []}`.

`_read_data()` безопасно читает JSON, проверяет top-level object и list по ключу.

`_write_data(data)` пишет JSON атомарно через `.tmp` и `os.replace()`.

`_find_document(documents, state)` ищет dict-document по `state`.

### `OAuthStateStorage`

Работает с `oauth_states`.

`state_exists(state)`:
- под lock читает storage;
- ищет document по state;
- возвращает результат `_is_valid_state_document()`.

`mark_callback_received(state)`:
- находит valid state;
- ставит `status="callback_received"`;
- записывает `updated_at`;
- атомарно сохраняет.

`mark_error(state)`:
- best-effort помечает state как `error`, если state найден и provider соответствует;
- не трогает used state.

`_is_valid_state_document(document)`:
- проверяет наличие document;
- provider;
- status не в invalid statuses;
- expiration через `_is_expired()`.

`_is_expired(expires_at)`:
- если expiration отсутствует, возвращает `False`;
- некорректный тип/формат считает expired;
- сравнивает parsed timestamp с current UTC.

### `AuthCodeStorage`

Работает с `auth_codes`.

`attach_auth_code(state, code, device_id="")`:
- под lock ищет auth-code placeholder по state;
- проверяет provider;
- запрещает overwrite already saved auth code;
- записывает `auth_code`;
- записывает stripped `device_id`;
- ставит `status="callback_received"`;
- пишет `updated_at`;
- атомарно сохраняет.

### `VKCallbackHandler`

Business logic callback без HTTP-specific деталей.

`__init__(config)`:
- сохраняет config;
- создает OAuth state storage;
- создает auth-code storage.

`handle_callback(code, state, error=None, error_description=None, device_id=None)`:
- нормализует inputs в `VKCallbackData`;
- если есть `error`, best-effort помечает state ошибочным и возвращает frontend error URL;
- если отсутствует code или state, возвращает error URL;
- проверяет state через `oauth_state_storage.state_exists()`;
- сохраняет code/device_id через `auth_code_storage.attach_auth_code()`;
- помечает OAuth state как callback received;
- при controlled RuntimeError возвращает error URL;
- при success возвращает frontend success URL.

`_mark_error_if_state_present(state)`:
- если state задан, пытается пометить OAuth state как error;
- suppresses controlled storage errors.

### FastAPI router

`router = APIRouter(prefix="/auth/vk", tags=["VK OAuth"])` публикует callback route.

`vk_callback(background_tasks, code, state, device_id, error, error_description)`:
- endpoint `GET /auth/vk/callback`;
- создает config и handler;
- вызывает handler в threadpool через `run_in_threadpool`;
- если redirect URL success и есть code/state, добавляет background task `exchange_vk_callback_code_in_background`;
- возвращает `RedirectResponse(status_code=302)`.

### Вспомогательный блок

`_utc_now_iso()` возвращает текущий UTC timestamp для обновления статусов.

## 7. Сервис token exchange — `VK/access_token_service.py`

Сервис token exchange читает temporary callback/OAuth data, извлекает PKCE `code_verifier`, отправляет authorization-code request в VK token endpoint, валидирует response, разбирает token data, рассчитывает expiration, сохраняет permanent account/token data через SQL service и удаляет temporary records после успешного сохранения.

### Константы

- `PROVIDER = "vk"` фильтрует documents.
- `STATUS_ACTIVE`, `STATUS_ERROR`, `STATUS_TOKEN_RECEIVED`, `STATUS_USED` задают значения status.
- `SKIP_AUTH_CODE_STATUSES` и `SKIP_OAUTH_STATE_STATUSES` исключают уже обработанные/error documents.

### `AccessTokenConfig`

Frozen dataclass конфигурации token exchange:
- `client_id`;
- `client_secret`;
- `redirect_uri`;
- `oauth_token_url`;
- `auth_code_storage_path`;
- `oauth_state_storage_path`;
- `http_timeout_seconds`.

`from_env()`:
- вызывает `load_dotenv()`;
- читает обязательные variable names для token exchange;
- валидирует наличие значений;
- добавляет HTTP timeout через `_read_http_timeout_seconds()`;
- возвращает config.

`_read_http_timeout_seconds()`:
- читает необязательный timeout;
- возвращает базовое значение `30.0`, если значение не задано;
- валидирует numeric positive timeout.

### Dataclass-структуры

`AuthCodeDocument` представляет готовый auth-code document:
- `state`;
- `auth_code`;
- `user_id`;
- `device_id`;
- `provider`;
- `status`.

`OAuthStateDocument` представляет OAuth state с PKCE verifier:
- `state`;
- `code_verifier`;
- `code_challenge`;
- `code_challenge_method`;
- `provider`;
- `user_id`;
- `status`.

`VKTokenData` представляет разобранный успешный token response:
- `access_token`;
- необязательный `refresh_token`;
- необязательный `token_type`;
- необязательный `expires_in`;
- необязательный `expires_at`;
- необязательный `scope`;
- необязательный `vk_user_id`;
- необязательный `id_token`.

`AccessTokenProcessResult` — безопасный result для batch processing:
- `state`;
- `success`;
- `status`;
- необязательный `vk_user_id`;
- `message`.

### JSON helpers

`JsonStoragePathResolver.resolve(storage_path)`:
- принимает строку storage path;
- возвращает absolute path;
- относительные пути строит от project root.

`_JsonStorage`:
- base class с `storage_key`;
- создает `FileLock`;
- `_default_data()` возвращает структуру с пустым list;
- `_read_data()` безопасно читает и валидирует JSON;
- `_write_data()` атомарно пишет JSON;
- `_find_document()` ищет document по state.

### `AuthCodeStorage`

`get_ready_auth_code_documents()`:
- читает `auth_codes`;
- выбирает documents с непустыми state/auth_code;
- проверяет provider;
- пропускает statuses из `SKIP_AUTH_CODE_STATUSES`;
- возвращает list `AuthCodeDocument`.

`mark_token_received(state)`:
- legacy-compatible method, который помечает auth-code document как token received;
- в основном успешном SQL flow temporary document удаляется.

`delete_by_state(state)`:
- удаляет auth-code document по state;
- ничего не делает, если document отсутствует.

`mark_error(state)`:
- best-effort помечает auth-code document как `error`, если он не был processed/used.

### `OAuthStateStorage`

`get_state_document(state)`:
- читает `oauth_states`;
- ищет document по state;
- проверяет provider;
- проверяет status;
- извлекает непустой `code_verifier`;
- возвращает `OAuthStateDocument`.

`mark_used(state)`:
- legacy-compatible method, который ставит state used.
- активный успешный SQL flow удаляет state document.

`delete_by_state(state)`:
- удаляет OAuth state document по state;
- ничего не делает, если document отсутствует.

`mark_error(state)`:
- best-effort помечает OAuth state как error.

### `AccessTokenStorage`

`AccessTokenStorage` остается в файле как JSON storage class, но реализованный рабочий flow сохраняет permanent token data через `SQLSaveService`. Для ревью активного runtime нужно проверять `AccessTokenService.sql_storage`, а не этот legacy helper.

### `AccessTokenService`

`__init__(config)`:
- сохраняет `AccessTokenConfig`;
- создает `AuthCodeStorage`;
- создает `OAuthStateStorage`;
- создает `SQLSaveService`.

`process_ready_auth_codes()`:
- берет готовые auth-code documents;
- для каждого state проверяет active SQL token;
- если token уже active, чистит temporary documents и возвращает skipped result;
- иначе вызывает `process_callback_code()`;
- при RuntimeError best-effort помечает temporary docs как error;
- возвращает list `AccessTokenProcessResult`.

`_mark_processing_error(state)`:
- вызывает `mark_error()` на auth-code и OAuth state storages;
- не прерывает batch processing.

`process_callback_code(state, code, user_id="", device_id="")`:
- валидирует state/code;
- проверяет, что active SQL token для state еще не существует;
- читает OAuth state и PKCE verifier;
- вызывает `exchange_code_for_tokens()`;
- сохраняет token data через `SQLSaveService.save_vk_token_data()`;
- передает state, provider, VK user id, user id, token metadata и очищенный `device_id`;
- удаляет temporary auth-code/OAuth-state documents;
- возвращает `VKTokenData`.

`exchange_code_for_tokens(code, code_verifier, device_id="")`:
- собирает request data: `grant_type=authorization_code`, client settings, redirect URI, code, code verifier;
- добавляет `device_id`, если он непустой;
- вызывает `_post_json()`;
- возвращает разобранный `VKTokenData`.

`_post_json(url, data)`:
- отправляет POST через `httpx.AsyncClient`;
- разбирает JSON response;
- при HTTP errors извлекает безопасный error text;
- проверяет VK error response;
- возвращает response dict.

`_parse_token_response(response_data)`:
- требует строковый `access_token`;
- парсит `expires_in`;
- рассчитывает `expires_at`;
- извлекает необязательную token metadata;
- возвращает `VKTokenData`.

`_raise_for_vk_error_response(response_data)`:
- если response содержит `error`, вызывает `_extract_safe_error_text()` и поднимает `RuntimeError`.

`_extract_safe_error_text(response_data)`:
- возвращает безопасный text для error/error_description/error_code без token values.

`_sanitize_vk_error_text(message)`:
- маскирует known token-like fragments в error text.

`_parse_optional_int(value)`:
- преобразует необязательное value в int;
- поднимает controlled RuntimeError при некорректном `expires_in`.

`_optional_string(value)`:
- преобразует value в string или `None`.

`_parse_scope(value)`:
- list scopes преобразует в space-separated string;
- scalar value преобразует в string.

`_parse_vk_user_id(response_data)`:
- ищет VK user id в keys `vk_user_id`, `user_id`, `id`.

### Вспомогательные функции и dev block

`_utc_now_iso()` возвращает текущий UTC ISO timestamp.

`_calculate_expires_at(expires_in)` возвращает ISO expiration timestamp или `None`.

`_run_dev_processing()` запускает batch processing готовых auth-code documents. Это dev script path внутри файла; рабочий callback flow использует background helper.

`if __name__ == "__main__"` запускает `_run_dev_processing()`.

## 8. SQL-сервис хранения — `app/sql_save_service.py`

SQL-сервис хранения управляет SQLite schema и постоянным состоянием, необходимым рабочей цепочке модуля: account links, token rows, refresh metadata, безопасным чтением status, поддержкой queue planning, due lookup, refresh locks и записью результатов refresh success/failure.

### Константы и состояние модуля

- `PROJECT_ROOT` и `DEFAULT_DB_PATH` задают расположение SQLite storage.
- `PROVIDER = "vk"` фиксирует provider.
- `STATUS_ACTIVE` и `STATUS_REAUTH_REQUIRED` используются для link status.
- `REFRESH_STATUS_IDLE`, `REFRESH_STATUS_QUEUED`, `REFRESH_STATUS_REFRESHING`, `REFRESH_STATUS_ERROR`, `REFRESH_STATUS_REAUTH_REQUIRED` задают refresh states.
- `REFRESH_SAFETY_WINDOW_SECONDS = 600` используется для расчета `next_refresh_at`.
- `REFRESH_SUITABLE_STATUSES` задает refresh statuses, которые due lookup может выбирать.
- `_schema_init_lock` защищает инициализацию schema.
- `_schema_initialized_paths` предотвращает повторную инициализацию одного DB path в том же process.

`_utc_now()` возвращает текущий UTC `datetime`.

### ORM base и models

`Base(DeclarativeBase)` — SQLAlchemy declarative base для ORM models.

#### `VKAccountLink`

ORM model для таблицы `vk_account_links`.

Поля:
- `id`: primary key.
- `user_id`: внутренний user id, nullable.
- `provider`: имя provider, базовое значение `vk`.
- `vk_user_id`: VK user id, nullable.
- `state`: OAuth state успешной привязки.
- `status`: status связи.
- `created_at`: timestamp создания.
- `token_data`: one-to-one relationship с `VKTokenData`.

Индексы:
- unique index по `state`;
- index по `vk_user_id`;
- index по `user_id`.

#### `VKTokenData`

ORM model для таблицы `vk_token_data`.

Поля:
- `id`: primary key.
- `link_id`: FK на `vk_account_links.id`, unique, indexed, с cascade delete.
- `access_token`: сохраненный access token.
- `refresh_token`: сохраненный refresh token.
- `token_type`: тип token.
- `expires_in`: срок жизни token в секундах.
- `expires_at`: timestamp истечения срока действия.
- `scope`: выданные scopes.
- `id_token`: необязательный ID token.
- `device_id`: необязательный callback/token parameter, который используется реализованным refresh request.
- `created_at`: timestamp создания row.
- `updated_at`: timestamp последнего обновления.
- `next_refresh_at`: запланированный refresh timestamp.
- `last_refresh_at`: timestamp последного успешного refresh.
- `refresh_status`: refresh state.
- `refresh_attempts`: число последовательных неудачных попыток.
- `refresh_lock_until`: срок действия lock.
- `last_refresh_error`: безопасный диагностический текст.
- `link`: обратный relationship к `VKAccountLink`.

### `SQLSaveService`

`__init__(db_path=None)`:
- resolves DB path;
- создает parent directory;
- создает SQLAlchemy engine;
- создает session factory;
- вызывает `init_db()`.

`_resolve_db_path(db_path)`:
- возвращает absolute DB path;
- базовый путь указывает на project runtime SQLite path;
- относительные пользовательские paths рассчитываются от project root.

`_create_engine(db_path)`:
- создает SQLite engine;
- использует `check_same_thread=False`;
- регистрирует connect event для выполнения `PRAGMA foreign_keys=ON`.

`init_db()`:
- быстро выходит, если DB path уже инициализирован в process;
- иначе захватывает `_schema_init_lock`;
- повторно проверяет initialized paths;
- запускает `Base.metadata.create_all(checkfirst=True)`;
- запускает `_ensure_refresh_columns()`;
- помечает path как initialized только после успешной инициализации.

`_ensure_refresh_columns()`:
- выполняет идемпотентную migration для refresh/device columns;
- читает table schema через `PRAGMA table_info(vk_token_data)`;
- добавляет missing columns через `ALTER TABLE`;
- не удаляет и не пересоздает tables.

`save_vk_token_data(...)`:
- валидирует state/provider/access token;
- нормализует `device_id`;
- ищет existing account link по state, provider/user_id, затем provider/vk_user_id через `_find_existing_link()`;
- создает или обновляет `VKAccountLink`;
- создает или обновляет одну `VKTokenData` row для link;
- разбирает `expires_at`;
- рассчитывает `next_refresh_at`;
- сбрасывает refresh metadata после обычного token exchange;
- сохраняет existing `device_id` при update, если новое значение пустое.

`has_active_token_for_state(state)`:
- вызывает `get_active_token_for_state()`;
- возвращает boolean наличия active token.

`get_active_token_for_state(state)`:
- возвращает backend/dev dict для active token по state;
- содержит `access_token` для внутреннего dev usage;
- также содержит безопасную metadata: refresh flags/timestamps;
- возвращает `None`, если active link/token отсутствует.

`get_token_safe_status_by_state(state)`:
- возвращает безопасный dict без token values;
- содержит признаки существования, active status, наличие refresh token, `device_id_present`, timestamps, refresh status, attempts, safe error, VK user id, scope и link status.

`schedule_refresh_now_by_state(state)`:
- ищет active token row по state;
- ставит `next_refresh_at` в текущее время;
- ставит `refresh_status="queued"`;
- очищает lock/error metadata;
- возвращает `True`, если row поставлена в очередь.

`get_active_tokens_for_refresh_planning()`:
- возвращает list безопасной token metadata для active links;
- используется `QueueRefreshService`;
- содержит token id, link id, expiration, наличие refresh token и statuses.

`update_refresh_plan(token_id, next_refresh_at, refresh_status="queued")`:
- обновляет planned refresh timestamp/status одной token row;
- очищает planning error;
- обновляет `updated_at`.

`mark_refresh_planning_error(token_id, refresh_status, safe_error, mark_link_reauth_required=False)`:
- записывает безопасную planning failure;
- при необходимости помечает link как требующий reauthorization.

`get_due_refresh_token_ids(now, limit)`:
- возвращает token ids, у которых `next_refresh_at <= now`;
- фильтрует active links;
- фильтрует suitable refresh statuses;
- пропускает locked rows;
- сортирует по `next_refresh_at`;
- применяет limit.

`acquire_refresh_lock(token_id, lock_until)`:
- загружает token/link row;
- отклоняет inactive links, reauth-required token rows и active locks;
- ставит `refresh_status="refreshing"`;
- ставит `refresh_lock_until`;
- возвращает результат захвата lock.

`get_token_for_refresh_by_token_id(token_id)`:
- возвращает internal dict для refresh executor;
- содержит refresh token и `device_id`, потому что они нужны executor;
- не возвращает raw ORM row.

`get_token_id_by_link_id(link_id)`:
- возвращает token id для link id или `None`.

`update_token_refresh_success(...)`:
- обновляет access token и metadata после refresh;
- обновляет refresh token только если пришло новое значение;
- обновляет expiration/scope/id token, если они переданы;
- ставит `last_refresh_at`, `updated_at`;
- пересчитывает `next_refresh_at`;
- сбрасывает status в `idle`, attempts в `0`, очищает lock/error;
- оставляет link active.

`update_token_refresh_failure(...)`:
- увеличивает attempts;
- записывает refresh status;
- очищает lock;
- записывает safe error;
- записывает необязательный next retry timestamp;
- при необходимости помечает link как требующий reauthorization.

`mark_token_reauth_required(token_id, safe_error)`:
- wrapper для permanent refresh failure;
- переводит token/link в reauthorization-required state.

`_find_existing_link(session, state, provider, user_id, vk_user_id)`:
- сначала ищет link по state;
- затем по provider/user_id;
- затем по provider/vk_user_id;
- по возможности предотвращает дублирование links для одного привязанного аккаунта.

`_parse_optional_datetime(value)`:
- разбирает ISO string в UTC-aware datetime;
- возвращает `None` для пустых или некорректных значений.

`_normalize_datetime(value)`:
- приводит datetime к UTC-aware форме.

`_datetime_to_iso(value)`:
- преобразует необязательный datetime в ISO string.

`_calculate_next_refresh_at(expires_at)`:
- возвращает `expires_at - 600 seconds` или `None`.

`_safe_error_text(message, max_length=500)`:
- обрезает безопасный diagnostic error text.

`_empty_safe_status()`:
- возвращает базовый безопасный status dict.

## 9. Сервис планирования refresh queue — `VK/queue_refresh_service.py`

Queue planner читает безопасную active token metadata из SQL, сортирует tokens по expiration, рассчитывает refresh schedule, записывает `next_refresh_at` и помечает rows, которые невозможно запланировать. Этот сервис не вызывает VK APIs и не меняет token values.

### Константы

- `REFRESH_SAFETY_WINDOW_SECONDS = 600`: ideal refresh time за 10 минут до expiration.
- `REFRESH_HARD_DEADLINE_SECONDS = 300`: hard deadline за 5 минут до expiration.
- `REFRESH_SPACING_SECONDS = 120`: spacing между planned refresh slots.
- `QUEUE_REBUILD_INTERVAL_SECONDS = 600`: interval background loop.
- `REFRESH_DUE_CHECK_INTERVAL_SECONDS = 60`: interval due loop.
- `REFRESH_BATCH_SIZE = 20`: максимальное число due ids в одном batch.

### Dataclass-структуры

`RefreshPlan`:
- `next_refresh_at`: scheduled refresh time;
- `hard_deadline_at`: hard deadline;
- `is_emergency`: признак, что token нужно refresh немедленно.

`QueueRefreshResult`:
- `planned_count`;
- `emergency_count`;
- `skipped_count`;
- `message`.

### `QueueRefreshService`

`__init__(sql_storage=None)`:
- принимает необязательный SQL service;
- создает `SQLSaveService`, если зависимость не передана.

`rebuild_refresh_queue()`:
- получает текущее UTC time;
- читает token rows через `get_active_tokens_for_refresh_planning()`;
- сортирует через `_sort_key()`;
- пропускает rows без valid `expires_at` и записывает planning error;
- помечает rows без refresh token как требующие reauthorization;
- рассчитывает plan через `calculate_next_refresh_at()`;
- записывает plan через `update_refresh_plan()`;
- считает planned/emergency/skipped rows;
- возвращает `QueueRefreshResult`.

`calculate_next_refresh_at(expires_at, previous_planned_refresh_at, now)`:
- нормализует datetimes к UTC;
- рассчитывает ideal refresh time;
- рассчитывает hard deadline;
- применяет spacing после previous planned slot;
- гарантирует, что planned time не раньше текущего времени;
- переключает в emergency, если planned slot позже hard deadline или текущее время уже внутри hard deadline window;
- возвращает `RefreshPlan`.

`get_due_token_ids(limit=REFRESH_BATCH_SIZE)`:
- передает выполнение в `SQLSaveService.get_due_refresh_token_ids()`;
- возвращает list token ids, которым пора выполнить refresh.

`_sort_key(token_row)`:
- возвращает UTC expiration datetime;
- rows with unknown expiration go to the end.

`_ensure_utc(value)`:
- normalizes datetime to UTC-aware value.

## 10. Сервис выполнения refresh — `VK/refresh_token_service.py`

Исполнитель refresh-обновления работает с одной конкретной token row. Он загружает refresh config, захватывает SQL lock, читает internal refresh data, отправляет refresh-token grant request, разбирает successful response, обновляет SQL при success и записывает controlled failure metadata при ошибках.

### Константы and errors

- `DEFAULT_HTTP_TIMEOUT_SECONDS = 10.0`.
- `REFRESH_LOCK_SECONDS = 180`.
- `TRANSIENT_BACKOFF_MAX_SECONDS = 300`.
- `TRANSIENT_BACKOFF_STEP_SECONDS = 60`.

`RefreshPermanentError` представляет refresh errors, которые должны переводить link/token в state, требующий reauthorization.

`RefreshTransientError` представляет retryable refresh errors.

### Dataclass-структуры

`RefreshTokenConfig`:
- `client_id`;
- `client_secret`;
- `oauth_token_url`;
- `http_timeout_seconds`.

`RefreshTokenConfig.from_env()`:
- загружает обязательные имена refresh config;
- валидирует наличие значений;
- читает HTTP timeout через `_read_http_timeout()`;
- возвращает config.

`RefreshTokenConfig._read_http_timeout()`:
- возвращает базовый timeout или положительный числовой пользовательский timeout.

`RefreshTokenResult`:
- безопасный результат с `token_id`, необязательным `link_id`, `refreshed`, `status` и `message`.

`ParsedRefreshResponse`:
- разобранный успешный VK refresh response с token values и metadata для внутреннего SQL update.

### `RefreshTokenService`

`__init__(config=None, sql_storage=None)`:
- принимает необязательные config и SQL service;
- создает базовые зависимости, если они не переданы.

`refresh_token_by_link_id(link_id)`:
- получает token id через `SQLSaveService.get_token_id_by_link_id()`;
- возвращает not-found result, если token row отсутствует;
- передает выполнение в `refresh_token_by_token_id()`.

`refresh_token_by_token_id(token_id)`:
- рассчитывает lock deadline;
- пытается захватить lock через `SQLSaveService.acquire_refresh_lock()`;
- возвращает locked/not-due result, если lock недоступен;
- читает internal token data через `get_token_for_refresh_by_token_id()`;
- валидирует refresh token и callback parameter, необходимый для refresh request;
- отправляет refresh request через `_request_refresh_token()`;
- разбирает response через `_parse_refresh_response()`;
- при permanent error вызывает `update_token_refresh_failure(..., refresh_status=reauth_required, mark_link_reauth_required=True)`;
- при transient error рассчитывает backoff и вызывает `update_token_refresh_failure(..., refresh_status=error, next_refresh_at=...)`;
- при success вызывает `update_token_refresh_success()`;
- возвращает safe `RefreshTokenResult`.

`_request_refresh_token(refresh_token, device_id)`:
- собирает refresh request data с `grant_type=refresh_token`, client settings, refresh token и callback parameter, который требуется VK ID refresh flow;
- отправляет запрос через `httpx.AsyncClient`;
- разбирает JSON;
- сопоставляет HTTP 429/5xx с transient errors;
- сопоставляет permanent VK error markers с `RefreshPermanentError`;
- возвращает response dict при success.

`_parse_refresh_response(response_data)`:
- требует строковый `access_token`;
- разбирает `expires_in`;
- рассчитывает `expires_at`;
- извлекает refresh token, token type, scope и id token;
- возвращает `ParsedRefreshResponse`.

`_calculate_expires_at(expires_in)`:
- возвращает current UTC + lifetime seconds.

`_parse_optional_int(value)`:
- преобразует необязательное numeric value в int;
- вызывает transient error для некорректных значений.

`_optional_string(value)`:
- возвращает пустую строку для missing value;
- иначе преобразует значение в строку.

`_parse_scope(value)`:
- преобразует scope в строку или объединяет list scopes.

`_extract_safe_error_text(response_data)`:
- извлекает безопасный error text из VK error shape.

`_is_permanent_error(response_data)`:
- проверяет error text на permanent markers, включая invalid/expired/revoked tokens и invalid callback parameter для VK ID refresh.

`_sanitize_vk_error_text(message)`:
- маскирует token-like fragments в diagnostic text и обрезает сообщение до 500 символов.

## 11. Background-задачи FastAPI — `app/fastapi/background_tasks.py`

Этот файл координирует асинхронные задачи, которые не должны выполняться прямо внутри HTTP request handler-ов.

### Background token exchange после callback

`exchange_vk_callback_code_in_background(state, code, device_id="", user_id="")`:
- получает callback state/code и необязательный callback parameter;
- пропускает обработку, если state/code отсутствуют;
- создает `AccessTokenConfig` и `AccessTokenService`;
- вызывает `process_callback_code()`;
- пишет sanitized error в log при ошибке;
- пишет safe success metadata в log при успехе.

### Refresh background worker

Глобальное состояние:
- `logger` — module logger.
- `SENSITIVE_FIELD_NAMES` и `SENSITIVE_FIELD_PATTERN` задают имена, которые маскируются в logs.
- `_refresh_worker_stop_event` хранит текущий stop signal.
- `_refresh_worker_tasks` хранит выполняющиеся queue/due loop tasks.

`_sanitize_error_message(message)`:
- маскирует sensitive fields, bearer tokens и token-like fragments в error text.

`start_vk_refresh_background_worker()`:
- prevents duplicate workers by checking active tasks;
- создает stop event;
- запускает `_refresh_queue_loop()` и `_due_refresh_loop()` через `asyncio.create_task()`.

`stop_vk_refresh_background_worker()`:
- выставляет stop event;
- отменяет tasks;
- ожидает завершения tasks с подавлением `CancelledError`;
- очищает module-level worker state.

`_refresh_queue_loop(stop_event)`:
- работает до stop event;
- вызывает `_rebuild_refresh_queue_once()` через `asyncio.to_thread()`;
- пишет в log counts planned/emergency/skipped;
- ожидает `QUEUE_REBUILD_INTERVAL_SECONDS`.

`_due_refresh_loop(stop_event)`:
- периодически получает due token ids через `_get_due_refresh_token_ids()`;
- вызывает `_refresh_due_tokens()`, если ids найдены;
- ожидает `REFRESH_DUE_CHECK_INTERVAL_SECONDS`.

`_rebuild_refresh_queue_once()`:
- создает `QueueRefreshService`;
- вызывает `rebuild_refresh_queue()`;
- возвращает `QueueRefreshResult`.

`_get_due_refresh_token_ids()`:
- создает `QueueRefreshService`;
- возвращает due ids с учетом `REFRESH_BATCH_SIZE`.

`_refresh_due_tokens(token_ids)`:
- загружает `RefreshTokenConfig`;
- создает `RefreshTokenService`;
- проходит по token ids;
- вызывает `refresh_token_by_token_id()`;
- пишет в log безопасную result metadata.

`_wait_for_stop(stop_event, timeout_seconds)`:
- ожидает stop event или timeout;
- возвращает `True`, если запрошена остановка.

## 12. Сборка FastAPI-приложение — `app/fastapi/app_factory.py` и `main.py`

### `app/fastapi/app_factory.py`

`lifespan(app)`:
- async context manager для FastAPI lifecycle;
- запускает refresh background worker перед обработкой запросов;
- останавливает refresh background worker при shutdown;
- удаляет неиспользуемый параметр `app`, чтобы функция оставалась сфокусированной.

`create_app()`:
- создает `FastAPI(title="VK Connect Project", lifespan=lifespan)`;
- подключает `health_router`;
- подключает `vk_oauth_router`;
- подключает callback router, импортированный из `VK.callback_service`;
- возвращает app instance.

Business logic остается в сервисах; app factory только связывает application components.

### `main.py`

`app = create_app()`:
- предоставляет FastAPI app object для Uvicorn import path `main:app`.

`if __name__ == "__main__"` block:
- запускает `uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)`;
- поддерживает локальный development launch.

## 13. FastAPI routers

### `app/fastapi/routers/health_router.py`

`router = APIRouter(tags=["Health"])` создает router group для health endpoint.

`health_check()`:
- endpoint `GET /health`;
- не принимает явные input-параметры;
- возвращает dict с `status`, `service`, `module`, `message`;
- предоставляет safe status для проверки доступности runtime.

### `app/fastapi/routers/vk_oauth_router.py`

`router = APIRouter(prefix="/auth/vk", tags=["VK OAuth"])` создает OAuth router.

`start_vk_oauth()`:
- endpoint `GET /auth/vk/start`;
- создает `OAuthConfig` через `OAuthConfig.fill_data()`;
- создает `OAuthService`;
- вызывает `service.create_authorization_data()` в threadpool;
- валидирует наличие `state` и `oauth_url`;
- возвращает JSON с `state`, `oauth_url`, `message`;
- при ошибке поднимает `HTTPException(status_code=500, detail="Не удалось создать VK OAuth URL.")`.

Router не обрабатывает callback, token exchange или refresh.

## 14. Development-интеграционный тест — `test_service.py`

`test_service.py` — development-only проверочный скрипт. Он проверяет рабочий модуль через HTTP endpoints, чтение temporary safe status и SQL safe status helpers.

### Константы и dataclass

- `DEFAULT_BASE_URL`, `DEFAULT_TIMEOUT_SECONDS`, `DEFAULT_POLL_INTERVAL_SECONDS`, `DEFAULT_REFRESH_TIMEOUT_SECONDS`, `DEFAULT_REFRESH_POLL_INTERVAL_SECONDS` задают базовые CLI-значения.
- `PROJECT_ROOT`, `AUTH_CODE_STORAGE_PATH`, `OAUTH_STATE_STORAGE_PATH` указывают на temporary runtime storages для safe dev polling.
- `VK_USER_INFO_URL` указывает на VK ID user info endpoint.
- `_SQL_STORAGE_SERVICE` кэширует instance `SQLSaveService` для polling.

`RefreshWaitResult`:
- `success`;
- `reason`;
- `access_token_changed`;
- `final_status`.

### CLI and HTTP helpers

`parse_args()`:
- задает CLI flags: base URL, timeouts, poll intervals, client id override, skip user info, skip refresh test и refresh timing options;
- возвращает argparse namespace.

`normalize_base_url(base_url)`:
- удаляет завершающий slash.

`request_json(client, url)`:
- выполняет GET request;
- поднимает RuntimeError при connection/HTTP/JSON shape errors;
- возвращает JSON object dict.

`check_backend_health(client, base_url)`:
- вызывает `/health`;
- возвращает parsed dict.

`start_vk_oauth(client, base_url)`:
- вызывает `/auth/vk/start`;
- валидирует `state` и `oauth_url`;
- возвращает `(state, oauth_url)`.

### Temporary storage polling helpers

`read_storage(storage_path, storage_key)`:
- читает JSON runtime storage для dev diagnostics;
- валидирует object/list shape;
- возвращает list documents.

`find_document_by_state(documents, state)`:
- возвращает document, совпадающий по state, или `None`.

`get_auth_code_safe_status(state)`:
- возвращает `exists`, `auth_code_saved`, `status`.

`get_oauth_state_safe_status(state)`:
- возвращает `exists`, `status`, `callback_received`.

### SQL polling helpers

`get_active_token_document_for_state(state)`:
- вызывает internal active-token helper SQL service;
- используется внутри script для сравнения access token и user info request.

`get_access_token_safe_status(state)`:
- вызывает SQL service safe status helper.

`get_sql_storage_service()`:
- лениво создает и кэширует `SQLSaveService`.

`schedule_refresh_now_by_state(state)`:
- вызывает SQL helper, чтобы поставить текущую token row в очередь immediate refresh.

### Safe output helpers

`print_safe_poll_status(auth_code_status, oauth_state_status, access_token_status)`:
- печатает temporary/SQL status booleans и metadata;
- не печатает token values.

`print_safe_refresh_status(status)`:
- печатает safe refresh metadata: existence, active token saved, наличие refresh token, наличие callback parameter, timestamps, status, attempts, lock и safe error.

`print_initial_refresh_status(status)`:
- печатает initial refresh status snapshot перед ожиданием automatic refresh.

### Waiting algorithms

`wait_for_access_token_refresh(...)`:
- опрашивает SQL safe status и internal token document;
- определяет reauthorization-required status как ошибочный результат;
- ожидает через transient error/lock status;
- проверяет `last_refresh_at`, `updated_at` и internal access token comparison;
- возвращает `RefreshWaitResult`.

`wait_for_token_exchange(state, timeout_seconds, poll_interval_seconds)`:
- опрашивает temporary auth-code status, OAuth state status и SQL status;
- возвращает active token document, когда SQL token существует;
- возвращает `None` при timeout или error status.

### User info helpers

`extract_client_id_from_oauth_url(oauth_url)`:
- разбирает public client id из OAuth URL query.

`request_vk_user_info(client, access_token, client_id)`:
- выполняет VK ID user info request, используя access token только внутри script;
- возвращает разобранный response dict.

`extract_safe_vk_profile(user_info)`:
- извлекает VK user/profile fields и boolean contact presence flags из response shape.

`print_safe_vk_profile(profile)`:
- печатает safe profile summary.

### `main()`

`main()`:
- разбирает CLI;
- валидирует timeouts;
- проверяет health;
- запускает OAuth;
- извлекает client id;
- открывает browser через `webbrowser.open(oauth_url)`;
- ожидает token exchange;
- при необходимости ставит immediate refresh;
- ожидает background refresh worker;
- при необходимости вызывает VK user info;
- возвращает process exit code.

`if __name__ == "__main__"` вызывает `sys.exit(main())`.

## 15. Жизненный цикл runtime storage

### Temporary OAuth/auth-code storage

Temporary OAuth state storage:
- создается во время OAuth start через `OAuthStateStorage.add_oauth_state()`;
- читается при callback validation через `OAuthStateStorage.state_exists()`;
- читается во время token exchange через `OAuthStateStorage.get_state_document()`;
- удаляется после успешного SQL save через `OAuthStateStorage.delete_by_state()`.

Temporary auth-code storage:
- placeholder создается во время OAuth start через `AuthCodeStorage.add_state()`;
- обновляется во время callback через `AuthCodeStorage.attach_auth_code()`;
- читается во время token exchange через `AuthCodeStorage.get_ready_auth_code_documents()` или прямую callback processing;
- удаляется после успешного SQL save через `AuthCodeStorage.delete_by_state()`.

### Permanent SQLite storage

Permanent storage:
- инициализируется через `SQLSaveService.__init__()` и `init_db()`;
- хранит account link в `VKAccountLink`;
- хранит token row в `VKTokenData`;
- создает/обновляет link/token data через `save_vk_token_data()`;
- предоставляет safe status через `get_token_safe_status_by_state()`;
- ставит refresh в очередь через `update_refresh_plan()` или `schedule_refresh_now_by_state()`;
- защищает refresh execution через `acquire_refresh_lock()`;
- обновляет token metadata через `update_token_refresh_success()` и `update_token_refresh_failure()`.

## 16. Docker runtime-архитектура

Docker-файлы описывают локальный container runtime для FastAPI-модуля.

### `app/docker/Dockerfile`

- `FROM python:3.13-slim` выбирает официальный slim-образ Python.
- `WORKDIR /app` задает runtime working directory.
- `PYTHONDONTWRITEBYTECODE=1` отключает запись bytecode files в container.
- `PYTHONUNBUFFERED=1` делает logs небуферизованными.
- `COPY app/docker/requirements.txt ./app/docker/requirements.txt` копирует dependency list.
- `RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r app/docker/requirements.txt` устанавливает runtime packages.
- `COPY main.py ./main.py` копирует app entry point.
- `COPY VK ./VK` копирует VK services.
- `COPY app/fastapi ./app/fastapi` копирует FastAPI layer.
- `COPY app/sql_save_service.py ./app/sql_save_service.py` копирует SQL storage service, необходимый runtime-импортов.
- `EXPOSE 8000` документирует server port.
- `CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]` запускает FastAPI app.

### `app/docker/docker-compose.yml`

- описывает service `vk-connect`.
- собирает image из project root context.
- использует `app/docker/Dockerfile`.
- загружает runtime environment через compose env-file configuration.
- пробрасывает host/container port `8000:8000`.
- монтирует runtime data directory в `/app/data`, чтобы temporary storage и SQLite storage сохранялись вне image.

### `app/docker/requirements.txt`

- `fastapi`: HTTP application framework.
- `uvicorn[standard]`: ASGI server runtime.
- `httpx`: async/sync HTTP client для VK token и user info requests.
- `python-dotenv`: загрузка local environment variables классами service config.
- `filelock`: cross-process file lock для temporary JSON storage.
- `sqlalchemy`: ORM и SQLite persistence layer.






