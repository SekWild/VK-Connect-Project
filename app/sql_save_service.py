from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
    or_,
    select,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "vk_storage.db"
PROVIDER = "vk"
STATUS_ACTIVE = "active"
STATUS_REAUTH_REQUIRED = "reauth_required"
REFRESH_STATUS_IDLE = "idle"
REFRESH_STATUS_QUEUED = "queued"
REFRESH_STATUS_REFRESHING = "refreshing"
REFRESH_STATUS_ERROR = "error"
REFRESH_STATUS_REAUTH_REQUIRED = "reauth_required"
REFRESH_SAFETY_WINDOW_SECONDS = 600
REFRESH_SUITABLE_STATUSES = (
    REFRESH_STATUS_QUEUED,
    REFRESH_STATUS_IDLE,
    REFRESH_STATUS_ERROR,
)
_schema_init_lock = threading.Lock()
_schema_initialized_paths: set[Path] = set()


def _utc_now() -> datetime:
    """Возвращает текущее UTC-время."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Базовый класс SQLAlchemy ORM-моделей."""


class VKAccountLink(Base):
    """Локальная связь внутреннего пользователя с VK-аккаунтом."""

    __tablename__ = "vk_account_links"
    __table_args__ = (
        Index("ix_vk_account_links_state", "state", unique=True),
        Index("ix_vk_account_links_vk_user_id", "vk_user_id"),
        Index("ix_vk_account_links_user_id", "user_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    provider: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=PROVIDER,
    )
    vk_user_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=STATUS_ACTIVE,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )

    token_data: Mapped["VKTokenData | None"] = relationship(
        back_populates="link",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )


class VKTokenData(Base):
    """Постоянные VK token data, связанные с account link."""

    __tablename__ = "vk_token_data"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    link_id: Mapped[int] = mapped_column(
        ForeignKey("vk_account_links.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    access_token: Mapped[str] = mapped_column(Text, nullable=False)
    refresh_token: Mapped[str] = mapped_column(Text, nullable=False, default="")
    token_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    expires_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="")
    id_token: Mapped[str] = mapped_column(Text, nullable=False, default="")
    device_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utc_now,
        onupdate=_utc_now,
    )
    next_refresh_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_refresh_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    refresh_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=REFRESH_STATUS_IDLE,
    )
    refresh_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    refresh_lock_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_refresh_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    link: Mapped[VKAccountLink] = relationship(back_populates="token_data")


class SQLSaveService:
    """Сервис постоянного хранения VK links и token data в SQLite."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = self._resolve_db_path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = self._create_engine(self.db_path)
        self.session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
        )
        self.init_db()

    @staticmethod
    def _resolve_db_path(db_path: str | Path | None) -> Path:
        """Возвращает абсолютный путь к SQLite database."""
        if db_path is None:
            return DEFAULT_DB_PATH.resolve()

        path = Path(db_path)
        if path.is_absolute():
            return path
        return (PROJECT_ROOT / path).resolve()

    @staticmethod
    def _create_engine(db_path: Path) -> Engine:
        """Создает SQLite engine и включает foreign keys."""
        engine = create_engine(
            f"sqlite:///{db_path.as_posix()}",
            future=True,
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(engine, "connect")
        def _enable_sqlite_foreign_keys(
            dbapi_connection: Any,
            connection_record: Any,
        ) -> None:
            del connection_record
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        return engine

    def init_db(self) -> None:
        """Создает SQL tables, если они еще не существуют."""
        db_path = self.db_path
        if db_path in _schema_initialized_paths:
            return

        with _schema_init_lock:
            if db_path in _schema_initialized_paths:
                return

            Base.metadata.create_all(self.engine, checkfirst=True)
            self._ensure_refresh_columns()
            _schema_initialized_paths.add(db_path)

    def _ensure_refresh_columns(self) -> None:
        """Добавляет недостающие refresh-колонки без пересоздания таблицы."""
        required_columns = {
            "device_id": "TEXT",
            "next_refresh_at": "DATETIME",
            "last_refresh_at": "DATETIME",
            "refresh_status": "VARCHAR(32) NOT NULL DEFAULT 'idle'",
            "refresh_attempts": "INTEGER NOT NULL DEFAULT 0",
            "refresh_lock_until": "DATETIME",
            "last_refresh_error": "TEXT",
        }

        with self.engine.begin() as connection:
            existing_columns = {
                row[1]
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info(vk_token_data)"
                )
            }

            for column_name, column_definition in required_columns.items():
                if column_name in existing_columns:
                    continue
                connection.exec_driver_sql(
                    f"ALTER TABLE vk_token_data "
                    f"ADD COLUMN {column_name} {column_definition}"
                )

    def save_vk_token_data(
        self,
        *,
        state: str,
        provider: str,
        vk_user_id: str,
        user_id: str,
        access_token: str,
        refresh_token: str,
        token_type: str,
        expires_in: int | None,
        expires_at: str,
        scope: str,
        id_token: str,
        device_id: str = "",
        status: str = STATUS_ACTIVE,
    ) -> None:
        """Создает или обновляет VK account link и его token data."""
        normalized_state = state.strip()
        normalized_provider = provider.strip().lower() or PROVIDER
        if not normalized_state:
            raise ValueError("State не может быть пустым при сохранении token data.")
        if normalized_provider != PROVIDER:
            raise ValueError("SQLSaveService поддерживает только provider=vk.")
        if not access_token:
            raise ValueError("Access token не может быть пустым при сохранении.")

        self.init_db()
        now = _utc_now()
        normalized_device_id = device_id.strip()

        with self.session_factory.begin() as session:
            link = self._find_existing_link(
                session=session,
                state=normalized_state,
                provider=PROVIDER,
                user_id=user_id.strip(),
                vk_user_id=vk_user_id.strip(),
            )

            if link is None:
                link = VKAccountLink(
                    user_id=user_id.strip() or None,
                    provider=PROVIDER,
                    vk_user_id=vk_user_id.strip() or None,
                    state=normalized_state,
                    status=status or STATUS_ACTIVE,
                    created_at=now,
                )
                session.add(link)
                session.flush()
            else:
                link.provider = PROVIDER
                link.state = normalized_state
                link.status = status or STATUS_ACTIVE
                if user_id.strip():
                    link.user_id = user_id.strip()
                if vk_user_id.strip():
                    link.vk_user_id = vk_user_id.strip()

            token_row = session.scalar(
                select(VKTokenData).where(VKTokenData.link_id == link.id)
            )
            parsed_expires_at = self._parse_optional_datetime(expires_at)
            next_refresh_at = self._calculate_next_refresh_at(parsed_expires_at)

            if token_row is None:
                token_row = VKTokenData(
                    link_id=link.id,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    token_type=token_type,
                    expires_in=expires_in,
                    expires_at=parsed_expires_at,
                    scope=scope,
                    id_token=id_token,
                    device_id=normalized_device_id or None,
                    created_at=now,
                    updated_at=now,
                    next_refresh_at=next_refresh_at,
                    last_refresh_at=None,
                    refresh_status=REFRESH_STATUS_IDLE,
                    refresh_attempts=0,
                    refresh_lock_until=None,
                    last_refresh_error=None,
                )
                session.add(token_row)
            else:
                token_row.access_token = access_token
                token_row.refresh_token = refresh_token
                token_row.token_type = token_type
                token_row.expires_in = expires_in
                token_row.expires_at = parsed_expires_at
                token_row.scope = scope
                token_row.id_token = id_token
                if normalized_device_id:
                    token_row.device_id = normalized_device_id
                token_row.updated_at = now
                token_row.next_refresh_at = next_refresh_at
                token_row.refresh_status = REFRESH_STATUS_IDLE
                token_row.refresh_attempts = 0
                token_row.refresh_lock_until = None
                token_row.last_refresh_error = None

    def has_active_token_for_state(self, state: str) -> bool:
        """Проверяет наличие активного VK token для state."""
        token_data = self.get_active_token_for_state(state)
        return bool(token_data and token_data.get("access_token"))

    def get_active_token_for_state(
        self,
        state: str,
    ) -> dict[str, Any] | None:
        """Возвращает token data для внутреннего backend/dev использования."""
        normalized_state = state.strip()
        if not normalized_state:
            return None

        with self.session_factory() as session:
            link = session.scalar(
                select(VKAccountLink).where(
                    VKAccountLink.state == normalized_state,
                    VKAccountLink.provider == PROVIDER,
                    VKAccountLink.status == STATUS_ACTIVE,
                )
            )
            if link is None:
                return None

            token_row = session.scalar(
                select(VKTokenData).where(VKTokenData.link_id == link.id)
            )
            if token_row is None or not token_row.access_token:
                return None

            return {
                "state": link.state,
                "provider": link.provider,
                "status": link.status,
                "user_id": link.user_id or "",
                "vk_user_id": link.vk_user_id or "",
                "access_token": token_row.access_token,
                "refresh_token_present": bool(token_row.refresh_token),
                "device_id_present": bool(token_row.device_id),
                "expires_at": self._datetime_to_iso(token_row.expires_at),
                "updated_at": self._datetime_to_iso(token_row.updated_at),
                "scope": token_row.scope,
                "next_refresh_at": self._datetime_to_iso(
                    token_row.next_refresh_at
                ),
                "last_refresh_at": self._datetime_to_iso(
                    token_row.last_refresh_at
                ),
                "refresh_status": token_row.refresh_status,
                "refresh_attempts": token_row.refresh_attempts,
                "refresh_lock_until": self._datetime_to_iso(
                    token_row.refresh_lock_until
                ),
                "last_refresh_error": token_row.last_refresh_error or "",
            }

    def get_token_safe_status_by_state(self, state: str) -> dict[str, Any]:
        """Возвращает безопасный статус link/token без token values."""
        normalized_state = state.strip()
        if not normalized_state:
            return self._empty_safe_status()

        with self.session_factory() as session:
            link = session.scalar(
                select(VKAccountLink).where(
                    VKAccountLink.state == normalized_state,
                    VKAccountLink.provider == PROVIDER,
                )
            )
            if link is None:
                return self._empty_safe_status()

            token_row = session.scalar(
                select(VKTokenData).where(VKTokenData.link_id == link.id)
            )
            return {
                "exists": token_row is not None,
                "active_token_saved": bool(
                    token_row
                    and token_row.access_token
                    and link.status == STATUS_ACTIVE
                ),
                "refresh_token_present": bool(
                    token_row and token_row.refresh_token
                ),
                "device_id_present": bool(token_row and token_row.device_id),
                "expires_at": (
                    self._datetime_to_iso(token_row.expires_at)
                    if token_row
                    else ""
                ),
                "updated_at": (
                    self._datetime_to_iso(token_row.updated_at)
                    if token_row
                    else ""
                ),
                "next_refresh_at": (
                    self._datetime_to_iso(token_row.next_refresh_at)
                    if token_row
                    else ""
                ),
                "last_refresh_at": (
                    self._datetime_to_iso(token_row.last_refresh_at)
                    if token_row
                    else ""
                ),
                "refresh_status": token_row.refresh_status if token_row else "",
                "refresh_attempts": token_row.refresh_attempts if token_row else 0,
                "refresh_lock_until": (
                    self._datetime_to_iso(token_row.refresh_lock_until)
                    if token_row
                    else ""
                ),
                "last_refresh_error": (
                    (token_row.last_refresh_error or "")
                    if token_row
                    else ""
                ),
                "vk_user_id": link.vk_user_id or "",
                "scope": token_row.scope if token_row else "",
                "status": link.status,
            }

    def schedule_refresh_now_by_state(self, state: str) -> bool:
        """Ставит активный token row в refresh queue без раскрытия token values."""
        normalized_state = state.strip()
        if not normalized_state:
            return False

        with self.session_factory.begin() as session:
            row = session.execute(
                select(VKTokenData, VKAccountLink)
                .join(VKAccountLink, VKTokenData.link_id == VKAccountLink.id)
                .where(
                    VKAccountLink.state == normalized_state,
                    VKAccountLink.provider == PROVIDER,
                    VKAccountLink.status == STATUS_ACTIVE,
                )
            ).first()
            if row is None:
                return False

            token_row, _link = row
            if not token_row.access_token:
                return False

            token_row.next_refresh_at = _utc_now()
            token_row.refresh_status = REFRESH_STATUS_QUEUED
            token_row.refresh_lock_until = None
            token_row.last_refresh_error = None
            return True

    def get_active_tokens_for_refresh_planning(self) -> list[dict[str, Any]]:
        """Возвращает безопасные token metadata для построения refresh-очереди."""
        with self.session_factory() as session:
            rows = session.execute(
                select(VKTokenData, VKAccountLink)
                .join(VKAccountLink, VKTokenData.link_id == VKAccountLink.id)
                .where(
                    VKAccountLink.provider == PROVIDER,
                    VKAccountLink.status == STATUS_ACTIVE,
                )
                .order_by(VKTokenData.expires_at.asc())
            ).all()

            return [
                {
                    "token_id": token_row.id,
                    "link_id": link.id,
                    "expires_at": self._normalize_datetime(
                        token_row.expires_at
                    ),
                    "refresh_token_present": bool(token_row.refresh_token),
                    "refresh_status": token_row.refresh_status,
                    "link_status": link.status,
                }
                for token_row, link in rows
            ]

    def update_refresh_plan(
        self,
        *,
        token_id: int,
        next_refresh_at: datetime,
        refresh_status: str = REFRESH_STATUS_QUEUED,
    ) -> None:
        """Сохраняет безопасный refresh plan для token row."""
        with self.session_factory.begin() as session:
            token_row = session.get(VKTokenData, token_id)
            if token_row is None:
                return

            token_row.next_refresh_at = self._normalize_datetime(next_refresh_at)
            token_row.refresh_status = refresh_status
            token_row.last_refresh_error = None
            token_row.updated_at = _utc_now()

    def mark_refresh_planning_error(
        self,
        *,
        token_id: int,
        refresh_status: str,
        safe_error: str,
        mark_link_reauth_required: bool = False,
    ) -> None:
        """Сохраняет безопасную ошибку планирования refresh без token values."""
        with self.session_factory.begin() as session:
            token_row = session.get(VKTokenData, token_id)
            if token_row is None:
                return

            token_row.refresh_status = refresh_status
            token_row.last_refresh_error = self._safe_error_text(safe_error)
            token_row.updated_at = _utc_now()

            if mark_link_reauth_required:
                link = session.get(VKAccountLink, token_row.link_id)
                if link is not None:
                    link.status = STATUS_REAUTH_REQUIRED

    def get_due_refresh_token_ids(
        self,
        *,
        now: datetime,
        limit: int,
    ) -> list[int]:
        """Возвращает token IDs, которым пора выполнить refresh."""
        normalized_now = self._normalize_datetime(now) or _utc_now()
        with self.session_factory() as session:
            rows = session.scalars(
                select(VKTokenData.id)
                .join(VKAccountLink, VKTokenData.link_id == VKAccountLink.id)
                .where(
                    VKAccountLink.provider == PROVIDER,
                    VKAccountLink.status == STATUS_ACTIVE,
                    VKTokenData.next_refresh_at.is_not(None),
                    VKTokenData.next_refresh_at <= normalized_now,
                    VKTokenData.refresh_status.in_(REFRESH_SUITABLE_STATUSES),
                    or_(
                        VKTokenData.refresh_lock_until.is_(None),
                        VKTokenData.refresh_lock_until <= normalized_now,
                    ),
                )
                .order_by(VKTokenData.next_refresh_at.asc())
                .limit(limit)
            ).all()
            return list(rows)

    def acquire_refresh_lock(
        self,
        *,
        token_id: int,
        lock_until: datetime,
    ) -> bool:
        """Захватывает refresh lock, если token row не заблокирован другим worker."""
        now = _utc_now()
        normalized_lock_until = self._normalize_datetime(lock_until) or now

        with self.session_factory.begin() as session:
            row = session.execute(
                select(VKTokenData, VKAccountLink)
                .join(VKAccountLink, VKTokenData.link_id == VKAccountLink.id)
                .where(VKTokenData.id == token_id)
            ).first()
            if row is None:
                return False

            token_row, link = row
            current_lock_until = self._normalize_datetime(
                token_row.refresh_lock_until
            )
            if link.status != STATUS_ACTIVE:
                return False
            if token_row.refresh_status == REFRESH_STATUS_REAUTH_REQUIRED:
                return False
            if current_lock_until is not None and current_lock_until > now:
                return False

            token_row.refresh_status = REFRESH_STATUS_REFRESHING
            token_row.refresh_lock_until = normalized_lock_until
            token_row.updated_at = now
            return True

    def get_token_for_refresh_by_token_id(
        self,
        token_id: int,
    ) -> dict[str, Any] | None:
        """Возвращает token data для внутреннего refresh executor без raw SQL rows."""
        with self.session_factory() as session:
            row = session.execute(
                select(VKTokenData, VKAccountLink)
                .join(VKAccountLink, VKTokenData.link_id == VKAccountLink.id)
                .where(VKTokenData.id == token_id)
            ).first()
            if row is None:
                return None

            token_row, link = row
            return {
                "token_id": token_row.id,
                "link_id": link.id,
                "link_status": link.status,
                "refresh_status": token_row.refresh_status,
                "refresh_token": token_row.refresh_token,
                "device_id": token_row.device_id or "",
                "refresh_attempts": token_row.refresh_attempts,
                "scope": token_row.scope,
                "id_token": token_row.id_token,
                "token_type": token_row.token_type,
            }

    def get_token_id_by_link_id(self, link_id: int) -> int | None:
        """Возвращает token ID по link ID для refresh executor."""
        with self.session_factory() as session:
            return session.scalar(
                select(VKTokenData.id).where(VKTokenData.link_id == link_id)
            )

    def update_token_refresh_success(
        self,
        *,
        token_id: int,
        access_token: str,
        refresh_token: str,
        token_type: str,
        expires_in: int | None,
        expires_at: datetime | None,
        scope: str,
        id_token: str,
    ) -> None:
        """Сохраняет результат успешного refresh без вывода token values."""
        now = _utc_now()
        normalized_expires_at = self._normalize_datetime(expires_at)
        next_refresh_at = self._calculate_next_refresh_at(normalized_expires_at)

        with self.session_factory.begin() as session:
            token_row = session.get(VKTokenData, token_id)
            if token_row is None:
                return

            link = session.get(VKAccountLink, token_row.link_id)
            if link is not None:
                link.status = STATUS_ACTIVE

            token_row.access_token = access_token
            if refresh_token:
                token_row.refresh_token = refresh_token
            if token_type:
                token_row.token_type = token_type
            token_row.expires_in = expires_in
            token_row.expires_at = normalized_expires_at
            if scope:
                token_row.scope = scope
            if id_token:
                token_row.id_token = id_token
            token_row.updated_at = now
            token_row.last_refresh_at = now
            token_row.next_refresh_at = next_refresh_at
            token_row.refresh_status = REFRESH_STATUS_IDLE
            token_row.refresh_attempts = 0
            token_row.refresh_lock_until = None
            token_row.last_refresh_error = None

    def update_token_refresh_failure(
        self,
        *,
        token_id: int,
        refresh_status: str,
        safe_error: str,
        next_refresh_at: datetime | None = None,
        mark_link_reauth_required: bool = False,
    ) -> None:
        """Сохраняет безопасный результат неуспешного refresh."""
        with self.session_factory.begin() as session:
            token_row = session.get(VKTokenData, token_id)
            if token_row is None:
                return

            token_row.refresh_attempts = (token_row.refresh_attempts or 0) + 1
            token_row.refresh_status = refresh_status
            token_row.refresh_lock_until = None
            token_row.last_refresh_error = self._safe_error_text(safe_error)
            token_row.next_refresh_at = self._normalize_datetime(next_refresh_at)
            token_row.updated_at = _utc_now()

            if mark_link_reauth_required:
                link = session.get(VKAccountLink, token_row.link_id)
                if link is not None:
                    link.status = STATUS_REAUTH_REQUIRED

    def mark_token_reauth_required(self, *, token_id: int, safe_error: str) -> None:
        """Помечает token/link как требующие повторной авторизации."""
        self.update_token_refresh_failure(
            token_id=token_id,
            refresh_status=REFRESH_STATUS_REAUTH_REQUIRED,
            safe_error=safe_error,
            next_refresh_at=None,
            mark_link_reauth_required=True,
        )

    @staticmethod
    def _find_existing_link(
        *,
        session: Session,
        state: str,
        provider: str,
        user_id: str,
        vk_user_id: str,
    ) -> VKAccountLink | None:
        """Ищет link по state, user_id и затем vk_user_id."""
        link = session.scalar(
            select(VKAccountLink).where(VKAccountLink.state == state)
        )
        if link is not None:
            return link

        if user_id:
            link = session.scalar(
                select(VKAccountLink).where(
                    VKAccountLink.provider == provider,
                    VKAccountLink.user_id == user_id,
                )
            )
            if link is not None:
                return link

        if vk_user_id:
            return session.scalar(
                select(VKAccountLink).where(
                    VKAccountLink.provider == provider,
                    VKAccountLink.vk_user_id == vk_user_id,
                )
            )

        return None

    @staticmethod
    def _parse_optional_datetime(value: str) -> datetime | None:
        """Преобразует ISO datetime в UTC-aware datetime."""
        if not value:
            return None

        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    @staticmethod
    def _normalize_datetime(value: datetime | None) -> datetime | None:
        """Приводит datetime к UTC-aware значению."""
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _datetime_to_iso(value: datetime | None) -> str:
        """Возвращает datetime в ISO-формате."""
        return value.isoformat() if value else ""

    @staticmethod
    def _calculate_next_refresh_at(expires_at: datetime | None) -> datetime | None:
        """Вычисляет время планового refresh до истечения token."""
        if expires_at is None:
            return None
        return expires_at - timedelta(seconds=REFRESH_SAFETY_WINDOW_SECONDS)

    @staticmethod
    def _safe_error_text(message: str, max_length: int = 500) -> str:
        """Возвращает короткий безопасный текст ошибки для SQL metadata."""
        safe_message = str(message or "Unknown refresh error.").strip()
        return safe_message[:max_length]

    @staticmethod
    def _empty_safe_status() -> dict[str, Any]:
        """Возвращает безопасный пустой token status."""
        return {
            "exists": False,
            "active_token_saved": False,
            "refresh_token_present": False,
            "device_id_present": False,
            "expires_at": "",
            "updated_at": "",
            "next_refresh_at": "",
            "last_refresh_at": "",
            "refresh_status": "",
            "refresh_attempts": 0,
            "refresh_lock_until": "",
            "last_refresh_error": "",
            "vk_user_id": "",
            "scope": "",
            "status": "",
        }
