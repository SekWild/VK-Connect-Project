from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from app.sql_save_service import (
    REFRESH_STATUS_QUEUED,
    REFRESH_STATUS_REAUTH_REQUIRED,
    SQLSaveService,
)


REFRESH_SAFETY_WINDOW_SECONDS = 600
REFRESH_HARD_DEADLINE_SECONDS = 300
REFRESH_SPACING_SECONDS = 120
QUEUE_REBUILD_INTERVAL_SECONDS = 600
REFRESH_DUE_CHECK_INTERVAL_SECONDS = 60
REFRESH_BATCH_SIZE = 20


@dataclass(frozen=True)
class RefreshPlan:
    """Безопасный план refresh для одного token row."""

    next_refresh_at: datetime
    hard_deadline_at: datetime
    is_emergency: bool


@dataclass(frozen=True)
class QueueRefreshResult:
    """Итог пересборки refresh-очереди без token values."""

    planned_count: int
    emergency_count: int
    skipped_count: int
    message: str


class QueueRefreshService:
    """Планировщик refresh-очереди для VK token data."""

    def __init__(self, sql_storage: SQLSaveService | None = None) -> None:
        self.sql_storage = sql_storage or SQLSaveService()

    def rebuild_refresh_queue(self) -> QueueRefreshResult:
        """Пересчитывает next_refresh_at для активных VK token rows."""
        now = datetime.now(UTC)
        previous_planned_refresh_at: datetime | None = None
        planned_count = 0
        emergency_count = 0
        skipped_count = 0

        token_rows = self.sql_storage.get_active_tokens_for_refresh_planning()
        token_rows.sort(key=self._sort_key)

        for token_row in token_rows:
            token_id = int(token_row["token_id"])
            expires_at = token_row.get("expires_at")

            if not isinstance(expires_at, datetime):
                skipped_count += 1
                self.sql_storage.mark_refresh_planning_error(
                    token_id=token_id,
                    refresh_status="error",
                    safe_error="Missing expires_at for queue planning.",
                )
                continue

            if not token_row.get("refresh_token_present"):
                skipped_count += 1
                self.sql_storage.mark_refresh_planning_error(
                    token_id=token_id,
                    refresh_status=REFRESH_STATUS_REAUTH_REQUIRED,
                    safe_error="Missing refresh token for queue planning.",
                    mark_link_reauth_required=True,
                )
                continue

            plan = self.calculate_next_refresh_at(
                expires_at=expires_at,
                previous_planned_refresh_at=previous_planned_refresh_at,
                now=now,
            )
            self.sql_storage.update_refresh_plan(
                token_id=token_id,
                next_refresh_at=plan.next_refresh_at,
                refresh_status=REFRESH_STATUS_QUEUED,
            )

            planned_count += 1
            if plan.is_emergency:
                emergency_count += 1
            previous_planned_refresh_at = plan.next_refresh_at

        return QueueRefreshResult(
            planned_count=planned_count,
            emergency_count=emergency_count,
            skipped_count=skipped_count,
            message="Refresh queue rebuilt safely.",
        )

    def calculate_next_refresh_at(
        self,
        *,
        expires_at: datetime,
        previous_planned_refresh_at: datetime | None,
        now: datetime,
    ) -> RefreshPlan:
        """Рассчитывает плановый refresh slot для одного token."""
        normalized_expires_at = self._ensure_utc(expires_at)
        normalized_now = self._ensure_utc(now)

        ideal_refresh_at = normalized_expires_at - timedelta(
            seconds=REFRESH_SAFETY_WINDOW_SECONDS
        )
        hard_deadline_at = normalized_expires_at - timedelta(
            seconds=REFRESH_HARD_DEADLINE_SECONDS
        )
        planned_refresh_at = ideal_refresh_at

        if previous_planned_refresh_at is not None:
            previous_slot = self._ensure_utc(previous_planned_refresh_at)
            planned_refresh_at = max(
                planned_refresh_at,
                previous_slot + timedelta(seconds=REFRESH_SPACING_SECONDS),
            )

        planned_refresh_at = max(planned_refresh_at, normalized_now)
        is_emergency = (
            planned_refresh_at > hard_deadline_at
            or normalized_now >= hard_deadline_at
        )
        if is_emergency:
            planned_refresh_at = normalized_now

        return RefreshPlan(
            next_refresh_at=planned_refresh_at,
            hard_deadline_at=hard_deadline_at,
            is_emergency=is_emergency,
        )

    def get_due_token_ids(self, *, limit: int = REFRESH_BATCH_SIZE) -> list[int]:
        """Возвращает token IDs, которым пора выполнить refresh."""
        return self.sql_storage.get_due_refresh_token_ids(
            now=datetime.now(UTC),
            limit=limit,
        )

    @staticmethod
    def _sort_key(token_row: dict[str, object]) -> datetime:
        """Сортирует token rows по expires_at, неизвестные даты отправляет в конец."""
        expires_at = token_row.get("expires_at")
        if isinstance(expires_at, datetime):
            return QueueRefreshService._ensure_utc(expires_at)
        return datetime.max.replace(tzinfo=UTC)

    @staticmethod
    def _ensure_utc(value: datetime) -> datetime:
        """Приводит datetime к UTC-aware виду."""
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
