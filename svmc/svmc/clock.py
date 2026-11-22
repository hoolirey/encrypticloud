"""Controllable virtual clock for deterministic expiry and replay."""

from __future__ import annotations

import datetime


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class VirtualClock:
    def __init__(self, start: datetime.datetime | None = None):
        self._now = start if start is not None else utcnow()

    def now(self) -> datetime.datetime:
        return self._now

    def set(self, moment: datetime.datetime) -> None:
        if moment.tzinfo is None:
            raise ValueError("moment must be timezone-aware")
        self._now = moment

    def advance(self, seconds: float) -> None:
        self._now = self._now + datetime.timedelta(seconds=seconds)
