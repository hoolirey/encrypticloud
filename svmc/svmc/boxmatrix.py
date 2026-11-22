"""4D BoxedMatrix: verifiable (x, y, z, w) grid with w = x*y*z.

The matrix models an SI-metric interior volume: side lengths in metres are
divided into boxes of configurable edge length (variable box size), giving
integer extents nx, ny, nz. Each addressable cell is a tuple
(x, y, z, w) where w is derived: w = x * y * z. Every put() and pull()
validates the relation and the bounds, so an invented address is never
accepted.

Location labels map each axis index to an "A0" style label (letter for the
decade, digit for the remainder), so the origin is "A0,A0,A0,A0" and the far
corner depends on the interior cubic dimensions.

The geographic overlay maps box columns to latitude/longitude bounds around
a configurable anchor (approximate metre-to-degree conversion, pure math,
no I/O).

Pull recordance: every operation is appended to a hash-chained in-memory
record; ``verify()`` re-computes the chain and raises ``RecordanceError`` on
any tampering. This is a data-integrity record, not a security boundary.
"""

from __future__ import annotations

import ast
import hashlib
import math
from typing import Any

from svmc.exceptions import SvmcError

LAT_METRES_PER_DEGREE = 111_320.0


class MatrixIndexError(SvmcError):
    """A box index violates the w = x*y*z relation or falls outside bounds."""


class RecordanceError(SvmcError):
    """The pull-recordance chain failed verification."""


def axis_label(i: int) -> str:
    if i < 0:
        raise MatrixIndexError("axis index must be non-negative")
    return f"{chr(ord('A') + (i // 10) % 26)}{i % 10}"


def label_to_axis(label: str) -> int:
    if len(label) < 2 or not label[0].isalpha() or not label[1:].isdigit():
        raise MatrixIndexError(f"invalid axis label {label!r}")
    decade = (ord(label[0].upper()) - ord("A")) * 10
    return decade + int(label[1:])


class BoxedMatrix4D:
    GENESIS_HASH = "0" * 64

    def __init__(
        self,
        length_m: float,
        width_m: float,
        height_m: float,
        cell_size_m: float = 1.0,
        geo_anchor: tuple[float, float] | None = None,
        recording: bool = True,
    ):
        for name, value in (
            ("length_m", length_m),
            ("width_m", width_m),
            ("height_m", height_m),
            ("cell_size_m", cell_size_m),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a number")
            if not math.isfinite(float(value)) or float(value) <= 0:
                raise ValueError(f"{name} must be a positive finite number")
        if float(cell_size_m) > min(float(length_m), float(width_m), float(height_m)):
            raise ValueError("cell_size_m cannot exceed any interior dimension")
        self.length_m = float(length_m)
        self.width_m = float(width_m)
        self.height_m = float(height_m)
        self.cell_size_m = float(cell_size_m)
        self.nx = int(self.length_m // self.cell_size_m)
        self.ny = int(self.width_m // self.cell_size_m)
        self.nz = int(self.height_m // self.cell_size_m)
        self.max_w = (max(self.nx, 1) - 1) * (max(self.ny, 1) - 1) * (max(self.nz, 1) - 1)
        self.geo_anchor = (
            (float(geo_anchor[0]), float(geo_anchor[1]))
            if geo_anchor is not None
            else None
        )
        self.recording = recording
        self._cells: dict[tuple[int, int, int, int], Any] = {}
        self._record_entries: list[dict[str, str | int | None]] = []

    def _check_index(
        self, index: tuple[int, int, int, int]
    ) -> tuple[int, int, int, int]:
        if not isinstance(index, tuple) or len(index) != 4:
            raise MatrixIndexError("index must be a tuple (x, y, z, w)")
        for v in index:
            if isinstance(v, bool) or not isinstance(v, int):
                raise MatrixIndexError(f"coordinates must be integers, got {index!r}")
        x, y, z, w = index
        if not 0 <= x < self.nx:
            raise MatrixIndexError(f"x {x} out of bounds 0..{self.nx - 1}")
        if not 0 <= y < self.ny:
            raise MatrixIndexError(f"y {y} out of bounds 0..{self.ny - 1}")
        if not 0 <= z < self.nz:
            raise MatrixIndexError(f"z {z} out of bounds 0..{self.nz - 1}")
        if w != x * y * z:
            raise MatrixIndexError(
                f"w must equal x*y*z: got w={w}, expected {x * y * z}"
            )
        return index

    @staticmethod
    def label(index: tuple[int, int, int, int]) -> str:
        return ",".join(axis_label(v) for v in index)

    def far_index(self) -> tuple[int, int, int, int]:
        return (self.nx - 1, self.ny - 1, self.nz - 1, self.max_w)

    def far_label(self) -> str:
        return self.label(self.far_index())

    @property
    def extents(self) -> tuple[int, int, int]:
        return (self.nx, self.ny, self.nz)

    def cell_volume_m3(self) -> float:
        return self.cell_size_m ** 3

    def pull(self, index: tuple[int, int, int, int]) -> Any:
        self._check_index(index)
        if index not in self._cells:
            raise KeyError(index)
        value = self._cells[index]
        if self.recording:
            self._append("pull", index, value)
        return value

    def put(self, index: tuple[int, int, int, int], value: Any) -> None:
        self._check_index(index)
        self._cells[index] = value
        if self.recording:
            self._append("put", index, value)

    def count(self) -> int:
        return len(self._cells)

    def clear_cell(self, index: tuple[int, int, int, int]) -> None:
        self._check_index(index)
        self._cells.pop(index, None)
        if self.recording:
            self._append("clear", index, None)

    @staticmethod
    def _digest(
        prev_hash: str, op: str, index_repr: str, value_repr: str | None
    ) -> str:
        payload = "\x00".join((prev_hash, op, index_repr, value_repr or ""))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _append(
        self, op: str, index: tuple[int, int, int, int], value: Any
    ) -> str:
        prev_hash = (
            str(self._record_entries[-1]["hash"])
            if self._record_entries
            else self.GENESIS_HASH
        )
        index_repr = repr(index)
        value_repr = repr(value)
        digest = self._digest(prev_hash, op, index_repr, value_repr)
        self._record_entries.append(
            {
                "seq": len(self._record_entries) + 1,
                "op": op,
                "index": index_repr,
                "value": value_repr,
                "prev_hash": prev_hash,
                "hash": digest,
            }
        )
        return digest

    def verify(self) -> bool:
        prev_hash = self.GENESIS_HASH
        for entry in self._record_entries:
            seq = entry["seq"]
            if entry["prev_hash"] != prev_hash:
                raise RecordanceError(f"broken recordance chain at entry {seq}")
            index_repr = str(entry["index"])
            try:
                index = ast.literal_eval(index_repr)
            except (ValueError, SyntaxError) as exc:
                raise RecordanceError(f"corrupt index at entry {seq}") from exc
            expected = self._digest(
                prev_hash, str(entry["op"]), index_repr, str(entry["value"])
            )
            if entry["hash"] != expected:
                raise RecordanceError(f"hash mismatch at entry {seq}")
            prev_hash = str(entry["hash"])
        return True

    def recordance(self) -> list[dict[str, str | int | None]]:
        return list(self._record_entries)

    def geo_bounds(
        self, index: tuple[int, int, int, int]
    ) -> tuple[tuple[float, float], tuple[float, float]]:
        """South-west floor / north-east ceiling corners of the box column.

        x extends north, y extends east, z is the vertical layer index; the
        metre-to-degree conversion is approximate and documented as such.
        """
        self._check_index(index)
        if self.geo_anchor is None:
            raise MatrixIndexError("no geographic anchor configured")
        lat0, lon0 = self.geo_anchor
        x, y, z, _ = index
        north0 = x * self.cell_size_m / LAT_METRES_PER_DEGREE
        north1 = (x + 1) * self.cell_size_m / LAT_METRES_PER_DEGREE
        lon_scale = LAT_METRES_PER_DEGREE * max(math.cos(math.radians(lat0)), 1e-9)
        east0 = y * self.cell_size_m / lon_scale
        east1 = (y + 1) * self.cell_size_m / lon_scale
        bottom_m = z * self.cell_size_m
        top_m = (z + 1) * self.cell_size_m
        return (
            (lat0 + north0, lon0 + east0, bottom_m),
            (lat0 + north1, lon0 + east1, top_m),
        )
