# SVMC v0

Pure-Python local simulator of virtual nodes with a policy gate and an
append-only audit chain. Every "hardware" part is a data structure plus a
state machine; nothing here pretends to be real hardware.

## Parts

| Module | Part |
|---|---|
| `svmc.hardware` | Virtual CPU and memory with enforced usage limits |
| `svmc.disk` | Virtual encrypted disk (mandatory Fernet encryption) |
| `svmc.identity` | Virtual TPM: identity keys, PCR measurements, attestation |
| `svmc.network` | Isolated virtual network: every operation raises |
| `svmc.clock` | Controllable virtual clock for expiry/replay |
| `svmc.snapshot` | Snapshot/restore of node state |
| `svmc.audit` | Append-only, hash-chained SQLite audit record |
| `svmc.advisor` | AI configuration advisor: proposes configs only |
| `svmc.policy` | Policy gate: limits + explicit approval before creation |
| `svmc.node` | Node lifecycle composing all of the above |
| `svmc.boxmatrix` | 4D boxed matrix: verifiable `w = x*y*z`, SI grid, geo overlay, pull recordance |

## Guarantees enforced in code

- Node construction requires an `ApprovalToken`; direct token construction
  raises, and only `PolicyGate` mints tokens. This is a guard against
  accidental bypass, not a security boundary: deliberate Python code can
  reach into `svmc.approval._ISSUER`.
- Disk contents are always ciphertext at rest. `destroy()` overwrites and
  removes node storage — best-effort deletion, not a security guarantee
  (no protection against COW/journaling filesystems, OS caches, or backups).
- TPM key material is never exported; snapshots carry only PCR/generation
  state. `destroy()` clears the in-process reference; CPython memory
  zeroization is best-effort and cannot guarantee secure erasure.
- The audit chain detects any row tampering via `verify_chain()`.
- The network module contains no socket code path.

This package is a simulation for testing configuration policy and
lifecycle semantics — treat it as a simulator, not a security boundary.

## 4D BoxedMatrix

`svmc.boxmatrix.BoxedMatrix4D` is a boxed 4D location grid: three axes span
the SI-metric interior cubic dimensions, and the fourth coordinate is fully
determined by the other three.

```python
from svmc.boxmatrix import BoxedMatrix4D

box = BoxedMatrix4D(
    length_m=5.0,
    width_m=4.0,
    height_m=3.0,
    cell_size_m=1.0,
    geo_anchor=(39.7392, -104.9903),
)
box.label(box.far_index())   # far corner depends on the cubic dimensions
```

- Coordinates are `(x, y, z, w)` with the invariant `w == x*y*z`, re-validated
  on every `put`, `pull`, `clear_cell`, and `geo_bounds` call; a violation
  raises `MatrixIndexError`, so a wrong fourth coordinate can never be stored.
- Per-axis labels run `A0`-`Z9` (`axis_label`, wrapping every 260 slots);
  the origin is `A0,A0,A0,A0` and `far_index()` / `far_label()` give the
  far corner derived from the cubic dimensions. `extents` and
  `cell_volume_m3()` expose the grid in SI metres.
- With `geo_anchor=(lat, lon)`, `geo_bounds(index)` maps x to north, y to
  east, and z to the vertical layer, returning the south-west floor and
  north-east ceiling corners as `((lat, lon, bottom_m), (lat, lon, top_m))`.
  The metre-to-degree conversion is an approximation and documented as such;
  no I/O is performed.
- Every `put`, `pull`, and `clear_cell` is appended to a hash-chained,
  in-memory recordance (`sha256` over previous hash, operation, index, and
  value). `verify()` re-walks the chain and raises `RecordanceError` on
  tampering; `recordance()` returns a copy. Pass `recording=False` to
  disable.

## Usage

```python
from pathlib import Path
import tempfile
from svmc import (
    AuditRecorder, ConfigurationAdvisor, PolicyGate, PolicyLimits, VirtualClock,
)

base = Path(tempfile.mkdtemp())
clock = VirtualClock()
audit = AuditRecorder(str(base / "audit.db"))
gate = PolicyGate(PolicyLimits(), audit, clock, base)
advisor = ConfigurationAdvisor(PolicyLimits())

request = gate.submit(advisor.propose("inference", valid_for_seconds=600), "advisor")
node = gate.approve(request, approver="ops")
node.disk.write_file("synthetic.bin", "synthetic-data-only")
```

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

The `cryptography` package is a mandatory dependency (`pip install .`);
disk encryption is always Fernet and there is no fallback cipher.
