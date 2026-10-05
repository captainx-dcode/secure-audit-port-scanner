"""
Socket connect scanner.

The `connect` ScanProfile: a full TCP three-way handshake via plain
`socket`/`asyncio`, mirroring nmap's `-sT`. No elevated privilege required,
per Step 1's non-functional requirements. A future `stealth` (raw-socket
SYN) profile would need root and belongs in a separate module entirely --
not a silent fallback from here.

Design reference: docs/sdlc/03-algorithm-design.md, module 4.
Threat model reference: docs/sdlc/04-threat-model.md, §5.2 (Socket Scanner).

Three outcomes per probe, matching the pseudocode:
  - OPEN:     connection succeeded.
  - CLOSED:   actively refused (RST) -- a live host, closed port.
  - FILTERED: no response at all (timeout), or any other connection-level
              OSError (host/route unreachable, etc.) -- collapsed into one
              state since none of these distinguish "firewalled" from
              "nothing there" from this vantage point alone.

Every single probe is logged via AuditLog regardless of outcome -- this is
what lets the evidence trail prove what was actually attempted, not just
what was found.

RESOURCE HANDOFF: on an OPEN result, if `on_open` is given, the live
connection is handed to it and this module does NOT close it -- that
callback (the banner grabber, eventually) owns the connection's lifecycle
from that point on. If `on_open` is omitted, the connection is closed
immediately here, so this module is safe to use standalone (e.g. for
testing, or if only port state matters) without leaking sockets.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Awaitable, Callable, Optional

if TYPE_CHECKING:
    from evidence.audit import AuditLog


DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_JITTER_RANGE = (0.01, 0.15)  # seconds
DEFAULT_CONCURRENCY = 50


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    state: PortState
    timestamp: str


OnOpenCallback = Callable[[str, int, asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


async def scan_port(
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    jitter_range: tuple[float, float] = DEFAULT_JITTER_RANGE,
    rng: random.Random | None = None,
    on_open: Optional[OnOpenCallback] = None,
) -> PortState:
    """
    Probe a single (host, port). See module docstring for the three
    possible outcomes and the on_open resource-handoff contract.

    A small random delay (uniform within `jitter_range`) is applied before
    every connect attempt -- this is the per-probe footprint-reduction
    measure from docs/sdlc/02-problem-analysis.md (avoiding a constant-rate
    signature), independent of the port *ordering* done upstream in
    src/scheduler/ordering.py.

    `rng` is injectable for deterministic tests; production callers should
    leave it as None.
    """
    jitter_min, jitter_max = jitter_range
    if jitter_min < 0 or jitter_max < jitter_min:
        raise ValueError(f"invalid jitter_range: {jitter_range}")

    # random (not `secrets`) is correct here, same justification as
    # src/scheduler/ordering.py: this jitter exists to avoid a constant-
    # rate probing signature, not to defeat an adversary predicting PRNG
    # state.
    rng = rng or random.Random()  # nosec B311
    if jitter_max > 0:
        await asyncio.sleep(rng.uniform(jitter_min, jitter_max))

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except ConnectionRefusedError:
        return PortState.CLOSED
    except (asyncio.TimeoutError, OSError):
        return PortState.FILTERED

    if on_open is not None:
        await on_open(host, port, reader, writer)
    else:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass  # peer may have already reset; the OPEN result stands regardless

    return PortState.OPEN


async def run_scan(
    host: str,
    ordered_ports: list[int],
    audit_log: "AuditLog",
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    jitter_range: tuple[float, float] = DEFAULT_JITTER_RANGE,
    concurrency: int = DEFAULT_CONCURRENCY,
    rng: random.Random | None = None,
    on_open: Optional[OnOpenCallback] = None,
) -> list[PortResult]:
    """
    Scan every port in `ordered_ports` against `host`, bounded by
    `concurrency`, logging a PORT_PROBE audit entry for every single probe
    regardless of outcome. Returns results in the same order as
    `ordered_ports` (asyncio.gather preserves input order regardless of
    completion order), so the result list reads naturally against the
    probe plan that produced `ordered_ports`.

    `ordered_ports` is expected to already be the output of
    src/scheduler/ordering.py:order_ports -- this function does not itself
    reorder or prioritize, it scans exactly what it's given, in the order
    given (subject to concurrent completion, which does not affect the
    returned order).
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _scan_one(port: int) -> PortResult:
        async with semaphore:
            state = await scan_port(
                host,
                port,
                timeout=timeout,
                jitter_range=jitter_range,
                rng=rng,
                on_open=on_open,
            )
            audit_log.record("PORT_PROBE", host=host, port=port, state=state.value)
            return PortResult(
                host=host,
                port=port,
                state=state,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

    return list(await asyncio.gather(*(_scan_one(p) for p in ordered_ports)))
