"""
Host discovery (liveness check).

Confirms a target responds at all before the probe plan spends time and
connections on individual ports. Runs after the scope gate and before the
scheduler, per docs/sdlc/03-algorithm-design.md module 2.

DESIGN DECISION -- TCP-based liveness, not ICMP:

ICMP echo (ping) needs raw sockets, which needs root/admin privilege on
most OSes. That conflicts with Step 1's constraint that the default scan
profile require no elevated privilege. So this module reuses the same
`socket`/asyncio connect approach as the scanner itself: attempt a TCP
connection to a small set of commonly-responsive ports, and treat ANY
response -- a successful connect, or an actively refused connection (RST)
-- as "the host is up." Both outcomes mean something at that address
answered; only a timeout (no response at all) is treated as unreachable.

KNOWN LIMITATION, stated explicitly rather than left implicit: a host that
is up but has every probed port filtered by a firewall will look identical
to a host that is actually down -- both just time out. This is a real
false-negative source. ICMP would resolve some of these cases but at the
cost of the no-root constraint, so it's accepted for v1. A future
`--profile stealth` raw-socket mode (see docs/sdlc/02-problem-analysis.md,
scan profiles) could add ICMP as an option behind an explicit privilege
check, but that is out of scope here.

Threat model note: this module makes outbound connections to targets that
already passed the scope gate, so it inherits the scope gate's
authorization guarantee -- it does not perform its own scope check. It
also inherits the untrusted-input caution from docs/sdlc/04-threat-model.md
§5.3: a target's response here is only ever used as a boolean (responded /
did not respond), never parsed or stored as content, so there is no
banner-grabbing-style attack surface in this module.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Literal, Sequence

if TYPE_CHECKING:
    from evidence.audit import AuditLog


# A handful of ports likely to get *some* response (open or actively
# refused) on a typical host. This is a reasonable default for a
# standalone call; when wired into the orchestrator, this should be
# sourced from config/scan-profile.yaml rather than hardcoded here --
# noted as a TODO at the orchestrator level, consistent with how the
# evidence module left CVE/signature-DB hashing as orchestrator wiring.
DEFAULT_PROBE_PORTS: tuple[int, ...] = (80, 443, 22, 445, 139)

ConnectResult = Literal["responded", "no_response"]


async def _attempt_connect(host: str, port: int, timeout: float) -> ConnectResult:
    """
    Attempt one TCP connection to (host, port).

    Returns "responded" if the connection succeeded OR was actively
    refused (both mean something answered at that address). Returns
    "no_response" on timeout or any other connection-level OSError
    (includes DNS resolution failures, network unreachable, etc. -- all
    collapsed into "no response" since none of them indicate liveness).

    Isolated as its own function (rather than inlined into
    check_host_alive) specifically so tests can monkeypatch it without
    needing a real network or a real listening socket.
    """
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except ConnectionRefusedError:
        return "responded"
    except (TimeoutError, OSError):
        return "no_response"

    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass  # best-effort close; the liveness result is already determined
    return "responded"


async def check_host_alive(
    host: str, probe_ports: Sequence[int], timeout: float
) -> bool:
    """
    True if `host` responds (success or refusal) on any of `probe_ports`.
    Stops at the first response -- no need to try every port once liveness
    is established.
    """
    for port in probe_ports:
        result = await _attempt_connect(host, port, timeout)
        if result == "responded":
            return True
    return False


async def discover_live_hosts(
    targets: list[str],
    audit_log: "AuditLog",
    *,
    probe_ports: Sequence[int] = DEFAULT_PROBE_PORTS,
    timeout: float = 1.0,
    max_concurrency: int = 50,
) -> list[str]:
    """
    Check liveness for every target, logging HOST_LIVE or HOST_UNREACHABLE
    for each through `audit_log`, and return only the live ones.

    Input is deduplicated (preserving first-seen order) before checking --
    defensive, since this function has no way to know whether its caller
    already deduplicated, and probing (or logging) the same host twice
    wastes budget and clutters the audit trail for no benefit.

    Concurrency is bounded by `max_concurrency` via a semaphore, same
    pattern the scanner module will use -- consistent with the asyncio
    strategy in docs/sdlc/02-problem-analysis.md §1.
    """
    seen: set[str] = set()
    unique_targets: list[str] = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)

    semaphore = asyncio.Semaphore(max_concurrency)

    async def _bounded_check(target: str) -> bool:
        async with semaphore:
            return await check_host_alive(target, probe_ports, timeout)

    results = await asyncio.gather(*[_bounded_check(t) for t in unique_targets])

    live: list[str] = []
    for target, alive in zip(unique_targets, results):
        if alive:
            live.append(target)
            audit_log.record("HOST_LIVE", target=target)
        else:
            audit_log.record("HOST_UNREACHABLE", target=target)

    return live
