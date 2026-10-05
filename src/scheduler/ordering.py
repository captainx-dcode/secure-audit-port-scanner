"""
Port ordering and adaptive timeout calibration.

The "searching" half of the scheduler module, per
docs/sdlc/03-algorithm-design.md §3a. The other half -- probe budgeting via
0/1 knapsack DP -- lives in src/scheduler/budget.py.

Two separate, composable decisions:
  1. order_ports: WHICH ports to try first (static priority list, common
     ports before the long tail, with the remainder randomized rather than
     scanned sequentially -- sequential 1,2,3... scanning is a textbook
     IDS signature, per the footprint-reduction discussion in
     docs/sdlc/02-problem-analysis.md).
  2. calibrate_timeout: HOW LONG to wait per probe on a given host, found
     via binary search between a fast and a safe bound rather than a
     single hardcoded timeout -- adapts to the actual lab/target network
     latency instead of guessing.
"""

from __future__ import annotations

import random
from typing import Awaitable, Callable, Iterable, Sequence


def order_ports(
    port_range: Iterable[int],
    priority_ports: Sequence[int],
    *,
    rng: random.Random | None = None,
) -> list[int]:
    """
    Return `port_range` as a list with `priority_ports` first (in the
    order given), followed by every other port in `port_range` in
    randomized order.

    Priority ports not present in `port_range` are skipped silently --
    this function orders what it's given, it doesn't expand the range.
    Duplicate ports in `port_range` are preserved as given (not
    deduplicated here; callers that care should dedupe before calling).

    `rng` is injectable so tests can assert on a reproducible order;
    production callers should leave it as None (a fresh, unseeded
    random.Random()).
    """
    # random (not `secrets`) is correct here: this shuffle exists only to
    # avoid a sequential 1,2,3... scan pattern being an easy IDS signature,
    # not to defeat an adversary who can observe and predict the PRNG
    # state. No cryptographic unpredictability is required.
    rng = rng or random.Random()  # nosec B311

    port_range = list(port_range)
    range_set = set(port_range)

    ordered_priority = [p for p in priority_ports if p in range_set]
    priority_set = set(ordered_priority)

    remainder = [p for p in port_range if p not in priority_set]
    rng.shuffle(remainder)

    return ordered_priority + remainder


async def calibrate_timeout(
    probe_fn: Callable[[float], Awaitable[float]],
    *,
    low: float,
    high: float,
    acceptable_success_rate: float = 0.8,
    precision: float = 0.05,
) -> float:
    """
    Binary-search between `low` and `high` seconds for a timeout that
    achieves at least `acceptable_success_rate` on a calibration sample,
    per docs/sdlc/03-algorithm-design.md §3a.

    `probe_fn(timeout) -> success_rate` is the caller's calibration probe
    (e.g. "connect to a handful of sample ports on this host at this
    timeout, return the fraction that succeeded"). This module has no
    socket code of its own -- it's deliberately decoupled from the
    scanner so it can be unit-tested with a fake probe_fn, and reused
    later against whatever the real scanner module (src/scanner/)
    provides.

    Converges toward `low` if the target responds quickly and reliably
    (fast timeout is enough), or toward `high` if it doesn't (fall back
    to the safe/slow bound) -- `high` is also what's returned immediately
    if `low` itself already meets the threshold, since the loop only
    narrows `high` downward in that case and never explores below `low`.
    """
    if low <= 0:
        raise ValueError(f"low must be > 0, got {low}")
    if high <= low:
        raise ValueError(f"high ({high}) must be greater than low ({low})")
    if not 0 < acceptable_success_rate <= 1:
        raise ValueError("acceptable_success_rate must be in (0, 1]")

    while high - low > precision:
        mid = (low + high) / 2
        success_rate = await probe_fn(mid)
        if success_rate >= acceptable_success_rate:
            high = mid
        else:
            low = mid

    return high
