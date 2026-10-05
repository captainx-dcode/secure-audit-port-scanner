"""
Tests for src/scheduler/ordering.py

Reference: docs/sdlc/03-algorithm-design.md §3a.

calibrate_timeout is async; consistent with tests/unit/test_discovery_liveness.py,
these call it via asyncio.run() inside plain sync test functions rather than
pulling in the pytest-asyncio plugin as a new dependency.
"""

import asyncio
import random

import pytest

from scheduler.ordering import calibrate_timeout, order_ports


# --- order_ports --------------------------------------------------------------


def test_priority_ports_come_first_in_given_order():
    result = order_ports(
        port_range=[80, 22, 443, 8080, 21],
        priority_ports=[21, 22, 80],
        rng=random.Random(0),
    )
    assert result[:3] == [21, 22, 80]


def test_remainder_contains_exactly_the_non_priority_ports():
    result = order_ports(
        port_range=[80, 22, 443, 8080, 21],
        priority_ports=[21, 22],
        rng=random.Random(0),
    )
    assert result[:2] == [21, 22]
    assert set(result[2:]) == {80, 443, 8080}
    assert len(result) == 5


def test_priority_ports_not_in_range_are_skipped():
    result = order_ports(
        port_range=[80, 443],
        priority_ports=[21, 22, 80],  # 21, 22 not in range
        rng=random.Random(0),
    )
    assert result[0] == 80
    assert set(result) == {80, 443}


def test_empty_port_range_returns_empty():
    assert order_ports([], [21, 22], rng=random.Random(0)) == []


def test_empty_priority_list_still_orders_full_range():
    result = order_ports([1, 2, 3], [], rng=random.Random(0))
    assert set(result) == {1, 2, 3}
    assert len(result) == 3


def test_remainder_order_is_shuffled_not_sequential():
    # With a large enough range, a fixed seed should NOT reproduce the
    # original ascending order -- confirms shuffle is actually applied,
    # not a no-op.
    port_range = list(range(1, 51))
    result = order_ports(port_range, [], rng=random.Random(42))
    assert result != port_range


def test_same_seed_is_reproducible():
    port_range = list(range(1, 51))
    result_a = order_ports(port_range, [21, 22], rng=random.Random(7))
    result_b = order_ports(port_range, [21, 22], rng=random.Random(7))
    assert result_a == result_b


# --- calibrate_timeout ----------------------------------------------------


def test_calibrate_timeout_converges_toward_low_when_fast_succeeds():
    # Any timeout >= 0.2s succeeds; should converge near the low bound.
    async def probe_fn(timeout: float) -> float:
        return 1.0 if timeout >= 0.2 else 0.0

    result = asyncio.run(
        calibrate_timeout(
            probe_fn, low=0.1, high=5.0, acceptable_success_rate=0.8, precision=0.05
        )
    )
    assert 0.1 <= result < 0.5


def test_calibrate_timeout_converges_toward_high_when_always_unreliable():
    async def probe_fn(timeout: float) -> float:
        return 0.1  # never meets the acceptable rate, regardless of timeout

    result = asyncio.run(
        calibrate_timeout(
            probe_fn, low=0.1, high=5.0, acceptable_success_rate=0.8, precision=0.05
        )
    )
    assert result >= 5.0 - 0.1  # ends up at (or just under) the high bound


def test_calibrate_timeout_returns_near_low_when_low_already_sufficient():
    async def probe_fn(timeout: float) -> float:
        return 1.0  # always succeeds, even at the low bound

    result = asyncio.run(
        calibrate_timeout(
            probe_fn, low=0.1, high=5.0, acceptable_success_rate=0.8, precision=0.5
        )
    )
    # loop only narrows `high` downward in this case -- result should be
    # close to `low`, not stuck at `high`.
    assert result < 1.0


def test_calibrate_timeout_respects_precision_bound():
    call_count = 0

    async def probe_fn(timeout: float) -> float:
        nonlocal call_count
        call_count += 1
        return 1.0 if timeout >= 1.0 else 0.0

    asyncio.run(calibrate_timeout(probe_fn, low=0.0001, high=10.0, precision=0.01))
    # log2((10 - 0.0001) / 0.01) =~ 10 iterations -- a loose upper bound
    # confirms this terminates promptly rather than looping excessively.
    assert call_count < 20


def test_calibrate_timeout_rejects_non_positive_low():
    async def probe_fn(timeout: float) -> float:
        return 1.0

    with pytest.raises(ValueError, match="low must be"):
        asyncio.run(calibrate_timeout(probe_fn, low=0, high=5.0))


def test_calibrate_timeout_rejects_high_not_greater_than_low():
    async def probe_fn(timeout: float) -> float:
        return 1.0

    with pytest.raises(ValueError, match="high"):
        asyncio.run(calibrate_timeout(probe_fn, low=5.0, high=5.0))


def test_calibrate_timeout_rejects_invalid_success_rate():
    async def probe_fn(timeout: float) -> float:
        return 1.0

    with pytest.raises(ValueError, match="acceptable_success_rate"):
        asyncio.run(
            calibrate_timeout(probe_fn, low=0.1, high=5.0, acceptable_success_rate=1.5)
        )
