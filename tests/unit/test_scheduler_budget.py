"""
Tests for src/scheduler/budget.py

Includes a brute-force cross-check against small random instances, since a
knapsack implementation that's subtly wrong (e.g. off-by-one in the DP
table) can still "look right" on hand-picked examples. If this doesn't
actually find the optimal subset, it's worse than not having a scheduler
at all -- it would silently under-deliver on the budget it claims to
respect.

Reference: docs/sdlc/03-algorithm-design.md §3b.
"""

import itertools
import random

import pytest

from scheduler.budget import ProbeUnit, schedule_probes


# --- ProbeUnit validation -----------------------------------------------------


def test_probe_unit_rejects_negative_cost():
    with pytest.raises(ValueError, match="cost"):
        ProbeUnit(id="a", cost=-1, value=5)


def test_probe_unit_rejects_negative_value():
    with pytest.raises(ValueError, match="value"):
        ProbeUnit(id="a", cost=5, value=-1)


def test_probe_unit_allows_zero_cost_and_value():
    unit = ProbeUnit(id="a", cost=0, value=0)
    assert unit.cost == 0 and unit.value == 0


# --- schedule_probes: basic behavior -----------------------------------------


def test_empty_units_returns_empty():
    selected, total = schedule_probes([], budget=100)
    assert selected == []
    assert total == 0


def test_zero_budget_still_includes_zero_cost_units():
    units = [
        ProbeUnit(id="free", cost=0, value=5),
        ProbeUnit(id="costly", cost=1, value=100),
    ]
    selected, total = schedule_probes(units, budget=0)
    assert [u.id for u in selected] == ["free"]
    assert total == 5


def test_negative_budget_raises():
    with pytest.raises(ValueError, match="budget"):
        schedule_probes([ProbeUnit(id="a", cost=1, value=1)], budget=-5)


def test_all_units_fit_selects_everything():
    units = [
        ProbeUnit(id="a", cost=2, value=3),
        ProbeUnit(id="b", cost=3, value=4),
    ]
    selected, total = schedule_probes(units, budget=10)
    assert {u.id for u in selected} == {"a", "b"}
    assert total == 7


def test_classic_knapsack_example():
    # Textbook instance with a known optimal: weights [1,3,4,5],
    # values [1,4,5,7], capacity 7 -> optimal value 9 (items with
    # weight 3+4=7, value 4+5=9), not the greedy-by-value pick.
    units = [
        ProbeUnit(id="w1", cost=1, value=1),
        ProbeUnit(id="w3", cost=3, value=4),
        ProbeUnit(id="w4", cost=4, value=5),
        ProbeUnit(id="w5", cost=5, value=7),
    ]
    selected, total = schedule_probes(units, budget=7)
    assert total == 9
    assert {u.id for u in selected} == {"w3", "w4"}


def test_result_order_matches_input_order_not_dp_table_order():
    units = [
        ProbeUnit(id="z_last", cost=5, value=10),
        ProbeUnit(id="a_first", cost=5, value=10),
    ]
    selected, _ = schedule_probes(units, budget=10)
    # both fit; result should preserve input order (z_last, a_first),
    # not alphabetical or value-sorted order
    assert [u.id for u in selected] == ["z_last", "a_first"]


def test_unit_costing_more_than_budget_is_excluded():
    units = [
        ProbeUnit(id="too_big", cost=1000, value=1000),
        ProbeUnit(id="fits", cost=1, value=1),
    ]
    selected, total = schedule_probes(units, budget=5)
    assert [u.id for u in selected] == ["fits"]
    assert total == 1


# --- schedule_probes: brute-force cross-check --------------------------------


def _brute_force_optimum(units: list[ProbeUnit], budget: int) -> int:
    best = 0
    for r in range(len(units) + 1):
        for combo in itertools.combinations(units, r):
            cost = sum(u.cost for u in combo)
            if cost <= budget:
                best = max(best, sum(u.value for u in combo))
    return best


@pytest.mark.parametrize("trial_seed", range(10))
def test_matches_brute_force_on_random_small_instances(trial_seed):
    rng = random.Random(trial_seed)
    units = [
        ProbeUnit(id=f"u{i}", cost=rng.randint(0, 10), value=rng.randint(0, 20))
        for i in range(8)
    ]
    budget = rng.randint(0, 30)

    _, dp_total = schedule_probes(units, budget)
    brute_total = _brute_force_optimum(units, budget)

    assert dp_total == brute_total


@pytest.mark.parametrize("trial_seed", range(10))
def test_selected_subset_is_itself_feasible_and_matches_claimed_total(trial_seed):
    rng = random.Random(trial_seed + 1000)
    units = [
        ProbeUnit(id=f"u{i}", cost=rng.randint(0, 10), value=rng.randint(0, 20))
        for i in range(8)
    ]
    budget = rng.randint(0, 30)

    selected, total = schedule_probes(units, budget)

    assert sum(u.cost for u in selected) <= budget
    assert sum(u.value for u in selected) == total
