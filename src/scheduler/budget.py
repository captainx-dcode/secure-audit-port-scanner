"""
Probe scheduling under a budget -- 0/1 knapsack dynamic programming.

The "dynamic programming" half of the scheduler module, per
docs/sdlc/03-algorithm-design.md §3b and the algorithm choice justified in
docs/sdlc/02-problem-analysis.md §3.3.

Each ProbeUnit represents one schedulable chunk of work (conventionally one
host x port-priority-tier group, not one individual port -- keeping units
coarse-grained is what keeps N, and therefore the DP table, small). Each
unit has a `cost` (estimated time/connections to probe it) and a `value`
(how informative it's expected to be -- e.g. higher for priority-tier ports,
or for a host flagged higher-risk in the engagement brief). Given a total
budget, schedule_probes selects the subset of units maximizing total value
without exceeding the budget.

Costs and the budget are plain integers (not floats): the DP table is
indexed by budget units, so a fractional cost would either need rounding
(silently losing precision) or a much larger table. Callers with
fractional time estimates (e.g. 2.5 seconds) should pick a granularity
(e.g. deciseconds) and scale both costs and the budget by it consistently
-- that scaling decision belongs to the caller, not this module.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProbeUnit:
    """One schedulable unit of scan work."""

    id: str
    cost: int
    value: int

    def __post_init__(self) -> None:
        if self.cost < 0:
            raise ValueError(f"ProbeUnit {self.id!r}: cost must be >= 0, got {self.cost}")
        if self.value < 0:
            raise ValueError(f"ProbeUnit {self.id!r}: value must be >= 0, got {self.value}")


def schedule_probes(
    units: list[ProbeUnit], budget: int
) -> tuple[list[ProbeUnit], int]:
    """
    Select the subset of `units` maximizing total value without exceeding
    `budget` total cost (classic 0/1 knapsack).

    Returns (selected_units, total_value) -- selected_units preserves the
    order `units` were given in (not DP-table order), so the result reads
    naturally and is stable for report rendering per
    docs/sdlc/03-algorithm-design.md §3b ("written to the stage-1 report
    so the budget decision is explainable").

    Time/space complexity: O(N * budget), N = len(units). This is cheap
    relative to actual network scan time by design -- see the efficiency
    table in docs/sdlc/02-problem-analysis.md §4.
    """
    if budget < 0:
        raise ValueError(f"budget must be >= 0, got {budget}")
    if not units:
        return [], 0

    n = len(units)
    # dp[i][w] = best achievable value using the first i units with
    # budget w. Row 0 (zero units considered) is implicitly all zeros.
    dp = [[0] * (budget + 1) for _ in range(n + 1)]

    for i in range(1, n + 1):
        unit = units[i - 1]
        for w in range(budget + 1):
            if unit.cost <= w:
                dp[i][w] = max(dp[i - 1][w], dp[i - 1][w - unit.cost] + unit.value)
            else:
                dp[i][w] = dp[i - 1][w]

    # Backtrack to recover which units were selected.
    selected_indices: set[int] = set()
    w = budget
    for i in range(n, 0, -1):
        if dp[i][w] != dp[i - 1][w]:
            selected_indices.add(i - 1)
            w -= units[i - 1].cost

    selected = [units[i] for i in range(n) if i in selected_indices]
    return selected, dp[n][budget]
