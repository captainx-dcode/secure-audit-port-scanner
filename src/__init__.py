"""
Scope and Authorization Gate.

Nothing in this pipeline may open a socket against a target that hasn't
passed through here. This module's entire job is to make that true.

Design reference: docs/sdlc/03-algorithm-design.md, module 1.
Threat model reference: docs/sdlc/04-threat-model.md, §5.1 (Scope Gate).

Design decisions worth stating explicitly rather than leaving implicit:

- EXCLUSION ALWAYS WINS over authorization. If a target matches both an
  authorized CIDR and an excluded entry, it is rejected. An operator who
  defensively excludes a host from a broad authorized range (e.g. the
  gateway in a /24) must never have that override silently undone by the
  broader range. See threat model §5.1 (Spoofing row).

- Scope is loaded ONCE per run and never re-read mid-run. There is no
  "refresh scope" operation in this module on purpose -- widening scope
  after a run has started is exactly the tampering scenario called out in
  the threat model. A new engagement needs a new run, not a hot-reloaded
  scope file.

- Hostname matching is EXACT (case-insensitive), not wildcard or
  subdomain-aware. "db.metrocare.local" in scope does not authorize
  "backup.db.metrocare.local". This is a deliberate conservative default --
  broadening it to subdomain matching is a future decision, not an
  accidental gap.

- An engagement window with `end <= start`, or a scope file with zero
  authorized targets, is rejected at LOAD time, before any target
  evaluation happens -- fail closed and fail early.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

if TYPE_CHECKING:
    from evidence.audit import AuditLog


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


class ScopeError(Exception):
    """
    Raised for any scope-file problem: missing file, invalid YAML, failed
    schema validation, or an engagement window that isn't currently active.

    Deliberately one exception type for all of these -- callers should
    treat "scope couldn't be established" as a single hard stop, not
    something to selectively recover from.
    """


# --- Schema -----------------------------------------------------------------


def _validate_target_entry(entry: str) -> None:
    """A target entry must be a valid IP, CIDR network, or hostname."""
    entry = entry.strip()
    if not entry:
        raise ValueError("empty target entry")
    try:
        ipaddress.ip_network(entry, strict=False)
        return
    except ValueError:
        pass
    if _HOSTNAME_RE.match(entry):
        return
    raise ValueError(f"'{entry}' is not a valid IP, CIDR range, or hostname")


class EngagementWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: datetime
    end: datetime

    @model_validator(mode="after")
    def check_end_after_start(self) -> "EngagementWindow":
        if self.end <= self.start:
            raise ValueError(
                "engagement_window.end must be after engagement_window.start"
            )
        return self


class ScopeConfig(BaseModel):
    """
    Schema for scope.yaml. extra="forbid" is deliberate: an unrecognized
    field (e.g. a typo'd key) fails loudly at load time instead of being
    silently ignored, which matters for a file whose entire purpose is
    authorization.
    """

    model_config = ConfigDict(extra="forbid")

    authorizer: str = Field(min_length=1)
    engagement_window: EngagementWindow
    authorized_targets: list[str] = Field(min_length=1)
    excluded_targets: list[str] = Field(default_factory=list)
    notes: Optional[str] = None

    @field_validator("authorized_targets", "excluded_targets")
    @classmethod
    def validate_entries(cls, values: list[str]) -> list[str]:
        for entry in values:
            _validate_target_entry(entry)
        return values


class ScopeSet:
    """A loaded, schema-validated scope, ready for membership checks."""

    def __init__(self, config: ScopeConfig):
        self.authorizer = config.authorizer
        self.engagement_window = config.engagement_window
        self.authorized_targets = config.authorized_targets
        self.excluded_targets = config.excluded_targets

    def is_active(self, at: Optional[datetime] = None) -> bool:
        at = at or datetime.now(timezone.utc)
        return self.engagement_window.start <= at <= self.engagement_window.end


# --- Loading ------------------------------------------------------------------


def load_scope(path: str | Path, *, check_time: Optional[datetime] = None) -> ScopeSet:
    """
    Load and validate a scope.yaml file.

    Raises ScopeError if: the file is missing, the YAML is malformed, the
    schema validation fails (missing/extra/invalid fields, bad target
    entries, end<=start), or the engagement window is not currently active.

    `check_time` is injectable so tests don't depend on wall-clock time;
    production callers should leave it as None (real UTC now()).
    """
    path = Path(path)
    if not path.exists():
        raise ScopeError(f"scope file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScopeError(f"scope file is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise ScopeError("scope file must contain a YAML mapping at the top level")

    try:
        config = ScopeConfig(**raw)
    except ValidationError as exc:
        raise ScopeError(f"scope file failed validation: {exc}") from exc

    scope = ScopeSet(config)

    now = check_time or datetime.now(timezone.utc)
    if not scope.is_active(now):
        raise ScopeError(
            f"outside authorized engagement window: now={now.isoformat()}, "
            f"window={scope.engagement_window.start.isoformat()}"
            f"..{scope.engagement_window.end.isoformat()}"
        )

    return scope


# --- Membership checks ----------------------------------------------------


def _target_matches_entry(target: str, entry: str) -> bool:
    """
    True if `target` falls under `entry`: either as a member of a CIDR
    network, an exact IP match, or an exact (case-insensitive) hostname
    match. An IP target is never matched against a hostname entry or
    vice versa -- string equality only applies when both sides fail IP
    parsing, which keeps "1.2.3.4" from ever accidentally string-matching
    a hostname that happens to look similar.
    """
    try:
        target_ip = ipaddress.ip_address(target.strip())
    except ValueError:
        target_ip = None

    try:
        entry_network = ipaddress.ip_network(entry.strip(), strict=False)
    except ValueError:
        entry_network = None

    if target_ip is not None and entry_network is not None:
        return target_ip in entry_network

    if target_ip is not None or entry_network is not None:
        # one side is an IP/network, the other is a hostname -- no match
        return False

    return target.strip().lower() == entry.strip().lower()


def is_in_scope(target: str, scope: ScopeSet) -> bool:
    """
    A target is in scope only if it matches an authorized entry AND does
    not match any excluded entry. See module docstring: exclusion always
    wins.
    """
    for excluded in scope.excluded_targets:
        if _target_matches_entry(target, excluded):
            return False

    for authorized in scope.authorized_targets:
        if _target_matches_entry(target, authorized):
            return True

    return False


def filter_targets(
    requested_targets: list[str],
    scope: ScopeSet,
    audit_log: "AuditLog",
) -> list[str]:
    """
    Evaluate every requested target against scope, logging each decision
    (approval or rejection) before returning. Only approved targets are
    returned -- this is the hard gate referenced throughout the design:
    nothing downstream should ever see a target that didn't pass through
    this function.
    """
    approved: list[str] = []
    for target in requested_targets:
        if is_in_scope(target, scope):
            approved.append(target)
            audit_log.record("TARGET_APPROVED", target=target)
        else:
            audit_log.record("TARGET_REJECTED_OUT_OF_SCOPE", target=target)
    return approved
