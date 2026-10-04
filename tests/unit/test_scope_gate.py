"""
Tests for src/scope/gate.py

Covers schema validation failures, engagement-window enforcement, the
exclusion-always-wins membership rule, and that filter_targets logs every
decision through the audit log (tying this module to the evidence module
built in the previous commit).

Reference: docs/sdlc/04-threat-model.md §5.1.
"""

from datetime import datetime, timedelta, timezone

import pytest

from evidence.audit import AuditLog
from scope.gate import ScopeError, filter_targets, is_in_scope, load_scope


# --- helpers ----------------------------------------------------------------


NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)


def write_scope(tmp_path, body: str):
    path = tmp_path / "scope.yaml"
    path.write_text(body, encoding="utf-8")
    return path


VALID_SCOPE = """
authorizer: "Jane Doe, CISO"
engagement_window:
  start: "2026-10-01T00:00:00Z"
  end: "2026-10-31T23:59:59Z"
authorized_targets:
  - "192.168.100.0/24"
  - "db.metrocare.local"
excluded_targets:
  - "192.168.100.1"
notes: "lab engagement"
"""


# --- load_scope: happy path --------------------------------------------------


def test_load_scope_valid(tmp_path):
    path = write_scope(tmp_path, VALID_SCOPE)
    scope = load_scope(path, check_time=NOW)
    assert scope.authorizer == "Jane Doe, CISO"
    assert "192.168.100.0/24" in scope.authorized_targets
    assert scope.is_active(NOW) is True


# --- load_scope: structural / file-level failures ---------------------------


def test_load_scope_missing_file(tmp_path):
    with pytest.raises(ScopeError, match="not found"):
        load_scope(tmp_path / "nope.yaml", check_time=NOW)


def test_load_scope_invalid_yaml(tmp_path):
    path = write_scope(tmp_path, "authorizer: [unterminated")
    with pytest.raises(ScopeError, match="not valid YAML"):
        load_scope(path, check_time=NOW)


def test_load_scope_non_mapping_yaml(tmp_path):
    path = write_scope(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ScopeError, match="mapping"):
        load_scope(path, check_time=NOW)


# --- load_scope: schema validation failures ----------------------------------


def test_load_scope_missing_required_field(tmp_path):
    body = VALID_SCOPE.replace('authorizer: "Jane Doe, CISO"\n', "")
    path = write_scope(tmp_path, body)
    with pytest.raises(ScopeError, match="failed validation"):
        load_scope(path, check_time=NOW)


def test_load_scope_rejects_unknown_field(tmp_path):
    body = VALID_SCOPE + "\nsome_typo_field: true\n"
    path = write_scope(tmp_path, body)
    with pytest.raises(ScopeError, match="failed validation"):
        load_scope(path, check_time=NOW)


def test_load_scope_empty_authorized_targets(tmp_path):
    body = """
authorizer: "Jane Doe"
engagement_window:
  start: "2026-10-01T00:00:00Z"
  end: "2026-10-31T23:59:59Z"
authorized_targets: []
"""
    path = write_scope(tmp_path, body)
    with pytest.raises(ScopeError, match="failed validation"):
        load_scope(path, check_time=NOW)


def test_load_scope_invalid_target_entry(tmp_path):
    body = VALID_SCOPE.replace(
        '  - "192.168.100.0/24"', '  - "not a valid target!!"'
    )
    path = write_scope(tmp_path, body)
    with pytest.raises(ScopeError, match="failed validation"):
        load_scope(path, check_time=NOW)


def test_load_scope_end_before_start(tmp_path):
    body = """
authorizer: "Jane Doe"
engagement_window:
  start: "2026-10-31T00:00:00Z"
  end: "2026-10-01T00:00:00Z"
authorized_targets:
  - "192.168.100.0/24"
"""
    path = write_scope(tmp_path, body)
    with pytest.raises(ScopeError, match="failed validation"):
        load_scope(path, check_time=NOW)


# --- load_scope: engagement window enforcement -------------------------------


def test_load_scope_rejects_before_window_start(tmp_path):
    path = write_scope(tmp_path, VALID_SCOPE)
    before_start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    with pytest.raises(ScopeError, match="outside authorized engagement window"):
        load_scope(path, check_time=before_start)


def test_load_scope_rejects_after_window_end(tmp_path):
    path = write_scope(tmp_path, VALID_SCOPE)
    after_end = datetime(2026, 11, 1, tzinfo=timezone.utc)
    with pytest.raises(ScopeError, match="outside authorized engagement window"):
        load_scope(path, check_time=after_end)


def test_load_scope_accepts_at_window_boundary(tmp_path):
    path = write_scope(tmp_path, VALID_SCOPE)
    at_start = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)
    scope = load_scope(path, check_time=at_start)
    assert scope.is_active(at_start) is True


# --- is_in_scope: CIDR / IP matching ------------------------------------------


def test_ip_in_authorized_cidr(tmp_path):
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    assert is_in_scope("192.168.100.50", scope) is True


def test_ip_outside_authorized_cidr(tmp_path):
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    assert is_in_scope("10.0.0.1", scope) is False


def test_excluded_ip_within_authorized_cidr_wins(tmp_path):
    # 192.168.100.1 is inside the authorized /24 AND individually excluded.
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    assert is_in_scope("192.168.100.1", scope) is False


def test_exact_ip_authorized_target():
    body = """
authorizer: "Jane Doe"
engagement_window:
  start: "2026-10-01T00:00:00Z"
  end: "2026-10-31T23:59:59Z"
authorized_targets:
  - "192.168.100.23"
"""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "scope.yaml"
        path.write_text(body)
        scope = load_scope(path, check_time=NOW)
    assert is_in_scope("192.168.100.23", scope) is True
    assert is_in_scope("192.168.100.24", scope) is False


# --- is_in_scope: hostname matching -------------------------------------------


def test_hostname_exact_match(tmp_path):
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    assert is_in_scope("db.metrocare.local", scope) is True


def test_hostname_case_insensitive(tmp_path):
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    assert is_in_scope("DB.METROCARE.LOCAL", scope) is True


def test_hostname_subdomain_not_authorized(tmp_path):
    # Deliberate: exact match only, no subdomain inheritance (see module docstring).
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    assert is_in_scope("backup.db.metrocare.local", scope) is False


def test_unrelated_hostname_not_authorized(tmp_path):
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    assert is_in_scope("evil.example.com", scope) is False


def test_ip_target_never_matches_hostname_entry(tmp_path):
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    # Confirms no accidental string-equality fallthrough between IPs and hostnames.
    assert is_in_scope("8.8.8.8", scope) is False


# --- filter_targets: integration with the audit log ---------------------------


def test_filter_targets_returns_only_approved(tmp_path):
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")

    requested = ["192.168.100.50", "10.0.0.1", "192.168.100.1", "db.metrocare.local"]
    approved = filter_targets(requested, scope, audit_log)

    assert approved == ["192.168.100.50", "db.metrocare.local"]


def test_filter_targets_logs_every_decision(tmp_path):
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")

    requested = ["192.168.100.50", "10.0.0.1"]
    filter_targets(requested, scope, audit_log)

    log_lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(log_lines) == 2

    import json

    events = [json.loads(line) for line in log_lines]
    assert events[0]["event"] == "TARGET_APPROVED"
    assert events[0]["details"]["target"] == "192.168.100.50"
    assert events[1]["event"] == "TARGET_REJECTED_OUT_OF_SCOPE"
    assert events[1]["details"]["target"] == "10.0.0.1"


def test_filter_targets_output_is_hash_chain_verifiable(tmp_path):
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")

    filter_targets(
        ["192.168.100.50", "10.0.0.1", "192.168.100.1"], scope, audit_log
    )

    assert audit_log.verify_chain() is True


def test_filter_targets_empty_request_returns_empty(tmp_path):
    scope = load_scope(write_scope(tmp_path, VALID_SCOPE), check_time=NOW)
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")
    assert filter_targets([], scope, audit_log) == []
