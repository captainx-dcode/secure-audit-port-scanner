"""
Tests for src/discovery/liveness.py

Two layers, deliberately:
  1. Direct tests of _attempt_connect's exception handling, using a fake
     asyncio.open_connection so the real connect/timeout/refuse code paths
     run, without touching an actual network.
  2. Fast, deterministic tests of check_host_alive / discover_live_hosts
     that monkeypatch _attempt_connect itself, so higher-level logic
     (iteration, ordering, dedup, audit logging, concurrency) is tested
     independently of any socket behavior.

Reference: docs/sdlc/03-algorithm-design.md module 2.
"""

import asyncio

import pytest

import discovery.liveness as liveness
from evidence.audit import AuditLog


# --- Layer 1: _attempt_connect's real exception-handling paths --------------


class FakeWriter:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def test_attempt_connect_success(monkeypatch):
    async def fake_open_connection(host, port):
        return (None, FakeWriter())

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    result = asyncio.run(liveness._attempt_connect("192.168.100.23", 80, timeout=1.0))
    assert result == "responded"


def test_attempt_connect_connection_refused(monkeypatch):
    async def fake_open_connection(host, port):
        raise ConnectionRefusedError()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    result = asyncio.run(liveness._attempt_connect("192.168.100.23", 80, timeout=1.0))
    assert result == "responded"


def test_attempt_connect_timeout(monkeypatch):
    async def fake_open_connection(host, port):
        await asyncio.sleep(10)  # much longer than the timeout below

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    result = asyncio.run(liveness._attempt_connect("192.168.100.23", 80, timeout=0.05))
    assert result == "no_response"


def test_attempt_connect_dns_failure_treated_as_no_response(monkeypatch):
    async def fake_open_connection(host, port):
        raise OSError("Name or service not known")

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    result = asyncio.run(
        liveness._attempt_connect("not-a-real-host.invalid", 80, timeout=1.0)
    )
    assert result == "no_response"


# --- Layer 2: check_host_alive, monkeypatching _attempt_connect -------------


def test_check_host_alive_true_on_first_responding_port(monkeypatch):
    calls = []

    async def fake_attempt(host, port, timeout):
        calls.append(port)
        return "responded"

    monkeypatch.setattr(liveness, "_attempt_connect", fake_attempt)

    alive = asyncio.run(
        liveness.check_host_alive("192.168.100.23", [80, 443, 22], timeout=1.0)
    )
    assert alive is True
    assert calls == [80]  # stopped after the first response, didn't try the rest


def test_check_host_alive_tries_subsequent_ports_on_no_response(monkeypatch):
    calls = []

    async def fake_attempt(host, port, timeout):
        calls.append(port)
        return "responded" if port == 443 else "no_response"

    monkeypatch.setattr(liveness, "_attempt_connect", fake_attempt)

    alive = asyncio.run(
        liveness.check_host_alive("192.168.100.23", [80, 443, 22], timeout=1.0)
    )
    assert alive is True
    assert calls == [80, 443]  # stopped at 443, never tried 22


def test_check_host_alive_false_when_every_port_times_out(monkeypatch):
    async def fake_attempt(host, port, timeout):
        return "no_response"

    monkeypatch.setattr(liveness, "_attempt_connect", fake_attempt)

    alive = asyncio.run(
        liveness.check_host_alive("192.168.100.99", [80, 443, 22], timeout=1.0)
    )
    assert alive is False


# --- Layer 2: discover_live_hosts -------------------------------------------


def test_discover_live_hosts_returns_only_live_in_input_order(tmp_path, monkeypatch):
    live_set = {"192.168.100.10", "192.168.100.30"}

    async def fake_check(host, probe_ports, timeout):
        return host in live_set

    monkeypatch.setattr(liveness, "check_host_alive", fake_check)

    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")
    targets = ["192.168.100.10", "192.168.100.20", "192.168.100.30"]

    result = asyncio.run(liveness.discover_live_hosts(targets, audit_log))
    assert result == ["192.168.100.10", "192.168.100.30"]


def test_discover_live_hosts_logs_every_target(tmp_path, monkeypatch):
    live_set = {"192.168.100.10"}

    async def fake_check(host, probe_ports, timeout):
        return host in live_set

    monkeypatch.setattr(liveness, "check_host_alive", fake_check)

    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")
    targets = ["192.168.100.10", "192.168.100.20"]
    asyncio.run(liveness.discover_live_hosts(targets, audit_log))

    import json

    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    events = [json.loads(line) for line in lines]
    assert len(events) == 2
    assert events[0]["event"] == "HOST_LIVE"
    assert events[0]["details"]["target"] == "192.168.100.10"
    assert events[1]["event"] == "HOST_UNREACHABLE"
    assert events[1]["details"]["target"] == "192.168.100.20"
    assert audit_log.verify_chain() is True


def test_discover_live_hosts_dedupes_preserving_first_occurrence(tmp_path, monkeypatch):
    async def fake_check(host, probe_ports, timeout):
        return True

    monkeypatch.setattr(liveness, "check_host_alive", fake_check)

    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")
    targets = ["192.168.100.10", "192.168.100.20", "192.168.100.10"]

    result = asyncio.run(liveness.discover_live_hosts(targets, audit_log))
    assert result == ["192.168.100.10", "192.168.100.20"]  # no duplicate

    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 2  # not logged twice either


def test_discover_live_hosts_empty_input(tmp_path, monkeypatch):
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")
    result = asyncio.run(liveness.discover_live_hosts([], audit_log))
    assert result == []
    assert not (tmp_path / "audit.log").exists()


def test_discover_live_hosts_respects_concurrency_limit(tmp_path, monkeypatch):
    """
    Confirms the semaphore actually bounds concurrent checks, not just that
    the final result is correct. Each fake check increments a shared
    counter, yields control (so overlapping calls actually overlap), then
    decrements -- the test asserts the observed peak concurrency never
    exceeds the configured limit.
    """
    max_concurrency = 3
    current = 0
    peak = 0

    async def fake_check(host, probe_ports, timeout):
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        await asyncio.sleep(0.01)  # force overlap with other pending calls
        current -= 1
        return True

    monkeypatch.setattr(liveness, "check_host_alive", fake_check)

    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")
    targets = [f"192.168.100.{i}" for i in range(2, 20)]  # 18 targets

    asyncio.run(
        liveness.discover_live_hosts(
            targets, audit_log, max_concurrency=max_concurrency
        )
    )

    assert peak <= max_concurrency
    assert peak == max_concurrency  # confirm it actually used the full budget
    