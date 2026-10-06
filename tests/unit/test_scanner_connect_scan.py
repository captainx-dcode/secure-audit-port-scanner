"""
Tests for src/scanner/connect_scan.py

Uses a real asyncio loopback server for the OPEN/CLOSED cases (these are
genuine local TCP behavior, not worth faking) and monkeypatches
asyncio.open_connection for FILTERED (a real timeout would make the suite
slow and flaky). Same layering approach as test_discovery_liveness.py.

Reference: docs/sdlc/03-algorithm-design.md module 4,
docs/sdlc/04-threat-model.md §5.2.
"""

import asyncio
import json
import random
import socket

import pytest

from evidence.audit import AuditLog
from scanner.connect_scan import PortResult, PortState, run_scan, scan_port


# --- fixtures -----------------------------------------------------------------


async def _start_loopback_server():
    """A minimal server that accepts and immediately does nothing further."""

    async def _handle(reader, writer):
        await asyncio.sleep(0.2)  # hold the connection briefly so tests can act
        writer.close()

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


def _find_unused_port() -> int:
    """A port on 127.0.0.1 nothing is listening on, for CLOSED tests."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port  # closed again immediately -- connecting here gets refused


# --- scan_port: real loopback behavior -----------------------------------------


def test_scan_port_open_on_listening_server():
    async def run():
        server, port = await _start_loopback_server()
        try:
            state = await scan_port(
                "127.0.0.1", port, timeout=1.0, jitter_range=(0, 0)
            )
            assert state == PortState.OPEN
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def test_scan_port_closed_on_refused_connection_monkeypatched():
    """
    Deterministically confirms scan_port maps ConnectionRefusedError to
    CLOSED, independent of any real OS/network/antivirus timing. This is
    the test that actually proves the exception-handling branch is
    correct; the real-loopback variant below is a best-effort smoke test
    on top of it, not a replacement for it.
    """

    async def refusing_open_connection(host, port):
        raise ConnectionRefusedError()

    async def run():
        import unittest.mock as mock

        with mock.patch("asyncio.open_connection", refusing_open_connection):
            return await scan_port(
                "127.0.0.1", 9999, timeout=1.0, jitter_range=(0, 0)
            )

    assert asyncio.run(run()) == PortState.CLOSED


def test_scan_port_on_real_unused_loopback_port_is_closed_or_filtered():
    """
    Best-effort integration check against a real unused loopback port.

    On Linux this reliably returns CLOSED (an immediate RST). On some
    Windows configurations, antivirus/EDR software intercepts rapid local
    connection attempts -- which is exactly what a port scanner does --
    and the RST either doesn't arrive or arrives late enough to hit the
    timeout, producing FILTERED instead. Per the module docstring,
    FILTERED deliberately collapses "no response" and "network
    uncertainty" into one state, so this is correct behavior from
    scan_port's perspective even when the OS-level cause differs.

    This test only asserts "not falsely OPEN" -- the CLOSED-specific
    exception-handling guarantee is covered deterministically by
    test_scan_port_closed_on_refused_connection_monkeypatched above.
    """

    async def run():
        port = _find_unused_port()
        return await scan_port("127.0.0.1", port, timeout=1.0, jitter_range=(0, 0))

    state = asyncio.run(run())
    assert state in (PortState.CLOSED, PortState.FILTERED)


def test_scan_port_on_open_callback_receives_live_connection():
    async def run():
        server, port = await _start_loopback_server()
        received = {}

        async def on_open(host, p, reader, writer):
            received["host"] = host
            received["port"] = p
            # connection must still be usable here -- scanner must not
            # have closed it before handing off
            writer.write(b"hello")
            await writer.drain()
            writer.close()

        try:
            state = await scan_port(
                "127.0.0.1", port, timeout=1.0, jitter_range=(0, 0), on_open=on_open
            )
            assert state == PortState.OPEN
            assert received == {"host": "127.0.0.1", "port": port}
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def test_scan_port_without_on_open_closes_connection_itself():
    # No direct way to assert "closed" externally without over-fitting to
    # asyncio internals, so this just confirms the no-callback path
    # completes cleanly (doesn't hang or raise) -- a leaked, un-awaited
    # connection would typically surface as a ResourceWarning / hang here.
    async def run():
        server, port = await _start_loopback_server()
        try:
            state = await scan_port(
                "127.0.0.1", port, timeout=1.0, jitter_range=(0, 0)
            )
            assert state == PortState.OPEN
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


# --- scan_port: filtered/timeout (monkeypatched) -------------------------------


def test_scan_port_filtered_on_timeout(monkeypatch):
    async def hanging_open_connection(host, port):
        await asyncio.sleep(10)

    monkeypatch.setattr(asyncio, "open_connection", hanging_open_connection)

    async def run():
        return await scan_port(
            "192.168.100.99", 9999, timeout=0.05, jitter_range=(0, 0)
        )

    assert asyncio.run(run()) == PortState.FILTERED


def test_scan_port_filtered_on_generic_oserror(monkeypatch):
    async def failing_open_connection(host, port):
        raise OSError("network is unreachable")

    monkeypatch.setattr(asyncio, "open_connection", failing_open_connection)

    async def run():
        return await scan_port(
            "192.168.100.99", 9999, timeout=1.0, jitter_range=(0, 0)
        )

    assert asyncio.run(run()) == PortState.FILTERED


# --- scan_port: jitter and validation -------------------------------------------


def test_scan_port_applies_jitter_within_range(monkeypatch):
    sleep_calls = []

    real_sleep = asyncio.sleep

    async def spy_sleep(duration):
        sleep_calls.append(duration)
        return  # skip the actual wait entirely

    monkeypatch.setattr(asyncio, "sleep", spy_sleep)

    async def fake_open_connection(host, port):
        class FakeWriter:
            def close(self):
                pass

            async def wait_closed(self):
                return None

        return None, FakeWriter()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    async def run():
        await scan_port(
            "127.0.0.1",
            80,
            timeout=1.0,
            jitter_range=(0.05, 0.1),
            rng=random.Random(0),
        )

    asyncio.run(run())
    assert len(sleep_calls) == 1
    assert 0.05 <= sleep_calls[0] <= 0.1


def test_scan_port_zero_jitter_skips_sleep(monkeypatch):
    sleep_calls = []

    async def spy_sleep(duration):
        sleep_calls.append(duration)

    monkeypatch.setattr(asyncio, "sleep", spy_sleep)

    async def fake_open_connection(host, port):
        raise ConnectionRefusedError()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    asyncio.run(
        scan_port("127.0.0.1", 80, timeout=1.0, jitter_range=(0, 0))
    )
    assert sleep_calls == []  # no sleep call at all when jitter_max is 0


def test_scan_port_rejects_invalid_jitter_range():
    async def run():
        await scan_port("127.0.0.1", 80, jitter_range=(0.5, 0.1))

    with pytest.raises(ValueError, match="jitter_range"):
        asyncio.run(run())


# --- run_scan --------------------------------------------------------------------


def test_run_scan_returns_results_in_port_order(tmp_path, monkeypatch):
    import scanner.connect_scan as scan_module

    state_by_port = {21: PortState.OPEN, 22: PortState.CLOSED, 80: PortState.FILTERED}

    async def fake_scan_port(host, port, **kwargs):
        # deliberately vary delay so completion order != input order
        await asyncio.sleep(0.03 if port == 80 else 0.0)
        return state_by_port[port]

    monkeypatch.setattr(scan_module, "scan_port", fake_scan_port)

    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")
    results = asyncio.run(
        run_scan("192.168.100.23", [80, 21, 22], audit_log)
    )

    assert [r.port for r in results] == [80, 21, 22]
    assert [r.state for r in results] == [
        PortState.FILTERED,
        PortState.OPEN,
        PortState.CLOSED,
    ]
    assert all(r.host == "192.168.100.23" for r in results)


def test_run_scan_logs_every_port(tmp_path, monkeypatch):
    import scanner.connect_scan as scan_module

    async def fake_scan_port(host, port, **kwargs):
        return PortState.OPEN if port == 22 else PortState.CLOSED

    monkeypatch.setattr(scan_module, "scan_port", fake_scan_port)

    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")
    asyncio.run(run_scan("192.168.100.23", [21, 22], audit_log))

    lines = (tmp_path / "audit.log").read_text().strip().splitlines()
    events = [json.loads(line) for line in lines]
    assert len(events) == 2
    assert events[0]["event"] == "PORT_PROBE"
    assert events[0]["details"] == {
        "host": "192.168.100.23",
        "port": 21,
        "state": "closed",
    }
    assert events[1]["details"]["state"] == "open"
    assert audit_log.verify_chain() is True


def test_run_scan_respects_concurrency_limit(tmp_path, monkeypatch):
    import scanner.connect_scan as scan_module

    max_concurrency = 4
    current = 0
    peak = 0

    async def fake_scan_port(host, port, **kwargs):
        nonlocal current, peak
        current += 1
        peak = max(peak, current)
        await asyncio.sleep(0.01)
        current -= 1
        return PortState.CLOSED

    monkeypatch.setattr(scan_module, "scan_port", fake_scan_port)

    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")
    ports = list(range(20, 50))  # 30 ports

    asyncio.run(
        run_scan(
            "192.168.100.23", ports, audit_log, concurrency=max_concurrency
        )
    )

    assert peak <= max_concurrency
    assert peak == max_concurrency


def test_run_scan_empty_ports_returns_empty(tmp_path):
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")
    results = asyncio.run(run_scan("192.168.100.23", [], audit_log))
    assert results == []
    assert not (tmp_path / "audit.log").exists()
