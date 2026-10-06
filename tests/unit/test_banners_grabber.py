"""
Tests for src/banners/grabber.py

This module is the threat model's highest-priority component
(docs/sdlc/04-threat-model.md §5.3), so these tests specifically target
the threats it names: oversized input, a server that never responds
(tarpit-adjacent), log-injection payloads (forged newlines, ANSI escape
sequences), and malformed/invalid UTF-8 -- not just the happy path of
"a normal banner arrives."

Uses a real asyncio loopback server throughout, consistent with
test_scanner_connect_scan.py -- this module's entire job is handling real
bytes off a real socket, so faking that away would test less than nothing.
"""

import asyncio
import base64

from banners.grabber import DEFAULT_MAX_BYTES, BannerResult, grab_banner


# --- test harness --------------------------------------------------------------


async def _grab_from_server(server_behavior, *, max_bytes=4096, read_timeout=1.0):
    """
    Starts a loopback server whose connection handler is `server_behavior`
    (an async fn taking (reader, writer)), connects a client to it, and
    runs grab_banner against that client connection. Returns the
    BannerResult.
    """
    server = await asyncio.start_server(server_behavior, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        result = await grab_banner(
            "127.0.0.1", port, reader, writer, max_bytes=max_bytes, read_timeout=read_timeout
        )
        return result
    finally:
        server.close()
        await server.wait_closed()


# --- normal banner capture -------------------------------------------------


def test_grabs_a_normal_banner():
    async def handler(reader, writer):
        writer.write(b"220 ftp.example.local FTP server ready\r\n")
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    result = asyncio.run(_grab_from_server(handler))
    assert "220 ftp.example.local FTP server ready" in result.sanitized
    assert result.byte_length > 0
    assert result.truncated is False


def test_empty_banner_on_silent_server():
    async def handler(reader, writer):
        await asyncio.sleep(0.05)
        writer.close()  # closes without ever writing -- EOF, zero bytes

    result = asyncio.run(_grab_from_server(handler))
    assert result.sanitized == ""
    assert result.byte_length == 0
    assert result.truncated is False


def test_empty_banner_on_read_timeout():
    # Server holds the connection open, writes nothing, for LONGER than
    # our read_timeout -- this exercises the asyncio.TimeoutError branch
    # specifically, not the EOF branch above.
    async def handler(reader, writer):
        await asyncio.sleep(1.0)
        writer.close()

    result = asyncio.run(_grab_from_server(handler, read_timeout=0.1))
    assert result.sanitized == ""
    assert result.byte_length == 0


# --- bounded read (threat model: oversized banner / memory exhaustion) --------


def test_oversized_banner_is_bounded_to_max_bytes():
    async def handler(reader, writer):
        writer.write(b"A" * (DEFAULT_MAX_BYTES * 4))  # far more than the cap
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    result = asyncio.run(_grab_from_server(handler, max_bytes=100))
    assert result.byte_length <= 100
    assert result.truncated is True


def test_banner_exactly_at_cap_is_marked_truncated():
    # Conservative: can't cheaply distinguish "exactly max_bytes sent,
    # nothing more" from "truncated" without a further read, so byte_length
    # == max_bytes is always reported as truncated=True. Document the
    # tradeoff via this test rather than leaving it implicit.
    async def handler(reader, writer):
        writer.write(b"X" * 50)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    result = asyncio.run(_grab_from_server(handler, max_bytes=50))
    assert result.byte_length == 50
    assert result.truncated is True


def test_banner_under_cap_is_not_truncated():
    async def handler(reader, writer):
        writer.write(b"short")
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    result = asyncio.run(_grab_from_server(handler, max_bytes=4096))
    assert result.truncated is False


# --- log injection / control character sanitization ---------------------------


def test_forged_newline_payload_is_stripped_from_sanitized():
    payload = b"220 normal banner\r\n[FAKE AUDIT LOG] ADMIN ACCESS GRANTED\r\n"

    async def handler(reader, writer):
        writer.write(payload)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    result = asyncio.run(_grab_from_server(handler))
    assert "\n" not in result.sanitized
    assert "\r" not in result.sanitized
    # the forged content is still THERE as text (sanitize doesn't censor
    # words), it just can't inject a fake structured log line anymore
    assert "FAKE AUDIT LOG" in result.sanitized


def test_ansi_escape_sequence_is_defanged():
    payload = b"\x1b[31mRED TEXT\x1b[0m normal"

    async def handler(reader, writer):
        writer.write(payload)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    result = asyncio.run(_grab_from_server(handler))
    assert "\x1b" not in result.sanitized
    assert "RED TEXT" in result.sanitized  # printable remainder survives, harmlessly


def test_null_bytes_and_other_control_chars_stripped():
    payload = b"before\x00\x01\x02\x07after"

    async def handler(reader, writer):
        writer.write(payload)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    result = asyncio.run(_grab_from_server(handler))
    assert result.sanitized == "beforeafter"


# --- malformed / invalid UTF-8 (threat model: untrusted input must not crash) --


def test_invalid_utf8_does_not_raise():
    payload = b"\xff\xfe\x00bad\xc0\xc0utf8"

    async def handler(reader, writer):
        writer.write(payload)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    result = asyncio.run(_grab_from_server(handler))
    # must not raise; replacement characters are acceptable, a crash is not
    assert isinstance(result.sanitized, str)
    assert result.byte_length == len(payload)


# --- raw fidelity (evidence integrity) ------------------------------------------


def test_raw_base64_round_trips_exactly_even_when_sanitized_is_lossy():
    payload = b"normal\r\ntext\x1b[31mwith control chars\x00\xff"

    async def handler(reader, writer):
        writer.write(payload)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    result = asyncio.run(_grab_from_server(handler))
    decoded = base64.b64decode(result.raw_base64)
    assert decoded == payload  # raw is byte-faithful regardless of sanitization
    assert decoded != result.sanitized.encode()  # sanitized is deliberately lossy


# --- connection lifecycle -------------------------------------------------------


def test_grab_banner_closes_the_connection():
    async def handler(reader, writer):
        writer.write(b"hi")
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()

    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await grab_banner("127.0.0.1", port, reader, writer)
            assert writer.is_closing()
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(run())


def test_result_includes_host_and_port():
    async def handler(reader, writer):
        writer.close()

    result = asyncio.run(_grab_from_server(handler))
    assert result.host == "127.0.0.1"
    assert isinstance(result.port, int)
