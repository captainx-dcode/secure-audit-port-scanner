"""
Fuzz test for src/banners/grabber.py -- the highest-priority module in the
threat model (docs/sdlc/04-threat-model.md §5.3), specifically because it
is the one place genuinely untrusted, attacker-controlled bytes enter the
system.

This is a lightweight, seeded, stdlib-`random`-based fuzzer rather than a
`hypothesis`-based property fuzzer, to avoid adding a new dependency before
it's actually needed (see requirements.txt's roadmap comments). It is
intentionally deterministic (fixed seed) so CI runs are reproducible; if
this ever finds a failure, the seed and iteration number reproduce it
exactly. Swapping in `hypothesis` later (already on the roadmap) can
subsume this file without losing anything -- hypothesis's shrinking would
be a strict improvement, not a different goal.

The property under test is intentionally narrow and absolute: grab_banner
must never raise on ANY byte sequence a remote peer could send, regardless
of length or content. A crash here means a hostile server can take down
the scanner -- exactly the threat model's concern.
"""

import asyncio
import random
import sys

import pytest

from banners.grabber import grab_banner

ITERATIONS = 200
MAX_PAYLOAD_LEN = 10_000  # deliberately well above the default 4096-byte cap
SEED = 1234


async def _fuzz_one(payload: bytes) -> None:
    async def handler(reader, writer):
        try:
            writer.write(payload)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass  # client may close early on a very large payload; not under test here
        await asyncio.sleep(0.01)
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        result = await grab_banner(
            "127.0.0.1", port, reader, writer, max_bytes=4096, read_timeout=0.5
        )
        # The only assertions that matter here: it returned at all (no
        # exception propagated out), and the basic invariants hold.
        assert isinstance(result.sanitized, str)
        assert isinstance(result.raw_base64, str)
        assert result.byte_length <= 4096
    finally:
        server.close()
        await server.wait_closed()


def test_grab_banner_never_raises_on_random_byte_sequences():
    rng = random.Random(SEED)
    failures: list[str] = []

    async def run_all():
        for i in range(ITERATIONS):
            length = rng.randint(0, MAX_PAYLOAD_LEN)
            payload = bytes(rng.randint(0, 255) for _ in range(length))
            try:
                await _fuzz_one(payload)
            except Exception as exc:  # noqa: BLE001 -- deliberately broad, see module docstring
                failures.append(
                    f"iteration {i} (seed={SEED}, len={length}): "
                    f"{type(exc).__name__}: {exc}\n"
                    f"  payload sample: {payload[:80]!r}"
                )

    asyncio.run(run_all())

    if failures:
        pytest.fail(
            f"{len(failures)}/{ITERATIONS} random payloads crashed grab_banner:\n\n"
            + "\n\n".join(failures)
        )


def test_grab_banner_never_raises_on_known_tricky_payloads():
    """
    A short, explicit list of payload shapes known to break naive parsers
    elsewhere, kept separate from the broad random sweep above so a
    regression here points directly at a specific, nameable case.
    """
    tricky_payloads = [
        b"",
        b"\x00" * 100,
        b"\xff" * 100,
        b"\r\n" * 500,  # many forged "log lines"
        "日本語テキスト".encode("utf-8") * 50,
        b"\xc0\xc0\xc0\xc0",  # invalid UTF-8 continuation bytes
        b"\xed\xa0\x80",  # UTF-8 encoding of a lone surrogate (invalid)
        b"\x1b]0;fake title\x07" * 20,  # terminal title-injection sequences
        (b"A" * MAX_PAYLOAD_LEN),  # maximal-length single-byte-repeated payload
    ]

    async def run_all():
        for payload in tricky_payloads:
            await _fuzz_one(payload)  # raises the test out directly on failure

    asyncio.run(run_all())
