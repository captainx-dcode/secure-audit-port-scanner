"""
Banner grabber -- THE PRIMARY UNTRUSTED-INPUT BOUNDARY in this codebase.

Every byte handled here originates from a host the operator is authorized
to scan, but authorization is not the same as trust (see module docstring
in src/scope/gate.py). A target can be compromised, misconfigured, or
deliberately hostile to the scanner itself. Nothing from this module's
input should ever be assumed well-formed, bounded, or safe to interpret.

Design reference: docs/sdlc/03-algorithm-design.md, module 5.
Threat model reference: docs/sdlc/04-threat-model.md, §5.3 (Banner Grabber
-- read the whole section, not just this docstring, before touching this
file).

Two outputs, deliberately kept separate and serving different purposes:

  - RAW bytes (base64-encoded): byte-faithful evidence. Never decoded,
    never interpreted, never written to a human-readable log or report.
    This is what an auditor or a later re-analysis can trust completely.

  - SANITIZED text: a best-effort, lossy, human-readable rendering for
    logs and reports. Control characters (including CR/LF, which could
    forge fake log lines -- a log-injection attack) are stripped. This is
    NOT evidence; it exists purely so a person can read a summary without
    the raw bytes being able to attack the thing displaying them.

Bounds enforced here, per the threat model:
  - max_bytes: a single bounded read, never an unbounded loop. A
    malicious server streaming forever cannot exhaust scanner memory.
  - read_timeout: a server that never sends anything (or trickles data
    deliberately slowly -- a "tarpit") cannot hold the connection open
    indefinitely.

This module OWNS the connection once it receives it from scan_port's
on_open callback -- it always closes the connection before returning,
whether the read succeeded, timed out, or errored.
"""

from __future__ import annotations

import asyncio
import base64
import re
from dataclasses import dataclass
from datetime import datetime, timezone

DEFAULT_MAX_BYTES = 4096
DEFAULT_READ_TIMEOUT_SECONDS = 3.0

# ASCII control characters (0x00-0x1F, 0x7F), including CR/LF and ESC.
# This is deliberately a plain, auditable set of explicit ranges rather
# than a broader Unicode-category sweep -- easy to reason about, and it
# covers the concrete log-injection vectors called out in the threat
# model (forged newlines, ANSI escape sequences). It will NOT catch every
# exotic Unicode control/format character; that tradeoff is accepted
# because the sanitized text is for human display only, never re-parsed
# or trusted -- the raw bytes remain the evidence of record regardless.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class BannerResult:
    host: str
    port: int
    raw_base64: str
    sanitized: str
    byte_length: int
    truncated: bool
    timestamp: str


def _sanitize(raw: bytes) -> str:
    """
    Best-effort, lossy, human-safe rendering of `raw`. Never raises on
    malformed input: invalid UTF-8 sequences become the Unicode
    replacement character rather than an exception. Control characters
    (including the ones that could forge a fake log line) are removed
    entirely, not escaped -- display safety matters more here than
    preserving an exact visual transcript, which the base64 raw copy
    already provides for anyone who needs it.
    """
    text = raw.decode("utf-8", errors="replace")
    return _CONTROL_CHAR_RE.sub("", text)


async def grab_banner(
    host: str,
    port: int,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    read_timeout: float = DEFAULT_READ_TIMEOUT_SECONDS,
) -> BannerResult:
    """
    Read up to `max_bytes` from an already-open connection, bounded by
    `read_timeout`. Always closes the connection before returning.

    Signature matches scanner.connect_scan.OnOpenCallback exactly, so this
    can be passed directly as run_scan's `on_open` argument -- but note it
    does NOT return None (the callback type's nominal return type); the
    orchestrator wiring this up needs to capture BannerResult itself (e.g.
    via a closure or a results list), not rely on on_open's return value,
    since scan_port awaits on_open without using what it returns.

    A read that times out, or that gets an empty read (EOF, nothing
    sent), both produce an empty banner (raw=b"") rather than an error --
    many services legitimately say nothing until spoken to, and that is
    not itself an anomaly worth raising on.
    """
    try:
        raw = await asyncio.wait_for(reader.read(max_bytes), timeout=read_timeout)
    except asyncio.TimeoutError:
        raw = b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass  # peer may have already reset; the banner captured so far still stands

    return BannerResult(
        host=host,
        port=port,
        raw_base64=base64.b64encode(raw).decode("ascii"),
        sanitized=_sanitize(raw),
        byte_length=len(raw),
        truncated=len(raw) >= max_bytes,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
