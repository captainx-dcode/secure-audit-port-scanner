"""
Signature-based service identification -- the first, and strongest, link
in the fallback chain described in docs/sdlc/03-algorithm-design.md module 6
(signature -> fuzzy -> ML). This module implements only the signature link;
fuzzy matching and the ML fallback are separate modules/commits.

Uses Aho-Corasick (pyahocorasick) to match a banner against every known
signature in ONE pass, O(len(banner) + matches), regardless of how large
the signature database grows -- the automaton is built once per run and
reused for every banner, per the efficiency analysis in
docs/sdlc/02-problem-analysis.md §4.

Matching is case-insensitive (both patterns and banners are lowercased
before matching) -- banner casing varies by server/OS and isn't a
meaningful signal, so normalizing it avoids silently missing an otherwise
exact match. This is a deliberate choice, not an oversight: if a future
signature genuinely needs case sensitivity (rare for service banners),
that would need a different mechanism, not a quiet exception here.

When multiple signatures match the same banner, the LONGEST matching
pattern wins (treated as "more specific" -- e.g. a full version-string
signature beats a bare product-name signature). This is a simple,
explainable tie-break rule, not a scored ranking -- exactly the kind of
decision that belongs in a signature match's output (so a report can show
*why* this one was chosen), which is why ServiceMatch carries the matched
pattern itself, not just the resulting service/version.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import ahocorasick

if TYPE_CHECKING:
    from evidence.audit import AuditLog


class SignatureError(Exception):
    """Raised for any problem loading or validating the signature database."""


@dataclass(frozen=True)
class Signature:
    pattern: str
    service: str
    version: Optional[str]


@dataclass(frozen=True)
class ServiceMatch:
    service: str
    version: Optional[str]
    source: str  # "signature" here; "fuzzy" / "ml" from their own modules later
    confidence: str  # "high" for an exact signature match
    matched_pattern: str


def load_signatures(path: str | Path) -> list[Signature]:
    """
    Load and validate the signature database JSON file (see
    signatures/banner-signatures.json for the format). Raises
    SignatureError on any structural or content problem -- a malformed
    signature DB should fail loudly at startup, not produce silently
    wrong matches later.
    """
    path = Path(path)
    if not path.exists():
        raise SignatureError(f"signature database not found: {path}")

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SignatureError(f"signature database is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict) or "signatures" not in raw:
        raise SignatureError(
            "signature database must be a JSON object with a 'signatures' key"
        )

    entries = raw["signatures"]
    if not isinstance(entries, list):
        raise SignatureError("'signatures' must be a JSON array")

    signatures: list[Signature] = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise SignatureError(f"signatures[{i}] must be a JSON object")

        pattern = entry.get("pattern")
        service = entry.get("service")
        version = entry.get("version")

        if not isinstance(pattern, str) or not pattern.strip():
            raise SignatureError(f"signatures[{i}]: 'pattern' must be a non-empty string")
        if not isinstance(service, str) or not service.strip():
            raise SignatureError(f"signatures[{i}]: 'service' must be a non-empty string")
        if version is not None and not isinstance(version, str):
            raise SignatureError(f"signatures[{i}]: 'version' must be a string or null")

        signatures.append(Signature(pattern=pattern, service=service, version=version))

    return signatures


def build_automaton(signatures: list[Signature]) -> ahocorasick.Automaton:
    """
    Build one Aho-Corasick automaton from `signatures`, intended to be
    built ONCE per run and reused across every banner matched during that
    run (see module docstring on why this matters for complexity).

    Patterns are lowercased as keys (case-insensitive matching -- see
    module docstring). If two signatures share the exact same lowercased
    pattern text, both are kept and are disambiguated at match time by
    identify_service's longest-match tie-break; since they're the SAME
    length in that case, the one added first wins deterministically. This
    is a data-quality edge case the signature DB author should avoid
    (duplicate patterns with different service/version claims), not
    something this function silently "fixes".
    """
    automaton = ahocorasick.Automaton()
    grouped: dict[str, list[Signature]] = {}
    for sig in signatures:
        grouped.setdefault(sig.pattern.lower(), []).append(sig)

    for pattern_lower, sigs in grouped.items():
        automaton.add_word(pattern_lower, sigs)

    if len(automaton) > 0:
        # make_automaton() on a zero-word trie leaves pyahocorasick in a
        # state where .iter() raises -- identify_service guards against
        # calling .iter() on an empty automaton for exactly this reason,
        # so skipping make_automaton() here is safe and matches that guard.
        automaton.make_automaton()
    return automaton


def identify_service(
    banner: str, automaton: ahocorasick.Automaton
) -> Optional[ServiceMatch]:
    """
    Match `banner` against every signature in `automaton` in one pass.
    Returns the ServiceMatch for the longest matching pattern, or None if
    nothing matched.

    `banner` should be the SANITIZED banner text from
    src/banners/grabber.py, not the raw bytes -- this function does no
    decoding or sanitization of its own.
    """
    if len(automaton) == 0:
        # An empty signature DB is valid (e.g. a fresh install before any
        # signatures are loaded) -- not an error, just "nothing to match
        # against". pyahocorasick's .iter() raises on a zero-word
        # automaton, so this is checked explicitly rather than caught as
        # an exception, keeping "no match" and "broken automaton" from
        # looking the same to a caller.
        return None

    banner_lower = banner.lower()

    best: Optional[Signature] = None
    for _end_index, sigs in automaton.iter(banner_lower):
        for sig in sigs:
            if best is None or len(sig.pattern) > len(best.pattern):
                best = sig

    if best is None:
        return None

    return ServiceMatch(
        service=best.service,
        version=best.version,
        source="signature",
        confidence="high",
        matched_pattern=best.pattern,
    )


def identify_and_log(
    host: str,
    port: int,
    banner: str,
    automaton: ahocorasick.Automaton,
    audit_log: "AuditLog",
) -> Optional[ServiceMatch]:
    """
    identify_service, plus an audit log entry recording the outcome
    (matched or unidentified) -- the thin logging wrapper pattern used
    consistently elsewhere (src/scope/gate.py:filter_targets,
    src/scanner/connect_scan.py:run_scan).
    """
    match = identify_service(banner, automaton)
    if match is not None:
        audit_log.record(
            "SERVICE_IDENTIFIED",
            host=host,
            port=port,
            service=match.service,
            version=match.version,
            source=match.source,
            confidence=match.confidence,
            matched_pattern=match.matched_pattern,
        )
    else:
        audit_log.record("SERVICE_UNIDENTIFIED", host=host, port=port)
    return match
