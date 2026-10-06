"""
Fuzzy (edit-distance) service identification -- the second link in the
signature -> fuzzy -> ML fallback chain described in
docs/sdlc/03-algorithm-design.md module 6. Only meant to run when
src/identify/signatures.py:identify_service has already found nothing --
this module does not know or care about that ordering itself, it just
answers "is this banner a near-miss of some known signature", and the
caller (a future combined engine, once the ML module also exists) decides
when to invoke it.

Classic example this catches that exact signature matching cannot: a
banner reading "ProFTPD 1.3.1a Server ready" when the signature DB only
knows "ProFTPD 1.3.1" -- one character different, almost certainly the
same software with a minor point-release or vendor patch suffix.

COST GUARD (threat model §5.4): edit distance is O(len(a) * len(b)) per
comparison. The banner's length is already bounded upstream by
src/banners/grabber.py's max_bytes cap, but that alone does not bound this
module's total cost -- a large signature database would still mean
comparing against every entry. The candidate pool is therefore separately
capped at `max_pool` entries, selected by proximity in length to the
banner (the signatures most plausibly a near-miss), so total cost here is
bounded by max_pool * O(banner_length * pattern_length) regardless of how
large the signature database grows.

A fuzzy match's `version` comes from the SIGNATURE it matched, not from
the banner itself -- if the banner says "1.3.1a" and the closest known
signature is "1.3.1", the reported version is "1.3.1" (the known
software's version), which may be a slight approximation of the exact
patched/vendor version actually running. This is exactly why fuzzy matches
carry confidence="medium", not "high" -- see module docstring in
src/identify/signatures.py for how this feeds into the report's
confirmed-vs-inferred distinction.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

import Levenshtein

from identify.signatures import ServiceMatch, Signature

if TYPE_CHECKING:
    from evidence.audit import AuditLog


DEFAULT_MAX_POOL = 20
DEFAULT_MAX_DISTANCE_RATIO = 0.2  # at most 20% of characters may differ


def _select_candidates(
    banner: str, signatures: list[Signature], max_pool: int
) -> list[Signature]:
    """
    Select up to `max_pool` signatures most plausibly a near-miss of
    `banner`, by proximity in length. This is the bound referenced in the
    module docstring -- it runs regardless of how large `signatures` is,
    and its own cost (a sort) is cheap relative to the edit-distance
    comparisons it's bounding.
    """
    candidates = sorted(signatures, key=lambda s: abs(len(s.pattern) - len(banner)))
    return candidates[:max_pool]


def fuzzy_match(
    banner: str,
    signatures: list[Signature],
    *,
    max_pool: int = DEFAULT_MAX_POOL,
    max_distance_ratio: float = DEFAULT_MAX_DISTANCE_RATIO,
) -> Optional[ServiceMatch]:
    """
    Compare `banner` against a bounded pool of candidate signatures via
    edit distance, normalized by the longer of the two strings' length
    (so the threshold means "at most this fraction of characters differ",
    independent of absolute length). Returns the closest qualifying match,
    or None if nothing is within `max_distance_ratio`.

    `banner` should be sanitized text from src/banners/grabber.py, same
    as src/identify/signatures.py:identify_service -- this function does
    no decoding or sanitization of its own.
    """
    if max_pool <= 0:
        raise ValueError(f"max_pool must be > 0, got {max_pool}")
    if not 0 < max_distance_ratio <= 1:
        raise ValueError(
            f"max_distance_ratio must be in (0, 1], got {max_distance_ratio}"
        )

    if not signatures:
        return None

    banner_lower = banner.lower()
    candidates = _select_candidates(banner_lower, signatures, max_pool)

    best_sig: Optional[Signature] = None
    best_ratio: Optional[float] = None

    for sig in candidates:
        pattern_lower = sig.pattern.lower()
        distance = Levenshtein.distance(banner_lower, pattern_lower)
        longer_len = max(len(banner_lower), len(pattern_lower), 1)
        ratio = distance / longer_len

        if ratio <= max_distance_ratio:
            if best_ratio is None or ratio < best_ratio:
                best_sig = sig
                best_ratio = ratio

    if best_sig is None:
        return None

    return ServiceMatch(
        service=best_sig.service,
        version=best_sig.version,
        source="fuzzy",
        confidence="medium",
        matched_pattern=best_sig.pattern,
    )


def fuzzy_match_and_log(
    host: str,
    port: int,
    banner: str,
    signatures: list[Signature],
    audit_log: "AuditLog",
    *,
    max_pool: int = DEFAULT_MAX_POOL,
    max_distance_ratio: float = DEFAULT_MAX_DISTANCE_RATIO,
) -> Optional[ServiceMatch]:
    """
    fuzzy_match, plus an audit log entry ONLY on a successful match --
    unlike src/identify/signatures.py:identify_and_log, this does not log
    a "not found" event on failure, because a fuzzy-match miss is not
    necessarily the end of the fallback chain (the ML link may still
    succeed). A single "fully unidentified" event belongs to whatever
    calls the complete chain end-to-end, not to any one link in it.
    """
    match = fuzzy_match(
        banner, signatures, max_pool=max_pool, max_distance_ratio=max_distance_ratio
    )
    if match is not None:
        audit_log.record(
            "SERVICE_IDENTIFIED_FUZZY",
            host=host,
            port=port,
            service=match.service,
            version=match.version,
            confidence=match.confidence,
            matched_pattern=match.matched_pattern,
        )
    return match
