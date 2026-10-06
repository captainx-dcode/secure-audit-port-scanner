"""
Tests for src/identify/fuzzy.py

Reference: docs/sdlc/03-algorithm-design.md module 6 (fuzzy link),
docs/sdlc/04-threat-model.md §5.4 (candidate-pool cost bound).
"""

import json
from unittest import mock

import pytest

from evidence.audit import AuditLog
from identify.fuzzy import _select_candidates, fuzzy_match, fuzzy_match_and_log
from identify.signatures import Signature, load_signatures


def _sigs(*entries: tuple[str, str, str | None]) -> list[Signature]:
    return [Signature(pattern=p, service=s, version=v) for p, s, v in entries]


# --- validation -------------------------------------------------------------


def test_rejects_non_positive_max_pool():
    with pytest.raises(ValueError, match="max_pool"):
        fuzzy_match("banner", _sigs(("x", "y", None)), max_pool=0)


def test_rejects_invalid_max_distance_ratio():
    with pytest.raises(ValueError, match="max_distance_ratio"):
        fuzzy_match("banner", _sigs(("x", "y", None)), max_distance_ratio=1.5)


def test_rejects_zero_max_distance_ratio():
    with pytest.raises(ValueError, match="max_distance_ratio"):
        fuzzy_match("banner", _sigs(("x", "y", None)), max_distance_ratio=0)


# --- basic behavior ----------------------------------------------------------


def test_empty_signature_list_returns_none():
    assert fuzzy_match("220 ProFTPD 1.3.1a Server", []) is None


def test_empty_banner_does_not_false_match():
    sigs = _sigs(("220 ProFTPD 1.3.1 Server", "ProFTPD", "1.3.1"))
    assert fuzzy_match("", sigs) is None


def test_classic_near_miss_version_suffix():
    # The example used throughout the design docs: banner has an extra
    # trailing letter the known signature doesn't.
    sigs = _sigs(("220 ProFTPD 1.3.1 Server", "ProFTPD", "1.3.1"))
    match = fuzzy_match("220 ProFTPD 1.3.1a Server", sigs)
    assert match is not None
    assert match.service == "ProFTPD"
    assert match.version == "1.3.1"  # the SIGNATURE's version, not banner's exact text
    assert match.source == "fuzzy"
    assert match.confidence == "medium"
    assert match.matched_pattern == "220 ProFTPD 1.3.1 Server"


def test_too_dissimilar_banner_returns_none():
    sigs = _sigs(("220 ProFTPD 1.3.1 Server", "ProFTPD", "1.3.1"))
    match = fuzzy_match("completely unrelated text about something else", sigs)
    assert match is None


def test_closest_candidate_wins_among_multiple_qualifying():
    sigs = _sigs(
        ("220 ProFTPD 1.3.1 Server", "ProFTPD", "1.3.1"),
        ("220 ProFTPD 1.3.1a Server", "ProFTPD", "1.3.1a"),
    )
    # banner is an exact match for the second signature -- it should win
    # over the first even though both are within threshold
    match = fuzzy_match("220 ProFTPD 1.3.1a Server", sigs)
    assert match.version == "1.3.1a"


def test_case_insensitive():
    sigs = _sigs(("220 ProFTPD 1.3.1 Server", "ProFTPD", "1.3.1"))
    match = fuzzy_match("220 PROFTPD 1.3.1A SERVER", sigs)
    assert match is not None
    assert match.service == "ProFTPD"


# --- candidate pool bound (threat model §5.4) ----------------------------------


def test_select_candidates_respects_max_pool():
    sigs = _sigs(*[(f"pattern-{i}", f"svc{i}", None) for i in range(100)])
    selected = _select_candidates("some banner text here", sigs, max_pool=10)
    assert len(selected) == 10


def test_select_candidates_prefers_similar_length():
    banner = "x" * 20
    sigs = _sigs(
        ("y" * 20, "close", None),   # same length as banner
        ("y" * 200, "far", None),    # very different length
    )
    selected = _select_candidates(banner, sigs, max_pool=1)
    assert selected[0].service == "close"


def test_fuzzy_match_only_compares_bounded_pool_regardless_of_db_size():
    """
    Directly proves the cost bound: with a signature DB of 500 entries
    but max_pool=5, Levenshtein.distance must be called at most 5 times,
    not 500 -- this is the actual guard against the threat model's
    "attacker-crafted banner inflates fuzzy-match cost" concern.
    """
    sigs = _sigs(*[(f"pattern-number-{i}", f"svc{i}", None) for i in range(500)])

    with mock.patch("identify.fuzzy.Levenshtein.distance", wraps=__import__("Levenshtein").distance) as spy:
        fuzzy_match("pattern-number-250", sigs, max_pool=5)
        assert spy.call_count <= 5


# --- fuzzy_match_and_log ----------------------------------------------------------


def test_fuzzy_match_and_log_logs_on_match(tmp_path):
    sigs = _sigs(("220 ProFTPD 1.3.1 Server", "ProFTPD", "1.3.1"))
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")

    match = fuzzy_match_and_log(
        "192.168.100.23", 21, "220 ProFTPD 1.3.1a Server", sigs, audit_log
    )
    assert match is not None

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.log").read_text().strip().splitlines()
    ]
    assert len(events) == 1
    assert events[0]["event"] == "SERVICE_IDENTIFIED_FUZZY"
    assert events[0]["details"]["service"] == "ProFTPD"
    assert events[0]["details"]["confidence"] == "medium"


def test_fuzzy_match_and_log_does_not_log_on_no_match(tmp_path):
    sigs = _sigs(("220 ProFTPD 1.3.1 Server", "ProFTPD", "1.3.1"))
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")

    match = fuzzy_match_and_log(
        "192.168.100.23", 21, "nothing remotely similar here", sigs, audit_log
    )
    assert match is None
    assert not (tmp_path / "audit.log").exists()


def test_fuzzy_match_and_log_chain_is_verifiable(tmp_path):
    sigs = _sigs(("220 ProFTPD 1.3.1 Server", "ProFTPD", "1.3.1"))
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")

    fuzzy_match_and_log(
        "192.168.100.23", 21, "220 ProFTPD 1.3.1a Server", sigs, audit_log
    )
    assert audit_log.verify_chain() is True


# --- real signature database smoke test -----------------------------------------


def test_real_signature_database_catches_version_suffix_near_miss():
    sigs = load_signatures("signatures/banner-signatures.json")
    # "220 (vsFTPd 2.3.4)" is in the real DB; a near-miss with an extra
    # trailing marker should still fuzzy-match it.
    match = fuzzy_match("220 (vsFTPd 2.3.4a)", sigs)
    assert match is not None
    assert match.service == "vsftpd"
