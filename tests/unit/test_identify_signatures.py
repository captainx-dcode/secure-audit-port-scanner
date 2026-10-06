"""
Tests for src/identify/signatures.py

Reference: docs/sdlc/03-algorithm-design.md module 6 (signature link of
the signature -> fuzzy -> ML fallback chain).
"""

import json

import pytest

from evidence.audit import AuditLog
from identify.signatures import (
    Signature,
    SignatureError,
    build_automaton,
    identify_and_log,
    identify_service,
    load_signatures,
)


# --- load_signatures ------------------------------------------------------------


def _write_db(tmp_path, data: dict):
    path = tmp_path / "sigs.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_load_signatures_valid(tmp_path):
    path = _write_db(
        tmp_path,
        {
            "signatures": [
                {"pattern": "OpenSSH", "service": "OpenSSH", "version": None},
                {"pattern": "vsFTPd 2.3.4", "service": "vsftpd", "version": "2.3.4"},
            ]
        },
    )
    sigs = load_signatures(path)
    assert len(sigs) == 2
    assert sigs[0] == Signature(pattern="OpenSSH", service="OpenSSH", version=None)
    assert sigs[1].version == "2.3.4"


def test_load_signatures_missing_file(tmp_path):
    with pytest.raises(SignatureError, match="not found"):
        load_signatures(tmp_path / "nope.json")


def test_load_signatures_invalid_json(tmp_path):
    path = tmp_path / "sigs.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(SignatureError, match="not valid JSON"):
        load_signatures(path)


def test_load_signatures_missing_signatures_key(tmp_path):
    path = _write_db(tmp_path, {"version": "2026-01-01"})
    with pytest.raises(SignatureError, match="signatures"):
        load_signatures(path)


def test_load_signatures_rejects_empty_pattern(tmp_path):
    path = _write_db(
        tmp_path, {"signatures": [{"pattern": "", "service": "X", "version": None}]}
    )
    with pytest.raises(SignatureError, match="pattern"):
        load_signatures(path)


def test_load_signatures_rejects_missing_service(tmp_path):
    path = _write_db(tmp_path, {"signatures": [{"pattern": "X", "version": None}]})
    with pytest.raises(SignatureError, match="service"):
        load_signatures(path)


def test_load_signatures_rejects_non_string_version(tmp_path):
    path = _write_db(
        tmp_path, {"signatures": [{"pattern": "X", "service": "Y", "version": 123}]}
    )
    with pytest.raises(SignatureError, match="version"):
        load_signatures(path)


def test_load_signatures_empty_list_is_valid(tmp_path):
    path = _write_db(tmp_path, {"signatures": []})
    assert load_signatures(path) == []


# --- build_automaton / identify_service: core matching ------------------------


def _sigs(*entries: tuple[str, str, str | None]) -> list[Signature]:
    return [Signature(pattern=p, service=s, version=v) for p, s, v in entries]


def test_exact_match_returns_service_and_version():
    sigs = _sigs(("OpenSSH_8.9p1", "OpenSSH", "8.9p1"))
    automaton = build_automaton(sigs)
    match = identify_service("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", automaton)
    assert match is not None
    assert match.service == "OpenSSH"
    assert match.version == "8.9p1"
    assert match.source == "signature"
    assert match.confidence == "high"
    assert match.matched_pattern == "OpenSSH_8.9p1"


def test_no_match_returns_none():
    sigs = _sigs(("OpenSSH", "OpenSSH", None))
    automaton = build_automaton(sigs)
    assert identify_service("totally unrelated banner text", automaton) is None


def test_empty_banner_returns_none():
    sigs = _sigs(("OpenSSH", "OpenSSH", None))
    automaton = build_automaton(sigs)
    assert identify_service("", automaton) is None


def test_empty_signature_db_always_returns_none():
    automaton = build_automaton([])
    assert identify_service("SSH-2.0-OpenSSH_8.9p1", automaton) is None


def test_case_insensitive_matching():
    sigs = _sigs(("vsFTPd", "vsftpd", None))
    automaton = build_automaton(sigs)
    match = identify_service("220 VSFTPD 2.3.4 READY", automaton)
    assert match is not None
    assert match.service == "vsftpd"


def test_longest_match_wins_over_shorter_generic_pattern():
    # A generic "ProFTPD" pattern and a specific version-string pattern
    # both appear in the banner -- the longer, more specific one must win.
    sigs = _sigs(
        ("ProFTPD", "ProFTPD", None),
        ("220 ProFTPD 1.3.1 Server", "ProFTPD", "1.3.1"),
    )
    automaton = build_automaton(sigs)
    match = identify_service("220 ProFTPD 1.3.1 Server ready.", automaton)
    assert match.version == "1.3.1"
    assert match.matched_pattern == "220 ProFTPD 1.3.1 Server"


def test_multiple_distinct_services_in_banner_picks_longest_overall():
    # Contrived but valid: banner mentions two different products: the
    # longer pattern match should still win regardless of which product.
    sigs = _sigs(
        ("nginx", "nginx", None),
        ("X-Powered-By: PHP/7.4", "PHP", "7.4"),
    )
    automaton = build_automaton(sigs)
    match = identify_service("Server: nginx X-Powered-By: PHP/7.4", automaton)
    assert match.matched_pattern == "X-Powered-By: PHP/7.4"
    assert match.service == "PHP"


def test_matched_pattern_field_is_populated():
    sigs = _sigs(("Apache/2.2.8", "Apache httpd", "2.2.8"))
    automaton = build_automaton(sigs)
    match = identify_service("Server: Apache/2.2.8 (Ubuntu)", automaton)
    assert match.matched_pattern == "Apache/2.2.8"


def test_duplicate_pattern_text_resolved_deterministically():
    # Two signatures sharing identical pattern text (a data-authoring
    # smell, not a runtime error) -- the first one added should win,
    # consistently, not raise or pick randomly.
    sigs = _sigs(
        ("Ambiguous", "ServiceA", "1.0"),
        ("Ambiguous", "ServiceB", "2.0"),
    )
    automaton = build_automaton(sigs)
    match = identify_service("banner says Ambiguous here", automaton)
    assert match.service == "ServiceA"


# --- real signature database file (smoke test against the shipped seed data) ---


def test_real_signature_database_loads_and_matches():
    sigs = load_signatures("signatures/banner-signatures.json")
    assert len(sigs) > 0
    automaton = build_automaton(sigs)

    match = identify_service("220 (vsFTPd 2.3.4)", automaton)
    assert match is not None
    assert match.service == "vsftpd"


# --- identify_and_log -------------------------------------------------------------


def test_identify_and_log_records_match(tmp_path):
    sigs = _sigs(("OpenSSH_8.9p1", "OpenSSH", "8.9p1"))
    automaton = build_automaton(sigs)
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")

    match = identify_and_log(
        "192.168.100.23", 22, "SSH-2.0-OpenSSH_8.9p1", automaton, audit_log
    )
    assert match is not None

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.log").read_text().strip().splitlines()
    ]
    assert len(events) == 1
    assert events[0]["event"] == "SERVICE_IDENTIFIED"
    assert events[0]["details"]["service"] == "OpenSSH"
    assert events[0]["details"]["confidence"] == "high"


def test_identify_and_log_records_unidentified(tmp_path):
    automaton = build_automaton([])
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")

    match = identify_and_log(
        "192.168.100.23", 31337, "mystery banner", automaton, audit_log
    )
    assert match is None

    events = [
        json.loads(line)
        for line in (tmp_path / "audit.log").read_text().strip().splitlines()
    ]
    assert events[0]["event"] == "SERVICE_UNIDENTIFIED"
    assert events[0]["details"] == {"host": "192.168.100.23", "port": 31337}


def test_identify_and_log_chain_is_verifiable(tmp_path):
    sigs = _sigs(("OpenSSH", "OpenSSH", None))
    automaton = build_automaton(sigs)
    audit_log = AuditLog(tmp_path / "audit.log", run_id="TEST-RUN")

    identify_and_log("192.168.100.23", 22, "OpenSSH banner", automaton, audit_log)
    identify_and_log("192.168.100.23", 999, "no match here", automaton, audit_log)

    assert audit_log.verify_chain() is True
