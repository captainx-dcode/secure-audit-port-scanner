"""
Tests for src/evidence/audit.py

Covers: normal append/verify, chain resumption across AuditLog instances,
and the tamper-detection cases that are the entire point of this module --
if these don't catch tampering, the module provides false assurance, which
is worse than providing none. Also covers write_immutable's refuse-to-
overwrite and read-only behavior per the threat model's immutability
requirement.

Reference: docs/sdlc/04-threat-model.md §5.7.
"""

import json
import os
import stat

import pytest

from evidence.audit import (
    GENESIS_HASH,
    AuditLog,
    ChainIntegrityError,
    generate_manifest,
    write_immutable,
)


# --- AuditLog: basic behavior ---------------------------------------------


def test_first_entry_chains_to_genesis(tmp_path):
    log = AuditLog(tmp_path / "audit.log", run_id="TEST-001")
    entry = log.record("HOST_LIVE", target="192.168.100.23")
    assert entry.prev_hash == GENESIS_HASH
    assert entry.run_id == "TEST-001"
    assert entry.event == "HOST_LIVE"
    assert entry.details == {"target": "192.168.100.23"}


def test_second_entry_chains_to_first(tmp_path):
    log = AuditLog(tmp_path / "audit.log", run_id="TEST-001")
    first = log.record("HOST_LIVE", target="192.168.100.23")
    second = log.record("PORT_PROBE", target="192.168.100.23", port=22, state="open")
    assert second.prev_hash == first.entry_hash
    assert second.prev_hash != GENESIS_HASH


def test_log_file_has_one_json_line_per_entry(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(log_path, run_id="TEST-001")
    log.record("EVENT_A")
    log.record("EVENT_B")

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 2
    # each line must be independently parseable JSON
    for line in lines:
        json.loads(line)


def test_verify_chain_passes_on_untouched_log(tmp_path):
    log = AuditLog(tmp_path / "audit.log", run_id="TEST-001")
    for i in range(10):
        log.record("PORT_PROBE", port=1000 + i)
    assert log.verify_chain() is True


def test_verify_chain_passes_on_empty_or_missing_log(tmp_path):
    log = AuditLog(tmp_path / "does_not_exist.log", run_id="TEST-001")
    assert log.verify_chain() is True


# --- AuditLog: resumption across process/instance boundaries --------------


def test_new_instance_resumes_chain_from_existing_log(tmp_path):
    log_path = tmp_path / "audit.log"

    first_run = AuditLog(log_path, run_id="TEST-001")
    last_entry = first_run.record("EVENT_A")

    # Simulate a new process picking up the same log file
    resumed = AuditLog(log_path, run_id="TEST-001")
    next_entry = resumed.record("EVENT_B")

    assert next_entry.prev_hash == last_entry.entry_hash
    assert resumed.verify_chain() is True


# --- AuditLog: tamper detection (the whole point of this module) ----------


def test_verify_chain_detects_edited_entry_content(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(log_path, run_id="TEST-001")
    log.record("PORT_PROBE", target="192.168.100.23", port=22, state="closed")
    log.record("PORT_PROBE", target="192.168.100.23", port=80, state="open")

    # Tamper: rewrite the first line's "details" without recomputing its hash,
    # simulating someone editing the raw log file directly.
    lines = log_path.read_text().strip().splitlines()
    tampered_record = json.loads(lines[0])
    tampered_record["details"]["state"] = "open"  # flip closed -> open
    lines[0] = json.dumps(tampered_record)
    log_path.write_text("\n".join(lines) + "\n")

    with pytest.raises(ChainIntegrityError, match="stored entry_hash does not match"):
        log.verify_chain()


def test_verify_chain_detects_deleted_entry(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(log_path, run_id="TEST-001")
    log.record("EVENT_A")
    log.record("EVENT_B")
    log.record("EVENT_C")

    # Tamper: remove the middle entry entirely. This breaks the prev_hash
    # link between entries 1 and 3.
    lines = log_path.read_text().strip().splitlines()
    del lines[1]
    log_path.write_text("\n".join(lines) + "\n")

    with pytest.raises(ChainIntegrityError, match="Chain broken"):
        log.verify_chain()


def test_verify_chain_detects_reordered_entries(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(log_path, run_id="TEST-001")
    log.record("EVENT_A")
    log.record("EVENT_B")

    lines = log_path.read_text().strip().splitlines()
    lines.reverse()
    log_path.write_text("\n".join(lines) + "\n")

    with pytest.raises(ChainIntegrityError):
        log.verify_chain()


def test_malformed_json_line_raises_on_load(tmp_path):
    log_path = tmp_path / "audit.log"
    log_path.write_text("not valid json\n")

    with pytest.raises(ChainIntegrityError, match="not valid JSON"):
        AuditLog(log_path, run_id="TEST-001")


# --- write_immutable --------------------------------------------------------


def test_write_immutable_writes_json(tmp_path):
    target = tmp_path / "ports.json"
    write_immutable({"host": "192.168.100.23", "port": 22, "state": "open"}, target)
    assert json.loads(target.read_text()) == {
        "host": "192.168.100.23",
        "port": 22,
        "state": "open",
    }


def test_write_immutable_sets_read_only(tmp_path):
    target = tmp_path / "ports.json"
    write_immutable({"a": 1}, target)
    mode = stat.S_IMODE(os.stat(target).st_mode)
    assert not (mode & stat.S_IWUSR), "owner write bit should be cleared"


def test_write_immutable_refuses_to_overwrite(tmp_path):
    target = tmp_path / "ports.json"
    write_immutable({"a": 1}, target)
    with pytest.raises(FileExistsError):
        write_immutable({"a": 2}, target)


# --- generate_manifest -------------------------------------------------------


def test_generate_manifest_hashes_every_file(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    (evidence_dir / "a.json").write_text('{"x": 1}')
    sub = evidence_dir / "sub"
    sub.mkdir()
    (sub / "b.json").write_text('{"y": 2}')

    manifest_path = tmp_path / "MANIFEST.sha256"
    manifest = generate_manifest(evidence_dir, manifest_path)

    assert set(manifest.keys()) == {"a.json", os.path.join("sub", "b.json")}
    assert json.loads(manifest_path.read_text()) == manifest


def test_generate_manifest_on_missing_dir_produces_empty_manifest(tmp_path):
    manifest = generate_manifest(tmp_path / "does_not_exist", tmp_path / "MANIFEST.sha256")
    assert manifest == {}
