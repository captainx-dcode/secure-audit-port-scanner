"""
Hash-chained audit log.

Every action the scanner takes (scope decision, probe attempt, banner grab,
finding, etc.) gets appended here as one immutable, linked entry. Each
entry's hash covers its own content plus the previous entry's hash, so the
log forms a chain: altering or removing any past entry breaks every hash
after it, and that break is detectable by replaying the chain.

Design reference: docs/sdlc/03-algorithm-design.md, module 9.
Threat model reference: docs/sdlc/04-threat-model.md, §5.7 (Evidence Store).

Important limits, stated plainly rather than implied:
- This is TAMPER-EVIDENT, not TAMPER-PROOF. A hash chain only proves "this
  is self-consistent" -- it cannot prove the log wasn't wholly regenerated
  by someone with write access to the whole file, consistently, from entry
  one. Real tamper-resistance requires storing the final chain hash
  somewhere off this host (see docs/sdlc/04-threat-model.md §5.7,
  "Residual risk -- insider/host compromise").
- This module does not handle concurrent writers. One AuditLog instance per
  run, used from a single process, is the supported usage pattern. If the
  pipeline becomes multi-process later, this needs a file lock or a
  different storage backend -- don't bolt concurrency on silently.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


GENESIS_HASH = "0" * 64  # the "previous hash" of the very first entry


@dataclass(frozen=True)
class AuditEntry:
    """One immutable, hash-linked record in the audit log."""

    timestamp: str
    run_id: str
    event: str
    details: dict[str, Any]
    prev_hash: str
    entry_hash: str = field(init=False)

    def __post_init__(self) -> None:
        # frozen dataclass -> use object.__setattr__ to set the computed field
        object.__setattr__(self, "entry_hash", self._compute_hash())

    def _compute_hash(self) -> str:
        payload = {
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "event": self.event,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }
        # sort_keys makes the hash reproducible regardless of dict insertion order
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "run_id": self.run_id,
            "event": self.event,
            "details": self.details,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


class ChainIntegrityError(Exception):
    """Raised when a loaded audit log's hash chain doesn't verify."""


class AuditLog:
    """
    Append-only, hash-chained audit log backed by a JSON Lines file.

    One line per entry, so the file can be tailed, streamed, and appended
    to without re-parsing the whole log on every write.
    """

    def __init__(self, log_path: str | Path, run_id: str):
        self.log_path = Path(log_path)
        self.run_id = run_id
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        """Resume the chain from an existing log file, or start fresh."""
        if not self.log_path.exists():
            return GENESIS_HASH

        last_hash = GENESIS_HASH
        with self.log_path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ChainIntegrityError(
                        f"{self.log_path}: line {line_num} is not valid JSON"
                    ) from exc
                last_hash = record.get("entry_hash", GENESIS_HASH)
        return last_hash

    def record(self, event: str, **details: Any) -> AuditEntry:
        """
        Append one event to the log. Returns the entry that was written.

        `details` is arbitrary structured context for the event (host,
        port, state, etc.) -- keep it JSON-serializable.
        """
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            run_id=self.run_id,
            event=event,
            details=details,
            prev_hash=self._last_hash,
        )
        self._append(entry)
        self._last_hash = entry.entry_hash
        return entry

    def _append(self, entry: AuditEntry) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry.to_dict(), sort_keys=True, separators=(",", ":"))
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def verify_chain(self) -> bool:
        """
        Replay the whole log and confirm every entry's hash is internally
        consistent and correctly links to the previous entry.

        Returns True if the chain is intact. Raises ChainIntegrityError
        with details on the first break found, rather than returning False
        silently -- an auditor needs to know *where* it broke, not just
        *that* it broke.
        """
        if not self.log_path.exists():
            return True  # an empty/nonexistent log is trivially "intact"

        expected_prev = GENESIS_HASH
        with self.log_path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)

                if record.get("prev_hash") != expected_prev:
                    raise ChainIntegrityError(
                        f"Chain broken at line {line_num}: "
                        f"expected prev_hash={expected_prev}, "
                        f"found prev_hash={record.get('prev_hash')}"
                    )

                # Recompute the hash from the entry's own content and
                # confirm it matches what's stored -- this catches a line
                # whose content was edited but whose entry_hash field
                # wasn't (or couldn't be) correspondingly updated.
                recomputed = AuditEntry(
                    timestamp=record["timestamp"],
                    run_id=record["run_id"],
                    event=record["event"],
                    details=record["details"],
                    prev_hash=record["prev_hash"],
                ).entry_hash

                if recomputed != record.get("entry_hash"):
                    raise ChainIntegrityError(
                        f"Chain broken at line {line_num}: "
                        f"stored entry_hash does not match recomputed hash "
                        f"(content was altered after writing)"
                    )

                expected_prev = record["entry_hash"]

        return True


def write_immutable(data: Any, path: str | Path) -> Path:
    """
    Write `data` to `path` as JSON, then mark the file read-only.

    This is the module-9 "raw evidence is written once and made read-only"
    guard from docs/sdlc/04-threat-model.md §5.7. It is an evidentiary
    control, not a security boundary -- a privileged process can still
    chmod it back. Its purpose is to prevent *this pipeline* from
    accidentally mutating stage output in a later stage, and to make
    accidental edits visible (a permission error) rather than silent.

    Raises FileExistsError if the target already exists, to avoid silently
    overwriting prior evidence.
    """
    path = Path(path)
    if path.exists():
        raise FileExistsError(
            f"Refusing to overwrite existing evidence file: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)

    serialized = json.dumps(data, sort_keys=True, indent=2)
    path.write_text(serialized, encoding="utf-8")

    # Read-only for owner/group/other (0o444) -- evidentiary control, see
    # docstring above.
    os.chmod(path, 0o444)
    return path


def generate_manifest(evidence_dir: str | Path, manifest_path: str | Path) -> dict[str, str]:
    """
    Walk `evidence_dir` and write a {relative_path: sha256} manifest to
    `manifest_path`.

    Per docs/sdlc/04-threat-model.md §8 ("What this changes in Step 3's
    design"), inputs like the signature DB and CVE snapshot should also be
    hashed into this manifest when those modules exist -- not just the
    evidence this run produced. That wiring happens at the orchestrator
    level once those modules are built; this function just hashes whatever
    directory it's pointed at.
    """
    evidence_dir = Path(evidence_dir)
    manifest_path = Path(manifest_path)
    manifest: dict[str, str] = {}

    if evidence_dir.exists():
        for file_path in sorted(evidence_dir.rglob("*")):
            if file_path.is_file():
                digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
                manifest[str(file_path.relative_to(evidence_dir))] = digest

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8"
    )
    return manifest
