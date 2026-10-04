
# metrocare-tcp-scanner

A Python TCP port scanner and enumeration toolkit built around a secure
SDLC. Developed as a simulated engagement for **MetroCare Hospital**:
discovers open TCP ports and services, grabs and preserves banners as
evidence, flags misconfigurations and CVE candidates, and generates
stage-by-stage audit-ready reports.

Uses `socket`-based connect scanning by default, with **searching** (port
prioritization, Aho-Corasick signature matching), **dynamic programming**
(probe-budget scheduling, fuzzy version matching), and **machine learning**
(unknown-service classification) applied where each adds measurable value
over a signature-only baseline.

> ⚠️ For use only against hosts explicitly listed in `scope.yaml` with
> written authorization. See [Authorization](#authorization).

## Scenario

MetroCare Hospital is preparing for a regulatory audit after IT noticed
unusual outbound traffic from a legacy server, and suspects misconfigurations
may be exposing the network to unauthorized access. This tool simulates the
internal assessment: scan the authorized scope, identify exposed services,
preserve evidence, and produce a report an auditor can follow. Full framing
in [`docs/sdlc/01-problem-definition.md`](docs/sdlc/01-problem-definition.md).

## Project status

Following the course's Process Algorithms SDLC. Documented so far:

| Step                                              | Doc                                                                         | Status         |
| ------------------------------------------------- | --------------------------------------------------------------------------- | -------------- |
| 1. Problem Definition                             | [`docs/sdlc/01-problem-definition.md`](docs/sdlc/01-problem-definition.md) | ✅ Done        |
| 2. Problem Analysis                               | [`docs/sdlc/02-problem-analysis.md`](docs/sdlc/02-problem-analysis.md)     | ✅ Done        |
| 3. Algorithm Design (pseudocode, data structures) | `docs/sdlc/03-algorithm-design.md`                                        | ✅ Done        |
| 4. Threat Model (STRIDE)                          | `docs/sdlc/04-threat-model.md`                                            | ✅ Done        |
| 5. Implementation                                 | `src/`                                                                    | ⬜ Not started |
| 6. Verification (tests, fuzzing, SAST, SCA)       | `tests/`                                                                  | ⬜ Not started |
| 7. Release & Maintenance                          | —                                                                          | ⬜ Not started |

Do not start implementation before Step 3 and the threat model are written —
the banner parser and fuzzy matcher both handle untrusted input and need
their constraints fixed before code is written against them.

## Repository structure

```Python
metrocare-tcp-scanner/
├── README.md                     ← this file
├── docs/
│   └── sdlc/
│       ├── 01-problem-definition.md
│       ├── 02-problem-analysis.md
│       ├── 03-algorithm-design.md
│       └── 04-threat-model.md
├── config/
│   ├── scope.example.yaml        ← template; real scope.yaml is git-ignored
│   └── scan-profile.yaml         ← timeouts, concurrency caps, jitter range
├── signatures/
│   └── banner-signatures.json    ← versioned, dated signature DB
├── src/
│   ├── scope/                    ← Step 1: authorization gate
│   ├── discovery/                ← Step 2: host liveness
│   ├── scheduler/                ← Step 3/4: port ordering + DP budget
│   ├── scanner/                  ← Step 4: socket connect scan
│   ├── banners/                  ← Step 5: bounded banner grab
│   ├── identify/                 ← Step 6: signature / fuzzy / ML matching
│   ├── enumerate/                ← Step 7: read-only service enumeration
│   ├── analyze/                  ← Step 8: misconfig + CVE findings
│   ├── evidence/                 ← Step 9: hash chain, manifest
│   └── report/                   ← Step 10: stage + final reports
├── models/
│   └── classifier.joblib         ← ML artifact, versioned (phase 2+)
├── tests/
│   ├── unit/
│   ├── fuzz/                     ← banner-parser fuzz corpus
│   └── lab/                      ← integration tests against the Flatiron lab
├── evidence/                     ← git-ignored; scan run output lands here
└── requirements.txt
```

This mirrors the subproblem breakdown in Step 1 — one module per pipeline
stage, one report section per stage, one evidence subdirectory per stage.

## Pipeline (recap)

```
scope.yaml → discovery → probe plan (ordering + DP budget) → socket scan
  → banner grab → identify (signature → fuzzy → ML) → enumeration
  → analysis (misconfig + CVE) → evidence hashing → stage + final reports
```

Full detail in [`docs/sdlc/02-problem-analysis.md`](docs/sdlc/02-problem-analysis.md).

## Scan profiles

| Profile     | Mechanism                     | Privilege             | Default                 |
| ----------- | ----------------------------- | --------------------- | ----------------------- |
| `connect` | `socket` full TCP handshake | None                  | ✅ Yes                  |
| `stealth` | Raw socket SYN scan           | Root /`CAP_NET_RAW` | Designed, not yet built |

Both profiles log identically — there is no hidden/unlogged mode. See the
scan-profile discussion earlier in this chat for why `stealth` reduces
footprint but does not guarantee evasion.

## Authorization

- Every run requires a `scope.yaml` listing authorized targets, an
  engagement window, and the authorizer's name.
- Any target not in scope is rejected before a socket is opened, and the
  rejection is logged.
- Default scan profile is non-intrusive and non-credentialed; no
  exploitation, credential guessing, or writes to discovered shares.

## Tools and dependencies

| Area                        | Tool / library                                          | Purpose                                               |
| --------------------------- | ------------------------------------------------------- | ----------------------------------------------------- |
| Scanning                    | `socket`, `asyncio` (stdlib)                        | Connect scan, concurrency                             |
| Network/scope parsing       | `ipaddress` (stdlib)                                  | CIDR/IP validation                                    |
| Config/scope validation     | `pydantic`                                            | Typed, validated`scope.yaml` / config loading       |
| Signature matching          | `pyahocorasick`                                       | Multi-pattern banner matching                         |
| Fuzzy matching              | `python-Levenshtein` (or stdlib `difflib` fallback) | Edit-distance version matching                        |
| ML classification (phase 2) | `scikit-learn`                                        | TF-IDF + classifier for unknown banners               |
| Cross-check scanning        | `python-nmap` / `libnmap`                           | Parse nmap XML for validation against our own results |
| Evidence integrity          | `hashlib` (stdlib), `cryptography`                  | Hash chaining, optional signing                       |
| Reporting                   | `Jinja2`                                              | Stage report templates (Markdown)                     |
| Final report                | `python-docx`                                         | Assembled DOCX                                        |
| PDF export                  | `WeasyPrint` or `ReportLab`                         | PDF rendering                                         |
| Charts                      | `matplotlib`                                          | Findings/port summary visuals in reports              |
| Testing                     | `pytest`                                              | Unit and lab integration tests                        |
| Fuzzing                     | `atheris` or `hypothesis`                           | Banner parser fuzzing                                 |
| SAST                        | `bandit`                                              | Static analysis for Python security issues            |
| SCA                         | `pip-audit`                                           | Dependency vulnerability scanning                     |
| CVE data                    | Dated local NVD snapshot                                | Version → CVE candidate lookup                       |

Lab environment (not a dependency of the tool itself, but required to test
it): Kali Linux + Metasploitable on an isolated VirtualBox NAT network
(`192.168.100.0/24`, named `Flatiron` in the source lesson).

`requirements.txt` should pin exact versions once implementation starts, so
every evidence manifest can record the dependency versions used for that
run (reproducibility requirement from Step 1).

## Standards and references

- Penetration Testing Execution Standard (PTES) — overall process
- NIST SP 800-115 — security testing methodology
- NIST SP 800-86 — evidence handling
- CVSS — severity scoring
- HIPAA Security Rule — audit-control mapping (default assumption; confirm
  with compliance contact)

## Non-goals (v1)

Source IP spoofing/decoys, packet fragmentation evasion, UDP scanning,
exploitation, credential guessing, writes to discovered shares. See Step 1
doc for the full constraint list.

## Next steps

1. Write `docs/sdlc/03-algorithm-design.md` — pseudocode and data structures
   per module.
2. Write `docs/sdlc/04-threat-model.md` — STRIDE, with emphasis on banners
   as untrusted input (feeds directly into `src/banners/` and
   `src/identify/`).
3. Only then begin `src/` implementation, stage by stage, with tests written
   alongside each module.
