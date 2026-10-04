
# Step 1: Problem Definition — Planning and Requirements

> Part of the `metrocare-tcp-scanner` SDLC documentation.
> Source course reference: *Step 1: Problem Definition — Planning and Requirements*.

## 1. Identify the Problem

MetroCare Hospital is preparing for a regulatory audit after IT noticed unusual
outbound traffic from a legacy server, and suspects misconfigurations may be
exposing the network to unauthorized access.

**Problem this tool solves:** within an explicitly authorized scope, determine
which TCP ports are open on target hosts, identify the service and version
behind each open port, capture and preserve its banner as evidence, flag
misconfigurations and outdated/vulnerable versions, and produce a
stage-by-stage audit trail and report suitable for a compliance review — all
without disrupting hospital operations and without exceeding the footprint the
rules of engagement allow.

**Explicitly out of scope:**

- Detecting the outbound traffic itself (that is flow/log analysis, a
  different data source than a port scanner).
- Exploitation of anything found.
- Guaranteeing the scan is undetectable — detection-resistance is a
  footprint-reduction goal (jitter, ordering, concurrency caps), not
  invisibility. Any TCP SYN or connect attempt is a real network event and
  can be seen by a NIDS, EDR, or the target's own logs.

## 2. Determine Inputs and Outputs

### Inputs

| Input                   | Description                                                                        | Required?                 |
| ----------------------- | ---------------------------------------------------------------------------------- | ------------------------- |
| `scope.yaml`          | Authorized IPs/CIDRs/hostnames, excluded hosts, engagement window, authorizer name | Yes — hard gate          |
| Target list             | Derived from the scope file, never typed ad hoc at runtime                         | Yes                       |
| Port range              | Default top-N common ports, full 1–65535, or custom list                          | Yes (has default)         |
| `ScanProfile`         | `connect` (socket-based, default) or `stealth` (raw socket, future)            | Yes (default:`connect`) |
| Rate/concurrency limits | Max concurrent connections, delay/jitter range, per-host cap                       | Yes (has default)         |
| Timeout settings        | Connect timeout, banner-read timeout                                               | Yes (has default)         |
| Signature DB            | Known banner patterns → service/version, with a version/date stamp                | Yes                       |
| CVE snapshot            | Dated local copy of version→CVE mappings                                          | Optional for v1           |
| ML model artifact       | Trained classifier + its version hash                                              | Optional, phase 2+        |
| Operator identity       | Who is running the scan, for the audit log                                         | Yes                       |

### Outputs

| Output                          | Description                                                                                           |
| ------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `ports.json`                  | Per host: port, state (open/closed/filtered), timestamp                                               |
| `services.json`               | Per open port: identified service, version (if known), confidence/source (signature vs ML vs unknown) |
| `banners.jsonl`               | Raw (base64) and sanitized banner text per port, immutable                                            |
| `findings.json`               | Misconfigurations and CVE candidates, each tagged`confirmed` or `inferred`                        |
| Stage reports (Markdown)        | One per pipeline stage                                                                                |
| Final`report.docx` / `.pdf` | Assembled, audit-ready document                                                                       |
| `audit.log`                   | Append-only, hash-chained record of every action taken                                                |
| `MANIFEST.sha256`             | Integrity manifest over the whole evidence folder                                                     |

## 3. Set Constraints and Requirements

### Hard constraints (must pass before anything else runs)

- No scan executes against a target not present in `scope.yaml`. Checked
  before socket creation, not after.
- Default `ScanProfile` is `connect` (plain `socket`), non-intrusive,
  non-credentialed.
- Concurrency/rate caps enforced regardless of user input (hard ceiling the
  config cannot override), since legacy clinical-adjacent systems can fail
  under load.
- Raw banner bytes are immutable once written; analysis stages never mutate
  stage 1/2 evidence in place.
- No exploitation code, no credential guessing, no write operations against
  discovered shares — read-only enumeration only.

### Functional requirements

- Support IPv4 initially (IPv6 stretch goal).
- Distinguish open / closed / filtered states.
- Grab banners with a bounded read (size + timeout limits — banners are
  untrusted input).
- Log every probe attempt, success, failure, and out-of-scope rejection.
- Produce a stage report automatically after each pipeline stage completes.

### Non-functional requirements

- **Performance:** scan the top 1000 ports of a single host within a target
  time budget, measured against the lab environment.
- **Footprint:** jittered timing, randomized port order, bounded concurrency —
  reduce signal, do not attempt to fake invisibility.
- **Auditability:** hash-chained log, immutable raw evidence, reproducible
  config/version stamps.
- **Portability:** standard-library `socket`, no root required for the
  default profile.

### Explicit non-goals for v1

Source IP spoofing/decoys, packet fragmentation evasion, UDP scanning,
SYN/stealth profile implementation (designed now, built later).

## 4. Break into Subproblems

1. **Scope and authorization gate** — parse/validate `scope.yaml`, reject
   anything outside it, log rejections.
2. **Host discovery** — confirm liveness before port probing.
3. **Port scanning** — `socket` connect loop: async, concurrency-bounded,
   jittered, randomized order, common-ports-first priority.
4. **Probe scheduling under budget** — decide which ports/hosts get probed
   first given a time/connection budget.
5. **Banner grabbing** — bounded-size, bounded-time read immediately after
   connect; store raw immutable copy.
6. **Service/version identification** — signature matching, fuzzy matching,
   ML classification fallback.
7. **Enumeration of flagged services** — read-only deeper checks (e.g.,
   anonymous FTP, SMB share listing) only where warranted.
8. **Misconfiguration and CVE-candidate analysis** — rule-based checks plus
   version→CVE lookup, each finding tagged with confidence and validation
   status.
9. **Evidence integrity** — hash chaining, manifest generation, immutability
   enforcement.
10. **Report generation** — per-stage Markdown, then assembled DOCX/PDF, with
    "analyst review required" flags on judgment-based sections.

Each subproblem maps to one module, one stage directory in the evidence
structure, and one report section.

## Evidence directory structure (reference)

```
evidence/MC-<date>-<run>/
├── 00_engagement/   scope.yaml, engagement.json
├── 01_recon/        raw/ (scan.log, nmap.xml)  parsed/ports.json  report_stage1.md
├── 02_services/     raw/banners.jsonl  parsed/services.json       report_stage2.md
├── 03_enumeration/  raw/ (ftp_anon.txt, smb_enum.txt, enum4linux.txt)  report_stage3.md
├── 04_analysis/     findings.json  report_stage4.md
├── 05_final/        report.docx, report.pdf
├── audit.log        append-only, hash-chained
└── MANIFEST.sha256  (+ signature)
```
