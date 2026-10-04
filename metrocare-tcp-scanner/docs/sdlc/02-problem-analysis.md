
# Step 2: Problem Analysis

> Part of the `metrocare-tcp-scanner` SDLC documentation.
> Source course reference: *Step 2: Problem Analysis*.
> Builds on [`01-problem-definition.md`](./01-problem-definition.md).

## 1. Develop a Strategy

A **staged, budget-aware pipeline** where each stage consumes the previous
stage's immutable output and produces its own. Three algorithmic layers do
the real work inside that pipeline:

- **Ordering/searching layer** — decide *what to probe first* and *what
  matches what* (port priority, signature matching).
- **Optimization layer (DP)** — decide *how to spend a limited budget* of
  time/connections across hosts and ports, and how to match imperfect
  version strings.
- **Classification layer (ML)** — decide *what a banner means* when no exact
  signature exists.

The strategy is **fallback-ordered**: exact signature match first (cheap,
deterministic, explainable) → fuzzy match second (cheap, still explainable)
→ ML only when both fail (more expensive, probabilistic, must be labeled as
such in the evidence). An audit-context finding backed by an exact signature
match is stronger evidence than one backed by a model's guess, and the
report must be able to say which kind it is.

**Concurrency strategy:** `asyncio` with a bounded semaphore around the
`socket`-based connect, since the task is I/O-bound. The algorithmic work
(DP scheduling, matching, classification) is CPU-bound but tiny relative to
network wait time, so it runs inline, with heavier ML inference pushed to a
thread executor if needed.

## 2. Identify Key Steps

1. Load and validate `scope.yaml` → authorized target list
2. Host discovery (lightweight liveness check) → live host list
3. Build the probe plan: **ordered** port list × **budgeted** schedule
   (search + DP) → probe plan
4. Execute `socket` connect scan per planned probe, jittered/bounded →
   `ports.json`
5. For each open port, grab banner (bounded read) → raw banner store
6. Match banner: exact (Aho-Corasick) → fuzzy (edit distance) → ML
   classifier → `services.json`
7. For services flagged as enumerable (FTP, SMB, HTTP), run read-only deep
   checks → enumeration evidence
8. Apply misconfiguration rules + CVE lookup against `services.json` +
   enumeration evidence → `findings.json`
9. Hash-chain every write, generate manifest → integrity evidence
10. Render per-stage report, then assemble final report

Step 3 (the probe plan) is where "searching" and "DP" actually live — it is
two decisions made together: order, then budget.

## 3. Explore Algorithms

### 3.1 Port ordering (searching family)

| Option                                                             | How it works                                                                                                 | Verdict                                                                                                 |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| Static priority list                                               | Common ports (21, 22, 23, 25, 80, 443, 3306, ...) first, rest after, as a fixed array                        | **Chosen for v1** — simple, matches nmap's own top-ports behavior, fully explainable in a report |
| Binary/adaptive search for timeout threshold                       | Probe a small calibration sample, binary-search between a fast and slow RTT bound to pick a per-host timeout | **Chosen** — adapts to the actual network/VM latency instead of a hardcoded timeout              |
| Learned port ordering (predict likely-open ports per host profile) | ML ranks ports by host fingerprint before scanning                                                           | Deferred to Phase 2 — needs training data not yet available                                            |

### 3.2 Banner-to-service matching (searching + DP)

| Option                                            | How it works                                                                        | Verdict                                                                                    |
| ------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Linear substring search per signature             | Loop every signature,`in` check                                                   | Rejected — O(n·m) over hundreds of signatures per banner, needless when a trie exists    |
| **Aho-Corasick multi-pattern match**        | Build one automaton from all signatures, scan each banner once                      | **Chosen** — O(banner length + number of matches), independent of signature DB size |
| **Edit distance (Levenshtein) fuzzy match** | DP table, compare near-misses (e.g.,`ProFTPD 1.3.1a` vs. known `ProFTPD 1.3.1`) | **Chosen** — classic DP, O(n·m) per comparison, only run on near-miss candidates   |
| Sequence alignment (Needleman-Wunsch)             | More general than edit distance, handles larger structural differences              | Deferred — overkill for short banner strings                                              |

### 3.3 Probe scheduling under a budget (DP)

| Option                     | How it works                                                                                                                                                                               | Verdict                                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Scan everything, no budget | Full port range × full host list, always                                                                                                                                                  | Rejected — ignores footprint/time constraints, risky on hospital legacy systems                                                                 |
| Greedy by priority only    | Always scan top ports first, truncate when time runs out                                                                                                                                   | Simple, but not optimal when hosts have different value/cost tradeoffs                                                                           |
| **0/1 knapsack DP**  | Each (host, port-group) probe has a cost (time) and a value (likelihood of being informative, from priority tier); DP selects the subset maximizing value under the time/connection budget | **Chosen** — directly answers "best use of the allotted scan window," explainable: the report can show the DP's chosen allocation and why |

### 3.4 Service classification for unknown banners (ML)

| Option                                                                                                                       | How it works                                              | Verdict                                                                                                                         |
| ---------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Signature-only, flag unknowns as "unidentified"                                                                              | No ML                                                     | Safe baseline, always available as fallback                                                                                     |
| **Text classifier (TF-IDF + logistic regression / small gradient-boosted model) over banner text + response behavior** | Trained on a lab-built labeled dataset                    | **Chosen for phase 2** — modest data needs, interpretable (top contributing tokens), appropriate for a small labeled set |
| Deep learning / LLM-based classification                                                                                     | Higher capacity, needs more data and compute              | Rejected for v1 — disproportionate to a small lab-derived dataset, harder to justify in an audit report                        |
| Anomaly detection for tarpits/honeypots                                                                                      | Statistical outlier detection on response timing/behavior | **Chosen, deferred to phase 2** — protects scan efficiency and the ML classifier from poisoned responses                 |

## 4. Evaluate Efficiency

Let **H** = hosts, **P** = ports per host, **S** = signatures in the DB,
**B** = banner length.

| Step                | Algorithm                               | Time complexity                                                | Space                                | Notes                                                            |
| ------------------- | --------------------------------------- | -------------------------------------------------------------- | ------------------------------------ | ---------------------------------------------------------------- |
| Port ordering       | Static priority list                    | O(P log P) once, O(1) lookup after                             | O(P)                                 | Negligible vs. network I/O                                       |
| Timeout calibration | Binary search                           | O(log(range)) probes                                           | O(1)                                 | A handful of extra connections, one-time per host                |
| Port scan execution | `socket` connect, bounded concurrency | O(H·P) attempts; wall-clock bounded by concurrency × timeout | O(concurrency) in flight             | I/O-bound; dominates real wall-clock time                        |
| Probe scheduling    | 0/1 knapsack DP                         | O(N·W), N = probe units, W = budget granularity               | O(N·W)                              | N is small (host×tier groups, not individual ports)             |
| Signature matching  | Aho-Corasick                            | O(B) per banner; O(ΣS) to build automaton once                | O(ΣS)                               | Automaton built once per run, reused for every banner            |
| Fuzzy matching      | Edit distance (DP)                      | O(len1·len2) per candidate pair, only on near-miss candidates | O(min(len1,len2)) with rolling array | Must be bounded — a malicious long banner is untrusted input    |
| ML classification   | Linear/tree model inference             | O(features), effectively O(B) for TF-IDF                       | O(model size)                        | Training is offline/one-time; inference is negligible per banner |
| Evidence hashing    | SHA-256 per write                       | O(data size)                                                   | O(1) streaming                       | Standard, not a bottleneck                                       |

**Bottleneck analysis:** the dominant cost is always network I/O (connection
attempts × timeout). None of the algorithmic layers (DP, Aho-Corasick, ML)
approach that cost — the intent is that they add *value* (better ordering,
better matching, better budget use) without becoming the new bottleneck.
Fuzzy matching is the one place that needs an explicit guard: an
attacker-controlled banner is exactly the kind of input that could be
crafted to maximize edit-distance cost, so banner length is bounded at
ingestion.

**Baseline to measure against:** a naive sequential scan with no ordering,
no budget, and linear signature search. Each chosen algorithm should be
benchmarked against that baseline in the lab (scan time, connections used,
match accuracy — with and without each optimization).
