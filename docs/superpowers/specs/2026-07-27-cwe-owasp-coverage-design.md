# CWE Top 25 / OWASP Top 10 Coverage — Design

**Date:** 2026-07-27
**Status:** Approved, pending implementation plan
**Spans two repos:** `cleancoders/github-actions` (this one) and `cleancoders/agent-plugins`
(the `clojure-security` plugin, currently v0.10.0)

## Problem

Nobody could answer "does our security workflow cover the CWE Top 25?" without
reverse-engineering it — reading `security.yml`, pulling the clj-holmes rule list off
GitHub, and checking semgrep's language support tiers. The answer turned out to be
*~2 of 25*, and for OWASP Top 10:2025, *1 solid category of 10*.

The single largest gap is access control. A01 Broken Access Control has been OWASP's
#1 for four editions and maps to five separate CWE Top 25 entries (862, 863, 284, 639,
plus 306 under A07). No SAST tool covers it, so no amount of scanner tuning closes it.

Two goals, in order:

1. Catch more real vulnerabilities in cleancoders Clojure applications.
2. Have the coverage evidence fall out as a byproduct, in a form an auditor can read.

## Reference editions

This design targets the current editions. Both superseded their predecessors recently
and the mappings differ materially from the 2021/2024 lists most tooling still assumes.

- **CWE Top 25 (2025)** — published 2025-12-11.
  <https://cwe.mitre.org/data/definitions/1435.html>
- **OWASP Top 10:2025** — announced Nov 2025, finalized Jan 2026.
  <https://owasp.org/Top10/2025/>

Every CWE→OWASP mapping in this document was verified against the official per-category
CWE lists on owasp.org. Six mappings that "looked obvious" turned out to be wrong; see
[Verified mappings](#verified-mappings).

## Architecture

**The seam between the two repos is a shared ID vocabulary.** Everything else is
implementation.

Every detection — scanner rule or manual audit class — carries three labels:

| label | example | purpose |
|---|---|---|
| stable class name | `sql-injection` | already a convention in `security-audit.md` Step 6; groups findings over time |
| CWE ID(s) | `cwe-89` | maps to CWE Top 25 |
| OWASP category | `owasp-a05-2025` | maps to OWASP Top 10:2025 |

Those labels flow into four artifacts, each authoritative for its own slice:

```
clj-holmes rule YAML          ──tags──►  SARIF run report  (repo A, per-run evidence)
  properties.tags                            │
       │                                     └──► scanner rows of coverage matrix
       └──generated──► README matrix (repo A, capability doc)

skill class index table       ──────────►  manual rows of coverage matrix
  (repo B, hand-written)                     │
       │                                     └──► /security-audit findings carry the same IDs
       └──►  references/*.md  (loaded on demand)
```

Two distinct artifact types, often conflated:

| | what it is | produced when | answers |
|---|---|---|---|
| **capability doc** | "the workflow has a rule for CWE-79" | static; changes when rules change | "what is your coverage?" |
| **run report** | "on commit `abc123`, 0 CWE-79 findings" | per CI run / per audit | "did it run, and what did it find?" |

Run reports cannot go stale. The capability doc can, which is why the scanner half is
generated and CI-checked rather than hand-maintained.

### Phasing

**Phase 1 — `cleancoders/agent-plugins`.** Restructure the `clojure-security` skill,
add the missing vulnerability classes, add the route-inventory procedure, update
`/security-audit`.

**Phase 2 — `cleancoders/github-actions`.** Rewrite the clj-holmes job, add custom
rules, retarget semgrep, add zizmor + actionlint, emit SARIF, add inputs, generate the
matrix.

Phase 1 goes first because its class index defines the ID vocabulary. Phase 2's rules
then adopt IDs that already exist rather than inventing a parallel set.

Phase 1 ships useful with zero Phase 2 work. Phase 2 depends on Phase 1 only for the
vocabulary, not for code.

## Phase 1 — the `clojure-security` plugin

### File layout

```
plugins/clojure-security/
  skills/clojure-security/
    SKILL.md                          # index + judgment layer, ~150 lines
    references/
      injection.md
      access-control.md
      route-inventory.md              # a procedure, not a pattern class
      deserialization.md
      exceptional-conditions.md
      config-and-ops.md
  commands/security-audit.md
```

`SKILL.md` is currently 341 lines with 12 flat classes. Adding 15 classes inline would
roughly double it, and skills load fully into context on every invoke. So `SKILL.md`
retains only the overview, investigation order, severity heuristic, tool coverage and
blind-spot table, false-positive discipline, common-mistakes table, and the class index.
Classes move into `references/`, loaded on demand.

The existing `reflection` item stops being a class and becomes a practice note
(`*warn-on-reflection*`) — it was never a vulnerability, and the skill already says so.

### Class index

This table is the manual half of the coverage matrix. It lives in `SKILL.md`, which
makes the skill's own table of contents the deliverable — it cannot drift from the
skill it describes.

| class | CWE | OWASP 2025 | ref | status |
|---|---|---|---|---|
| `read-string-rce` | 94 | A05 | injection | existing |
| `dynamic-eval` | 94 | A05 | injection | existing |
| `sql-injection` | 89 | A05 | injection | existing |
| `hiccup-injection` | 79 | A05 | injection | existing |
| `cljs-dom-xss` | 79 | A05 | injection | existing |
| `macro-runtime-input` | 94 | A05 | injection | existing |
| `xxe` | 611 | **A02** | injection | existing |
| `java-deserialization` | 502 | A08 | deserialization | existing |
| `transitive-cve` | *varies per advisory* | A03 | deserialization | existing |
| `atom-toctou` | 367 | *(none)* | access-control | existing |
| `spec-malli-leak` | 209, 550 | A10 | exceptional-conditions | existing |
| `missing-authz` | 862 | A01 | access-control | new |
| `incorrect-authz` | 863, 284 | A01 | access-control | new |
| `idor` | 639 | A01 | access-control | new |
| `csrf` | 352 | A01 | access-control | new |
| `path-traversal` | 22 | A01 | access-control | new |
| `ssrf` | 918 | A01 | access-control | new |
| `missing-authn` | 306 | **A07** | access-control | new |
| `mass-assignment` | 915 | **A08** | access-control | new |
| `fail-open` | 636, 396 | A10 | exceptional-conditions | new |
| `security-misconfig` | 16, 614, 1004 | A02 | config-and-ops | new |
| `logging-failures` | 778, 532 | A09 | config-and-ops | new |
| `unrestricted-upload` | 434 | **A06** | config-and-ops | new |
| `resource-exhaustion` | 770, 400 | *(none)* | config-and-ops | new |
| `weak-crypto` | 327, 328 | A04 | config-and-ops | new |
| `insecure-tls-verification` | 295 | **A07** | config-and-ops | new |

`weak-crypto` and `insecure-tls-verification` are new to the skill but not to CI —
clj-holmes already hard-fails on MD5, SHA1, Blowfish, DESede, ECB, weak SSL context, and
insecure hostname verifiers. The skill currently lists crypto as out-of-scope, meaning it
has no guidance for triaging findings the pipeline already produces. These classes close
that seam.

`atom-toctou` (CWE-367) and `resource-exhaustion` (CWE-770/400) have **no** OWASP
Top 10:2025 category. That is a fact about the taxonomy, not an omission — CWE-770 is
#25 on the CWE Top 25 while appearing in no OWASP category.

### Route-inventory procedure

`references/route-inventory.md`. This is the part with no scanner equivalent, and the
reason Phase 1 delivers most of the value.

1. **Locate routes** — reitit route vectors, compojure `defroutes` / `GET` / `POST`,
   ring handler maps, c3kit.wire conventions.
2. **Per route, record**: path, method, handler var, authn guard in effect (walk the
   middleware stack and route-data `:middleware`), authz guard, and whether the handler
   ownership-checks any entity ID it accepts.
3. **Emit a matrix**: `route | method | handler | authn | authz | owns-check | notes`.
4. **Flag by sibling comparison, not absolute rule:**

   | condition | class | CWE |
   |---|---|---|
   | no authn guard, siblings under same prefix have one | `missing-authn` | 306 |
   | no authz guard, siblings under same prefix have one | `missing-authz` | 862 |
   | authn present, takes an entity ID, no ownership check | `idor` | 639 |
   | guard weaker than siblings | `incorrect-authz` | 863 |
   | mutating verb, no anti-forgery middleware | `csrf` | 352 |

5. Severity via the skill's existing three-axis heuristic. Any route whose guard cannot
   be traced is **provisional**, per existing discipline.

Sibling comparison is the mechanism that makes this work with no codebase convention
required. It infers intent from the codebase's own patterns rather than imposing one.
An app where *every* route is unauthenticated correctly produces no findings — it may
be a public API.

### `/security-audit` command changes

- **Step 3** stops restating the skill's grep block and references it instead. The
  command currently duplicates it with a `keep in sync` comment — an existing drift
  smell that predates this work.
- **New step** — route-inventory sweep. Runs on `all` scope; on `diff` / `staged` only
  when a route-defining file is in the diff, since it is token-heavy.
- **Step 6 report** — findings gain CWE and OWASP columns, a route-matrix section, and
  a coverage footer stating which classes were checked versus skipped.
- **New arg** for opt-in file output to `docs/security-audits/YYYY-MM-DD-<sha>.md`.
  Stdout remains the default, preserving the existing no-surprise-side-effects design.

## Phase 2 — the `security.yml` workflow

### Constraint: reusable workflows cannot reference their own repo

`uses: ./...` inside a reusable workflow resolves against the **caller's** checkout, and
GitHub exposes no reliable "what ref am I running at" variable for reusable workflows.
Fetching cleancoders rules therefore requires a second checkout with an explicit ref:

```yaml
- uses: actions/checkout@<sha>
  with:
    repository: cleancoders/github-actions
    ref: ${{ inputs.rules-ref }}      # default "v1"
    path: .cc-security-rules
```

A consumer pinning `@v2` or a SHA still gets `v1` rules unless they set `rules-ref`. A
composite action was considered — it *does* get `${{ github.action_path }}` — but still
needs a hardcoded ref in its own `uses:`, so it trades the same coupling for more
indirection. The explicit input is the honest version.

### Finding: upstream rules are currently unpinned

The existing job SHA-pins `clj-holmes-action`, but the action's entrypoint runs
`clj-holmes fetch-rules -r "$rules_repository"` against the default
`git://clj-holmes/clj-holmes-rules#main` — **at runtime, from a moving branch**. A
workflow that carefully SHA-pins every other third-party action is pulling its detection
rules unpinned. New input `holmes-upstream-ref` fixes this.

### Rewritten clj-holmes job

`clj-holmes` separates rule fetching from scanning, and `-d/--rules-directory` reads from
any local directory. Rules are plain YAML files, so unioning sources is a `cp`. The only
blocker was the action's rigid entrypoint (one `fetch-rules`, never passes `-d`), so the
action is dropped in favor of a direct binary install — matching the pattern
`security.yml` already uses for gitleaks.

```bash
set -euo pipefail
clj-holmes fetch-rules -r "$HOLMES_UPSTREAM_REF" -o /tmp/rules
cp -r .cc-security-rules/security-rules/clj-holmes/. /tmp/rules/
[ -d "$EXTRA_RULES_DIR" ] && cp -r "$EXTRA_RULES_DIR"/. /tmp/rules/
count=$(find /tmp/rules -name '*.yml' | wc -l)
[ "$count" -ge "$MIN_RULE_COUNT" ] || { echo "::error::only $count rules loaded"; exit 1; }
clj-holmes scan -p . -d /tmp/rules --fail-on-result -t sarif -o clj-holmes.sarif
```

Three-way union: upstream + cleancoders + optional consumer rules.

Two similarly-named directories, kept distinct on purpose:

| path | whose | contents |
|---|---|---|
| `security-rules/clj-holmes/` | this repo | the `cc-*` rules, checked out to `.cc-security-rules/` |
| `.security-rules/` | consumer repo | optional project-specific rules; the `extra-rules-dir` default |

`MIN_RULE_COUNT` is the count of upstream + cleancoders rules known at authoring time,
minus a small tolerance for upstream churn — concretely, `10` at the time of writing
(9 upstream security rules + 12 cleancoders rules = 21, floored well below to avoid
false alarms when upstream prunes a rule). It exists to catch *catastrophic* rule loss
(zero, or a handful), not to assert an exact inventory. `bin/check-rule-tags.sh` asserts
the cleancoders rules specifically.

### Why clj-holmes rather than semgrep for Clojure rules

clj-holmes rules support namespace-aware resolution:

```yaml
- pattern: "($& $custom-function $&)"
  namespace: hiccup.util
  function: raw-string
  custom-function?: true
```

This matches `(h/raw-string x)` where `h` is an alias. Semgrep's Clojure support is
**Experimental** tier (tree-sitter based) and cannot resolve aliases — it would need a
literal-text pattern per alias. clj-holmes also has a `precision` field that maps cleanly
onto the skill's existing provisional/false-positive discipline, and `-T/--rule-tags` for
filtering on the CWE/OWASP tags.

Trade-offs accepted: neither engine does dataflow or taint analysis, clj-holmes has no
first-class `cwe:`/`owasp:` metadata field (IDs ride in `properties.tags`, which still
flows into SARIF), and clj-holmes is a lower-activity upstream project than semgrep.

semgrep remains, retargeted as the **non-Clojure** engine — yaml, Dockerfile, JS/TS,
HTML — keeping `p/owasp-top-ten` and `p/default`, plus its five upstream Clojure rules
as redundant backup.

### Custom rules — `security-rules/clj-holmes/*.yml`

Each carries `class-*`, `cwe-*`, and `owasp-*` tags drawn from the Phase 1 index.

| rule | class | CWE | precision |
|---|---|---|---|
| `cc-sql-string-concat` | `sql-injection` | 89 | medium |
| `cc-hiccup-raw` | `hiccup-injection` | 79 | high |
| `cc-cljs-innerhtml` | `cljs-dom-xss` | 79 | high |
| `cc-cljs-eval` | `cljs-dom-xss` | 94 | high |
| `cc-dangerously-set-html` | `cljs-dom-xss` | 79 | high |
| `cc-shell-exec` | `dynamic-eval` | 78, 77 | medium |
| `cc-load-string` | `dynamic-eval` | 94 | medium |
| `cc-path-traversal` | `path-traversal` | 22 | low |
| `cc-explain-data-response` | `spec-malli-leak` | 209 | medium |
| `cc-generic-catch` | `fail-open` | 396, 636 | low |
| `cc-nippy-thaw` | `java-deserialization` | 502 | high |
| `cc-snakeyaml-unsafe` | `java-deserialization` | 502 | high |

`cc-path-traversal` and `cc-generic-catch` are `precision: low`. Without taint analysis,
`(io/file base x)` cannot be known to be user-derived, and many generic catches are
legitimate. They exist to feed the skill's triage, not to block.

There is deliberately **no** CSRF rule. Absence checks are poorly expressible in a
pattern language, so CWE-352 stays with the route-inventory sweep.

### Other jobs

| job | change | blocking |
|---|---|---|
| `clj-kondo` | unchanged | yes |
| `clj-holmes` | rewritten per above, emits SARIF | yes |
| `shellcheck` | unchanged | yes |
| `gitleaks` | unchanged | yes |
| `clj-watson` | unchanged | consumer input |
| `semgrep` | retargeted non-Clojure, adds `--sarif` | consumer input |
| `actionlint` | **new** — workflow syntax/expression correctness | yes |
| `zizmor` | **new** — Actions security (A02, A03) | advisory by default |

`zizmor` is advisory by default via a `zizmor-blocking` input because its default
settings light up existing repos; blocking on adoption would wedge consumers.
`actionlint` hard-fails because it is mostly correctness, not opinion. Both self-skip
when `.github/workflows` is absent, matching the existing `shellcheck-dir` idiom.

SARIF artifacts upload per job via `actions/upload-artifact` with `if: always()`, so a
failing scan still produces its evidence. Upload to GitHub code scanning is **not** in
scope: it requires GitHub Advanced Security on private repos, and `security.yml`'s
private-git-deps code path implies most consumers are private.

### New inputs

| input | default | purpose |
|---|---|---|
| `extra-rules-dir` | `.security-rules` | consumer clj-holmes rules; self-skips if absent |
| `rules-ref` | `v1` | ref for the cleancoders rules checkout |
| `holmes-upstream-ref` | `git://clj-holmes/clj-holmes-rules#main` | pin upstream rules |
| `zizmor-blocking` | `false` | advisory by default |

### Matrix generation

- `bin/check-rule-tags.sh` — fails if any rule lacks a `cwe-*`, `owasp-*`, or `class-*`
  tag.
- `bin/gen-coverage-matrix.sh` — emits scanner rows into the README; CI fails if the
  checked-in table is stale.

Both are bash + `yq`, so the existing `shellcheck` job covers them at no extra cost.

## Coverage matrix — end state

Status vocabulary, defined so the table cannot weasel:

| status | means |
|---|---|
| `scanned` | a blocking CI rule detects it |
| `scanned (low)` | rule exists at `precision: low`; feeds triage, does not block confidently |
| `audit` | manual step in `/security-audit`; no CI detection |
| `partial` | incidental coverage from a non-security tool |
| `n/a` | not reachable in JVM/JS Clojure |

### CWE Top 25 (2025)

| # | CWE | status | by |
|---|---|---|---|
| 1 | 79 XSS | scanned | `cc-hiccup-raw`, `cc-cljs-innerhtml`, `cc-dangerously-set-html` |
| 2 | 89 SQLi | scanned | `cc-sql-string-concat` |
| 3 | 352 CSRF | audit | route sweep |
| 4 | 862 Missing Authz | audit | route sweep |
| 5 | 787 OOB Write | n/a | — |
| 6 | 22 Path Traversal | scanned (low) + audit | `cc-path-traversal` |
| 7 | 416 Use After Free | n/a | — |
| 8 | 125 OOB Read | n/a | — |
| 9 | 78 OS Cmd Injection | scanned | `cc-shell-exec`, semgrep upstream |
| 10 | 94 Code Injection | scanned | upstream `clojure-read-string`, `cc-load-string` |
| 11 | 120 Buffer Overflow | n/a | — |
| 12 | 434 Upload | audit | `unrestricted-upload` |
| 13 | 476 NULL Deref | partial | clj-kondo `:type-mismatch` |
| 14 | 121 Stack Overflow | n/a | — |
| 15 | 502 Deserialization | scanned | `cc-nippy-thaw`, `cc-snakeyaml-unsafe` |
| 16 | 122 Heap Overflow | n/a | — |
| 17 | 863 Incorrect Authz | audit | route sweep |
| 18 | 20 Input Validation | audit | — |
| 19 | 284 Improper Access Ctl | audit | route sweep |
| 20 | 200 Info Exposure | scanned + audit | `cc-explain-data-response` |
| 21 | 306 Missing Authn | audit | route sweep |
| 22 | 918 SSRF | audit | — |
| 23 | 77 Command Injection | scanned | `cc-shell-exec` |
| 24 | 639 IDOR | audit | route sweep |
| 25 | 770 Throttling | audit | `resource-exhaustion` |

Six entries are `n/a` (memory safety on a memory-safe runtime), leaving **19
applicable**. Today: 2 partially covered. End state: 8 scanned, 10 audit, 1 partial.

### OWASP Top 10 (2025)

| cat | today | end state |
|---|---|---|
| A01 Broken Access Control | none | audit (route sweep) + 2 low-precision rules |
| A02 Security Misconfiguration | near none | scanned (zizmor, actionlint, xxe) + audit |
| A03 Supply Chain Failures | partial | scanned (clj-watson, gitleaks, actionlint, pinned upstream rules) |
| A04 Cryptographic Failures | solid, untriageable | scanned + audit class for triage |
| A05 Injection | partial | scanned (7 rules) + audit |
| A06 Insecure Design | none | **still effectively none** |
| A07 Authentication Failures | none | audit (route sweep authn column) |
| A08 Integrity Failures | partial | scanned (deser rules, gitleaks, pinned actions) |
| A09 Logging Failures | none | audit |
| A10 Exceptional Conditions | near none | scanned (low) + audit |

## Testing

### Primary failure mode

**A scan that runs with zero or partial rules passes green.** That is worse than no scan
— it produces evidence of coverage that did not happen. Guards:

- Hard-fail on `fetch-rules` failure. No `|| true` anywhere in a detection path. (The
  existing `clj-kondo --dependencies || true` is legitimately best-effort and stays.)
- Rule-count floor before scanning.
- Hard-fail on a bad `rules-ref`; silent fallback to upstream-only rules is exactly the
  false-confidence case.
- Hard-fail on malformed consumer YAML.

### Rules are built TDD, one at a time

```
spec-fixtures/
  vulnerable/sql_injection.clj      # must trip cc-sql-string-concat
  safe/sql_injection.clj            # must NOT trip it
  expectations.edn                  # fixture path → expected rule ids
```

1. **RED** — add the vulnerable fixture and its `expectations.edn` entry; `self-test.yml`
   fails because no rule matches.
2. **GREEN** — write the rule until it matches.
3. **REFACTOR** — add the safe fixture; confirm zero findings.

The self-test diffs actual findings against `expectations.edn` and fails on **both**
missing and unexpected findings. Unexpected-finding failures are what catch an upstream
rules-repo change silently altering behavior.

### Testability

| artifact | how |
|---|---|
| `cc-*` rules | deterministic — fixture diff in `self-test.yml` |
| `bin/check-rule-tags.sh` | deterministic — fixture rules with missing tags must fail |
| matrix staleness check | deterministic — mutate a rule tag, CI must fail |
| workflow inputs / self-skips | `self-test.yml` cases: absent `extra-rules-dir`, absent `.github/workflows`, no `deps.edn` |
| skill + `/security-audit` | **not deterministically testable** |

Skill behavior is LLM behavior; there is no assertion to write. The best available check
is a one-time manual verification during implementation: run `/security-audit` against a
fixture Clojure app carrying one planted instance of every class in the index, and
confirm each fires with the correct class name, CWE, and OWASP tag. This is a checklist
item in the plan, not automated coverage.

## Named limitations

These are stated in the shipped README, not just here. A coverage doc that overstates is
worse than none.

1. **No taint analysis anywhere.** Every `scanned` row is pattern matching. Neither
   clj-holmes nor semgrep OSS tracks dataflow, so a sink reached by an unusual path is
   missed. The matrix says "we look for this shape," not "we would catch this bug."
2. **A06 Insecure Design remains uncovered.** It is a threat-modeling category. The route
   matrix brushes it; nothing covers it.
3. **10 of 19 applicable CWEs depend on a manual audit run.** CI cannot invoke
   `/security-audit`. The README states an expected cadence; nothing enforces it.
   Enforcement (a freshness gate in `cleancoders.build.release`, a scheduled reminder) was
   considered and deliberately deferred to a future spec.
4. **Two rules do not block** — `cc-path-traversal`, `cc-generic-catch`.
5. **CWE-476 coverage is nominal.** `:type-mismatch` is a type linter, not NPE analysis.
6. **Rules track `rules-ref`, default `v1`.** Consumers on another ref get v1 rules
   unless they override.

## Verified mappings

Verified against the official per-category CWE lists on owasp.org. Six mappings that
looked obvious were wrong, which is the reason this section exists — anyone extending
the matrix should verify rather than infer.

| CWE | inferred | actual | source |
|---|---|---|---|
| 611 XXE | A05 Injection | **A02** | A02 list |
| 306 Missing Authn | A01 | **A07** | A01 list excludes it; A07 includes it |
| 915 Mass Assignment | A01 | **A08** | A08 list |
| 434 Upload | A02 or A05 | **A06** | A06 notable CWEs |
| 770 / 400 Throttling | A02 or A06 | **no category** | absent from A01, A02, A06, A10 |
| 295 TLS Verification | A04 Crypto | **A07** | A04 list excludes it; A07 includes it |

Additional confirmations: CWE-502 is in A08 only, **not** A05. CWE-22, 352, 918, 639,
862, 863, 284, and 200 are all A01 (40 CWEs total). CWE-209, 550, 636, 396, and 476 are
A10. CWE-367 (`atom-toctou`) appears in no category.

## Out of scope

- **OSSF Scorecard** — considered, deferred.
- **SARIF upload to GitHub code scanning** — needs GHAS on private repos.
- **CodeQL** — sees post-AOT bytecode, not Clojure idioms.
- **Convention-based authz enforcement** (mandating `require-auth!` wrappers) — invasive
  to consumer codebases and says nothing about whether a guard is *correct*.
- **Authz test-parity CI check** (route inventory vs. test inventory) — attractive for
  evidence, but a large upfront test-writing burden. Revisit after the route sweep has
  run against real repos.
- **Audit freshness enforcement** — see limitation 3.

## Note on spec location

This design spans two repos. It is committed to `cleancoders/github-actions` because that
is where the work was scoped, but Phase 1 implements in `cleancoders/agent-plugins`. The
Phase 1 plan should link back to this document.
