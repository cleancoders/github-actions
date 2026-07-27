# security.yml CWE/OWASP Coverage — Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace `clj-holmes-action` with a direct binary install so upstream, cleancoders, and consumer rules can be unioned; add 12 custom Clojure detection rules covering CWE Top 25 entries; add `actionlint` and `zizmor`; emit SARIF evidence artifacts; and generate the scanner half of the coverage matrix from rule tags.

**Architecture:** `clj-holmes` separates rule fetching from scanning (`fetch-rules -o <dir>`, `scan -d <dir>`), and rules are plain YAML, so unioning sources is a `cp`. The action's entrypoint hardcodes one fetch and never passes `-d`, so it goes. Every custom rule carries `class-*`, `cwe-*`, and `owasp-*` tags matching the Phase 1 skill index; a generator reads those tags to produce the README coverage table, and CI fails if a rule lacks tags or the table is stale. Rules are built TDD against paired vulnerable/safe fixtures.

**Tech Stack:** GitHub Actions reusable workflows, `clj-holmes` v1.4.3 (shape-shifter pattern DSL), bash + `yq` + `jq`, SARIF.

**Spec:** `docs/superpowers/specs/2026-07-27-cwe-owasp-coverage-design.md`

**Depends on:** Phase 1 (`cleancoders/agent-plugins`, plan `2026-07-27-clojure-security-cwe-owasp-coverage.md`) for the class-name and taxonomy vocabulary only — not for code. Phase 1 must be merged before Task 2, because rule `class-*` tags must match its class index.

## Global Constraints

- **Reference editions:** CWE Top 25 (2025), OWASP Top 10:2025. Never cite 2021 or 2024.
- **Never infer a CWE→OWASP mapping.** Use only mappings from the spec's verified table. Six obvious-looking inferences were wrong.
- **No `|| true` in any detection path.** A scan that runs with zero rules passes green, which is worse than no scan. The existing `clj-kondo --dependencies || true` is legitimately best-effort and stays.
- **SHA-pin every third-party action**, with a trailing comment naming the version — existing convention throughout `security.yml`.
- **Every job self-skips gracefully** when its inputs are absent, matching the existing `shellcheck-dir` / `src-paths` idiom. This repo has no root `deps.edn`, `src/`, or `bin/` precisely so those paths get exercised.
- **`clj-holmes` version: `1.4.3`**, asset `clj-holmes-ubuntu-latest`, installed via the release URL — the pattern `security.yml` already uses for gitleaks.
- **Rule ids are prefixed `cc-`** and must not collide with upstream ids.
- **Class names are fixed by Phase 1.** Valid values: `sql-injection`, `hiccup-injection`, `cljs-dom-xss`, `dynamic-eval`, `path-traversal`, `spec-malli-leak`, `fail-open`, `java-deserialization`.

---

## File Structure

| path | responsibility | task |
|---|---|---|
| `security-rules/clj-holmes/*.yml` | the 12 `cc-*` detection rules | 2–7 |
| `test/fixtures/vulnerable/*.clj[s]` | one planted instance per rule | 2–7 |
| `test/fixtures/safe/*.clj[s]` | the false-positive regression corpus | 2–7 |
| `test/fixtures/expectations.tsv` | `rule-id<TAB>fixture-path` | 1–7 |
| `bin/test-rules.sh` | scans fixtures, diffs against expectations | 1 |
| `bin/check-rule-tags.sh` | fails on a rule missing `class-`/`cwe-`/`owasp-` tags | 1 |
| `bin/gen-coverage-matrix.sh` | emits scanner rows into README | 10 |
| `.github/workflows/security.yml` | the product | 1, 8, 9 |
| `.github/workflows/self-test.yml` | exercises the product | 1, 11 |
| `README.md` | inputs table + coverage matrix + limitations | 10, 11 |

**Directory naming, kept deliberately distinct:** `security-rules/clj-holmes/` is *ours*, checked out into a consumer's workspace at `.cc-security-rules/`. `.security-rings/` — no. `.security-rules/` is the *consumer's* optional directory, the `extra-rules-dir` default. Two similar names, different owners.

---

### Task 1: Rule harness and the clj-holmes job rewrite

The foundational task. Establishes the union, the safety floor, the tag check, and the fixture loop — then proves all of it with one rule (`cc-hiccup-raw`, chosen because it is `precision: high` and exercises namespace-alias resolution, the capability that justified picking clj-holmes over semgrep).

**Files:**
- Create: `security-rules/clj-holmes/cc-hiccup-raw.yml`
- Create: `test/fixtures/vulnerable/hiccup_raw.clj`, `test/fixtures/safe/hiccup_raw.clj`, `test/fixtures/expectations.tsv`
- Create: `bin/test-rules.sh`, `bin/check-rule-tags.sh`
- Modify: `.github/workflows/security.yml` (clj-holmes job, new inputs)
- Modify: `.github/workflows/self-test.yml`

**Interfaces:**
- Produces: `bin/test-rules.sh` (exit 0 iff findings match `expectations.tsv`); `bin/check-rule-tags.sh` (exit 0 iff every rule is fully tagged); `expectations.tsv` format `<rule-id>\t<fixture-path>`; inputs `extra-rules-dir`, `rules-ref`, `holmes-upstream-ref`, `holmes-ignored-paths`. Tasks 2–7 append one line per rule to `expectations.tsv` and add fixtures.

- [ ] **Step 1: Write the failing fixture harness**

Create `bin/test-rules.sh`:

```bash
#!/usr/bin/env bash
# Scans the fixture corpus with ONLY the cleancoders rules and diffs the result
# against expectations.tsv. Fails on missing findings (a rule stopped matching)
# and on unexpected ones (a rule got too broad, or an upstream change altered
# behaviour). Both directions matter: a silently non-matching rule still appears
# in the coverage matrix, which is exactly the false confidence this repo exists
# to prevent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${ROOT}/security-rules/clj-holmes"
FIXTURES="${ROOT}/test/fixtures"
EXPECTED="${FIXTURES}/expectations.tsv"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

command -v clj-holmes >/dev/null || { echo "clj-holmes not installed"; exit 1; }
command -v jq         >/dev/null || { echo "jq not installed"; exit 1; }

# --- vulnerable corpus: every expected finding must appear -------------------
clj-holmes scan -p "${FIXTURES}/vulnerable" -d "${RULES}" \
  --no-fail-on-result -t sarif -o "${WORK}/vuln.sarif" >/dev/null

# SARIF: ruleId plus the basename of the file it fired on.
jq -r '.runs[].results[]
       | .ruleId + "\t" + (.locations[0].physicalLocation.artifactLocation.uri
                           | split("/") | last)' \
  "${WORK}/vuln.sarif" | sort -u > "${WORK}/actual.tsv"

grep -v '^#' "${EXPECTED}" | grep -v '^[[:space:]]*$' | sort -u > "${WORK}/expected.tsv"

missing="$(comm -23 "${WORK}/expected.tsv" "${WORK}/actual.tsv")"
unexpected="$(comm -13 "${WORK}/expected.tsv" "${WORK}/actual.tsv")"

status=0
if [ -n "${missing}" ]; then
  echo "MISSING findings (rule stopped matching):"; echo "${missing}"; status=1
fi
if [ -n "${unexpected}" ]; then
  echo "UNEXPECTED findings (rule too broad):"; echo "${unexpected}"; status=1
fi

# --- safe corpus: must be completely clean -----------------------------------
clj-holmes scan -p "${FIXTURES}/safe" -d "${RULES}" \
  --no-fail-on-result -t sarif -o "${WORK}/safe.sarif" >/dev/null

safe_hits="$(jq -r '.runs[].results[]
                    | .ruleId + " in " + .locations[0].physicalLocation.artifactLocation.uri' \
             "${WORK}/safe.sarif")"
if [ -n "${safe_hits}" ]; then
  echo "FALSE POSITIVES on the safe corpus:"; echo "${safe_hits}"; status=1
fi

[ "${status}" -eq 0 ] && echo "rule tests passed"
exit "${status}"
```

Create `test/fixtures/expectations.tsv`:

```
# <rule-id>	<fixture basename>   — tab-separated. One line per expected finding.
cc-hiccup-raw	hiccup_raw.clj
```

- [ ] **Step 2: Run the harness to verify it fails**

Run: `bash bin/test-rules.sh`
Expected: FAIL. Either `clj-holmes not installed` (install it first, Step 3) or, once installed, `MISSING findings (rule stopped matching): cc-hiccup-raw hiccup_raw.clj` — because neither the rule nor the fixtures exist yet.

- [ ] **Step 3: Install clj-holmes locally**

```bash
curl -L https://github.com/clj-holmes/clj-holmes/releases/download/v1.4.3/clj-holmes-ubuntu-latest \
  -o /tmp/clj-holmes
sudo install -m 755 /tmp/clj-holmes /usr/local/bin/clj-holmes
clj-holmes --help >/dev/null && echo ok
```

On macOS substitute `clj-holmes-macos-latest`.

- [ ] **Step 4: Write the fixtures**

`test/fixtures/vulnerable/hiccup_raw.clj`:

```clojure
(ns fixtures.hiccup-raw
  (:require [hiccup.util :as hu]
            [hiccup.core :as h]))

;; Aliased call — the whole reason this repo uses clj-holmes rather than
;; semgrep. Semgrep's experimental Clojure tree-sitter cannot resolve `hu` back
;; to hiccup.util and would need one literal pattern per alias.
(defn render-bio [user]
  [:div.bio (hu/raw-string (:bio user))])

(defn render-post [post]
  [:article (h/raw (:body post))])
```

`test/fixtures/safe/hiccup_raw.clj`:

```clojure
(ns fixtures.hiccup-raw-safe
  (:require [hiccup.util :as hu]))

;; Constant markup is not attacker-controlled — must NOT fire.
(def ^:private +divider+ (hu/raw-string "<hr class=\"rule\">"))

;; Ordinary hiccup auto-escapes; no raw call at all.
(defn render-bio [user]
  [:div.bio (:bio user)])

(defn divider [] [:div +divider+])
```

- [ ] **Step 5: Write the rule**

`security-rules/clj-holmes/cc-hiccup-raw.yml`:

```yaml
- id: cc-hiccup-raw
  name: Unescaped HTML via hiccup raw / raw-string
  severity: error
  message: >-
    hiccup.util/raw-string and hiccup.core/raw bypass Hiccup's auto-escaping. If
    the value is user-controlled this is stored or reflected XSS. Sanitize with
    the OWASP Java HTML Sanitizer, or drop the raw call and let Hiccup escape.
  properties:
    precision: high
    tags:
      - security
      - class-hiccup-injection
      - cwe-79
      - owasp-a05-2025
  patterns:
    - patterns-either:
      - pattern: "($& $custom-function $&)"
        namespace: hiccup.util
        function: raw-string
        custom-function?: true
      - pattern: "($& $custom-function $&)"
        namespace: hiccup.core
        function: raw
        custom-function?: true
```

- [ ] **Step 6: Run the harness to verify it passes**

Run: `bash bin/test-rules.sh`
Expected: `rule tests passed`.

If the safe fixture trips the rule, that is real signal, not a test to weaken: clj-holmes has no dataflow, so it cannot tell a constant from user input. Resolve by removing the constant `raw-string` call from the safe fixture and noting the limitation in the rule's `message` — do **not** loosen the pattern, and do **not** delete the safe fixture.

- [ ] **Step 7: Write the tag checker**

Create `bin/check-rule-tags.sh`:

```bash
#!/usr/bin/env bash
# Every cleancoders rule must carry class-, cwe-, and owasp- tags. The coverage
# matrix in README.md is generated from these tags, so an untagged rule is a
# detection that exists but is invisible to the evidence trail.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${ROOT}/security-rules/clj-holmes"

command -v yq >/dev/null || { echo "yq not installed"; exit 1; }

status=0
for f in "${RULES}"/*.yml; do
  id="$(yq -r '.[0].id' "${f}")"
  tags="$(yq -r '.[0].properties.tags[]' "${f}" 2>/dev/null || true)"

  case "${id}" in
    cc-*) ;;
    *) echo "${f}: rule id '${id}' must be prefixed cc-"; status=1 ;;
  esac

  echo "${tags}" | grep -qE '^class-[a-z0-9-]+$' \
    || { echo "${f}: missing a class- tag"; status=1; }
  echo "${tags}" | grep -qE '^cwe-[0-9]+$' \
    || { echo "${f}: missing a cwe- tag"; status=1; }

  owasp_count="$(echo "${tags}" | grep -cE '^owasp-a(0[1-9]|10)-2025$' || true)"
  [ "${owasp_count}" -eq 1 ] \
    || { echo "${f}: needs exactly one owasp-aNN-2025 tag (found ${owasp_count})"; status=1; }
done

[ "${status}" -eq 0 ] && echo "all rules tagged"
exit "${status}"
```

- [ ] **Step 8: Verify the tag checker passes, then prove it can fail**

Run: `bash bin/check-rule-tags.sh`
Expected: `all rules tagged`

Now prove it is not vacuous:
```bash
yq -i 'del(.[0].properties.tags[] | select(. == "cwe-79"))' security-rules/clj-holmes/cc-hiccup-raw.yml
bash bin/check-rule-tags.sh; echo "exit=$?"
git checkout security-rules/clj-holmes/cc-hiccup-raw.yml
```
Expected: `missing a cwe- tag` and `exit=1`, then the file is restored.

- [ ] **Step 9: Rewrite the clj-holmes job in security.yml**

Replace the entire `clj-holmes:` job with:

```yaml
  clj-holmes:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10  # v6
      - name: Check out cleancoders detection rules
        # A reusable workflow cannot reference files from its own repo: `uses: ./`
        # resolves against the CALLER's checkout, and GitHub exposes no reliable
        # "what ref am I running at" variable for reusable workflows. Hence an
        # explicit ref. A consumer on a non-v1 ref must set rules-ref to match.
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10  # v6
        with:
          repository: cleancoders/github-actions
          ref: ${{ inputs.rules-ref }}
          path: .cc-security-rules
      - name: Install clj-holmes
        shell: bash
        run: |
          set -euo pipefail
          VER=1.4.3
          curl -fsSL "https://github.com/clj-holmes/clj-holmes/releases/download/v${VER}/clj-holmes-ubuntu-latest" \
            -o /tmp/clj-holmes
          sudo install -m 755 /tmp/clj-holmes /usr/local/bin/clj-holmes
      - name: Assemble rule set
        # Three-way union: upstream + cleancoders + optional consumer. Rules are
        # plain YAML in a directory, so unioning is a cp; `scan -d` reads any
        # local dir. This is why the stock clj-holmes-action was dropped — its
        # entrypoint hardcodes one fetch-rules and never passes -d.
        shell: bash
        env:
          HOLMES_UPSTREAM_REF: ${{ inputs.holmes-upstream-ref }}
          EXTRA_RULES_DIR: ${{ inputs.extra-rules-dir }}
        run: |
          set -euo pipefail
          clj-holmes fetch-rules -r "$HOLMES_UPSTREAM_REF" -o /tmp/rules
          cp -r .cc-security-rules/security-rules/clj-holmes/. /tmp/rules/
          if [ -d "$EXTRA_RULES_DIR" ]; then
            echo "::notice::adding consumer rules from $EXTRA_RULES_DIR"
            cp -r "$EXTRA_RULES_DIR"/. /tmp/rules/
          fi
          # A scan with no rules exits 0 and looks like a clean build. Floor set
          # well below the real count (9 upstream + 12 cleancoders) so upstream
          # pruning a rule does not false-alarm; this catches catastrophic loss.
          count=$(find /tmp/rules -name '*.yml' | wc -l)
          echo "loaded $count rules"
          if [ "$count" -lt 10 ]; then
            echo "::error::only $count rules loaded; refusing to scan"
            exit 1
          fi
      - name: clj-holmes SAST
        shell: bash
        env:
          IGNORED: ${{ inputs.holmes-ignored-paths }}
        run: |
          set -euo pipefail
          args=(scan -p . -d /tmp/rules --fail-on-result -t sarif -o clj-holmes.sarif)
          [ -n "$IGNORED" ] && args+=(-i "$IGNORED")
          clj-holmes "${args[@]}"
      - name: Upload SARIF
        if: always()   # evidence of a FAILING scan is the evidence most worth keeping
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02  # v4.6.2
        with:
          name: clj-holmes-sarif
          path: clj-holmes.sarif
          retention-days: 90
```

- [ ] **Step 10: Add the four new inputs**

In the `workflow_call.inputs` block:

```yaml
      extra-rules-dir:
        description: "Consumer-supplied clj-holmes rules; unioned in when the directory exists"
        type: string
        default: ".security-rules"
      rules-ref:
        description: >-
          Ref of cleancoders/github-actions to source detection rules from. Must match
          the ref this workflow is consumed at; a reusable workflow cannot determine
          its own ref.
        type: string
        default: "v1"
      holmes-upstream-ref:
        description: >-
          Upstream clj-holmes rules repo. Pinned rather than floating: the stock action
          fetched #main at runtime, leaving detection rules unpinned in a workflow that
          SHA-pins everything else.
        type: string
        default: "git://clj-holmes/clj-holmes-rules#main"
      holmes-ignored-paths:
        description: "Regex of paths clj-holmes must skip (e.g. deliberately-vulnerable test fixtures)"
        type: string
        default: ""
```

- [ ] **Step 11: Wire the fixture tests into self-test.yml**

Two changes. First, the existing `security` job must not scan our own planted vulnerabilities, and must test *this commit's* rules rather than released ones:

```yaml
  security:
    uses: ./.github/workflows/security.yml
    with:
      # Without this, the rules checkout would fetch v1 from GitHub and a PR
      # would be validated against RELEASED rules instead of its own.
      rules-ref: ${{ github.sha }}
      # test/fixtures/ contains deliberate vulnerabilities; scanning them would
      # fail this repo's own build.
      holmes-ignored-paths: "test/fixtures"
      # This repo now has bin/, so shellcheck no longer self-skips here. The
      # skip path is covered by security-skips below.
```

Second, add two jobs:

```yaml
  security-skips:
    # Portability guard: every job must self-skip cleanly on a repo missing the
    # thing it scans. bin/ now exists, so point shellcheck at a path that does not.
    uses: ./.github/workflows/security.yml
    with:
      rules-ref: ${{ github.sha }}
      holmes-ignored-paths: "test/fixtures"
      shellcheck-dir: "./no-such-dir"
      extra-rules-dir: "./no-such-rules"

  rule-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd  # v5
      - name: Install clj-holmes
        shell: bash
        run: |
          set -euo pipefail
          curl -fsSL "https://github.com/clj-holmes/clj-holmes/releases/download/v1.4.3/clj-holmes-ubuntu-latest" \
            -o /tmp/clj-holmes
          sudo install -m 755 /tmp/clj-holmes /usr/local/bin/clj-holmes
      - name: Check rule tags
        run: bash bin/check-rule-tags.sh
      - name: Run rule fixture tests
        run: bash bin/test-rules.sh
```

- [ ] **Step 12: Verify locally**

```bash
bash bin/check-rule-tags.sh && bash bin/test-rules.sh && shellcheck -S error bin/*.sh
```
Expected: `all rules tagged`, `rule tests passed`, and no shellcheck output.

- [ ] **Step 13: Commit**

```bash
git add security-rules/ test/ bin/ .github/workflows/
git commit -m "feat: union clj-holmes rule sources and add the first custom rule

Drops clj-holmes-action for a direct binary install. The action's entrypoint
hardcodes a single fetch-rules and never passes -d, which blocked custom
rules; clj-holmes itself reads rules from any local directory, so upstream,
cleancoders, and consumer rules union with a cp.

Also pins the upstream rules ref. The action fetched
git://clj-holmes/clj-holmes-rules#main at runtime, leaving detection rules
unpinned in a workflow that SHA-pins every other third-party action.

Adds a rule-count floor: a scan with no rules exits 0 and looks like a clean
build, which is worse than no scan.

First rule is cc-hiccup-raw (CWE-79/A05), chosen because it exercises
namespace-alias resolution — the clj-holmes capability that ruled out semgrep,
whose Clojure support is experimental and cannot resolve aliases.

Fixture harness fails on missing AND unexpected findings; a silently
non-matching rule would still appear in the coverage matrix."
```

---

### Task 2: SQL injection rule

**Files:**
- Create: `security-rules/clj-holmes/cc-sql-string-concat.yml`
- Create: `test/fixtures/vulnerable/sql_injection.clj`, `test/fixtures/safe/sql_injection.clj`
- Modify: `test/fixtures/expectations.tsv`

**Interfaces:**
- Consumes: `bin/test-rules.sh`, `expectations.tsv` format from Task 1.
- Produces: rule id `cc-sql-string-concat`, class `sql-injection`.

- [ ] **Step 1: Add the expectation and fixtures**

Append to `test/fixtures/expectations.tsv`:
```
cc-sql-string-concat	sql_injection.clj
```

`test/fixtures/vulnerable/sql_injection.clj`:

```clojure
(ns fixtures.sql-injection
  (:require [next.jdbc :as jdbc]))

(defn find-user [db name]
  (jdbc/execute! db (str "SELECT * FROM users WHERE name = '" name "'")))

(defn list-sorted [db col]
  ;; The dynamic-identifier trap: parameters cannot help here.
  (jdbc/execute! db (str "SELECT * FROM posts ORDER BY " col)))
```

`test/fixtures/safe/sql_injection.clj`:

```clojure
(ns fixtures.sql-injection-safe
  (:require [next.jdbc :as jdbc]))

(defn find-user [db name]
  (jdbc/execute! db ["SELECT * FROM users WHERE name = ?" name]))

(def ^:private +sortable+ {"created" "created_at" "title" "title"})

(defn list-sorted [db col]
  (let [safe-col (get +sortable+ col "created_at")]
    (jdbc/execute! db [(str "SELECT * FROM posts ORDER BY " safe-col)])))
```

Note the safe fixture still builds a string with `str` — deliberately. It proves the rule keys on `str` reaching an *execute* call, not on `str` near SQL text.

- [ ] **Step 2: Run to verify it fails**

Run: `bash bin/test-rules.sh`
Expected: `MISSING findings (rule stopped matching): cc-sql-string-concat sql_injection.clj`

- [ ] **Step 3: Write the rule**

`security-rules/clj-holmes/cc-sql-string-concat.yml`:

```yaml
- id: cc-sql-string-concat
  name: SQL built by string concatenation
  severity: error
  message: >-
    A jdbc execute call receives a (str ...)-built query. Use a parameterized
    vector ["SELECT ... WHERE x = ?" v]. Where parameters cannot help — ORDER BY
    columns, table names, dynamic WHERE fragments — allowlist the identifier
    against a static map rather than interpolating it.
  properties:
    precision: medium
    tags:
      - security
      - class-sql-injection
      - cwe-89
      - owasp-a05-2025
  patterns:
    - patterns-either:
      - pattern: "($& $custom-function $& (str $&) $&)"
        namespace: next.jdbc
        function: execute!
        custom-function?: true
      - pattern: "($& $custom-function $& (str $&) $&)"
        namespace: next.jdbc
        function: execute-one!
        custom-function?: true
      - pattern: "($& $custom-function $& (str $&) $&)"
        namespace: clojure.java.jdbc
        function: query
        custom-function?: true
```

- [ ] **Step 4: Run to verify it passes**

Run: `bash bin/test-rules.sh`
Expected: `rule tests passed`

If the safe fixture fires, the pattern is matching a bare `(str ...)` rather than one in the query position — tighten the pattern; do not edit the fixture.

- [ ] **Step 5: Commit**

```bash
git add security-rules/clj-holmes/cc-sql-string-concat.yml test/fixtures/
git commit -m "feat(rules): detect SQL built by string concatenation

CWE-89 is #2 on the CWE Top 25 and had no detection. Keys on a (str ...) form
reaching a jdbc execute call rather than on SQL-looking text, so the safe
fixture's allowlisted ORDER BY — which legitimately uses str — stays clean."
```

---

### Task 3: ClojureScript DOM XSS rules

Three rules sharing one fixture pair; they are one sink family and one test cycle.

**Files:**
- Create: `security-rules/clj-holmes/cc-cljs-innerhtml.yml`, `cc-cljs-eval.yml`, `cc-dangerously-set-html.yml`
- Create: `test/fixtures/vulnerable/cljs_xss.cljs`, `test/fixtures/safe/cljs_xss.cljs`
- Modify: `test/fixtures/expectations.tsv`

**Interfaces:**
- Produces: rule ids `cc-cljs-innerhtml`, `cc-cljs-eval`, `cc-dangerously-set-html`; class `cljs-dom-xss`.

- [ ] **Step 1: Add expectations and fixtures**

Append to `test/fixtures/expectations.tsv`:
```
cc-cljs-innerhtml	cljs_xss.cljs
cc-cljs-eval	cljs_xss.cljs
cc-dangerously-set-html	cljs_xss.cljs
```

`test/fixtures/vulnerable/cljs_xss.cljs`:

```cljs
(ns fixtures.cljs-xss
  (:require [dommy.core :as dommy]))

(defn show-note [el note]
  (set! (.-innerHTML el) note))

(defn show-via-dommy [el note]
  (dommy/set-html! el note))

(defn run-expr [expr]
  (js/eval expr))

(defn make-fn [src]
  ((js/Function. "x" src) 1))

(defn bio-panel [user]
  [:div {:dangerouslySetInnerHTML #js {:__html (:bio user)}}])
```

`test/fixtures/safe/cljs_xss.cljs`:

```cljs
(ns fixtures.cljs-xss-safe)

;; textContent escapes; no HTML parsing occurs.
(defn show-note [el note]
  (set! (.-textContent el) note))

;; Reagent escapes string children by default.
(defn bio-panel [user]
  [:div.bio (:bio user)])

;; Dispatch through a hard-coded map, never eval.
(def ^:private +actions+ {"greet" (fn [] "hi") "bye" (fn [] "bye")})

(defn run-action [k]
  (when-let [f (get +actions+ k)] (f)))
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash bin/test-rules.sh`
Expected: three `MISSING findings` lines for `cc-cljs-innerhtml`, `cc-cljs-eval`, `cc-dangerously-set-html`.

- [ ] **Step 3: Write the three rules**

`cc-cljs-innerhtml.yml`:

```yaml
- id: cc-cljs-innerhtml
  name: Direct innerHTML assignment in ClojureScript
  severity: error
  message: >-
    Assigning to .-innerHTML (or dommy/set-html!) parses the value as HTML. If it
    crosses a trust boundary this is DOM XSS. Use .-textContent, or sanitize with
    DOMPurify first.
  properties:
    precision: high
    tags: [security, class-cljs-dom-xss, cwe-79, owasp-a05-2025]
  patterns:
    - patterns-either:
      - pattern: "(set! (.-innerHTML $&) $&)"
      - pattern: "($& $custom-function $&)"
        namespace: dommy.core
        function: set-html!
        custom-function?: true
```

`cc-cljs-eval.yml`:

```yaml
- id: cc-cljs-eval
  name: js/eval or js/Function in ClojureScript
  severity: error
  message: >-
    js/eval and (js/Function. ...) execute arbitrary JavaScript. Never call either
    on a runtime value. Dispatch through a hard-coded map keyed by a user-facing
    string and reject unknown keys.
  properties:
    precision: high
    tags: [security, class-cljs-dom-xss, cwe-94, owasp-a05-2025]
  patterns:
    - patterns-either:
      - pattern: "(js/eval $&)"
      - pattern: "(js/Function. $&)"
      - pattern: "(new js/Function $&)"
```

`cc-dangerously-set-html.yml`:

```yaml
- id: cc-dangerously-set-html
  name: Reagent dangerouslySetInnerHTML
  severity: error
  message: >-
    :dangerouslySetInnerHTML bypasses Reagent's escaping. Render the value as a
    string child, or sanitize with DOMPurify before setting __html.
  properties:
    precision: high
    tags: [security, class-cljs-dom-xss, cwe-79, owasp-a05-2025]
  patterns:
    - patterns:
      - pattern: ":dangerouslySetInnerHTML"
```

- [ ] **Step 4: Run to verify they pass**

Run: `bash bin/test-rules.sh`
Expected: `rule tests passed`

- [ ] **Step 5: Verify tags**

Run: `bash bin/check-rule-tags.sh`
Expected: `all rules tagged`. The inline `tags: [...]` flow style must still parse under `yq` — if it reports missing tags, switch these three to the block style used in Tasks 1 and 2.

- [ ] **Step 6: Commit**

```bash
git add security-rules/clj-holmes/cc-cljs-*.yml \
        security-rules/clj-holmes/cc-dangerously-set-html.yml test/fixtures/
git commit -m "feat(rules): detect ClojureScript DOM XSS sinks

Covers .-innerHTML, dommy/set-html!, js/eval, js/Function, and
:dangerouslySetInnerHTML. CWE-79 is #1 on the CWE Top 25 and the CLJS half of
it had no coverage at all — semgrep's Clojure rules are server-side only."
```

---

### Task 4: Dynamic execution rules

**Files:**
- Create: `security-rules/clj-holmes/cc-shell-exec.yml`, `cc-load-string.yml`
- Create: `test/fixtures/vulnerable/dynamic_exec.clj`, `test/fixtures/safe/dynamic_exec.clj`
- Modify: `test/fixtures/expectations.tsv`

**Interfaces:**
- Produces: rule ids `cc-shell-exec`, `cc-load-string`; class `dynamic-eval`.

- [ ] **Step 1: Add expectations and fixtures**

Append:
```
cc-shell-exec	dynamic_exec.clj
cc-load-string	dynamic_exec.clj
```

`test/fixtures/vulnerable/dynamic_exec.clj`:

```clojure
(ns fixtures.dynamic-exec
  (:require [clojure.java.shell :refer [sh]]))

(defn convert [path]
  (sh "bash" "-c" (str "convert " path " out.png")))

(defn run-report [ns-name fn-name]
  ((requiring-resolve (symbol ns-name fn-name))))

(defn eval-rule [src]
  (load-string src))
```

`test/fixtures/safe/dynamic_exec.clj`:

```clojure
(ns fixtures.dynamic-exec-safe
  (:require [clojure.java.shell :refer [sh]]))

;; Fixed argv, no shell interpretation of user data.
(defn convert [path]
  (sh "convert" path "out.png"))

;; Static symbol literal, resolved once at load.
(def ^:private report-fn (requiring-resolve 'clojure.string/upper-case))

(defn run-report [s] (report-fn s))
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash bin/test-rules.sh`
Expected: `MISSING findings` for `cc-shell-exec` and `cc-load-string`.

- [ ] **Step 3: Write the rules**

`cc-shell-exec.yml`:

```yaml
- id: cc-shell-exec
  name: Shell invocation via clojure.java.shell/sh
  severity: error
  message: >-
    clojure.java.shell/sh invoked through a shell interpreter (bash -c, sh -c)
    executes its argument as a command line, so any interpolated value is command
    injection. Pass a fixed argv instead — (sh "convert" path "out.png") — so the
    OS never parses user data as syntax.
  properties:
    precision: medium
    tags:
      - security
      - class-dynamic-eval
      - cwe-78
      - cwe-77
      - owasp-a05-2025
  patterns:
    - patterns:
      - pattern: "($& $custom-function $BASH $&)"
        namespace: clojure.java.shell
        function: sh
        custom-function?: true
      - metavariable-regex:
          metavariable: $BASH
          regex: (.*)(sh|bash|ksh|csh|tcsh|zsh)
```

`cc-load-string.yml`:

```yaml
- id: cc-load-string
  name: Runtime code loading via load-string / load-file / requiring-resolve
  severity: error
  message: >-
    load-string, load-file, and requiring-resolve on a non-literal symbol compile
    and run code chosen at runtime. Replace with a hard-coded map from a
    user-facing key to a resolved var, and reject unknown keys with a 4xx.
  properties:
    precision: medium
    tags:
      - security
      - class-dynamic-eval
      - cwe-94
      - owasp-a05-2025
  patterns:
    - patterns-either:
      - pattern: "(load-string $&)"
      - pattern: "(load-file $&)"
      - pattern: "(requiring-resolve (symbol $&))"
      - pattern: "(resolve (symbol $&))"
```

- [ ] **Step 4: Run to verify they pass**

Run: `bash bin/test-rules.sh`
Expected: `rule tests passed`. The safe fixture's `(requiring-resolve 'clojure.string/upper-case)` must stay clean — the pattern requires a `(symbol ...)` call, not a quoted literal.

- [ ] **Step 5: Commit**

```bash
git add security-rules/clj-holmes/cc-shell-exec.yml \
        security-rules/clj-holmes/cc-load-string.yml test/fixtures/
git commit -m "feat(rules): detect shell and runtime-code-loading sinks

CWE-78 (#9) and CWE-77 (#23) via clojure.java.shell/sh through a shell
interpreter; CWE-94 (#10) via load-string, load-file, and requiring-resolve on
a constructed symbol.

Both safe fixtures use the same functions benignly — fixed argv, quoted symbol
literal — so the rules key on the dangerous shape, not the function name."
```

---

### Task 5: Low-precision triage rules

Two rules that deliberately do **not** block. Without dataflow, `(io/file base x)` cannot be known to be user-derived and most generic catches are legitimate. They exist to feed `/security-audit` triage.

**Files:**
- Create: `security-rules/clj-holmes/cc-path-traversal.yml`, `cc-generic-catch.yml`
- Create: `test/fixtures/vulnerable/triage_low.clj`, `test/fixtures/safe/triage_low.clj`
- Modify: `test/fixtures/expectations.tsv`

**Interfaces:**
- Produces: rule ids `cc-path-traversal` (class `path-traversal`), `cc-generic-catch` (class `fail-open`).

- [ ] **Step 1: Add expectations and fixtures**

Append:
```
cc-path-traversal	triage_low.clj
cc-generic-catch	triage_low.clj
```

`test/fixtures/vulnerable/triage_low.clj`:

```clojure
(ns fixtures.triage-low
  (:require [clojure.java.io :as io]))

(defn read-upload [params]
  (slurp (io/file "uploads" (:name params))))

(defn authorized? [user]
  ;; Fails OPEN: an exception in the permission lookup grants access.
  (try (check-permissions user)
       (catch Exception _ true)))
```

`test/fixtures/safe/triage_low.clj`:

```clojure
(ns fixtures.triage-low-safe
  (:require [clojure.java.io :as io]))

(def ^:private +docs+ {"terms" "terms.md" "privacy" "privacy.md"})

(defn read-doc [k]
  (when-let [f (get +docs+ k)] (slurp (io/resource (str "docs/" f)))))

(defn authorized? [user]
  ;; Fails CLOSED and narrows the catch.
  (try (check-permissions user)
       (catch java.sql.SQLException e
         (log/warn e "permission lookup failed")
         false)))
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash bin/test-rules.sh`
Expected: `MISSING findings` for `cc-path-traversal` and `cc-generic-catch`.

- [ ] **Step 3: Write the rules**

`cc-path-traversal.yml`:

```yaml
- id: cc-path-traversal
  name: File path built from a request map
  severity: warning
  message: >-
    io/file built from a params-derived value. If the value reaches this point
    unvalidated, "../" escapes the intended directory. Canonicalize and assert the
    prefix, or index a static allowlist map. LOW PRECISION — clj-holmes has no
    dataflow, so provenance is not proven; triage with /security-audit.
  properties:
    precision: low
    tags:
      - security
      - class-path-traversal
      - cwe-22
      - owasp-a01-2025
  patterns:
    - patterns-either:
      - pattern: "($& $custom-function $& (:name $&) $&)"
        namespace: clojure.java.io
        function: file
        custom-function?: true
      - pattern: "($& $custom-function $& (:path $&) $&)"
        namespace: clojure.java.io
        function: file
        custom-function?: true
      - pattern: "($& $custom-function $& (:filename $&) $&)"
        namespace: clojure.java.io
        function: file
        custom-function?: true
```

`cc-generic-catch.yml`:

```yaml
- id: cc-generic-catch
  name: Generic catch returning a permissive default
  severity: warning
  message: >-
    A catch of Exception/Throwable that returns true or nil. When the guarded
    expression is a security decision this fails OPEN — the error path grants what
    the success path would have denied. Catch narrowly, log, and return the
    restrictive value. LOW PRECISION — many generic catches are legitimate;
    triage with /security-audit.
  properties:
    precision: low
    tags:
      - security
      - class-fail-open
      - cwe-636
      - cwe-396
      - owasp-a10-2025
  patterns:
    - patterns-either:
      - pattern: "(catch Exception $E true)"
      - pattern: "(catch Throwable $E true)"
      - pattern: "(catch Exception $E nil)"
      - pattern: "(catch Throwable $E nil)"
```

- [ ] **Step 4: Run to verify they pass**

Run: `bash bin/test-rules.sh`
Expected: `rule tests passed`

- [ ] **Step 5: Confirm severity is warning, not error**

Run: `grep -h 'severity:' security-rules/clj-holmes/cc-path-traversal.yml security-rules/clj-holmes/cc-generic-catch.yml`
Expected: `severity: warning` twice. These must not block; the spec commits to that and the README will say so.

- [ ] **Step 6: Commit**

```bash
git add security-rules/clj-holmes/cc-path-traversal.yml \
        security-rules/clj-holmes/cc-generic-catch.yml test/fixtures/
git commit -m "feat(rules): add low-precision triage rules for traversal and fail-open

CWE-22 (#6) and CWE-636/396 (OWASP A10). Both are severity: warning by design.
Without dataflow, (io/file base x) cannot be proven user-derived and most
generic catches are legitimate, so these feed /security-audit triage rather
than blocking. Their messages say so explicitly.

A10 Mishandling of Exceptional Conditions is new in OWASP 2025 and maps
unusually well onto Clojure: CWE-396 is literally (catch Exception e ...)."
```

---

### Task 6: Deserialization rules

**Files:**
- Create: `security-rules/clj-holmes/cc-nippy-thaw.yml`, `cc-snakeyaml-unsafe.yml`
- Create: `test/fixtures/vulnerable/deser.clj`, `test/fixtures/safe/deser.clj`
- Modify: `test/fixtures/expectations.tsv`

**Interfaces:**
- Produces: rule ids `cc-nippy-thaw`, `cc-snakeyaml-unsafe`; class `java-deserialization`.

- [ ] **Step 1: Add expectations and fixtures**

Append:
```
cc-nippy-thaw	deser.clj
cc-snakeyaml-unsafe	deser.clj
```

`test/fixtures/vulnerable/deser.clj`:

```clojure
(ns fixtures.deser
  (:require [taoensso.nippy :as nippy])
  (:import [org.yaml.snakeyaml Yaml]))

(defn load-session [^bytes b]
  (nippy/thaw b))

(defn parse-config [s]
  (.load (Yaml.) s))
```

`test/fixtures/safe/deser.clj`:

```clojure
(ns fixtures.deser-safe
  (:require [taoensso.nippy :as nippy])
  (:import [org.yaml.snakeyaml Yaml]
           [org.yaml.snakeyaml.constructor SafeConstructor]))

(defn load-session [^bytes b]
  (nippy/thaw b {:incl-class-allowlist #{"clojure.lang.PersistentArrayMap"}}))

(defn parse-config [s]
  (.load (Yaml. (SafeConstructor.)) s))
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash bin/test-rules.sh`
Expected: `MISSING findings` for `cc-nippy-thaw` and `cc-snakeyaml-unsafe`.

- [ ] **Step 3: Write the rules**

`cc-nippy-thaw.yml`:

```yaml
- id: cc-nippy-thaw
  name: nippy/thaw without a class allowlist
  severity: error
  message: >-
    nippy/thaw on untrusted bytes without :incl-class-allowlist can instantiate
    arbitrary classes, reaching JVM gadget chains. Pass an explicit allowlist, or
    move to a transit/EDN envelope for anything crossing a trust boundary.
  properties:
    precision: high
    tags:
      - security
      - class-java-deserialization
      - cwe-502
      - owasp-a08-2025
  patterns:
    - patterns:
      - pattern: "($& $custom-function $&)"
        namespace: taoensso.nippy
        function: thaw
        custom-function?: true
      - pattern-not: ":incl-class-allowlist"
```

`cc-snakeyaml-unsafe.yml`:

```yaml
- id: cc-snakeyaml-unsafe
  name: SnakeYAML default constructor
  severity: error
  message: >-
    The no-arg Yaml constructor deserializes arbitrary classes named in the
    document. Use (Yaml. (SafeConstructor.)), or SnakeYAML 2.0+ where the safe
    behaviour is the default.
  properties:
    precision: high
    tags:
      - security
      - class-java-deserialization
      - cwe-502
      - owasp-a08-2025
  patterns:
    - patterns:
      - pattern: "(Yaml.)"
```

- [ ] **Step 4: Run to verify they pass**

Run: `bash bin/test-rules.sh`
Expected: `rule tests passed`

If `cc-nippy-thaw` fires on the safe fixture, the `pattern-not` is scoped to the wrong form. Fix the scoping; do not remove the safe fixture.

- [ ] **Step 5: Commit**

```bash
git add security-rules/clj-holmes/cc-nippy-thaw.yml \
        security-rules/clj-holmes/cc-snakeyaml-unsafe.yml test/fixtures/
git commit -m "feat(rules): detect nippy and SnakeYAML deserialization sinks

CWE-502 is #15 on the CWE Top 25. Upstream clj-holmes covers read-string but
not nippy/thaw or the SnakeYAML no-arg constructor, both common in c3kit
codebases. Note CWE-502 maps to OWASP A08 only — it is absent from A05's
37-CWE injection list."
```

---

### Task 7: Sensitive-data-in-error-response rule

**Files:**
- Create: `security-rules/clj-holmes/cc-explain-data-response.yml`
- Create: `test/fixtures/vulnerable/error_leak.clj`, `test/fixtures/safe/error_leak.clj`
- Modify: `test/fixtures/expectations.tsv`

**Interfaces:**
- Produces: rule id `cc-explain-data-response`; class `spec-malli-leak`.

- [ ] **Step 1: Add expectations and fixtures**

Append:
```
cc-explain-data-response	error_leak.clj
```

`test/fixtures/vulnerable/error_leak.clj`:

```clojure
(ns fixtures.error-leak
  (:require [clojure.spec.alpha :as s]
            [malli.error :as me]))

(defn create-user [req]
  (if (s/valid? ::user (:body req))
    {:status 201}
    {:status 400 :body (s/explain-data ::user (:body req))}))

(defn update-user [req errors]
  {:status 400 :body (me/humanize errors)})
```

`test/fixtures/safe/error_leak.clj`:

```clojure
(ns fixtures.error-leak-safe
  (:require [clojure.spec.alpha :as s]))

(defn- field-names [ed]
  (mapv #(-> % :path first name) (::s/problems ed)))

(defn create-user [req]
  (if (s/valid? ::user (:body req))
    {:status 201}
    ;; Log the detail server-side; return field names only.
    (let [ed (s/explain-data ::user (:body req))]
      (log/warn "validation failed" {:fields (field-names ed)})
      {:status 400 :body {:errors (field-names ed)}})))
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash bin/test-rules.sh`
Expected: `MISSING findings (rule stopped matching): cc-explain-data-response error_leak.clj`

- [ ] **Step 3: Write the rule**

```yaml
- id: cc-explain-data-response
  name: Spec/Malli explain output in a response body
  severity: error
  message: >-
    s/explain-data and me/humanize embed the offending value, so returning them in
    a response body dumps internal structures and likely PII to the client. Log the
    detail server-side and return field names only.
  properties:
    precision: medium
    tags:
      - security
      - class-spec-malli-leak
      - cwe-209
      - owasp-a10-2025
  patterns:
    - patterns-either:
      - pattern: "{$& :body (s/explain-data $&) $&}"
      - pattern: "{$& :body (me/humanize $&) $&}"
      - pattern: "{$& :body (m/explain $&) $&}"
```

- [ ] **Step 4: Run to verify it passes**

Run: `bash bin/test-rules.sh`
Expected: `rule tests passed`. The safe fixture calls `s/explain-data` but never places it in `:body`, so keying on the response-map position is what keeps it clean.

- [ ] **Step 5: Confirm the full rule set**

```bash
ls security-rules/clj-holmes/*.yml | wc -l
bash bin/check-rule-tags.sh
```
Expected: `12` and `all rules tagged`.

- [ ] **Step 6: Commit**

```bash
git add security-rules/clj-holmes/cc-explain-data-response.yml test/fixtures/
git commit -m "feat(rules): detect spec/malli explain output in response bodies

CWE-209, OWASP A10. Keys on the value appearing in :body rather than on the
call itself, so the safe pattern — explain server-side, return field names —
stays clean. Completes the 12-rule set."
```

---

### Task 8: semgrep retarget and SARIF artifact

**Files:**
- Modify: `.github/workflows/security.yml` (semgrep job)

**Interfaces:**
- Consumes: nothing from Tasks 2–7.
- Produces: `semgrep.sarif` artifact.

- [ ] **Step 1: Update the semgrep job**

Replace the job's comment block and step with:

```yaml
  semgrep:
    runs-on: ubuntu-latest
    # Secondary engine, deliberately. clj-holmes owns Clojure: its shape-shifter
    # patterns resolve namespace aliases, so (h/raw-string x) matches without a
    # pattern per alias. Semgrep's Clojure support is Experimental tier
    # (tree-sitter) and cannot. Semgrep earns its place on the NON-Clojure
    # surface — yaml, Dockerfile, JS/TS, HTML — plus its five upstream Clojure
    # rules as redundant backup.
    #
    # semgrep ALWAYS runs with --error, so any finding turns this job red and
    # stays visible — its "Blocking" label is a policy tag, NOT an exit code.
    # continue-on-error decides only whether that red BLOCKS the build.
    continue-on-error: ${{ !inputs.semgrep-blocking }}
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10  # v6
      - name: Semgrep (OWASP Top 10 + default)
        shell: bash
        env:
          IGNORED: ${{ inputs.holmes-ignored-paths }}
        run: |
          set -euo pipefail
          args=(scan --config p/owasp-top-ten --config p/default --error
                --sarif --output semgrep.sarif)
          [ -n "$IGNORED" ] && args+=(--exclude "$IGNORED")
          semgrep "${args[@]}"
      - name: Upload SARIF
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02  # v4.6.2
        with:
          name: semgrep-sarif
          path: semgrep.sarif
          retention-days: 90
```

- [ ] **Step 2: Verify workflow syntax**

Run: `actionlint .github/workflows/security.yml`
(Install first if absent: `brew install actionlint` or download the release binary.)
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "refactor: retarget semgrep as the non-Clojure engine, emit SARIF

clj-holmes now owns Clojure detection because its patterns resolve namespace
aliases; semgrep's Clojure tier is Experimental and cannot. Semgrep keeps the
yaml/Dockerfile/JS/TS/HTML surface and its upstream Clojure rules as backup.

Adds a SARIF artifact uploaded with if: always() — evidence of a failing scan
is the evidence most worth keeping. Honors holmes-ignored-paths so fixture
corpora stay excluded from both engines."
```

---

### Task 9: actionlint and zizmor jobs

**Files:**
- Modify: `.github/workflows/security.yml`

**Interfaces:**
- Produces: `zizmor.sarif` artifact; input `zizmor-blocking`.

- [ ] **Step 1: Add the `zizmor-blocking` input**

```yaml
      zizmor-blocking:
        description: >-
          Fail the workflow on zizmor findings (default: advisory). Advisory by default
          because zizmor's default settings light up existing repos; blocking on
          adoption would wedge consumers.
        type: boolean
        default: false
```

- [ ] **Step 2: Add both jobs**

```yaml
  actionlint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10  # v6
      - name: Detect workflows
        id: detect
        shell: bash
        run: |
          set -euo pipefail
          if [ -n "$(find .github/workflows -name '*.y*ml' 2>/dev/null | head -1)" ]; then
            echo "run=true" >> "$GITHUB_OUTPUT"
          else
            echo "::notice::no .github/workflows; skipping actionlint"
            echo "run=false" >> "$GITHUB_OUTPUT"
          fi
      - name: actionlint
        if: steps.detect.outputs.run == 'true'
        shell: bash
        run: |
          set -euo pipefail
          VER=1.7.7
          curl -fsSL "https://github.com/rhysd/actionlint/releases/download/v${VER}/actionlint_${VER}_linux_amd64.tar.gz" \
            | sudo tar -xz -C /usr/local/bin actionlint
          actionlint

  zizmor:
    runs-on: ubuntu-latest
    # Advisory by default: zizmor's default settings light up existing repos, so
    # blocking on adoption would wedge every consumer on day one. Covers OWASP
    # A02 Security Misconfiguration and A03 Supply Chain — CI config is itself
    # attack surface, and this repo's entire product is workflows.
    continue-on-error: ${{ !inputs.zizmor-blocking }}
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10  # v6
      - name: Detect workflows
        id: detect
        shell: bash
        run: |
          set -euo pipefail
          if [ -n "$(find .github/workflows -name '*.y*ml' 2>/dev/null | head -1)" ]; then
            echo "run=true" >> "$GITHUB_OUTPUT"
          else
            echo "::notice::no .github/workflows; skipping zizmor"
            echo "run=false" >> "$GITHUB_OUTPUT"
          fi
      - uses: astral-sh/setup-uv@e92bafb6253dcd438e0484186d7669ea7a8ca1cc  # v6.4.3
        if: steps.detect.outputs.run == 'true'
      - name: zizmor
        if: steps.detect.outputs.run == 'true'
        shell: bash
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: uvx zizmor@1.11.0 --format sarif . > zizmor.sarif
      - name: Upload SARIF
        if: always() && steps.detect.outputs.run == 'true'
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02  # v4.6.2
        with:
          name: zizmor-sarif
          path: zizmor.sarif
          retention-days: 90
```

- [ ] **Step 3: Run zizmor against this repo and triage**

```bash
uvx zizmor@1.11.0 .github/workflows/
```
Expected: findings. Fix any genuine ones in this repo's own workflows — this repo's product *is* workflows, so it must pass its own check. Record any deliberate suppressions in `.github/zizmor.yml` with a reason comment. Do not silence a finding you have not understood.

- [ ] **Step 4: Verify syntax**

Run: `actionlint .github/workflows/security.yml .github/workflows/self-test.yml`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ .github/zizmor.yml
git commit -m "feat: add actionlint and zizmor jobs

Covers OWASP A02 Security Misconfiguration and A03 Supply Chain. CI config is
itself attack surface — template injection into run:, unpinned actions,
over-broad permissions — and this repo's entire product is workflows, so it
dogfoods both.

actionlint hard-fails (mostly correctness). zizmor is advisory via
zizmor-blocking because its defaults light up existing repos and blocking on
adoption would wedge consumers. Both self-skip with no .github/workflows,
matching the shellcheck-dir idiom."
```

---

### Task 10: Generate the coverage matrix

**Files:**
- Create: `bin/gen-coverage-matrix.sh`
- Modify: `README.md`
- Modify: `.github/workflows/self-test.yml`

**Interfaces:**
- Consumes: `properties.tags` on all 12 rules.
- Produces: a `<!-- BEGIN/END COVERAGE -->` delimited section in `README.md`.

- [ ] **Step 1: Write the generator**

```bash
#!/usr/bin/env bash
# Emits the scanner rows of the coverage matrix from rule tags. Hand-maintaining
# this table is how a coverage doc starts lying: a rule gets deleted or renamed
# and the table keeps claiming it. --check fails CI when the committed table no
# longer matches the rules.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${ROOT}/security-rules/clj-holmes"
README="${ROOT}/README.md"
BEGIN='<!-- BEGIN COVERAGE -->'
END='<!-- END COVERAGE -->'

generate() {
  echo "${BEGIN}"
  echo
  echo "| rule | class | CWE | OWASP 2025 | precision |"
  echo "|------|-------|-----|------------|-----------|"
  for f in "${RULES}"/*.yml; do
    id="$(yq -r '.[0].id' "${f}")"
    prec="$(yq -r '.[0].properties.precision' "${f}")"
    tags="$(yq -r '.[0].properties.tags[]' "${f}")"
    class="$(echo "${tags}" | sed -n 's/^class-//p' | paste -sd, -)"
    cwe="$(echo "${tags}" | sed -n 's/^cwe-//p' | paste -sd', ' -)"
    owasp="$(echo "${tags}" | sed -n 's/^owasp-a\([0-9]*\)-2025$/A\1/p')"
    echo "| \`${id}\` | \`${class}\` | ${cwe} | ${owasp} | ${prec} |"
  done
  echo
  echo "${END}"
}

if [ "${1:-}" = "--check" ]; then
  current="$(sed -n "/${BEGIN}/,/${END}/p" "${README}")"
  if [ "${current}" != "$(generate)" ]; then
    echo "README coverage table is stale. Run: bash bin/gen-coverage-matrix.sh"
    diff <(echo "${current}") <(generate) || true
    exit 1
  fi
  echo "coverage table current"
  exit 0
fi

tmp="$(mktemp)"
awk -v b="${BEGIN}" -v e="${END}" '
  $0 ~ b {print; skip=1; next}
  $0 ~ e {skip=0; print; next}
  !skip  {print}
' "${README}" > "${tmp}"
# Re-insert the generated body between the markers.
python3 - "${tmp}" "${README}" <<'PY'
import sys, subprocess, re
tmp, readme = sys.argv[1], sys.argv[2]
body = subprocess.run(["bash", "bin/gen-coverage-matrix.sh", "--emit"],
                      capture_output=True, text=True, check=True).stdout
src = open(tmp).read()
out = re.sub(r"<!-- BEGIN COVERAGE -->.*?<!-- END COVERAGE -->", body.strip(),
             src, flags=re.S)
open(readme, "w").write(out)
PY
echo "README coverage table regenerated"
```

Add an `--emit` branch immediately after the `--check` branch:

```bash
if [ "${1:-}" = "--emit" ]; then generate; exit 0; fi
```

- [ ] **Step 2: Add the markers to README.md**

Under a new `### Coverage` heading in the `security.yml` section:

```markdown
### Coverage

Scanner rows below are generated from rule tags by `bin/gen-coverage-matrix.sh`
and checked in CI, so they cannot claim a rule that no longer exists. The
manual-review rows live in the `clojure-security` plugin's class index — see
the spec for why the halves are split.

<!-- BEGIN COVERAGE -->
<!-- END COVERAGE -->
```

- [ ] **Step 3: Generate and verify**

```bash
bash bin/gen-coverage-matrix.sh
bash bin/gen-coverage-matrix.sh --check
```
Expected: `README coverage table regenerated`, then `coverage table current`. The table must show 12 rows.

- [ ] **Step 4: Prove --check can fail**

```bash
sed -i.bak 's/cwe-79/cwe-999/' security-rules/clj-holmes/cc-hiccup-raw.yml
bash bin/gen-coverage-matrix.sh --check; echo "exit=$?"
mv security-rules/clj-holmes/cc-hiccup-raw.yml.bak security-rules/clj-holmes/cc-hiccup-raw.yml
```
Expected: `README coverage table is stale`, `exit=1`, then restored.

- [ ] **Step 5: Wire into self-test.yml**

Add to the `rule-tests` job, after the tag check:

```yaml
      - name: Check coverage table is current
        run: bash bin/gen-coverage-matrix.sh --check
```

- [ ] **Step 6: Commit**

```bash
git add bin/gen-coverage-matrix.sh README.md .github/workflows/self-test.yml
git commit -m "feat: generate the scanner coverage matrix from rule tags

Hand-maintaining this table is how a coverage doc starts lying: a rule gets
renamed or deleted and the table keeps claiming it, which is worse than no
table when it reaches an auditor. Generated from properties.tags and checked
in CI, so the scanner half physically cannot overstate.

Manual-review rows stay in the clojure-security class index — the two halves
live in different repos and each is authoritative for its own."
```

---

### Task 11: Document, verify end to end, retag v1

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the README inputs table**

Add the five new inputs, matching the existing table's tone:

```markdown
| `extra-rules-dir` | `.security-rules` | Consumer-supplied clj-holmes rules, unioned with upstream + cleancoders rules. Self-skips when the directory is absent. |
| `rules-ref` | `v1` | Ref of this repo to source detection rules from. Must match the ref you consume the workflow at — a reusable workflow cannot determine its own ref. |
| `holmes-upstream-ref` | `git://clj-holmes/clj-holmes-rules#main` | Upstream clj-holmes rules source. Override to pin a SHA. |
| `holmes-ignored-paths` | `""` | Regex of paths clj-holmes and semgrep must skip, e.g. deliberately-vulnerable test fixtures. |
| `zizmor-blocking` | `false` | When `true`, zizmor findings fail the workflow. Default advisory. |
```

- [ ] **Step 2: Update the job-count sentence**

The README opens "Runs six scanners." Replace with:

```markdown
Runs eight scanners. **Hard-fail** (block the caller): `clj-kondo`, `clj-holmes`,
`shellcheck`, `gitleaks`, `actionlint`. **Advisory by default** (report, never
block): `clj-watson`, `semgrep`, `zizmor` — each can be made blocking per-consumer
via the `clj-watson-blocking` / `semgrep-blocking` / `zizmor-blocking` inputs.
```

- [ ] **Step 3: Add the limitations section**

Verbatim from the spec — a coverage doc that overstates is worse than none:

```markdown
### What this coverage does not claim

1. **No taint analysis.** Every scanned row is pattern matching. Neither clj-holmes
   nor semgrep OSS tracks dataflow, so a sink reached by an unusual path is missed.
   The matrix says "we look for this shape," not "we would catch this bug."
2. **OWASP A06 Insecure Design is uncovered.** It is a threat-modeling category.
3. **10 of 19 applicable CWE Top 25 entries depend on a manual `/security-audit`
   run.** CI cannot invoke it. Expected cadence is once per release; nothing
   enforces that.
4. **`cc-path-traversal` and `cc-generic-catch` are `severity: warning`** and do not
   block — without dataflow they cannot be precise enough to gate a build.
5. **CWE-476 coverage is nominal** — clj-kondo `:type-mismatch` is a type linter,
   not NPE analysis.
6. **Rules track `rules-ref`, default `v1`.** Consuming another ref without setting
   it gets v1 rules.
```

- [ ] **Step 4: Full local verification**

```bash
bash bin/check-rule-tags.sh
bash bin/test-rules.sh
bash bin/gen-coverage-matrix.sh --check
shellcheck -S error bin/*.sh
actionlint .github/workflows/*.yml
```
Expected: all pass, no output from shellcheck or actionlint.

- [ ] **Step 5: Push and confirm CI is green**

```bash
git add README.md && git commit -m "docs: document the new inputs, scanners, and coverage limits

Eight scanners now, five new inputs. States plainly what the coverage does not
claim: no taint analysis anywhere, A06 uncovered, two rules non-blocking, and
10 of 19 applicable CWE Top 25 entries reachable only by a manual audit run."
git push origin master
```

Confirm on the PR/push run that: `security`, `security-skips`, `rule-tests`, and
`clj-lib` all pass; `security-skips` shows shellcheck and extra-rules skip notices;
and the SARIF artifacts are attached.

- [ ] **Step 6: Retag v1**

Only after CI is green. Consumers pin `@v1`, so this publishes to all of them at once.

```bash
git tag -f v1 && git push -f origin v1
git ls-remote --tags origin v1
```

Then verify a real consumer: open a trivial PR in one c3kit repo and confirm its
security workflow picks up the new jobs and passes.

---

## Self-Review

**Spec coverage.** clj-holmes rewrite → Task 1; 12 custom rules → Tasks 1–7; semgrep retarget + SARIF → Task 8; actionlint + zizmor → Task 9; `bin/check-rule-tags.sh` → Task 1; `bin/gen-coverage-matrix.sh` → Task 10; new inputs → Tasks 1, 9, 11; self-test cases → Tasks 1, 10, 11; named limitations → Task 11; TDD-per-rule → every rule task.

**Three deliberate deviations from the spec:**

1. **A fifth input, `holmes-ignored-paths`.** The spec listed four. Without this, `test/fixtures/vulnerable/` fails this repo's own security job — the fixtures are real vulnerabilities. It is also generally useful for generated code.
2. **`expectations.tsv`, not `expectations.edn`.** EDN needs a Clojure runtime in the test job; TSV is read by the same bash+jq the rest of `bin/` uses. No behavioral difference.
3. **`security-skips` job in self-test.** Adding `bin/` means this repo now has a `bin/`, destroying the existing "shellcheck self-skips" portability guard. A second workflow invocation with deliberately-absent paths restores it.

**Placeholder scan.** No TBDs. Every rule task contains complete YAML, complete fixtures for both corpora, the exact expectations line, and a named failure mode with instructions that forbid weakening the test. Every verification step names a command and its expected output.

**Type consistency.** Rule ids are `cc-` prefixed and identical across the rule file, `expectations.tsv`, and commit messages. Class tags use exactly the eight Phase 1 names listed in Global Constraints. `bin/test-rules.sh` reads `expectations.tsv` in `<rule-id>\t<basename>` order, which is the order every task appends in. The SARIF jq path `.runs[].results[].ruleId` matches what `-t sarif` emits and what Task 10's generator does not depend on.

**Known risk, accepted.** clj-holmes' shape-shifter DSL is thinly documented; several patterns here (notably `cc-nippy-thaw`'s `pattern-not` scoping and `cc-explain-data-response`'s map-position match) may need iteration against real output. That is why every rule task is TDD with a safe fixture — the loop catches an over-broad pattern immediately rather than at the first false positive in a consumer repo.
