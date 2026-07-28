#!/usr/bin/env bash
# Tests bin/detect.sh. These predicates decide whether a scanner runs at all, so
# a wrong answer means a job silently skips and the build still goes green —
# indistinguishable from "scanned and found nothing". That is the failure mode
# this whole repo exists to prevent, which is why one-line predicates get tests.
#
# Replaces the old `security-skips` job in self-test.yml, which duplicated all 9
# scanner jobs to exercise two conditionals. This covers more cases in
# milliseconds.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DETECT="${ROOT}/bin/detect.sh"
pass=0; fail=0

ok()   { pass=$((pass+1)); }
bad()  { fail=$((fail+1)); echo "FAIL: $1"; }
check(){ if [ "$2" = "$3" ]; then ok; else bad "$1 — expected '$3', got '$2'"; fi; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- dir-has-files -----------------------------------------------------------
mkdir -p "${WORK}/empty" "${WORK}/full" "${WORK}/nested/deep"
touch "${WORK}/full/a.sh"
touch "${WORK}/nested/deep/b.sh"

bash "${DETECT}" dir-has-files "${WORK}/full"    && r=yes || r=no
check "dir with a file"            "$r" "yes"
bash "${DETECT}" dir-has-files "${WORK}/empty"   && r=yes || r=no
check "empty dir"                  "$r" "no"
bash "${DETECT}" dir-has-files "${WORK}/absent"  && r=yes || r=no
check "absent dir"                 "$r" "no"
bash "${DETECT}" dir-has-files ""                && r=yes || r=no
check "empty string"               "$r" "no"
bash "${DETECT}" dir-has-files "${WORK}/nested"  && r=yes || r=no
check "file only in subdirectory"  "$r" "yes"

# --- existing-dirs -----------------------------------------------------------
mkdir -p "${WORK}/src/clj" "${WORK}/src/cljc"
cd "${WORK}"
r="$(bash "${DETECT}" existing-dirs src/clj src/cljs src/cljc | paste -sd' ' -)"
check "filters out the absent root" "$r" "src/clj src/cljc"
r="$(bash "${DETECT}" existing-dirs src/nope other/nope | paste -sd' ' -)"
check "all absent yields empty"     "$r" ""

# --- outputs -----------------------------------------------------------------
# A library-shaped repo: no bin/, no deps.edn, no workflows, one source root.
mkdir -p "${WORK}/lib/src/clj" && cd "${WORK}/lib"
out="$(SHELLCHECK_DIR=./bin EXTRA_RULES_DIR=.security-rules \
       SRC_PATHS="src/clj src/cljs src/cljc" bash "${DETECT}" outputs)"
check "no bin/ -> shellcheck skips" \
  "$(echo "$out" | grep '^has-shellcheck-target=')" "has-shellcheck-target=false"
check "no workflows -> actionlint/zizmor skip" \
  "$(echo "$out" | grep '^has-workflows=')" "has-workflows=false"
check "no consumer rules dir" \
  "$(echo "$out" | grep '^has-extra-rules=')" "has-extra-rules=false"
check "no deps.edn -> clj-watson skips" \
  "$(echo "$out" | grep '^has-deps-edn=')" "has-deps-edn=false"
check "src-dirs narrowed to the one that exists" \
  "$(echo "$out" | grep '^src-dirs=')" "src-dirs=src/clj"

# An app-shaped repo: everything present.
mkdir -p "${WORK}/app/bin" "${WORK}/app/.github/workflows" \
         "${WORK}/app/.security-rules" "${WORK}/app/src/cljs"
touch "${WORK}/app/bin/run.sh" "${WORK}/app/.github/workflows/ci.yml" \
      "${WORK}/app/deps.edn"
cd "${WORK}/app"
out="$(SHELLCHECK_DIR=./bin EXTRA_RULES_DIR=.security-rules \
       SRC_PATHS="src/clj src/cljs src/cljc" bash "${DETECT}" outputs)"
check "bin/ present -> shellcheck runs" \
  "$(echo "$out" | grep '^has-shellcheck-target=')" "has-shellcheck-target=true"
check "workflows present -> actionlint runs" \
  "$(echo "$out" | grep '^has-workflows=')" "has-workflows=true"
check "consumer rules dir found" \
  "$(echo "$out" | grep '^has-extra-rules=')" "has-extra-rules=true"
check "deps.edn present" \
  "$(echo "$out" | grep '^has-deps-edn=')" "has-deps-edn=true"
check "src-dirs narrowed to cljs" \
  "$(echo "$out" | grep '^src-dirs=')" "src-dirs=src/cljs"

echo "detect tests: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
