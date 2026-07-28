#!/usr/bin/env bash
# Tests bin/report-sarif.sh against a real SARIF captured from a consumer run.
#
# The exit code here decides whether a build passes, so the warnings-only case is
# the one that matters: cc-path-traversal, cc-generic-catch and
# cc-clojure-xml-xxe are WARNING on purpose and the README promises they do not
# block. A regression that counted every result would quietly start failing
# builds on low-precision findings.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${ROOT}/bin/report-sarif.sh"
SAMPLE="${ROOT}/spec-fixtures/sarif/sample.sarif"
pass=0; fail=0

ok()    { pass=$((pass+1)); }
bad()   { fail=$((fail+1)); echo "FAIL: $1"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1 — expected '$3', got '$2'"; fi; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- the real sample: 7 results, 2 nosemgrep-suppressed, 1 error-level --------
# The suppressed pair is the important part. cleancoders.com annotated both
# secret findings with `nosemgrep`; semgrep honours that by setting
# suppressions:[{kind:"inSource"}] but still emits the result. Counting them
# blocks a build on findings a developer already accepted.
out="$(bash "${REPORT}" "${SAMPLE}" 2>&1)"; rc=$?
check "one error-level finding blocks"        "$rc" "1"
check "excludes suppressed from the counts"   "$(echo "$out" | grep -c '5 finding(s), 1 blocking')" "1"
check "reports the suppressed count"          "$(echo "$out" | grep -c '2 additional finding(s) suppressed')" "1"
check "emits one row per unsuppressed finding" "$(echo "$out" | grep -cE '^[1-5] +(error|warning) ')" "5"
check "suppressed findings stay out of table" "$(echo "$out" | grep -cE 'detected-jwt-token|detected-generic-secret')" "0"
check "legend omits suppressed-only CWEs"     "$(echo "$out" | grep -cE 'CWE-321|CWE-798')" "0"
# cc-generic-catch fires 4x, so its multi-CWE cell appears on all 4 rows.
check "surfaces multi-CWE cells per row"      "$(echo "$out" | grep -c 'CWE-396, CWE-636')" "4"
check "reports confidence"                    "$(echo "$out" | grep -cE 'cc-cljs-innerhtml.*HIGH')" "1"
check "legend expands a CWE id once"          "$(echo "$out" | grep -c "CWE-636: Not Failing Securely")" "1"
check "legend expands an OWASP category"      "$(echo "$out" | grep -c 'A10:2025 - Mishandling')" "1"
check "annotates the failure for GitHub"      "$(echo "$out" | grep -c '::error::semgrep found 1')" "1"

# --- warnings only: must NOT block -------------------------------------------
jq '.runs |= map(
      (.tool.driver.rules | map(select(.defaultConfiguration.level == "warning") | .id)) as $warn
      | .results |= map(select(.ruleId as $i | $warn | index($i))))' \
   "${SAMPLE}" > "${WORK}/warn.sarif"
out="$(bash "${REPORT}" "${WORK}/warn.sarif" 2>&1)"; rc=$?
check "warnings alone do not block"      "$rc" "0"
check "warning count still reported"     "$(echo "$out" | grep -c '4 finding(s), 0 blocking')" "1"
check "no error annotation on warnings"  "$(echo "$out" | grep -c '::error::')" "0"

# --- suppressed-only: nothing actionable, must pass and say why ---------------
jq '.runs |= map(.results |= map(select(.suppressions != null)))' "${SAMPLE}" > "${WORK}/supp.sarif"
out="$(bash "${REPORT}" "${WORK}/supp.sarif" 2>&1)"; rc=$?
check "suppressed-only passes"           "$rc" "0"
check "suppressed-only is not silent"    "$(echo "$out" | grep -c '2 suppressed in source')" "1"

# --- no findings --------------------------------------------------------------
jq '.runs |= map(.results = [])' "${SAMPLE}" > "${WORK}/clean.sarif"
out="$(bash "${REPORT}" "${WORK}/clean.sarif" 2>&1)"; rc=$?
check "clean scan passes"        "$rc" "0"
check "clean scan says so"       "$(echo "$out" | grep -c 'no findings')" "1"

# --- missing file: a scan that never ran must fail loudly --------------------
out="$(bash "${REPORT}" "${WORK}/absent.sarif" 2>&1)"; rc=$?
check "missing SARIF fails"           "$rc" "1"
check "missing SARIF explains why"    "$(echo "$out" | grep -c 'did not complete')" "1"

echo "report-sarif tests: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
