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
