#!/usr/bin/env bash
# Scans the fixture corpus with ONLY the cleancoders rules and diffs the result
# against expectations.tsv. Fails on missing findings (a rule stopped matching)
# and on unexpected ones (a rule got too broad, or an upstream change altered
# behaviour). Both directions matter: a silently non-matching rule still appears
# in the coverage matrix, which is exactly the false confidence this repo exists
# to prevent.
#
# semgrep cannot resolve namespace aliases, so every rule enumerates the aliases
# it expects and every vulnerable fixture exercises more than one of them. That
# is the whole mitigation for choosing semgrep over clj-holmes — if it stops
# working, these tests must fail rather than the scan going quiet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${ROOT}/security-rules/semgrep"
FIXTURES="${ROOT}/spec-fixtures"
EXPECTED="${FIXTURES}/expectations.tsv"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

command -v semgrep >/dev/null || { echo "semgrep not installed"; exit 1; }
command -v jq      >/dev/null || { echo "jq not installed"; exit 1; }

# semgrep namespaces SARIF ruleId with the config directory: "semgrep.cc-foo".
# Strip everything up to the last dot to get the bare rule id.
scan_to_tsv() {
  local target="$1" out="$2"
  semgrep scan --config "${RULES}" --no-git-ignore --sarif -q "${target}" \
    > "${out}.sarif" 2>/dev/null
  jq -r '.runs[].results[]
         | ((.ruleId | split(".") | last) + "\t"
            + (.locations[0].physicalLocation.artifactLocation.uri
               | split("/") | last))' "${out}.sarif" | sort -u
}

# --- vulnerable corpus: every expected finding must appear -------------------
scan_to_tsv "${FIXTURES}/vulnerable" "${WORK}/vuln" > "${WORK}/actual.tsv"
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
safe_hits="$(scan_to_tsv "${FIXTURES}/safe" "${WORK}/safe")"
if [ -n "${safe_hits}" ]; then
  echo "FALSE POSITIVES on the safe corpus:"; echo "${safe_hits}"; status=1
fi

[ "${status}" -eq 0 ] && echo "rule tests passed"
exit "${status}"
