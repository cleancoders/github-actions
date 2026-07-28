#!/usr/bin/env bash
# Emits the scanner rows of the coverage matrix from rule metadata. Hand-
# maintaining this table is how a coverage doc starts lying: a rule gets renamed
# or deleted and the table keeps claiming it, which is worse than no table once
# it reaches an auditor. --check fails CI when the committed table no longer
# matches the rules on disk.
#
#   gen-coverage-matrix.sh          rewrite the table in README.md
#   gen-coverage-matrix.sh --emit   print the table to stdout
#   gen-coverage-matrix.sh --check  exit 1 if README.md is stale
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${ROOT}/security-rules/semgrep"
README="${ROOT}/README.md"
BEGIN='<!-- BEGIN COVERAGE -->'
END='<!-- END COVERAGE -->'

command -v yq >/dev/null || { echo "yq not installed"; exit 1; }

generate() {
  echo "${BEGIN}"
  echo
  echo "| rule | class | CWE | OWASP 2025 | blocking |"
  echo "|------|-------|-----|------------|----------|"
  for f in "${RULES}"/*.yaml; do
    id="$(yq -r '.rules[0].id' "${f}")"
    cls="$(yq -r '.rules[0].metadata.class' "${f}")"
    sev="$(yq -r '.rules[0].severity' "${f}")"
    # "CWE-79: Improper ..." -> "79"; join multiples with ", "
    cwe="$(yq -r '.rules[0].metadata.cwe[]' "${f}" \
           | sed -E 's/^CWE-([0-9]+).*/\1/' | paste -sd', ' - | sed 's/,/, /g')"
    # "A05:2025 - Injection" -> "A05"
    owasp="$(yq -r '.rules[0].metadata.owasp[0]' "${f}" | sed -E 's/^(A[0-9]+):.*/\1/')"
    # WARNING rules are triage-only by design and must not gate a build.
    if [ "${sev}" = "WARNING" ]; then blocking="no (triage)"; else blocking="yes"; fi
    echo "| \`${id}\` | \`${cls}\` | ${cwe} | ${owasp} | ${blocking} |"
  done
  echo
  echo "${END}"
}

case "${1:-}" in
  --emit)
    generate
    ;;
  --check)
    current="$(sed -n "/${BEGIN}/,/${END}/p" "${README}")"
    if [ "${current}" != "$(generate)" ]; then
      echo "README coverage table is stale. Run: bash bin/gen-coverage-matrix.sh"
      diff <(echo "${current}") <(generate) || true
      exit 1
    fi
    echo "coverage table current"
    ;;
  *)
    tmp="$(mktemp)"
    generate > "${tmp}"
    python3 - "${README}" "${tmp}" <<'PY'
import re, sys
readme, table = sys.argv[1], sys.argv[2]
body = open(table).read().strip()
src = open(readme).read()
new = re.sub(r"<!-- BEGIN COVERAGE -->.*?<!-- END COVERAGE -->", lambda _: body,
             src, flags=re.S)
open(readme, "w").write(new)
PY
    rm -f "${tmp}"
    echo "README coverage table regenerated"
    ;;
esac
