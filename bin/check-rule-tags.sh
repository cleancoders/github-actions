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
