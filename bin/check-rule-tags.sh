#!/usr/bin/env bash
# Every cleancoders rule must carry metadata.cwe, metadata.owasp, and
# metadata.class. The coverage matrix in README.md is generated from these, so an
# untagged rule is a detection that exists but is invisible to the evidence trail.
#
# Also enforces the alias mitigation: semgrep cannot resolve namespace aliases, so
# a rule that matches a namespaced function must enumerate its aliases. Rules that
# opt out declare metadata.alias-exempt with a reason (special forms and interop
# like js/eval or .-innerHTML cannot be aliased).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${ROOT}/security-rules/semgrep"

command -v yq >/dev/null || { echo "yq not installed"; exit 1; }

status=0
for f in "${RULES}"/*.yaml; do
  id="$(yq -r '.rules[0].id' "${f}")"

  case "${id}" in
    cc-*) ;;
    *) echo "${f}: rule id '${id}' must be prefixed cc-"; status=1 ;;
  esac

  [ "$(yq -r '.rules[0].languages | contains(["clojure"])' "${f}")" = "true" ] \
    || { echo "${f}: must declare languages: [clojure]"; status=1; }

  # Capture first, then match. `yq ... | grep -q` breaks under `set -o pipefail`:
  # grep -q exits on the first match and closes the pipe, yq takes SIGPIPE, and
  # pipefail reports the whole pipeline as failed. Only shows up on rules with
  # more than one CWE entry, which makes it a nasty intermittent.
  cwes="$(yq -r '.rules[0].metadata.cwe[]' "${f}" 2>/dev/null || true)"
  echo "${cwes}" | grep -qE '^CWE-[0-9]+' \
    || { echo "${f}: metadata.cwe must list at least one 'CWE-<n>: ...' entry"; status=1; }

  owasp_count="$(yq -r '.rules[0].metadata.owasp[]' "${f}" 2>/dev/null \
                 | grep -cE '^A(0[1-9]|10):2025' || true)"
  [ "${owasp_count}" -eq 1 ] \
    || { echo "${f}: needs exactly one 'A<NN>:2025 - ...' owasp entry (found ${owasp_count})"; status=1; }

  cls="$(yq -r '.rules[0].metadata.class // ""' "${f}")"
  echo "${cls}" | grep -qE '^[a-z0-9-]+$' \
    || { echo "${f}: metadata.class must name a clojure-security class"; status=1; }

  exempt="$(yq -r '.rules[0].metadata.alias-exempt // ""' "${f}")"
  if [ -z "${exempt}" ]; then
    # A rule matching a namespaced fn must enumerate aliases, because semgrep
    # cannot resolve them. Count distinct "(prefix/" tokens in the pattern lines;
    # fewer than two means the rule only matches one spelling of the sink.
    prefixes="$(grep -E '^\s+- pattern' -A0 "${f}" \
                | grep -oE '\(([a-zA-Z0-9._-]+)/' | sort -u | wc -l | tr -d ' ')"
    [ "${prefixes}" -ge 2 ] \
      || { echo "${f}: enumerate at least 2 namespace aliases, or set metadata.alias-exempt with a reason"; status=1; }
  fi
done

[ "${status}" -eq 0 ] && echo "all rules tagged"
exit "${status}"
