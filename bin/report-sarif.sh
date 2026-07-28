#!/usr/bin/env bash
# Renders a semgrep SARIF file as a CI-readable table and sets the exit code.
#
#   report-sarif.sh <file.sarif>
#     exit 0  no error-level findings
#     exit 1  at least one error-level finding
#
# Why a table: the previous one-line-per-finding format told you WHERE but not
# WHAT CLASS, so acting on a finding meant looking the rule up by hand. Semgrep
# already carries CWE, OWASP category and confidence in
# tool.driver.rules[].properties.tags — this surfaces them.
#
# Severity lives on the rule, not the result: semgrep leaves results[].level null
# and puts it in tool.driver.rules[].defaultConfiguration.level. Everything below
# joins through that.
#
# Only error-level findings affect the exit code. cc-path-traversal,
# cc-generic-catch and cc-clojure-xml-xxe are WARNING on purpose — without
# dataflow they cannot be precise enough to gate a build, and the README promises
# they do not block.
#
# Results carrying a `suppressions` array are excluded from the table and the
# exit code. semgrep still emits a finding when source has a `nosemgrep`
# annotation, marking it suppressions:[{kind:"inSource"}]. Counting those means
# blocking a build on a finding a developer already triaged, and makes nosemgrep
# look broken. They are reported as a count so the suppression stays visible
# rather than silent.
set -euo pipefail

SARIF="${1:?usage: report-sarif.sh <file.sarif>}"

command -v jq >/dev/null || { echo "jq not installed"; exit 1; }
[ -f "$SARIF" ] || { echo "::error::$SARIF not found; the scan did not complete"; exit 1; }

total="$(jq '[.runs[].results[]? | select(.suppressions == null or (.suppressions | length) == 0)] | length' "$SARIF")"
suppressed="$(jq '[.runs[].results[]? | select(.suppressions != null and (.suppressions | length) > 0)] | length' "$SARIF")"
if [ "$total" -eq 0 ]; then
  echo "semgrep: no findings${suppressed:+ (${suppressed} suppressed in source)}"
  exit 0
fi

# One TSV row per finding. Tag shapes semgrep emits:
#   "CWE-79: Improper Neutralization of Input ... ('Cross-site Scripting')"
#   "OWASP-A05:2025 - Injection"          (a rule may carry several editions)
#   "HIGH CONFIDENCE"
# CWE and OWASP are reduced to identifiers here to keep the table narrow; the
# legend below prints the full names once each.
rows="$(jq -r '
  .runs[] as $r
  | ($r.tool.driver.rules
     | map({key: .id, value: .}) | from_entries) as $rules
  | [$r.results[] | select(.suppressions == null or (.suppressions | length) == 0)]
    | to_entries[]
  | .key as $i | .value as $res
  | ($rules[$res.ruleId] // {}) as $rule
  | ($rule.properties.tags // []) as $tags
  | ($rule.defaultConfiguration.level // "unknown") as $lvl
  | ($tags | map(select(startswith("CWE-")) | split(":")[0]) | join(", ")) as $cwe
  | ($tags | map(select(startswith("OWASP-")) | sub("^OWASP-";"") | split(" ")[0])
           | join(", ")) as $owasp
  | ($tags | map(select(endswith(" CONFIDENCE")) | sub(" CONFIDENCE";""))
           | first // "-") as $conf
  | [ ($i + 1 | tostring),
      $lvl,
      ($res.locations[0].physicalLocation.artifactLocation.uri
       + ":" + ($res.locations[0].physicalLocation.region.startLine // 0 | tostring)),
      ($res.ruleId | split(".") | last),
      (if $cwe == "" then "-" else $cwe end),
      (if $owasp == "" then "-" else $owasp end),
      $conf ]
  | @tsv' "$SARIF")"

{
  printf '#\tSEVERITY\tFILE:LINE\tRULE\tCWE\tOWASP\tCONFIDENCE\n'
  printf '%s\n' "$rows"
} | { command -v column >/dev/null && column -t -s "$(printf '\t')" || cat; }

# Legend: expand each identifier once rather than repeating long names per row.
echo
echo "CWE:"
jq -r '.runs[] as $r
       | ([$r.results[] | select(.suppressions == null or (.suppressions | length) == 0)
           | .ruleId] | unique) as $shown
       | [$r.tool.driver.rules[] | select(.id as $i | $shown | index($i))
          | .properties.tags[]? | select(startswith("CWE-"))]
       | unique | .[] | "  " + .' "$SARIF"
echo "OWASP:"
jq -r '.runs[] as $r
       | ([$r.results[] | select(.suppressions == null or (.suppressions | length) == 0)
           | .ruleId] | unique) as $shown
       | [$r.tool.driver.rules[] | select(.id as $i | $shown | index($i))
          | .properties.tags[]? | select(startswith("OWASP-")) | sub("^OWASP-";"")]
       | unique | .[] | "  " + .' "$SARIF"

blocking="$(jq '[.runs[] as $r
                 | ($r.tool.driver.rules
                    | map({key: .id, value: .defaultConfiguration.level})
                    | from_entries) as $lv
                 | $r.results[]
                 | select(.suppressions == null or (.suppressions | length) == 0)
                 | select($lv[.ruleId] == "error")] | length' "$SARIF")"

echo
echo "semgrep: ${total} finding(s), ${blocking} blocking (error-level)"
if [ "$suppressed" -gt 0 ]; then
  echo "         ${suppressed} additional finding(s) suppressed in source (nosemgrep)"
fi
if [ "$blocking" -gt 0 ]; then
  echo "::error::semgrep found ${blocking} blocking finding(s); see the table above and the semgrep-sarif artifact"
  exit 1
fi
exit 0
