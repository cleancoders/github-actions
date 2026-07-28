#!/usr/bin/env bash
# Runs zizmor and writes SARIF to the given path.
#
# zizmor's online audits (ref-confusion, and the commit lookup inside
# unpinned-uses) resolve every repository a workflow references with `uses:`.
# When one of them is private to the token in use, zizmor 1.28.0 does not skip
# that audit — it aborts the whole run with "fatal: no audit was performed", so
# a repo whose build calls a private reusable workflow gets NO audit rather than
# a partial one, and the SARIF comes out empty.
#
# GITHUB_TOKEN is scoped to the repository being scanned, so this is the default
# state for any consumer that calls a private reusable workflow, not an edge
# case. Rather than drop the online audits for everyone, run them and fall back
# to offline audits only when that specific lookup failure occurs. Consumers who
# want the online audits kept can pass a token that reaches every referenced
# repository.
#
# Deliberately narrow: only the lookup failure triggers the retry. Retrying on
# any nonzero exit would turn an unparseable workflow or a missing binary into a
# green job, which is indistinguishable from "audited and found nothing".
#
# Tested by bin/test-run-zizmor.sh.
set -uo pipefail

OUT="${1:?usage: run-zizmor.sh <output.sarif> [target...]}"
shift
targets=("$@")
[ "${#targets[@]}" -eq 0 ] && targets=(".")

args=(--no-progress --format sarif)

# zizmor decides online-vs-offline from the token's presence and warns when it
# picks offline implicitly. Being explicit keeps that warning out of the log and
# makes the choice visible in the argv.
offline=0
if [ -z "${GH_TOKEN:-}" ]; then
  echo "zizmor: no API token supplied; running offline audits only"
  args+=(--no-online-audits)
  offline=1
fi

err="$(mktemp)"
trap 'rm -f "${err}"' EXIT

zizmor "${args[@]}" "${targets[@]}" > "${OUT}" 2>"${err}"
rc=$?
cat "${err}" >&2

if [ "${rc}" -ne 0 ] && [ "${offline}" -eq 0 ] &&
   grep -qE "no audit was performed|no access|couldn't list branches" "${err}"; then
  echo "::warning::zizmor could not resolve every repository referenced by a \`uses:\`, which aborts its online audits. Retrying with them disabled — offline audits still ran. To keep the online audits, pass the gh-api-token secret with read access to every referenced repository."
  zizmor "${args[@]}" --no-online-audits "${targets[@]}" > "${OUT}" 2>"${err}"
  rc=$?
  cat "${err}" >&2
fi

exit "${rc}"
