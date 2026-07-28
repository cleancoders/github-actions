#!/usr/bin/env bash
# Tests bin/run-zizmor.sh, which decides whether zizmor runs its online audits.
#
# The case that matters is a `uses:` pointing at a repository the token cannot
# read. zizmor 1.28.0 treats that as fatal — "no audit was performed" — so a
# consumer whose build calls a private reusable workflow gets no audit at all,
# not a partial one. Degrading to offline audits keeps the scan meaningful;
# propagating the failure keeps a genuinely broken scan visible.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN="${ROOT}/bin/run-zizmor.sh"
pass=0; fail=0

ok()    { pass=$((pass+1)); }
bad()   { fail=$((fail+1)); echo "FAIL: $1"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1 — expected '$3', got '$2'"; fi; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# A fake zizmor recording its argv, so the tests assert on the flags actually
# passed rather than on zizmor's behaviour. FAKE_MODE picks the failure to
# simulate; FAKE_CALLS counts invocations so a retry is distinguishable from a
# single run.
mkdir -p "${WORK}/bin"
cat > "${WORK}/bin/zizmor" <<'FAKE'
#!/usr/bin/env bash
echo "$*" >> "${FAKE_ARGV}"
echo "1" >> "${FAKE_CALLS}"
case "${FAKE_MODE}" in
  ok) exit 0 ;;
  private-uses)
    # Verbatim shape of the zizmor 1.28.0 failure, minus the repository name.
    if grep -q -- "--no-online-audits" <<<"$*"; then exit 0; fi
    echo "fatal: no audit was performed" >&2
    echo "'ref-confusion' audit failed on file://./.github/workflows/build.yml" >&2
    echo "    2: can't access some-org/some-repo: missing or you have no access" >&2
    exit 1 ;;
  broken) echo "error: failed to parse workflow" >&2; exit 1 ;;
esac
FAKE
chmod +x "${WORK}/bin/zizmor"

# Each run gets fresh argv/call logs.
run() {
  FAKE_MODE="$1"; shift
  FAKE_ARGV="${WORK}/argv"; FAKE_CALLS="${WORK}/calls"
  : > "${FAKE_ARGV}"; : > "${FAKE_CALLS}"
  export FAKE_MODE FAKE_ARGV FAKE_CALLS
  PATH="${WORK}/bin:${PATH}" bash "${RUN}" "${WORK}/zizmor.sarif" "$@" 2>&1
}
argv()  { cat "${WORK}/argv"; }
calls() { grep -c . "${WORK}/calls"; }

# --- token present and every `uses:` reachable: online audits stay on ---------
out="$(GH_TOKEN=tok run ok)"; rc=$?
check "reachable scan passes"              "$rc" "0"
check "online audits are not disabled"     "$(argv | grep -c -- '--no-online-audits')" "0"
check "runs once when it succeeds"         "$(calls)" "1"

# --- no token: zizmor would warn it is implicitly offline, so be explicit -----
out="$(GH_TOKEN='' run ok)"; rc=$?
check "tokenless scan passes"              "$rc" "0"
check "tokenless scan disables online"     "$(argv | grep -c -- '--no-online-audits')" "1"
check "tokenless scan says why"            "$(echo "$out" | grep -c 'no API token')" "1"

# --- the regression: a `uses:` the token cannot read --------------------------
# Without the retry this is a hard failure and the SARIF is empty, so the job is
# red for a reason unrelated to any finding in the consumer's workflows.
out="$(GH_TOKEN=tok run private-uses)"; rc=$?
check "unreachable uses: still passes"     "$rc" "0"
check "retries with online audits off"     "$(argv | grep -c -- '--no-online-audits')" "1"
check "retry is a second invocation"       "$(calls)" "2"
check "degradation is announced"           "$(echo "$out" | grep -c '::warning::')" "1"
check "names the audit that failed"        "$(echo "$out" | grep -c 'ref-confusion')" "1"

# --- a genuinely broken scan must stay broken --------------------------------
# Retrying everything would turn real breakage (unparseable workflow, missing
# binary) into a green job — the silent-pass failure mode this repo exists to
# prevent.
out="$(GH_TOKEN=tok run broken)"; rc=$?
check "unrelated failure propagates"      "$rc" "1"
check "unrelated failure is not retried"  "$(calls)" "1"

# --- wiring: the workflow must call the script, not zizmor directly -----------
WF="${ROOT}/.github/workflows/security.yml"
if [ -f "$WF" ]; then
  check "the runner is actually called" \
    "$(grep -c 'run-zizmor.sh zizmor.sarif' "$WF")" "1"
  check "zizmor is not invoked inline" \
    "$(grep -cE '^\s+zizmor --no-progress' "$WF")" "0"
fi

echo "run-zizmor tests: ${pass} passed, ${fail} failed"
[ "${fail}" -eq 0 ]
