#!/usr/bin/env bash
# Self-skip predicates for security.yml, in one tested place.
#
# Every scanner job must skip cleanly on a repo that lacks the thing it scans —
# a library with no bin/, a repo with no deps.edn. That logic used to be an
# inline `if [ -d ... ]` duplicated across jobs, which meant it could not be
# tested and drifted between copies. The `detect` job runs this once and exposes
# the answers as job outputs.
#
# Usage:
#   detect.sh dir-has-files <dir>        exit 0 if dir exists and holds >=1 file
#   detect.sh existing-dirs <paths...>   print the subset of paths that are dirs
#   detect.sh outputs                    emit key=value lines for GITHUB_OUTPUT
#
# `outputs` reads SHELLCHECK_DIR, EXTRA_RULES_DIR, and SRC_PATHS from the env so
# the workflow passes inputs in one place.
set -euo pipefail

dir_has_files() {
  local d="${1:-}"
  [ -n "$d" ] || return 1
  [ -d "$d" ] || return 1
  [ -n "$(find "$d" -type f 2>/dev/null | head -1)" ]
}

# Filters a space-separated list down to paths that exist as directories. Used
# for src-paths, where the default names three roots and most repos have one.
existing_dirs() {
  local out=()
  for p in "$@"; do
    [ -d "$p" ] && out+=("$p")
  done
  [ ${#out[@]} -gt 0 ] && printf '%s\n' "${out[@]}"
  return 0
}

emit_outputs() {
  local sc="${SHELLCHECK_DIR:-}" extra="${EXTRA_RULES_DIR:-}" src="${SRC_PATHS:-}"

  if dir_has_files "$sc"; then echo "has-shellcheck-target=true"
  else echo "has-shellcheck-target=false"; fi

  if dir_has_files ".github/workflows"; then echo "has-workflows=true"
  else echo "has-workflows=false"; fi

  if [ -n "$extra" ] && [ -d "$extra" ]; then echo "has-extra-rules=true"
  else echo "has-extra-rules=false"; fi

  if [ -f deps.edn ]; then echo "has-deps-edn=true"
  else echo "has-deps-edn=false"; fi

  # shellcheck disable=SC2086  # deliberate word-splitting: src is a path list
  local dirs
  dirs="$(existing_dirs $src | paste -sd' ' - || true)"
  echo "src-dirs=${dirs}"
  if [ -n "$dirs" ]; then echo "has-src-dirs=true"; else echo "has-src-dirs=false"; fi
}

case "${1:-}" in
  dir-has-files)  shift; dir_has_files "$@" ;;
  existing-dirs)  shift; existing_dirs "$@" ;;
  outputs)        emit_outputs ;;
  *) echo "usage: detect.sh {dir-has-files <dir>|existing-dirs <paths...>|outputs}" >&2
     exit 2 ;;
esac
