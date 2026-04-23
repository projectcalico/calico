#!/usr/bin/env bash
# Enumerates Go source files, or the top-level directories that contain them,
# for use from the root Makefile.
#
# Skips:
#   - dot-directories (e.g. .git, .go-pkg-cache, .claude, .idea); these have
#     no component Go code but many inodes, so descending into them is slow.
#   - lib/ and pkg/ (separate go.mod modules / not standalone components).
#   - crypto/ (shared utility package, not a top-level component).
#
# Usage:
#   hack/list-go-sources.sh dirs   # top-level dirs containing *.go files
#   hack/list-go-sources.sh files  # all *.go files under the repo
set -euo pipefail

# Directory-name excludes applied to top-level entries. `.*` excludes
# dot-directories; the rest are component-layout exclusions.
EXCLUDES=( '.*' lib pkg crypto )

excluded() {
  local d=$1 pat
  for pat in "${EXCLUDES[@]}"; do
    # shellcheck disable=SC2053 # intentional glob match, not string compare
    [[ $d == $pat ]] && return 0
  done
  return 1
}

list_dirs() {
  # For each non-excluded top-level directory, print its name if it contains
  # at least one `.go` file. `find -print -quit` exits on the first match, so
  # we don't walk through every source file in huge components (felix,
  # libcalico-go, ...) just to recover the directory name.
  #
  # The `*/` glob is already lexically sorted and skips dot-dirs (no dotglob),
  # so no trailing `sort -u` is needed.
  local d
  for d in */; do
    d=${d%/}
    excluded "$d" && continue
    if find "$d" -name '*.go' -print -quit 2>/dev/null | read -r _; then
      echo "$d"
    fi
  done
}

list_files() {
  # No early-exit possible: callers (the DEP_FILES prereq) need every file.
  # Dot-directories are pruned at any depth (e.g. a stray `.cache`); the
  # component-layout exclusions only prune at the top level, because
  # `pkg/` appears inside most components as an ordinary subdirectory.
  find . -mindepth 1 \
    \( -type d \( \
         -name '.*' \
      -o -path './lib' \
      -o -path './pkg' \
      -o -path './crypto' \
    \) -prune \) \
    -o -name '*.go' -print
}

case "${1:-dirs}" in
  files) list_files ;;
  dirs)  list_dirs ;;
  *)     echo "usage: $0 [dirs|files]" >&2; exit 2 ;;
esac
