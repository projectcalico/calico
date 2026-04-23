#!/usr/bin/env bash
# Enumerates Go source files, or the top-level directories that contain them,
# for use from the root Makefile.
#
# Prunes:
#   - dot-directories (e.g. .git, .go-pkg-cache, .claude, .idea); these have
#     no component Go code but many inodes, so descending into them is slow.
#   - lib/ and pkg/ (separate go.mod modules / not standalone components).
#   - crypto/ (shared utility package, not a top-level component).
#
# Usage:
#   hack/list-go-sources.sh dirs   # top-level dirs containing *.go files
#   hack/list-go-sources.sh files  # all *.go files under the repo
set -euo pipefail

mode=${1:-dirs}

find_go_files() {
  find . -mindepth 1 \
    \( -type d \( \
         -name '.*' \
      -o -path './lib' \
      -o -path './pkg' \
      -o -path './crypto' \
    \) -prune \) \
    -o -name '*.go' -print
}

case "$mode" in
  files)
    find_go_files
    ;;
  dirs)
    find_go_files | awk -F/ 'NF>=3 { print $2 }' | sort -u
    ;;
  *)
    echo "usage: $0 [dirs|files]" >&2
    exit 2
    ;;
esac
