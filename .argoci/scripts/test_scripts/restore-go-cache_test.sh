#!/usr/bin/env bash
# Tests for restore-go-cache: a machine's go-build containers read the shared
# caches in place through the exports it prints.
set -u
cd "$(dirname "$0")/../../.." || exit 1
script="$PWD/.argoci/scripts/restore-go-cache"
fails=0

check() {
  local desc="$1"
  shift
  if "$@"; then echo "PASS: $desc"; else
    echo "FAIL: $desc"
    fails=$((fails + 1))
  fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export CI_HOME="$work/home" CI_GIT_DIR=repo GOCACHE="$work/gocache" GO_LOCAL_MOD="$work/home/go-mod"

shared="$work/shared"
mkdir -p "$shared/build" "$shared/mod/example.com/m@v1.0.0" "$shared/mod/example.com/img@v1.0.0" "$shared/mod/cache/download/example.com/m/@v"
echo src > "$shared/mod/example.com/m@v1.0.0/m.go"
echo zip > "$shared/mod/cache/download/example.com/m/@v/v1.0.0.zip"
: > "$shared/mod/cache/lock"
chmod -R a-w "$shared"
local_mod="$GO_LOCAL_MOD"
# An image's own copy of a module stays as it is.
mkdir -p "$local_mod/example.com/img@v1.0.0"
out=$("$script" some-step "$shared" 2>/dev/null)
check "pod: a module already in the local cache is kept" bash -c '[ -d "$1" ] && ! [ -L "$1" ]' _ "$local_mod/example.com/img@v1.0.0"
check "pod: prints the local module cache" grep -qx "export GOMODCACHE='$local_mod'" <<<"$out"
check "pod: prints the build cache helper" grep -qx "export GOCACHEPROG='gocacheprog -v -ro $shared/build -dir $GOCACHE/prog'" <<<"$out"
check "pod: the exports eval" bash -c "eval \"\$1\" && [ -n \"\$GOMODCACHE\" ] && [ -n \"\$GOCACHEPROG\" ]" _ "$out"
check "pod: a shared module is a link to it" test "$(readlink "$local_mod/example.com/m@v1.0.0")" = "$shared/mod/example.com/m@v1.0.0"
check "pod: its download is a linked file" test -L "$local_mod/cache/download/example.com/m/@v/v1.0.0.zip"
check "pod: a new version of the module can be downloaded locally" touch "$local_mod/cache/download/example.com/m/@v/v1.1.0.zip"
check "pod: a new module can be unpacked locally" mkdir -p "$local_mod/example.com/n@v1.0.0"
check "pod: the module lock is local, not the shared one" bash -c '! [ -e "$1/cache/lock" ] || ! [ -L "$1/cache/lock" ]' _ "$local_mod"
check "pod: a second run relinks" bash -c '"$1" some-step "$2" >/dev/null 2>&1' _ "$script" "$shared"
chmod -R u+w "$shared"

check "no caches: fails" bash -c '! "$1" some-step "$2" 2>/dev/null' _ "$script" "$work/empty"

[ "$fails" -eq 0 ] || { echo "$fails failed"; exit 1; }
