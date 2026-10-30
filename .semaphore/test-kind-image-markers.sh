#!/usr/bin/env bash

# Smoke tests for the KIND_IMAGE_MARKERS rules: what a kind lane sees after
# load-cached-images restores an image and `make -C e2e build` then compiles
# libbpf.a. Run manually; every case is a `make -n`.

set -u
cd "$(dirname "$0")/.." || exit 1
repo_root="$PWD"
arch=${ARCH:-amd64}
fails=0

check() {
  local desc="$1"
  shift
  if "$@"; then echo "PASS: $desc"; else
    echo "FAIL: $desc"
    fails=$((fails + 1))
  fi
}

node_marker="$repo_root/node/.image.created-$arch"
calico_marker="$repo_root/cmd/calico/.image.created-$arch"
libbpf_a="$repo_root/felix/bpf-gpl/libbpf/src/$arch/libbpf.a"

# Only clean up what this run created; a developer tree may hold real markers,
# and deleting one would cost them a rebuild.
created=()

create() {
  [ -e "$1" ] && return
  mkdir -p "$(dirname "$1")"
  touch "$1"
  created+=("$1")
}

trap '[ ${#created[@]} -eq 0 ] || rm -f "${created[@]}"' EXIT

if [ -f "$libbpf_a" ]; then
  echo "SKIP: a real libbpf.a is present in the tree; run this in a clean checkout"
  exit 0
fi

dry_run() { make -n "$@" 2>&1; }

# A libbpf.a newer than the markers must not invalidate them. It is an
# order-only prereq precisely so a cache hit survives `make -C e2e build`.
create "$node_marker"
create "$calico_marker"
sleep 1
create "$libbpf_a"
out=$(dry_run "$node_marker" "$calico_marker")
check "fresh libbpf keeps the node image" grep -q "'$node_marker' is up to date" <<<"$out"
check "fresh libbpf keeps the calico image" grep -q "'$calico_marker' is up to date" <<<"$out"

# Order-only must not cost us staleness: a newer source file still rebuilds.
dep=$(grep '^local:' "$repo_root/cmd/deps.txt" | cut -d: -f2- | tr ' ' '\n' | head -1)
touch "$repo_root/$dep"/*.go
out=$(dry_run "$calico_marker")
check "a newer source file rebuilds the calico image" grep -q "make -C $repo_root/cmd/calico image" <<<"$out"

# A missing libbpf.a is still built first, without dragging the image in.
rm -f "$libbpf_a"
touch "$node_marker"
out=$(dry_run "$node_marker")
check "missing libbpf is built" grep -q "make -C $repo_root/felix libbpf ARCH=$arch" <<<"$out"
check "missing libbpf does not rebuild the image" test "$(grep -c "make -C $repo_root/node image" <<<"$out")" = 0

echo "FAILURES: $fails"
exit $fails
