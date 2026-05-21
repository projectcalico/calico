#!/bin/bash

set -e

hack_dir="$(dirname $0)"
repo_dir="$(dirname $hack_dir)"

file_list=$(mktemp)
trap "rm -f $file_list" EXIT

# Always operate from the repo root: the `find` should walk the whole tree
# and `go tool goimports` needs to resolve against the top-level Calico
# module (the repo also contains nested go.mod files under api/, lib/std/,
# lib/httpmachinery/ that don't carry the tool dependency).
pushd "$repo_dir" > /dev/null

find . -iname "*.go" \
       ! -wholename "./vendor/*" \
       ! -wholename "./third_party/*" \
       -print0 > ${file_list}


# Run extra copy of goimports first to coalesce multiple single-line imports
# into blocks.
xargs -0 go tool goimports -w -local github.com/projectcalico/calico/ < ${file_list}
# Coalesce imports then removes whitespace within blocks.
xargs -0 go run ./hack/cmd/coalesce-imports -w < ${file_list}
# Finally run goimports again to insert only the desired whitespace.
xargs -0 go tool goimports -w -local github.com/projectcalico/calico/ < ${file_list}
popd > /dev/null
