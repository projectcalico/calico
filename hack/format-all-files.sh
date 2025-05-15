#!/bin/bash

set -e

hack_dir="$(dirname $0)"
repo_dir="$(dirname $hack_dir)"

file_list=$(mktemp)
trap "rm -f $file_list" EXIT

find . -iname "*.go" \
       ! -wholename "./vendor/*" \
       ! -wholename "./third_party/*" \
       -print0 > ${file_list}


# Run extra copy of goimports first to coalesce multiple single-line imports
# into blocks.
xargs -0 goimports -w -local github.com/projectcalico/calico/ < ${file_list}
# Coalesce imports then removes whitespace within blocks.
xargs -0 go run "${repo_dir}/hack/cmd/coalesce-imports" -w < ${file_list}
# Finally run goimports again to insert only the desired whitespace.
xargs -0 goimports -w -local github.com/projectcalico/calico/ < ${file_list}