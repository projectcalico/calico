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

xargs -0 go run "${repo_dir}/hack/cmd/coalesce-imports" -w < ${file_list}
xargs -0 goimports -w -local github.com/projectcalico/calico/ < ${file_list}