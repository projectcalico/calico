#!/bin/bash

set -e

hack_dir="$(dirname $0)"
repo_dir="$(dirname $hack_dir)"

find . -iname "*.go" ! -wholename "./vendor/*" -print0 | \
  xargs -0 go run "${repo_dir}/hack/cmd/coalesce-imports" -w
find . -iname "*.go" ! -wholename "./vendor/*" -print0 | \
  xargs -0 goimports -w -local github.com/projectcalico/calico/