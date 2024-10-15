#!/bin/bash

set -e

hack_dir="$(dirname $0)"
repo_dir="$(dirname $hack_dir)"

parent_branch="$($repo_dir/hack/find-parent-release-branch.sh)"
echo "Detected parent branch: $parent_branch"

# Find all the .go files that have changed vs the parent branch.  We use
# --diff-filter=d to filter out deleted files and -z to use NUL as the
# line terminator.
#
# We can be called from a subdirectory but git diff outputs the full path from
# the repo root.  Run git diff from the current directory to get the filtered
# list of files.  Then switch to the repo root to run the formatting commands.
file_list=$(mktemp)
trap "rm -f $file_list" EXIT

git diff -z --name-only --diff-filter=d $parent_branch -- . | \
  grep -z '\.go$' > $file_list || {
    echo "No files to format.";
    exit 0;
}

# Print the files we plan to change.
echo "Formatting changed files:"
xargs -n 1 -0 echo "  " < $file_list

pushd "$repo_dir" > /dev/null
xargs -0 go run ./hack/cmd/coalesce-imports -w < $file_list
xargs -0 goimports -w -local github.com/projectcalico/calico/ < $file_list
popd > /dev/null
