#!/bin/bash

set -e

hack_dir="$(dirname $0)"
repo_dir="$(dirname $hack_dir)"

# Allow for the parent branch to be passed in as an env var
if [[ -z "${parent_branch}" ]]; then
  parent_branch="$($repo_dir/hack/find-parent-release-branch.sh)"
fi

if [ -z "$parent_branch" ]; then
  echo "No parent branch found."
  exit 1
fi
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

# Collect files changed vs the parent branch...
git diff -z --name-only --diff-filter=d --merge-base "$parent_branch" -- . > $file_list || true
# ...and also any files that are dirty in the working tree (e.g. regenerated
# by a previous build step like "make protobuf").
git diff -z --name-only --diff-filter=d -- . >> $file_list || true

# De-duplicate (sort -uz works with NUL-delimited input), filter to .go files,
# and exclude vendored code.
sorted_list=$(mktemp)
trap "rm -f $file_list $sorted_list" EXIT
sort -uz < $file_list | \
  grep -z -v -e '^vendor/' -e '^third_party/' | \
  grep -z '\.go$' > $sorted_list || {
    echo "No files to format.";
    exit 0;
}
mv $sorted_list $file_list

# Print the files we plan to change.
echo "Formatting changed files:"
xargs -n 1 -0 echo "  " < $file_list

pushd "$repo_dir" > /dev/null

# Run extra copy of goimports first to coalesce multiple single-line imports
# into blocks.
xargs -0 goimports -w -local github.com/projectcalico/calico/ < $file_list
# Coalesce imports then removes whitespace within blocks.
xargs -0 go run ./hack/cmd/coalesce-imports -w < $file_list
# Finally run goimports again to insert only the desired whitespace.
xargs -0 goimports -w -local github.com/projectcalico/calico/ < $file_list
popd > /dev/null
