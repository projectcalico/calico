#!/bin/bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Give an extracted upstream tree a git baseline for go.mod and go.sum, for the
# dependency-patch generator to diff against.
#
#   init-dep-baseline.sh <upstream-tree>
#
# Call it from the fetch target, right after extraction: the baseline must
# record upstream's files. Created later it captures an already-patched tree,
# every pin then reads as satisfied, and the generator deletes the patch.
#
# No-op for cloned trees, which already have one. The repo it creates lives
# inside the extracted tree, so `make clean` removes it too.

set -e -u -o pipefail

[ $# -eq 1 ] || { echo "usage: $(basename "$0") <upstream-tree>" >&2; exit 64; }
TREE=$1

[ -d "$TREE" ] || { echo "error: no upstream tree at $TREE" >&2; exit 1; }
[ -d "$TREE/.git" ] && exit 0

# Identity is passed inline because CI has no global git config, and -f guards
# against an upstream .gitignore excluding either file.
git -C "$TREE" -c init.defaultBranch=main init -q
git -C "$TREE" add -f go.mod go.sum
git -C "$TREE" -c user.email=noreply@tigera.io -c user.name=Tigera \
	commit -q -m "Baseline: go.mod and go.sum as extracted from upstream"
echo "recorded a go.mod/go.sum baseline for $TREE"
