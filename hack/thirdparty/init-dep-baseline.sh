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
# Make an upstream tree's git HEAD hold the go.mod and go.sum the
# dependency-patch generator should diff against.
#
#   init-dep-baseline.sh <upstream-tree>
#
# Call it from the fetch target, after the custom patches and before any
# generated one. The baseline has to be the post-custom state: a custom patch
# may itself pin a dependency, and the generated patch is the delta on top of
# it. Called later it captures an already-generated tree, every pin then reads
# as satisfied, and the generator deletes the patch.
#
# An extracted tree gets a throwaway repo; a cloned one already has HEAD, and
# only needs a commit if a custom patch moved either file. Either repo lives
# inside the tree, so `make clean` removes it too.

set -e -u -o pipefail

[ $# -eq 1 ] || { echo "usage: $(basename "$0") <upstream-tree>" >&2; exit 64; }
TREE=$1

[ -d "$TREE" ] || { echo "error: no upstream tree at $TREE" >&2; exit 1; }

[ -d "$TREE/.git" ] || git -C "$TREE" -c init.defaultBranch=main init -q

if git -C "$TREE" rev-parse -q --verify HEAD >/dev/null 2>&1 &&
	git -C "$TREE" diff --quiet HEAD -- go.mod go.sum; then
	exit 0
fi

# Identity is passed inline because CI has no global git config, and -f guards
# against an upstream .gitignore excluding either file.
git -C "$TREE" add -f go.mod go.sum
git -C "$TREE" -c user.email=noreply@tigera.io -c user.name=Tigera \
	commit -q -m "Baseline: go.mod and go.sum with the custom patches applied"
echo "recorded a go.mod/go.sum baseline for $TREE"
