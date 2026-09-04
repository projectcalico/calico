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
# Regenerate a bundled component's derived dependency patch from its pin file.
#
#   regen-dep-patch.sh <upstream-tree> <pin-file> <output-patch>
#
# go.mod and go.sum are reset first -- to the baseline init-dep-baseline.sh
# recorded at fetch time for an extracted tree, or to the checked-out ref for a
# cloned one -- so the output depends only on the pin file and that starting
# point. Custom patches stay applied.
#
# Run inside $(DOCKER_GO_BUILD): go mod tidy's output depends on the Go version.
#
# Pins are floors. A pin the ref already satisfies is skipped rather than
# pinning the module back down, and if every pin is satisfied the patch is
# removed -- as it is when the pin file is missing or empty. So a component
# whose patch is still hand-maintained must not be passed here.

set -e -u -o pipefail

if [ $# -ne 3 ]; then
	echo "usage: $(basename "$0") <upstream-tree> <pin-file> <output-patch>" >&2
	exit 64
fi

TREE=$1
PIN_FILE=$2
OUT=$3

# Placeholders, not provenance: patch(1) ignores them, and real values would
# change the output on every run.
PATCH_SHA=0000000000000000000000000000000000000000
PATCH_AUTHOR="Tigera <noreply@tigera.io>"
PATCH_DATE="Thu, 1 Jan 1970 00:00:00 +0000"
PATCH_SUBJECT="Update dependencies for CVE fixes"

# drop_output <reason> -- leave the component with no derived patch.
drop_output() {
	if [ -e "$OUT" ]; then
		rm -f "$OUT"
		echo "removed $OUT: $1"
	else
		echo "no patch needed: $1"
	fi
}

# Pin lines are "<module> <version>"; comments become the patch header.
if [ -f "$PIN_FILE" ]; then
	mapfile -t pin_lines < <(grep -vE '^[[:space:]]*(#|$)' "$PIN_FILE" || true)
else
	pin_lines=()
fi

if [ ${#pin_lines[@]} -eq 0 ]; then
	if [ -f "$PIN_FILE" ]; then
		drop_output "$PIN_FILE declares no pins"
	else
		drop_output "no pin file at $PIN_FILE"
	fi
	exit 0
fi

# Must have been recorded at fetch time. One created here would capture an
# already-patched tree, every pin would read as satisfied, and this would
# delete the patch it was asked to rebuild.
[ -d "$TREE/.git" ] || {
	echo "error: $TREE has no baseline to diff against." >&2
	echo "       It is recorded by the component's fetch target; run 'make clean' and retry." >&2
	exit 1
}

# Discard any previously applied dependency patch.
git -C "$TREE" checkout -- go.mod go.sum

# selected_version <module> -- the version the module graph currently resolves
# to, or the empty string if the module is not in the graph at all.
selected_version() {
	(cd "$TREE" && go list -m -f '{{.Version}}' "$1" 2>/dev/null) || true
}

# is_at_least <candidate> <floor>. sort -V does not implement semver prerelease
# ordering, so avoid prerelease pins.
is_at_least() {
	[ "$1" = "$2" ] && return 0
	[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

targets=()
for line in "${pin_lines[@]}"; do
	read -r module version extra <<<"$line"
	if [ -z "${version:-}" ] || [ -n "${extra:-}" ]; then
		echo "error: $PIN_FILE: expected '<module> <version>', got: $line" >&2
		exit 1
	fi

	current=$(selected_version "$module")
	if [ -n "$current" ] && is_at_least "$current" "$version"; then
		echo "  satisfied: $module is already at $current upstream (pin $version), skipping"
		continue
	fi
	echo "  pinning:   $module $current -> $version"
	targets+=("$module@$version")
done

if [ ${#targets[@]} -gt 0 ]; then
	(cd "$TREE" && go get "${targets[@]}")
fi
(cd "$TREE" && go mod tidy)

# A module absent after tidy was never reachable, so the pin is misleading; one
# below its pin means something in the graph is holding it down.
status=0
for line in "${pin_lines[@]}"; do
	read -r module version _ <<<"$line"
	resulting=$(selected_version "$module")
	if [ -z "$resulting" ]; then
		echo "warning: $module is not in the module graph after tidy; the pin has no effect" >&2
	elif ! is_at_least "$resulting" "$version"; then
		echo "error: $module resolved to $resulting, below its pin of $version" >&2
		status=1
	fi
done
[ $status -eq 0 ] || exit $status

# core.abbrev is pinned because git scales index-line abbreviation with the
# object count, which would make the output depend on how the tree was fetched.
diff=$(git -C "$TREE" -c core.abbrev=7 diff -- go.mod go.sum)

if [ -z "$diff" ]; then
	drop_output "the pinned ref satisfies every pin on its own"
	exit 0
fi

mkdir -p "$(dirname "$OUT")"
{
	echo "From $PATCH_SHA Mon Sep 17 00:00:00 2001"
	echo "From: $PATCH_AUTHOR"
	echo "Date: $PATCH_DATE"
	echo "Subject: [PATCH] $PATCH_SUBJECT"
	echo
	# Rationale, copied from the pin file with the comment markers stripped.
	sed -n 's/^#[[:space:]]\?//p' "$PIN_FILE"
	echo
	echo "Generated from $(basename "$PIN_FILE") by hack/thirdparty/regen-dep-patch.sh."
	echo "Do not edit by hand: run 'make regen-dep-patches' in this component after"
	echo "changing a pin or the upstream ref."
	echo "---"
	echo "$diff"
} >"$OUT"

echo "wrote $OUT"
