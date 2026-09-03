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
# The upstream tree must be a git checkout at the pinned upstream ref. go.mod
# and go.sum are reset to that ref first, so this is idempotent: the output
# depends only on the pin file and the ref, never on what the tree happened to
# contain. Functional patches are left applied -- they touch source only, and
# the emitted diff is scoped to go.mod and go.sum.
#
# Run inside $(DOCKER_GO_BUILD) so the Go toolchain is the pinned one. Running
# it with a different Go can produce a different go.sum, which the drift check
# will then report on every unrelated PR.
#
# A pin is a floor, never a ceiling: if the ref already satisfies a pin, the
# pin is reported as satisfied and left out of the patch rather than pinning
# the module back down. If every pin is satisfied the patch is removed
# entirely, which is the correct end state for a component that upstream has
# caught up with.

set -e -u -o pipefail

if [ $# -ne 3 ]; then
	echo "usage: $(basename "$0") <upstream-tree> <pin-file> <output-patch>" >&2
	exit 64
fi

TREE=$1
PIN_FILE=$2
OUT=$3

# Deterministic identity for the emitted patch. These are placeholders, not
# provenance: the patch is applied with patch(1), which ignores them, and a
# real author or date would make the output differ on every regeneration.
PATCH_SHA=0000000000000000000000000000000000000000
PATCH_AUTHOR="Tigera <noreply@tigera.io>"
PATCH_DATE="Thu, 1 Jan 1970 00:00:00 +0000"
PATCH_SUBJECT="Update dependencies for CVE fixes"

[ -d "$TREE/.git" ] || { echo "error: $TREE is not a git checkout" >&2; exit 1; }
[ -f "$PIN_FILE" ] || { echo "error: no pin file at $PIN_FILE" >&2; exit 1; }

# Reset the derived files to the pinned ref, discarding any previously applied
# dependency patch.
git -C "$TREE" checkout -- go.mod go.sum

# Pins are "<module> <version>" lines; everything else is rationale that gets
# copied into the patch header verbatim.
mapfile -t pin_lines < <(grep -vE '^[[:space:]]*(#|$)' "$PIN_FILE" || true)
if [ ${#pin_lines[@]} -eq 0 ]; then
	echo "error: $PIN_FILE declares no pins" >&2
	exit 1
fi

# selected_version <module> -- the version the module graph currently resolves
# to, or the empty string if the module is not in the graph at all.
selected_version() {
	(cd "$TREE" && go list -m -f '{{.Version}}' "$1" 2>/dev/null) || true
}

# is_at_least <candidate> <floor> -- true when candidate >= floor. sort -V is
# enough for the release versions used as pins; it does not implement semver
# prerelease ordering, so avoid prerelease pins.
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

# Confirm each pin actually took. A pin whose module is absent afterwards was
# tidied away as unused, which means it was never reachable and the pin is
# misleading; a pin that resolved lower than asked means something in the graph
# is holding it down.
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
# size of the object database, which would otherwise make the output depend on
# how the upstream tree was fetched.
diff=$(git -C "$TREE" -c core.abbrev=7 diff -- go.mod go.sum)

if [ -z "$diff" ]; then
	if [ -e "$OUT" ]; then
		rm -f "$OUT"
		echo "removed $OUT: the pinned ref satisfies every pin on its own"
	else
		echo "no patch needed: the pinned ref satisfies every pin on its own"
	fi
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
