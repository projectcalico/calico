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

# validate_stamps.sh removes stale kind image marker/stamp files whose Docker
# images no longer exist locally. Docker images can disappear (pruned, manual
# rmi) while their stamp files remain, causing Make to skip needed rebuilds.
#
# Must run as a separate Make invocation BEFORE kind-build-images-run evaluates
# its prerequisites — otherwise Make will see the stale stamps as satisfied.
#
# Usage: validate_stamps.sh ARCH BUILD_TAG STAMP_FILE...

set -euo pipefail

arch="${1:?Usage: validate_stamps.sh ARCH BUILD_TAG STAMP_FILE...}"
build_tag="${2:?}"
shift 2

# Derive the Docker image that a stamp file tracks. Most follow a regular
# naming pattern; the case statement handles the exceptions.
image_for_stamp() {
	local stamp="$1"
	case "$stamp" in
		*/.stamp.operator)
			echo "tigera/operator:${build_tag}" ;;
		*/.stamp.*)
			local name="${stamp##*/.stamp.}"
			echo "calico/${name}:latest-${arch}" ;;
		*/cni-plugin/.image.created-*)
			echo "calico/cni:latest-${arch}" ;;
		*/pod2daemon/.image.created-*)
			echo "calico/pod2daemon-flexvol:latest-${arch}" ;;
		*/.image.created-*)
			local dir="${stamp%/.image.created-*}"
			local name="${dir##*/}"
			echo "calico/${name}:latest-${arch}" ;;
		*)
			;;
	esac
}

removed=0
for stamp in "$@"; do
	[ -f "$stamp" ] || continue

	image=$(image_for_stamp "$stamp")
	[ -z "$image" ] && continue

	if ! docker image inspect "$image" &>/dev/null; then
		rm -f "$stamp"
		echo "Stale: removed $(basename "$stamp") ($image not in Docker)"
		((removed++)) || true
	fi
done

if [ "$removed" -gt 0 ]; then
	echo "Cleaned $removed stale marker(s), affected images will be rebuilt."
fi
