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
# Each stamp file contains the Docker image name it tracks (written by the
# Makefile rule that creates it). This script reads that name and checks
# whether the image still exists in Docker.
#
# Must run as a separate Make invocation BEFORE kind-build-images-run evaluates
# its prerequisites — otherwise Make will see the stale stamps as satisfied.
#
# Usage: validate_stamps.sh STAMP_FILE...

set -euo pipefail

removed=0
for stamp in "$@"; do
	[ -f "$stamp" ] || continue

	image=$(<"$stamp")
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
