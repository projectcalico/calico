#!/bin/bash

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Sets max-concurrent-uploads in the Docker daemon config and reloads dockerd.
#
# Usage: set-docker-max-concurrent-uploads.sh [--no-reload] <count>
#
# max-concurrent-uploads is a live-reloadable daemon option, so dockerd is sent
# SIGHUP instead of being restarted; running containers and logins survive.
# Other keys already in the config are preserved.

set -euo pipefail

DOCKER_DAEMON_CONFIG="${DOCKER_DAEMON_CONFIG:-/etc/docker/daemon.json}"

usage() {
  echo "Usage: $0 [--no-reload] <count>" >&2
  exit 1
}

reload=true
if [ "${1:-}" = "--no-reload" ]; then
  reload=false
  shift
fi
[ $# -eq 1 ] || usage
count="$1"
if ! [[ "$count" =~ ^[1-9][0-9]*$ ]]; then
  echo "Error: count must be a positive integer, got '$count'" >&2
  exit 1
fi

# Only escalate when needed so the script also works against a user-owned config file.
SUDO=""
config_dir="$(dirname "$DOCKER_DAEMON_CONFIG")"
existing_dir="$config_dir"
while [ ! -d "$existing_dir" ]; do
  existing_dir="$(dirname "$existing_dir")"
done
if { [ -e "$DOCKER_DAEMON_CONFIG" ] && [ ! -w "$DOCKER_DAEMON_CONFIG" ]; } || [ ! -w "$existing_dir" ]; then
  SUDO="sudo"
fi

$SUDO mkdir -p "$config_dir"
existing="{}"
if $SUDO test -s "$DOCKER_DAEMON_CONFIG"; then
  existing="$($SUDO cat "$DOCKER_DAEMON_CONFIG")"
fi

# python3 rather than jq: it is always present on the CI images, jq is not.
updated="$(python3 -c '
import json, sys
cfg = json.loads(sys.argv[1])
if not isinstance(cfg, dict):
    sys.exit("daemon config is not a JSON object")
cfg["max-concurrent-uploads"] = int(sys.argv[2])
print(json.dumps(cfg, indent=2))
' "$existing" "$count")"

# Write to a temp file and move it into place so a failure can't leave dockerd with a truncated config.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
printf '%s\n' "$updated" >"$tmp"
$SUDO install -m 0644 "$tmp" "$DOCKER_DAEMON_CONFIG"
echo "Set max-concurrent-uploads=$count in $DOCKER_DAEMON_CONFIG"

if [ "$reload" = true ]; then
  $SUDO systemctl reload docker
  # A config dockerd rejects is logged, not returned, so confirm the daemon is still answering.
  docker info >/dev/null
  echo "Reloaded dockerd"
fi
