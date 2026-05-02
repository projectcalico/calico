#!/bin/bash -e

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

# registry.sh manages a local docker registry container used as the image
# source for kind clusters. Idempotent: safe to call repeatedly.
#
# Usage: registry.sh up | down
#
# The registry container is named "kind-registry" and is joined to the "kind"
# docker network so kind nodes can resolve it by DNS as kind-registry:5000.
# It is bound to 127.0.0.1:${KIND_REGISTRY_PORT} on the host so `docker push`
# from the host can reach it. The container persists across kind cluster
# create/destroy so its layer cache survives reprovisioning.

KIND_REGISTRY_NAME=${KIND_REGISTRY_NAME:-kind-registry}
KIND_REGISTRY_PORT=${KIND_REGISTRY_PORT:-5001}
KIND_REGISTRY_IMAGE=${KIND_REGISTRY_IMAGE:-registry:2}

case "${1:-}" in
  up)
    # Start the registry if it isn't already running.
    running=$(docker inspect -f '{{.State.Running}}' "${KIND_REGISTRY_NAME}" 2>/dev/null || echo "false")
    if [ "${running}" != "true" ]; then
      echo "Starting ${KIND_REGISTRY_NAME} on 127.0.0.1:${KIND_REGISTRY_PORT}"
      docker run -d --restart=always \
        -p "127.0.0.1:${KIND_REGISTRY_PORT}:5000" \
        --name "${KIND_REGISTRY_NAME}" \
        "${KIND_REGISTRY_IMAGE}" >/dev/null
    fi

    # Connect the registry to the kind network if not already. The kind
    # network is created on first `kind create cluster`, so this may need to
    # run after cluster creation; calling it pre-create works once the
    # network exists from a previous cluster, otherwise it's retried below.
    if docker network inspect kind >/dev/null 2>&1; then
      if ! docker network inspect kind -f '{{range .Containers}}{{.Name}} {{end}}' | grep -qw "${KIND_REGISTRY_NAME}"; then
        docker network connect kind "${KIND_REGISTRY_NAME}"
      fi
    fi
    ;;
  down)
    docker rm -f "${KIND_REGISTRY_NAME}" >/dev/null 2>&1 || true
    ;;
  *)
    echo "Usage: $0 up | down" >&2
    exit 1
    ;;
esac
