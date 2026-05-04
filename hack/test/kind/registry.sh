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
KIND_REGISTRY_PORT=${KIND_REGISTRY_PORT:-5000}
KIND_REGISTRY_IMAGE=${KIND_REGISTRY_IMAGE:-registry:2}

case "${1:-}" in
  up)
    # Start the registry if it isn't already running. Three cases:
    # running -> nothing to do; stopped -> docker start; missing -> docker run.
    state=$(docker inspect -f '{{.State.Status}}' "${KIND_REGISTRY_NAME}" 2>/dev/null || echo "missing")
    case "${state}" in
      running)
        ;;
      missing)
        echo "Starting ${KIND_REGISTRY_NAME} on 127.0.0.1:${KIND_REGISTRY_PORT}"
        docker run -d --restart=always \
          -p "127.0.0.1:${KIND_REGISTRY_PORT}:5000" \
          --name "${KIND_REGISTRY_NAME}" \
          "${KIND_REGISTRY_IMAGE}" >/dev/null
        ;;
      *)
        echo "Restarting existing ${KIND_REGISTRY_NAME} (was ${state})"
        docker start "${KIND_REGISTRY_NAME}" >/dev/null
        ;;
    esac

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
  configure-nodes)
    # Tell containerd on each kind node to redirect localhost:5000 to the
    # in-network registry. Containerd reads /etc/containerd/certs.d/ on
    # demand, so no restart is required. See
    # https://kind.sigs.k8s.io/docs/user/local-registry/.
    : "${KIND_NAME:?KIND_NAME must be set}"
    nodes=$(docker ps --filter "label=io.x-k8s.kind.cluster=${KIND_NAME}" --format '{{.Names}}')
    if [ -z "${nodes}" ]; then
      echo "No nodes found for kind cluster '${KIND_NAME}'" >&2
      exit 1
    fi
    reg_dir="/etc/containerd/certs.d/localhost:5000"
    for node in ${nodes}; do
      docker exec "${node}" mkdir -p "${reg_dir}"
      docker exec -i "${node}" sh -c "cat > ${reg_dir}/hosts.toml" <<EOF
[host."http://${KIND_REGISTRY_NAME}:5000"]
EOF
    done
    ;;
  down)
    docker rm -f "${KIND_REGISTRY_NAME}" >/dev/null 2>&1 || true
    ;;
  *)
    echo "Usage: $0 up | configure-nodes | down" >&2
    exit 1
    ;;
esac
