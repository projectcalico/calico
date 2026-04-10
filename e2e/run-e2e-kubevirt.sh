#!/bin/bash
set -euo pipefail

ROOT="${ROOT:-.}"

export EXT_IP="${EXT_IP:-$(cat "${ROOT}/external_ip" 2>/dev/null || true)}"
export EXT_KEY="${EXT_KEY:-${ROOT}/external_key}"
export EXT_USER="${EXT_USER:-ubuntu}"
export KUBECONFIG="${KUBECONFIG:-${ROOT}/kubeconfig}"

bin/k8s/e2e.test \
        --kubeconfig="${KUBECONFIG}" \
        --ginkgo.focus="KubeVirt IP persistence" \
        -ginkgo.v | tee result.log
