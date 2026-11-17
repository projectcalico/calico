#!/usr/bin/env bash
# Set up sandcat's inline per-spec failure diagnosis, then exec the wrapped
# command. Runs after the cluster is up because calico-mcp's probe needs it.
# Inert without a Gemini key: the command runs exactly as it would have.

set -uo pipefail

# A bare `exec` succeeds and runs nothing, which would report a green job.
if [[ $# -eq 0 ]]; then
  echo "[ERROR] $(basename "$0"): no command to wrap" >&2
  exit 1
fi

_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

if _inline_env=$("${_dir}/sandcat.sh" inline-env \
    --kubeconfig "${KUBECONFIG:-}" --source-dir "${PWD}"); then
  eval "${_inline_env}"

  export SANDCAT_INLINE_DIAG=1
  export SANDCAT_BIN="${SANDCAT_INLINE_BIN}"
  export SANDCAT_GEMINI_KEY="${SANDCAT_INLINE_GEMINI_KEY}"
  export SANDCAT_SIG_DIR SANDCAT_MAX_DIAGNOSES SANDCAT_TOTAL_BUDGET

  export E2E_SANDCAT_SOURCE_DIR="${PWD}"
  export E2E_SANDCAT_OUT_DIR="${PWD}/report/sandcat"
  export E2E_SANDCAT_E2E_BINARY="${PWD}/e2e/bin/k8s/e2e.test"
  export E2E_SANDCAT_SHA="${SANDCAT_INLINE_SHA}"

  # The hook reads both as paths, so an empty value must not be exported.
  if [[ -n "${SANDCAT_INLINE_CALICO_MCP_BIN}" ]]; then
    export CALICO_MCP_BIN="${SANDCAT_INLINE_CALICO_MCP_BIN}"
  fi
  if [[ -n "${SANDCAT_INLINE_PR_CONTEXT}" ]]; then
    export SANDCAT_PR_CONTEXT="${SANDCAT_INLINE_PR_CONTEXT}"
  fi
fi

exec "$@"
