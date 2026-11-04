#!/usr/bin/env bash
# Set up sandcat's inline per-spec failure diagnosis for the command it wraps,
# then exec that command.
#
# Used as a prefix in the kind e2e targets (E2E_RUN_WRAPPER), around the ginkgo
# run: the one point where the cluster is up and the suite has not started.
# calico-mcp's probe needs a live cluster, so this cannot run any earlier.
#
# The banzai path wires the same hook by bind-mounting into the e2e run
# container; here ginkgo runs straight on the host, so the host paths that
# sandcat.sh prints are exported as-is. sandcat.sh owns every decision about
# whether the hook can run at all, and says why on stderr when it cannot.
#
# Inert without a Gemini key, which is the normal case for a local run: the
# setup is skipped and the wrapped command runs exactly as it would have.

set -uo pipefail

# An argument-less `exec` is a successful no-op, so a wrapper that lost its
# command would report a green job that ran nothing at all -- worse than a
# failing one, because nothing flags it.
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

  # Absolute, all of them -- see the rule and the reason in sandcat.sh, next to
  # the payload. Here that is simply ${PWD}: the job runs from the repo root.
  export E2E_SANDCAT_SOURCE_DIR="${PWD}"
  export E2E_SANDCAT_OUT_DIR="${PWD}/report/sandcat"
  export E2E_SANDCAT_E2E_BINARY="${PWD}/e2e/bin/k8s/e2e.test"
  export E2E_SANDCAT_SHA="${SANDCAT_INLINE_SHA}"

  # Empty when calico-mcp is switched off, and when the PR context is absent (a
  # branch run has no PR). Exporting an empty value would be worse than not
  # exporting: the hook reads both as paths.
  if [[ -n "${SANDCAT_INLINE_CALICO_MCP_BIN}" ]]; then
    export CALICO_MCP_BIN="${SANDCAT_INLINE_CALICO_MCP_BIN}"
  fi
  if [[ -n "${SANDCAT_INLINE_PR_CONTEXT}" ]]; then
    export SANDCAT_PR_CONTEXT="${SANDCAT_INLINE_PR_CONTEXT}"
  fi
fi

exec "$@"
