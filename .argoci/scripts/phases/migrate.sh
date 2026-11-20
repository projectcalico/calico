#!/usr/bin/env bash
# migrate.sh - optional cluster modifications before tests run.
#
# Handles three independent migration/upgrade workflows, each gated on its
# own env var:
#   OPERATOR_MIGRATE     - run the operator migration script
#     (see https://projectcalico.docs.tigera.io/maintenance/operator-migration)
#   DESIRED_POLICY       - run the AKS migration add-on
#     (see https://docs.tigera.io/calico/latest/getting-started/kubernetes/managed-public-cloud/aks-migrate)
#   UPLEVEL_RELEASE_STREAM - run bz upgrade
#
# Required env:
#   BZ_LOGS_DIR, CI_HOME, CI_GIT_DIR (and BZ_LOCAL_DIR for an upgrade)
# Optional env:
#   VERBOSE
#
# Sourced from body_*.sh.

for _var in BZ_LOGS_DIR CI_HOME CI_GIT_DIR; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

if [[ -n "${OPERATOR_MIGRATE}" ]]; then
  "${CI_HOME}/${CI_GIT_DIR}/.argoci/scripts/test_scripts/operator_migrate.sh" \
    |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/operator_migrate.log.gz")
fi

if [[ -n "${DESIRED_POLICY}" ]]; then
  echo "[INFO] starting AKS migration..."
  bz addons run aks-migrate:setup
fi

# upgrade_kubectl - the host shell never exports KUBECONFIG; only the e2e
# container gets one.
upgrade_kubectl() {
  KUBECONFIG="${BZ_LOCAL_DIR}/kubeconfig" "${BZ_LOCAL_DIR}/bin/kubectl" "$@"
}

# record_upgrade_window - tell the upgrade scenarios' verify specs when the
# upgrade ran; they read this ConfigMap by name. Called with no argument at the
# start, and with the result at the end.
record_upgrade_window() {
  local args=(--from-literal=start="${_upgrade_start}")
  if [[ -n "${1:-}" ]]; then
    args+=(--from-literal=end="$(date -u +%Y-%m-%dT%H:%M:%SZ)" --from-literal=result="$1")
  fi
  if ! { upgrade_kubectl create namespace e2e-upgrade-system --dry-run=client -o yaml | upgrade_kubectl apply -f - >/dev/null &&
         upgrade_kubectl -n e2e-upgrade-system create configmap upgrade-window "${args[@]}" --dry-run=client -o yaml \
           | upgrade_kubectl apply -f - >/dev/null; }; then
    echo "[WARN] could not record the upgrade window; upgrade scenarios will fail to verify"
  fi
}

# wait_for_rollout - the window must end when Calico has finished rolling out,
# not when bz returns, or probes would be judged mid-rollout.
wait_for_rollout() {
  local ns rc=0
  ns="$(calico_ns)"
  # The operator rewrites calico-node some time after bz returns. Until then
  # the old DaemonSet reports rolled out and every check below passes at once.
  if [[ -n "${_pre_image}" ]]; then
    local deadline=$(( $(date +%s) + 600 ))
    until [[ "$(calico_node_image)" != "${_pre_image}" ]]; do
      if (( $(date +%s) > deadline )); then
        echo "[ERROR] calico-node still runs ${_pre_image} 10 minutes after bz upgrade"
        return 1
      fi
      sleep 5
    done
  else
    echo "[WARN] couldn't read calico-node's image before the upgrade; the window may end before the rollout starts"
  fi
  upgrade_kubectl -n "${ns}" rollout status ds/calico-node --timeout=15m || rc=1
  upgrade_kubectl -n "${ns}" rollout status deploy/calico-kube-controllers --timeout=15m || rc=1
  if upgrade_kubectl -n "${ns}" get deploy calico-typha >/dev/null 2>&1; then
    upgrade_kubectl -n "${ns}" rollout status deploy/calico-typha --timeout=15m || rc=1
  fi
  if upgrade_kubectl get crd tigerastatuses.operator.tigera.io >/dev/null 2>&1; then
    upgrade_kubectl wait tigerastatus --all --for=condition=Available --timeout=15m || rc=1
  fi
  return ${rc}
}

calico_ns() {
  if upgrade_kubectl -n calico-system get ds calico-node >/dev/null 2>&1; then echo calico-system; else echo kube-system; fi
}

calico_node_image() {
  upgrade_kubectl -n "$(calico_ns)" get ds calico-node -o jsonpath='{.spec.template.spec.containers[?(@.name=="calico-node")].image}' 2>/dev/null
}

if [[ -n "${UPLEVEL_RELEASE_STREAM}" ]]; then
  echo "[INFO] starting bz upgrade..."
  _pre_image="$(calico_node_image || true)"
  _upgrade_start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  record_upgrade_window
  _upgrade_rc=0
  bz upgrade ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/upgrade.log.gz") || _upgrade_rc=$?
  if [[ ${_upgrade_rc} -eq 0 ]] && ! wait_for_rollout; then
    echo "[ERROR] Calico didn't finish rolling out after bz upgrade"
    _upgrade_rc=1
  fi
  if [[ ${_upgrade_rc} -ne 0 ]]; then
    record_upgrade_window failed
    exit ${_upgrade_rc}
  fi
  record_upgrade_window succeeded
fi
