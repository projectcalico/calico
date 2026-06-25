#!/usr/bin/env bash
# install.sh - install Calico onto a provisioned cluster.
#
# When IMAGE_TAG is set (self-service e2e trigger), install Calico from the
# OCI helm chart pushed by the GHA workflow. Otherwise, install via `bz`.
#
# Required env:
#   BZ_HOME, BZ_LOGS_DIR
# Required when IMAGE_TAG is set:
#   IMAGE_REGISTRY, IMAGE_PATH, HOME, SEMAPHORE_GIT_DIR, BZ_LOCAL_DIR
# Optional env:
#   VERBOSE, HCP_STAGE, HOSTING_CLUSTER, SEMAPHORE_WORKFLOW_ID, DATAPLANE
#
# Sourced from body_*.sh. Assumes cwd == $BZ_HOME.

for _var in BZ_HOME BZ_LOGS_DIR; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

if [[ -n "${IMAGE_TAG:-}" ]]; then
  echo "[INFO] installing Calico from PR helm chart..."
  CALICO_SRC="${HOME}/${SEMAPHORE_GIT_DIR}"
  KUBECONFIG="${BZ_LOCAL_DIR}/kubeconfig"
  CHART_REF="oci://${IMAGE_REGISTRY}/${IMAGE_PATH}/charts/tigera-operator"
  CHART_VERSION="0.0.0-${IMAGE_TAG}"

  # Build the repo-pinned helm binary.
  make -C "${CALICO_SRC}" bin/helm
  export PATH="${CALICO_SRC}/bin:${PATH}"

  echo "[INFO] installing CRDs..."
  KUBECONFIG="${KUBECONFIG}" helm install calico-crds "${CALICO_SRC}/charts/crd.projectcalico.org.v1" \
    --namespace tigera-operator --create-namespace

  # Map banzai DATAPLANE values to helm linuxDataplane values.
  HELM_DATAPLANE_ARGS=""
  case "${DATAPLANE:-CalicoIptables}" in
    CalicoBPF)
      HELM_DATAPLANE_ARGS="--set installation.calicoNetwork.linuxDataplane=BPF --set installation.calicoNetwork.bpfNetworkBootstrap=Enabled --set installation.calicoNetwork.kubeProxyManagement=Enabled" ;;
    CalicoNftables)
      HELM_DATAPLANE_ARGS="--set installation.calicoNetwork.linuxDataplane=Nftables" ;;
    CalicoVPP)
      HELM_DATAPLANE_ARGS="--set installation.calicoNetwork.linuxDataplane=VPP" ;;
  esac

  echo "[INFO] installing tigera-operator chart..."
  #shellcheck disable=SC2086
  KUBECONFIG="${KUBECONFIG}" helm install calico "${CHART_REF}" \
    --version "${CHART_VERSION}" \
    --namespace tigera-operator \
    --wait --timeout 300s \
    ${HELM_DATAPLANE_ARGS}

  echo "[INFO] waiting for Calico to be ready..."
  KUBECONFIG="${KUBECONFIG}" kubectl wait --for=condition=Available --timeout=300s tigerastatus/calico

  echo "[INFO] Calico installed from PR helm chart"
else
  echo "[INFO] starting bz install..."
  bz install ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/install.log.gz")
fi

if [[ "${HCP_STAGE}" == "setup-hosting" ]]; then
  echo "[INFO] HCP_STAGE=${HCP_STAGE}, storing hosting cluster profile in cache"
  cache store "${SEMAPHORE_WORKFLOW_ID}-hosting-${HOSTING_CLUSTER}" "${BZ_HOME}"
fi
