#!/usr/bin/env bash
set -eo pipefail

echo "[INFO] starting job..."
if [[ "${BZ_VERBOSE}" == "true" ]]; then
  VERBOSE="--verbose"
else
  VERBOSE=""
fi

cd "${BZ_HOME}"

echo "[INFO] starting bz provision..."
bz provision $VERBOSE | tee >(gzip --stdout > ${BZ_LOGS_DIR}/provision.log.gz)

cache delete $SEMAPHORE_JOB_ID
cache store ${SEMAPHORE_JOB_ID} ${BZ_HOME}

echo "[INFO] starting bz install..."
bz install $VERBOSE | tee >(gzip --stdout > ${BZ_LOGS_DIR}/install.log.gz)

# Put the bin dir into the PATH
export PATH=$PATH:${BZ_LOCAL_DIR}/bin

if [[ "${ENABLE_EXTERNAL_NODE}" == "true" ]]; then
  export EXT_USER=ubuntu
  EXT_IP=$(cat "${BZ_LOCAL_DIR}"/external_ip)
  export EXT_IP
  export EXT_KEY=${BZ_LOCAL_DIR}/external_key
  export K8S_E2E_DOCKER_EXTRA_FLAGS="-v $EXT_KEY:/key --env EXT_USER --env EXT_KEY=/key --env EXT_IP $K8S_E2E_DOCKER_EXTRA_FLAGS"
  echo "EXT_USER=ubuntu EXT_IP=$EXT_IP, EXT_KEY=$EXT_KEY"
  echo "K8S_E2E_DOCKER_EXTRA_FLAGS=$K8S_E2E_DOCKER_EXTRA_FLAGS"
fi

if [ -n "${IPAM_TEST_POOL_SUBNET}" ]; then
  export K8S_E2E_DOCKER_EXTRA_FLAGS="$K8S_E2E_DOCKER_EXTRA_FLAGS --env IPAM_TEST_POOL_SUBNET"
  echo "IPAM_TEST_POOL_SUBNET=$IPAM_TEST_POOL_SUBNET"
fi

if [ "${FAILSAFE_443}" == "true" ]; then
  KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl patch felixconfiguration default --type=merge -p '{"spec":{"failsafeOutboundHostPorts": [{"protocol": "udp", "port":53},{"protocol": "udp", "port":67},{"protocol": "tcp", "port":179},{"protocol": "tcp", "port":2379},{"protocol": "tcp", "port":2380},{"protocol": "tcp", "port":5473},{"protocol": "tcp", "port":443},{"protocol": "tcp", "port":6666},{"protocol": "tcp", "port":6667}]}}'
fi

# Perform the operator migration following the instructions here:
# https://projectcalico.docs.tigera.io/maintenance/operator-migration
if [[ -n "$OPERATOR_MIGRATE" ]]; then
  ${HOME}/${SEMAPHORE_GIT_DIR}/.semaphore/end-to-end/scripts/test_scripts/operator_migrate.sh
fi

# Perform the AKS migration following the instructions here:
# https://docs.tigera.io/calico/latest/getting-started/kubernetes/managed-public-cloud/aks-migrate
if [[ -n "$DESIRED_POLICY" ]]; then
  echo "[INFO] starting AKS migration..."
  bz addons run aks-migrate:setup
fi

if [[ -n "$UPLEVEL_RELEASE_STREAM" ]]; then
  echo "[INFO] starting bz upgrade..."
  bz upgrade $VERBOSE | tee >(gzip --stdout > ${BZ_LOGS_DIR}/upgrade.log.gz)
fi

echo "[INFO] Test logs will be available here after the run: ${SEMAPHORE_ORGANIZATION_URL}/artifacts/jobs/${SEMAPHORE_JOB_ID}?path=semaphore%2Flogs"
echo "[INFO] Alternatively, you can view logs while job is running using 'sem attach ${SEMAPHORE_JOB_ID}' and then 'tail -f ${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log'"

echo "[INFO] starting bz testing..."
bz tests $VERBOSE | tee >(gzip --stdout > ${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log.gz)
