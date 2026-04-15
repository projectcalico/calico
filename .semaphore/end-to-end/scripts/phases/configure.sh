#!/usr/bin/env bash
# configure.sh - configure test environment after cluster install.
#
# Sets PATH to include the bz-provisioned bin dir, exports external-node
# credentials when ENABLE_EXTERNAL_NODE=true, propagates IPAM test config,
# and applies the optional failsafe patch.
#
# Required env:
#   BZ_LOCAL_DIR
# Optional env:
#   ENABLE_EXTERNAL_NODE, IPAM_TEST_POOL_SUBNET, FAILSAFE_443,
#   K8S_E2E_DOCKER_EXTRA_FLAGS
#
# Exports consumed by later phases:
#   PATH, EXT_USER, EXT_IP, EXT_KEY, K8S_E2E_DOCKER_EXTRA_FLAGS
#
# Sourced from body_*.sh.

for _var in BZ_LOCAL_DIR; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

export PATH=$PATH:${BZ_LOCAL_DIR}/bin

if [[ "${ENABLE_EXTERNAL_NODE}" == "true" ]]; then
  export EXT_USER=ubuntu
  EXT_IP=$(cat "${BZ_LOCAL_DIR}/external_ip")
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
  KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl patch felixconfiguration default --type=merge \
    -p '{"spec":{"failsafeOutboundHostPorts": [{"protocol": "udp", "port":53},{"protocol": "udp", "port":67},{"protocol": "tcp", "port":179},{"protocol": "tcp", "port":2379},{"protocol": "tcp", "port":2380},{"protocol": "tcp", "port":5473},{"protocol": "tcp", "port":443},{"protocol": "tcp", "port":6666},{"protocol": "tcp", "port":6667}]}}'
fi
