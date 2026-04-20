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
#   BZ_LOGS_DIR, HOME, SEMAPHORE_GIT_DIR
# Optional env:
#   VERBOSE
#
# Sourced from body_*.sh.

for _var in BZ_LOGS_DIR HOME SEMAPHORE_GIT_DIR; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

if [[ -n "${OPERATOR_MIGRATE}" ]]; then
  "${HOME}/${SEMAPHORE_GIT_DIR}/.semaphore/end-to-end/scripts/test_scripts/operator_migrate.sh" \
    |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/operator_migrate.log.gz")
fi

if [[ -n "${DESIRED_POLICY}" ]]; then
  echo "[INFO] starting AKS migration..."
  bz addons run aks-migrate:setup
fi

if [[ -n "${UPLEVEL_RELEASE_STREAM}" ]]; then
  echo "[INFO] starting bz upgrade..."
  bz upgrade ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/upgrade.log.gz")
fi
