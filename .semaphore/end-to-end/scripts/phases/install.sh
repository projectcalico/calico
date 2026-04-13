#!/usr/bin/env bash
# install.sh - install Calico onto a provisioned cluster via bz.
#
# Required env:
#   BZ_HOME, BZ_LOGS_DIR
# Optional env:
#   VERBOSE, HCP_STAGE, HOSTING_CLUSTER, SEMAPHORE_WORKFLOW_ID
#
# Sourced from body_*.sh. Assumes cwd == $BZ_HOME.

echo "[INFO] starting bz install..."
bz install ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/install.log.gz")

if [[ "${HCP_STAGE}" == "setup-hosting" ]]; then
  echo "[INFO] HCP_STAGE=${HCP_STAGE}, storing hosting cluster profile in cache"
  cache store "${SEMAPHORE_WORKFLOW_ID}-hosting-${HOSTING_CLUSTER}" "${BZ_HOME}"
fi
