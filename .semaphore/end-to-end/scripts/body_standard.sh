#!/usr/bin/env bash
# body_standard.sh - orchestrator for the standard e2e flow.
#
# Dispatches to phase scripts in scripts/phases/. Each phase is self-contained
# and documents its required env vars. See scripts/README.md for the phase
# model and guidance on running phases standalone.
set -eo pipefail

PHASES="$(dirname "$0")/phases"

if [[ "${BZ_VERBOSE}" == "true" ]]; then
  VERBOSE="--verbose"
else
  VERBOSE=""
fi
export VERBOSE

echo "[INFO] starting job..."
echo "[INFO] BZ_HOME=${BZ_HOME}"

# HCP jobs take a separate path with their own provision/test tooling.
if [[ "${HCP_ENABLED}" == "true" ]]; then
  source "${PHASES}/hcp.sh"
  exit 0
fi

cd "${BZ_HOME}"

# HCP hosting/destroy-hosting stages join an existing cluster provisioned by a
# prior workflow step, so they skip provisioning and install entirely.
if [[ "${HCP_STAGE}" != "hosting" && "${HCP_STAGE}" != "destroy-hosting" ]]; then
  source "${PHASES}/provision.sh"
  source "${PHASES}/install.sh"
fi

source "${PHASES}/configure.sh"
source "${PHASES}/migrate.sh"

# MCM (Multi-Cluster Management) management stages and HCP hosting stages
# only provision infrastructure for other jobs to test against - they don't
# run tests themselves. These are enterprise-only flows; MCM_STAGE and
# HCP_STAGE are unset for OSS jobs.
if [[ ${MCM_STAGE:-} == *-mgmt* || ${HCP_STAGE:-} == *-hosting* ]]; then
  exit 0
fi

echo "[INFO] Test logs will be available here after the run: ${SEMAPHORE_ORGANIZATION_URL}/artifacts/jobs/${SEMAPHORE_JOB_ID}?path=semaphore%2Flogs"
echo "[INFO] Alternatively, you can view logs while job is running using 'sem attach ${SEMAPHORE_JOB_ID}' and then 'tail -f ${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log'"

source "${PHASES}/run_tests.sh"
