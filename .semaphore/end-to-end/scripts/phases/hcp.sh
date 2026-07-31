#!/usr/bin/env bash
# hcp.sh - hosted control plane (HCP) provision + test flow.
#
# HCP jobs have their own provisioning tool (hcp-provision.sh) and test
# runner (hcp-test.sh), and don't share phases with the standard bz flow.
#
# Required env:
#   BZ_HOME, BZ_LOGS_DIR, SEMAPHORE_JOB_ID, SEMAPHORE_ORGANIZATION_URL,
#   TEST_TYPE
#
# Sourced from body_*.sh.

for _var in BZ_HOME BZ_LOGS_DIR SEMAPHORE_JOB_ID SEMAPHORE_ORGANIZATION_URL TEST_TYPE; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

echo "[INFO] starting hcp job..."

echo "[INFO] starting hcp provision..."
hcp-provision.sh |& tee "${BZ_LOGS_DIR}/provision.log"

cache delete "${SEMAPHORE_JOB_ID}"
cache store "${SEMAPHORE_JOB_ID}" "${BZ_HOME}"

echo "[INFO] Test logs will be available here after the run: ${SEMAPHORE_ORGANIZATION_URL}/artifacts/jobs/${SEMAPHORE_JOB_ID}?path=semaphore%2Flogs"
echo "[INFO] Alternatively, you can view logs while job is running using 'sem attach ${SEMAPHORE_JOB_ID}' and then 'tail -f ${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log'"

echo "[INFO] starting hcp testing..."
hcp-test.sh |& tee "${BZ_LOGS_DIR}/${TEST_TYPE}-tests.log"
