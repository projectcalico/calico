#!/usr/bin/env bash
# provision.sh - provision a test cluster with bz.
#
# Required env:
#   BZ_HOME, BZ_LOGS_DIR, SEMAPHORE_JOB_ID
# Optional env:
#   VERBOSE (e.g. "--verbose")
#
# Sourced from body_*.sh. Assumes cwd == $BZ_HOME. Safe to run standalone once
# env is set.

echo "[INFO] starting bz provision..."
bz provision ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/provision.log.gz")

cache delete "${SEMAPHORE_JOB_ID}"
cache store "${SEMAPHORE_JOB_ID}" "${BZ_HOME}"
