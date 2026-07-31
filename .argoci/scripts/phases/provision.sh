#!/usr/bin/env bash
# provision.sh - provision a test cluster with bz.
#
# Required env:
#   BZ_HOME, BZ_LOGS_DIR
# Optional env:
#   VERBOSE (e.g. "--verbose")
#
# Sourced from body_*.sh. Assumes cwd == $BZ_HOME. Safe to run standalone once
# env is set.

for _var in BZ_HOME BZ_LOGS_DIR; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

echo "[INFO] starting bz provision..."
bz provision ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/provision.log.gz")

