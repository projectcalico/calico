#!/usr/bin/env bash
# install.sh - install Calico onto a provisioned cluster via bz.
#
# Required env:
#   BZ_HOME, BZ_LOGS_DIR
# Optional env:
#   VERBOSE
#
# Sourced from body_standard.sh. Assumes cwd == $BZ_HOME.

for _var in BZ_HOME BZ_LOGS_DIR; do
  if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
done

echo "[INFO] starting bz install..."
bz install ${VERBOSE} |& tee >(gzip --stdout > "${BZ_LOGS_DIR}/install.log.gz")
