#!/usr/bin/env bash
# body_standard.sh - ArgoCI orchestrator for the standard OSS e2e flow.
#
# Dispatches to the phase scripts in phases/. Ported from
# .semaphore/end-to-end/scripts/body_standard.sh, trimmed to the OSS path
# (the Semaphore version's HCP/MCM/hosting branches are Calico-Enterprise-only
# and are dropped here). Each phase is self-contained; see phases/*.sh.
set -eo pipefail

PHASES="$(cd "$(dirname "$0")" && pwd)/phases"

echo "[INFO] starting job (PROVISIONER=${PROVISIONER} DATAPLANE=${DATAPLANE} RELEASE_STREAM=${RELEASE_STREAM})"

# bz commands must run from the profile dir (== BZ_HOME); PHASES is absolute above.
cd "${BZ_HOME}"

source "${PHASES}/provision.sh"
source "${PHASES}/install.sh"
source "${PHASES}/configure.sh"
source "${PHASES}/migrate.sh"
source "${PHASES}/run_tests.sh"
