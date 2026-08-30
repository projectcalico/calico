#!/usr/bin/env bash
# body_standard.sh - ArgoCI orchestrator for the standard OSS e2e flow.
#
# Dispatches to the phase scripts in phases/. Ported from
# .semaphore/end-to-end/scripts/body_standard.sh, trimmed to the OSS path (the
# Semaphore version's MCM branch and its HCP_ENABLED/ocp-hcp path are
# Calico-Enterprise-only / unused by OSS and dropped). The HCP_STAGE gating used
# by the certification pipeline IS kept (see .argoci/design/hcp.md). Each phase
# is self-contained; see phases/*.sh.
set -eo pipefail

PHASES="$(cd "$(dirname "$0")" && pwd)/phases"

echo "[INFO] starting job (PROVISIONER=${PROVISIONER} DATAPLANE=${DATAPLANE} RELEASE_STREAM=${RELEASE_STREAM})"

# bz commands must run from the profile dir (== BZ_HOME); PHASES is absolute above.
cd "${BZ_HOME}"

# HCP hosting/destroy-hosting stages join an existing cluster provisioned by a
# prior workflow step, so they skip provisioning and install entirely.
if [[ "${HCP_STAGE}" != "hosting" && "${HCP_STAGE}" != "destroy-hosting" ]]; then
  source "${PHASES}/provision.sh"
  source "${PHASES}/install.sh"
fi
source "${PHASES}/configure.sh"
source "${PHASES}/migrate.sh"

# Hosting stages only stand up infrastructure for other jobs to test against;
# they don't run tests themselves.
if [[ "${HCP_STAGE:-}" == *-hosting* ]]; then
  exit 0
fi

source "${PHASES}/run_tests.sh"
