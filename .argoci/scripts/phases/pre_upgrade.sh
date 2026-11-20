#!/usr/bin/env bash
# pre_upgrade.sh - seed the upgrade scenarios on the downlevel cluster.
#
# Runs the e2e binary once with E2E_UPGRADE_PHASE=seed, which selects only the
# scenario seed specs valid for RELEASE_STREAM (see e2e/pkg/tests/upgrade).
# The post-upgrade run in run_tests.sh then adds their verify specs.
#
# A seed failure is reported but doesn't stop the job: the upgrade and the
# rest of the suite are still worth running, and each unseeded scenario's
# verify spec fails with "no seed record".
#
# Required env:
#   BZ_LOGS_DIR, CI_HOME, CI_GIT_DIR, REPORT_DIR, RELEASE_STREAM
# Optional env:
#   UPLEVEL_RELEASE_STREAM (the phase is skipped when unset)
#
# Sourced from body_standard.sh.

if [[ -z "${UPLEVEL_RELEASE_STREAM:-}" || "${TEST_TYPE:-}" != "k8s-e2e" ]]; then
  echo "[INFO] pre_upgrade: skipping (no upgrade, or not an e2e lane)"
else
  for _var in BZ_LOGS_DIR CI_HOME CI_GIT_DIR REPORT_DIR RELEASE_STREAM; do
    if [[ -z "${!_var}" ]]; then echo "[ERROR] ${_var} is required but not set"; exit 1; fi
  done

  echo "[INFO] pre_upgrade: seeding upgrade scenarios from ${RELEASE_STREAM}"
  # run_tests.sh exits when it finishes, hence a child shell. The component-log
  # check belongs to the post-upgrade run, which reads the whole job's logs.
  _seed_rc=0
  # scenarios.yaml gates the run on a hashrelease whose binary knows the phase.
  E2E_UPGRADE_PHASE=seed E2E_UPGRADE_FROM="${RELEASE_STREAM}" STERN_CHECK=DISABLED \
    E2E_TEST_CONFIG="${E2E_TEST_CONFIG:-} e2e/config/upgrade/scenarios.yaml" \
    bash "$(dirname "${BASH_SOURCE[0]}")/run_tests.sh" || _seed_rc=$?

  # The post-upgrade run reuses these paths, so keep the seed results apart.
  # Lens and the job viewer read every top-level XML in REPORT_DIR.
  _report="${CI_HOME}/${CI_GIT_DIR}/report"
  mkdir -p "${REPORT_DIR}"
  mv "${REPORT_DIR}/junit.xml" "${REPORT_DIR}/junit-upgrade-seed.xml" 2>/dev/null || true
  mv "${BZ_LOGS_DIR}/k8s-e2e-tests.log" "${BZ_LOGS_DIR}/upgrade-seed-tests.log" 2>/dev/null || true
  rm -rf "${_report}/junit.xml" "${_report}/report.json" "${_report}/sandcat" "${HOME}/.sandcat-analyzed"

  if [[ ${_seed_rc} -ne 0 ]]; then
    echo "[WARN] pre_upgrade: seeding failed (rc=${_seed_rc}); continuing. See junit-upgrade-seed.xml."
  fi
  # Tells run_tests.sh to add the verify specs; a lane that never seeded must not.
  export E2E_UPGRADE_SEEDED=1
fi
