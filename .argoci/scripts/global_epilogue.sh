#!/usr/bin/env bash
# global_epilogue.sh - ArgoCI e2e epilogue for OSS Calico.
#
# Ported from .semaphore/end-to-end/scripts/global_epilogue.sh, adapted for
# ArgoCI: artifacts via the bundled `artifact` shim (no Semaphore `cache`/
# `test-results` CLIs), diags/destroy via bz. Best-effort throughout (|| true)
# so teardown always runs. Sourced by the e2e-test template.
set -o pipefail

echo "[INFO] starting global_epilogue"

# bz diags/destroy must run from the profile dir (== BZ_HOME).
cd "${BZ_HOME}" 2>/dev/null || echo "[WARN] could not cd to BZ_HOME=${BZ_HOME}"

# The handler wraps the step body in an EXIT trap that exposes the body's exit
# status as CI_STEP_EXIT_CODE (set in both the container and VM paths); plain
# CI_EXIT_CODE is never set for container steps, so reading it here defaulted
# every failure to 0 and skipped the diags capture below. Read the handler's
# variable, falling back to CI_EXIT_CODE then 0.
CI_EXIT_CODE=${CI_STEP_EXIT_CODE:-${CI_EXIT_CODE:-0}}

# The viewer lists artifacts under CI_ARTIFACT_STEP_STORAGE, which is where
# `artifact push job` publishes.
echo "[INFO] publishing artifacts to ${CI_ARTIFACT_STEP_STORAGE}"

# Capture diags on failure (or always for cert runs).
if [[ "${CI_EXIT_CODE}" != "0" || "${TEST_TYPE}" == "ocp-cert" ]]; then
  echo "[INFO] capturing diags"
  bz diags |& tee "${BZ_LOGS_DIR}/diagnostic.log" || true
  artifact push job "${BZ_LOCAL_DIR}/${DIAGS_ARCHIVE_FILENAME}" -d diags.tgz -f || true

  # Per-test diags, where the suite collects them (openstack-e2e does, into
  # ${REPORT_DIR}/diags/) — distinct from the bz cluster diags above.
  if [[ -d "${REPORT_DIR}/diags" ]]; then
    artifact push job "${REPORT_DIR}/diags" -f || true
  fi
fi

# Suites that emit a tree of JUnit files rather than a single junit.xml (e.g.
# openstack-e2e writes one xmlrunner file per test class under results/) get
# them merged into ${REPORT_DIR}/junit.xml, so the publish below uploads one
# test report that the ArgoCI viewer renders with collapsible suites.
if [[ ! -f "${REPORT_DIR}/junit.xml" && -d "${REPORT_DIR}" ]]; then
  python3 "$(dirname "${BASH_SOURCE[0]}")/merge_junit.py" "${REPORT_DIR}" "${REPORT_DIR}/junit.xml" || true
fi

# Publish JUnit + logs.
if [[ -f "${REPORT_DIR}/junit.xml" ]]; then
  artifact push job "${REPORT_DIR}/junit.xml" -f || true
fi
artifact push job "${BZ_LOGS_DIR}" -d logs -f || true

# Upload results to Lens (best-effort; token from banzai-secrets).
if [[ -n "${GITHUB_ACCESS_TOKEN:-}" ]]; then
  curl --retry 3 -fsSL -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" \
    -H "Accept: application/vnd.github.v3.raw" \
    -o /tmp/run-lens.sh \
    https://raw.githubusercontent.com/tigera/banzai-lens/main/uploader/run-lens.sh && \
    chmod +x /tmp/run-lens.sh && /tmp/run-lens.sh || true
fi

# Tear the cluster down.
echo "[INFO] destroying cluster ${CLUSTER_NAME}"
bz destroy |& tee "${BZ_LOGS_DIR}/destroy.log" || true

echo "[INFO] exiting global_epilogue (CI_EXIT_CODE=${CI_EXIT_CODE})"
