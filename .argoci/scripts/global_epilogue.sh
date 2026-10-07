#!/usr/bin/env bash
# global_epilogue.sh - ArgoCI e2e epilogue for OSS Calico.
#
# Ported from .semaphore/end-to-end/scripts/global_epilogue.sh, adapted for
# ArgoCI: artifacts go to GCS via gsutil (no Semaphore `artifact`/`cache`/
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
ARTIFACT_DEST="gs://${GS_BUCKET}/${ARGO_WORKFLOW_NAME:-local}/${HOSTNAME:-pod}"

# Capture diags on failure (or always for cert runs).
if [[ "${CI_EXIT_CODE}" != "0" || "${TEST_TYPE}" == "ocp-cert" ]]; then
  echo "[INFO] capturing diags"
  bz diags |& tee "${BZ_LOGS_DIR}/diagnostic.log" || true
  gsutil cp "${BZ_LOCAL_DIR}/${DIAGS_ARCHIVE_FILENAME}" "${ARTIFACT_DEST}/diags.tgz" || true

  # Per-test diags, where the suite collects them (openstack-e2e does, into
  # ${REPORT_DIR}/diags/) — distinct from the bz cluster diags above.
  if [[ -d "${REPORT_DIR}/diags" ]]; then
    gsutil -m cp -r "${REPORT_DIR}/diags" "${ARTIFACT_DEST}/" || true
  fi
fi

# Lens reads each top-level .xml in REPORT_DIR, so subdir reports go into
# junit.xml and top-level ones stay out of it.
_merge_junit="$(dirname "${BASH_SOURCE[0]}")/merge_junit.py"
if [[ -d "${REPORT_DIR}" && ! -f "${REPORT_DIR}/junit.xml" ]]; then
  python3 "${_merge_junit}" --scope=subdirs "${REPORT_DIR}" "${REPORT_DIR}/junit.xml" || true
fi

# The viewer shows one junit.xml; build it outside REPORT_DIR so Lens doesn't
# read it twice.
_junit="${REPORT_DIR}/junit.xml"
if [[ -d "${REPORT_DIR}" ]] && [[ -n "$(find "${REPORT_DIR}" -maxdepth 1 -name '*.xml' ! -name junit.xml -print -quit)" ]]; then
  _merged="${BZ_LOCAL_DIR:-/tmp}/junit-merged.xml"
  rm -f "${_merged}"
  python3 "${_merge_junit}" --scope=top "${REPORT_DIR}" "${_merged}" || true
  # merge_junit.py writes nothing when no file parses as JUnit.
  [[ -f "${_merged}" ]] && _junit="${_merged}"
fi

# Publish JUnit + logs.
if [[ -f "${_junit}" ]]; then
  gsutil cp "${_junit}" "${ARTIFACT_DEST}/junit.xml" || true
fi
gsutil -m cp -r "${BZ_LOGS_DIR}/." "${ARTIFACT_DEST}/logs/" || true

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
