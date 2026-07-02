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

CI_EXIT_CODE=${CI_EXIT_CODE:-0}
ARTIFACT_DEST="gs://${GS_BUCKET}/${ARGO_WORKFLOW_NAME:-local}/${HOSTNAME:-pod}"

# Capture diags on failure (or always for cert runs).
if [[ "${CI_EXIT_CODE}" != "0" ]]; then
  echo "[INFO] capturing diags"
  bz diags |& tee "${BZ_LOGS_DIR}/diagnostic.log" || true
  gsutil cp "${BZ_LOCAL_DIR}/${DIAGS_ARCHIVE_FILENAME}" "${ARTIFACT_DEST}/diags.tgz" || true
fi

# Publish JUnit + logs.
if [[ -f "${REPORT_DIR}/junit.xml" ]]; then
  gsutil cp "${REPORT_DIR}/junit.xml" "${ARTIFACT_DEST}/junit.xml" || true
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
