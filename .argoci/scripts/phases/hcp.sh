#!/usr/bin/env bash
# hcp.sh - ArgoCI HCP (hosted control plane) stage dispatcher.
#
# HCP has no single BZ_HOME; it drives a multi-cluster tree under
# ${BZ_PROFILES_PATH} (=$HOME/bzprofiles) via the vendored hcp-*.sh scripts
# (.argoci/scripts/hcp, on PATH). The Semaphore cache/artifact cross-stage
# handoff is replaced by a single GCS object (the whole tree, tarred). See
# .argoci/design/hcp.md.
#
# Sourced by body_standard.sh only when HCP_ENABLED=true. Dispatches on
# HCP_STAGE via a case with no default, so a non-HCP job never reaches it.
# Does NOT set an EXIT trap (that would clobber global_epilogue's).

BLOB="gs://${GS_BUCKET}/${ARGO_WORKFLOW_NAME}/hcp/${HOSTING_CLUSTER}/bzprofiles.tgz"

# push_tree: upload the whole bzprofiles tree. pipefail makes a mid-stream tar
# failure fail the pipe (no truncated blob). No-op if the tree doesn't exist.
push_tree() {
  set -o pipefail
  [ -d "${BZ_PROFILES_PATH}" ] || { echo "[INFO] hcp: no ${BZ_PROFILES_PATH} to push"; return 0; }
  echo "[INFO] hcp: pushing profile tree to ${BLOB}"
  tar czf - -C "$(dirname "${BZ_PROFILES_PATH}")" "$(basename "${BZ_PROFILES_PATH}")" | gsutil cp - "${BLOB}"
}

# pull_tree: restore the tree over a clean dir. Returns non-zero if the blob is
# absent so the caller can decide fatal (hosted) vs no-op (destroy).
pull_tree() {
  set -o pipefail
  rm -rf "${BZ_PROFILES_PATH}"
  gsutil -q stat "${BLOB}" || return 1
  echo "[INFO] hcp: pulling profile tree from ${BLOB}"
  gsutil cp "${BLOB}" - | tar xzf - -C "$(dirname "${BZ_PROFILES_PATH}")"
}

case "${HCP_STAGE}" in
  setup-hosting)
    # Provision hosting + all hosted clusters up front; hand the tree off.
    # '&&' so an hcp-init failure (no .status written) propagates into rc
    # instead of an empty provision loop false-greening.
    hcp-init.sh && hcp-provision.sh
    rc=$?
    push_tree
    exit "${rc}"
    ;;
  hosted)
    pull_tree || { echo "[ERROR] hcp: hosting state not found at ${BLOB}"; exit 1; }
    hcp-test.sh
    rc=$?
    # Surface junit through the standard epilogue like every other suite.
    mkdir -p "${REPORT_DIR}"
    cp "${BZ_PROFILES_PATH}"/.report/*.xml "${REPORT_DIR}/" 2>/dev/null || true
    exit "${rc}"
    ;;
  destroy-hosting)
    # Absent blob => setup created nothing => nothing to destroy.
    pull_tree || { echo "[INFO] hcp: no state to destroy"; exit 0; }
    hcp-diags.sh || true
    if hcp-destroy.sh; then
      gsutil rm "${BLOB}" || true
    else
      echo "[WARN] hcp: destroy failed; leaving ${BLOB} for retry/reaper"
      exit 1
    fi
    ;;
  *)
    echo "[ERROR] hcp: unknown HCP_STAGE='${HCP_STAGE}'"; exit 1
    ;;
esac
