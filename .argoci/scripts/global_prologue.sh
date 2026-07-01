#!/usr/bin/env bash
# global_prologue.sh - ArgoCI e2e prologue for OSS Calico.
#
# Ported from .semaphore/end-to-end/scripts/global_prologue.sh and adapted for
# ArgoCI (see .argoci/DESIGN.md):
#   - secrets are materialised from mounted k8s Secrets via the platform
#     `createLocalSecret` helper (not Semaphore's ~/secrets copy);
#   - no `checkout`/`cache`, no gcloud/aws/az/bz install — the ArgoCI base
#     image already provides bz + the cloud CLIs;
#   - Semaphore vars (SEMAPHORE_*) become CI_*/ARGO_* equivalents;
#   - RELEASE_STREAM is derived from the checked-out branch.
#
# Sourced (not executed) by the e2e-test template, so no `set -e`/`exit`.
set -o pipefail

echo "[INFO] starting prologue"

# Stagger parallel jobs to spread cloud-API load.
sleep $((RANDOM % 60))

# Materialise the secrets the e2e flow needs into files bz/git expect.
createLocalSecret "marvin" "${HOME}/.keys/marvin" || true
createLocalSecret "banzai-google-service-account.json" "${HOME}/secrets/banzai-google-service-account.json" || true
createLocalSecret "docker_cfg.json" "${HOME}/.docker/config.json" || true
chmod 0600 "${HOME}"/.keys/* 2>/dev/null || true
if [[ -f "${HOME}/.keys/marvin" ]]; then eval "$(ssh-agent -s)" >/dev/null 2>&1 || true; ssh-add "${HOME}/.keys/marvin" 2>/dev/null || true; fi

git config --global user.name "${GITHUB_USER_NAME:-marvin-tigera}"
git config --global user.email "${GITHUB_USER_EMAIL:-marvin@tigera.io}"

echo "[INFO] generating random token for unique cluster name..."
RANDOM_TOKEN1=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 5 || true)

echo "[INFO] exporting default env vars..."
export PRODUCT=${PRODUCT:-calico}
export PROVISIONER=${PROVISIONER:-gcp-kubeadm}
export INSTALLER=${INSTALLER:-operator}
export DATAPLANE=${DATAPLANE:-CalicoIptables}
export TEST_TYPE=${TEST_TYPE:-k8s-e2e}
export GOOGLE_PROJECT=${GOOGLE_PROJECT:-unique-caldron-775}
export GOOGLE_REGION=${GOOGLE_REGION:-us-central1}
export GOOGLE_ZONE=${GOOGLE_ZONE:-us-central1-a}
export GOOGLE_NETWORK=${GOOGLE_NETWORK:-semaphore-autotest}
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}

# RELEASE_STREAM: release-vX.Y -> vX.Y, else master. BRANCH is passed by the
# workflow (from the cron's `branch` parameter).
export RELEASE_STREAM=${RELEASE_STREAM:-$( _b="${BRANCH:-master}"; [[ "${_b}" =~ ^release-(v[0-9]+\.[0-9]+)$ ]] && echo "${BASH_REMATCH[1]}" || echo "master" )}

export CLUSTER_NAME=${CLUSTER_NAME:-bz-${PRODUCT}-${RANDOM_TOKEN1}}
export DIAGS_ARCHIVE_FILENAME=${DIAGS_ARCHIVE_FILENAME:-${PROVISIONER}-${CLUSTER_NAME}-diags.tgz}

# bz working directories and artifact bucket.
export BZ_HOME=${BZ_HOME:-${HOME}/bz}
export BZ_LOCAL_DIR=${BZ_LOCAL_DIR:-${BZ_HOME}/.local}
export BZ_LOGS_DIR=${BZ_LOGS_DIR:-${HOME}/.bz/logs}
export REPORT_DIR=${REPORT_DIR:-${BZ_LOCAL_DIR}/report/${TEST_TYPE}}
export GS_BUCKET=${GS_BUCKET:-argoci-artifacts}
mkdir -p "${BZ_HOME}" "${BZ_LOCAL_DIR}" "${BZ_LOGS_DIR}" "${REPORT_DIR}"

echo "[INFO] initialising bz profile..."
bz init profile -n "${ARGO_WORKFLOW_NAME:-local}-${RANDOM_TOKEN1}" --skip-prompt --secretsPath "${HOME}/secrets" \
  |& tee "${BZ_LOGS_DIR}/initialize.log" || true

echo "[INFO] exiting prologue (PROVISIONER=${PROVISIONER} RELEASE_STREAM=${RELEASE_STREAM} CLUSTER_NAME=${CLUSTER_NAME})"
