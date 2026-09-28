#!/bin/bash
# Prepares a step to drive the GCE test-VM fleet: the gcloud login, SSH key and
# SEMAPHORE_* variables the fleet scripts expect and a pod lacks.
#
# Source it rather than running it; it exports.

set -e

if [ -z "${GCE_SERVICE_ACCOUNT_KEY:-}" ]; then
  echo "ERROR: the google-service-account-for-gce bundle is not mounted on this step." >&2
  return 1 2>/dev/null || exit 1
fi

export GOOGLE_PROJECT="${GOOGLE_PROJECT:-unique-caldron-775}"
export CALICO_DIR_NAME="${CI_GIT_DIR}"

# Not the artifact store: the VMs read this with their own service account,
# which is scoped to this project.
export GCS_BUILD_CACHE_BUCKET="${GCS_BUILD_CACHE_BUCKET:-calico-transient-build-artifacts-us-central1}"
export GCS_WORKFLOW_DIR="gs://${GCS_BUILD_CACHE_BUCKET}/workflow/${CI_WORKFLOW_NAME}"

# The whole directory is copied onto every VM the fleet brings up, so anything
# added here reaches the tests as well.
mkdir -p "${HOME}/secrets"
printf '%s' "${GCE_SERVICE_ACCOUNT_KEY}" > "${HOME}/secrets/secret.google-service-account-key.json"
chmod 600 "${HOME}/secrets/secret.google-service-account-key.json"
export GOOGLE_APPLICATION_CREDENTIALS="${HOME}/secrets/secret.google-service-account-key.json"
gcloud auth activate-service-account --key-file="${GOOGLE_APPLICATION_CREDENTIALS}"
gcloud config set project "${GOOGLE_PROJECT}"
# Otherwise gsutil, and so `artifact`, silently switches to the account above.
gcloud config set pass_credentials_to_gsutil false

# Nothing outlives the fleet, so there is no shared key to rotate.
mkdir -p "${HOME}/.ssh"
chmod 700 "${HOME}/.ssh"
if [ ! -f "${HOME}/.ssh/id_rsa" ]; then
  ssh-keygen -t rsa -b 4096 -N '' -f "${HOME}/.ssh/id_rsa" -C "argoci-${CI_WORKFLOW_NAME}" >/dev/null
fi
touch "${HOME}/.ssh/known_hosts"

# Labels every fleet instance, so the exit-handler sweep deletes only ours.
export CI_SYSTEM="${ARGOCI_RESOURCE_PREFIX:-argoci}"

export SEMAPHORE_PROJECT_NAME="${CI_GIT_REPO_NAME}"
export SEMAPHORE_WORKFLOW_ID="${CI_WORKFLOW_NAME}"
export SEMAPHORE_JOB_ID="${CI_STEP_NAME:-unknown}"
export SEMAPHORE_GIT_BRANCH="${CI_GIT_BRANCH}"
export SEMAPHORE_GIT_REF_TYPE="${CI_GIT_REF_TYPE}"
export SEMAPHORE_GIT_PR_NUMBER="${CI_GIT_PR_NUMBER}"
export SEMAPHORE_GIT_SHA="${CI_GIT_SHA}"
# GCP label values must be lowercase, and the fleet does not sanitise this one.
CI_JOB_TYPE_LABEL=$(echo "${CI_GIT_REF_TYPE}" | tr '[:upper:]' '[:lower:]')
export CI_JOB_TYPE_LABEL

# GCE instance names cap at 63 characters. Derived rather than passed, so an
# epilogue finds the same fleet the commands created.
SHORT_WORKFLOW_ID=$(echo "${CI_WORKFLOW_NAME}" | sha256sum | cut -c -8)
export SHORT_WORKFLOW_ID
