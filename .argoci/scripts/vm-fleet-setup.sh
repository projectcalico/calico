#!/bin/bash
# Prepares a step to drive the GCE test-VM fleet that .semaphore/vms/ creates.
#
# Those scripts are shared with Semaphore, whose agent arrives with gcloud
# authenticated, an SSH key on disk, and a SEMAPHORE_* environment. A pod has
# none of the three, so this supplies each and leaves the scripts themselves
# alone — they stay the single implementation of the fleet.
#
# Source it rather than running it; it exports.

set -e

if [ -z "${GCE_SERVICE_ACCOUNT_KEY:-}" ]; then
  echo "ERROR: the google-service-account-for-gce bundle is not mounted on this step." >&2
  return 1 2>/dev/null || exit 1
fi

export GOOGLE_PROJECT="${GOOGLE_PROJECT:-unique-caldron-775}"
export CALICO_DIR_NAME="${CI_GIT_DIR}"

# The fleet's own bucket rather than the workflow's artifact store: the test VMs
# fetch these with the service account attached to them, which is scoped to this
# project. Keyed on the workflow so two runs never collide.
export GCS_BUILD_CACHE_BUCKET="${GCS_BUILD_CACHE_BUCKET:-calico-transient-build-artifacts-europe-west3}"
export GCS_WORKFLOW_DIR="gs://${GCS_BUILD_CACHE_BUCKET}/workflow/${CI_WORKFLOW_NAME}"

# Under $HOME because configure-test-vm copies the whole directory onto every VM
# it brings up, and the fleet scripts default to this path.
mkdir -p "${HOME}/secrets"
printf '%s' "${GCE_SERVICE_ACCOUNT_KEY}" > "${HOME}/secrets/secret.google-service-account-key.json"
chmod 600 "${HOME}/secrets/secret.google-service-account-key.json"
export GOOGLE_APPLICATION_CREDENTIALS="${HOME}/secrets/secret.google-service-account-key.json"
gcloud auth activate-service-account --key-file="${GOOGLE_APPLICATION_CREDENTIALS}"
gcloud config set project "${GOOGLE_PROJECT}"

# One keypair per step, handed to the VMs as instance metadata when they are
# created. Nothing outlives the fleet, so there is no shared key to rotate.
mkdir -p "${HOME}/.ssh"
chmod 700 "${HOME}/.ssh"
if [ ! -f "${HOME}/.ssh/id_rsa" ]; then
  ssh-keygen -t rsa -b 4096 -N '' -f "${HOME}/.ssh/id_rsa" -C "argoci-${CI_WORKFLOW_NAME}" >/dev/null
fi
touch "${HOME}/.ssh/known_hosts"

# What the fleet scripts read for VM names and GCP instance labels. A label
# value takes only lowercase alphanumerics, dashes and underscores, which the
# scripts sanitise for the branch but not for these.
export SEMAPHORE_PROJECT_NAME="${CI_GIT_REPO_NAME}"
export SEMAPHORE_WORKFLOW_ID="${CI_WORKFLOW_NAME}"
export SEMAPHORE_JOB_ID="${CI_STEP_NAME:-unknown}"
export SEMAPHORE_GIT_BRANCH="${CI_GIT_BRANCH}"
export SEMAPHORE_GIT_REF_TYPE="${CI_GIT_REF_TYPE}"
export SEMAPHORE_GIT_PR_NUMBER="${CI_GIT_PR_NUMBER}"
export SEMAPHORE_GIT_SHA="${CI_GIT_SHA}"
export CI_JOB_TYPE_LABEL="$(echo "${CI_GIT_REF_TYPE}" | tr '[:upper:]' '[:lower:]')"

# A GCE instance name is capped at 63 characters, so the workflow contributes a
# digest rather than its own name. Derived rather than passed, so a step's
# epilogue reaches the same fleet its commands created.
SHORT_WORKFLOW_ID=$(echo "${CI_WORKFLOW_NAME}" | sha256sum | cut -c -8)
export SHORT_WORKFLOW_ID
