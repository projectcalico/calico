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

# GCP auth for provisioning + docker registry auth (ported from Semaphore prologue
# lines 122-123 / 166; our first port dropped these, assuming ArgoCI provided them).
export GOOGLE_APPLICATION_CREDENTIALS="${GOOGLE_APPLICATION_CREDENTIALS:-${HOME}/secrets/banzai-google-service-account.json}"
if [[ -f "${GOOGLE_APPLICATION_CREDENTIALS}" ]]; then
  gcloud auth activate-service-account --key-file="${GOOGLE_APPLICATION_CREDENTIALS}" || echo "[WARN] gcloud auth activate-service-account failed"
else
  echo "[WARN] GOOGLE_APPLICATION_CREDENTIALS missing: ${GOOGLE_APPLICATION_CREDENTIALS}"
fi
export DOCKER_AUTH_FILE="${DOCKER_AUTH_FILE:-${HOME}/.docker/config.json}"
chmod 0600 "${HOME}"/.keys/* 2>/dev/null || true
if [[ -f "${HOME}/.keys/marvin" ]]; then eval "$(ssh-agent -s)" >/dev/null 2>&1 || true; ssh-add "${HOME}/.keys/marvin" 2>/dev/null || true; fi

# AWS auth for aws-* provisioners (EKS, aws-openshift, aws-talos). banzai-secrets
# is loaded via envFrom, so AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY arrive as env
# when present in the bundle; also write ~/.aws/credentials so tools that don't
# inherit the shell env still find them. No-op (with a warning) if absent.
if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
  mkdir -p "${HOME}/.aws"
  {
    echo "[default]"
    echo "aws_access_key_id=${AWS_ACCESS_KEY_ID}"
    echo "aws_secret_access_key=${AWS_SECRET_ACCESS_KEY}"
    [[ -n "${AWS_SESSION_TOKEN:-}" ]] && echo "aws_session_token=${AWS_SESSION_TOKEN}"
  } > "${HOME}/.aws/credentials"
  chmod 0600 "${HOME}/.aws/credentials"
  echo "[INFO] wrote ~/.aws/credentials from banzai-secrets env"
else
  echo "[WARN] AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not in env; aws-* provisioners will fail (add them to banzai-secrets)"
fi

# DEBUG (migration bring-up): list env var NAMES only. Uses `compgen -e` (exported
# names, no values) — NOT `env`, whose multi-line values (e.g. the GCP SA JSON)
# would leak secret material into the logs. Confirms which secret keys are present.
# TODO: remove once ArgoCI onboarding is signed off.
echo "[DEBUG] env var names present:"; compgen -e | sort | sed 's/^/[DEBUG]   /'

git config --global user.name "${GITHUB_USER_NAME:-marvin-tigera}"
git config --global user.email "${GITHUB_USER_EMAIL:-marvin@tigera.io}"

echo "[INFO] generating random token for unique cluster name..."
RANDOM_TOKEN1=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 5 || true)

echo "[INFO] exporting default env vars..."
export PRODUCT=${PRODUCT:-calico}
export PROVISIONER=${PROVISIONER:-gcp-kubeadm}
export INSTALLER=${INSTALLER:-"manual"}
export DATAPLANE=${DATAPLANE:-CalicoIptables}
export TEST_TYPE=${TEST_TYPE:-k8s-e2e}
export GOOGLE_PROJECT=${GOOGLE_PROJECT:-unique-caldron-775}
export GOOGLE_REGIONS=("us-central1" "us-west1")
export GOOGLE_REGION=${GOOGLE_REGION:-${GOOGLE_REGIONS[RANDOM%${#GOOGLE_REGIONS[@]}]}}
export GOOGLE_ZONE=${GOOGLE_ZONE:-$(gcloud compute zones list --filter="region~'$GOOGLE_REGION'" --format="value(name)" | awk 'BEGIN {srand()} {a[NR]=$0} rand() * NR < 1 {zone=$0} END {print zone}')}
export GOOGLE_NETWORK=${GOOGLE_NETWORK:-semaphore-autotest}
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2}

# RELEASE_STREAM: release-vX.Y -> vX.Y, else master. BRANCH is passed by the
# workflow (from the cron's `branch` parameter).
# Branch comes from the ArgoCI handler (CI_GIT_CLONED_BRANCH); fall back to
# BRANCH then master. release-vX.Y -> vX.Y, else master.
export RELEASE_STREAM=${RELEASE_STREAM:-$( _b="${CI_GIT_CLONED_BRANCH:-${BRANCH:-master}}"; [[ "${_b}" =~ ^release-(v[0-9]+\.[0-9]+)$ ]] && echo "${BASH_REMATCH[1]}" || echo "master" )}

export K8S_VERSION=${K8S_VERSION:-stable-3}
export K8S_E2E_EXTRA_FLAGS=${K8S_E2E_EXTRA_FLAGS:-" --e2ecfg.calicoctl-opensource-image=calico/ctl:release-${RELEASE_STREAM} "}
export HELM_PATCH=${HELM_PATCH:-"0"}
export CALICOCTL_INSTALL_TYPE=${CALICOCTL_INSTALL_TYPE:-"binary"}

export CLUSTER_NAME=${CLUSTER_NAME:-bz-${PRODUCT}-${RANDOM_TOKEN1}}
export DIAGS_ARCHIVE_FILENAME=${DIAGS_ARCHIVE_FILENAME:-${PROVISIONER}-${CLUSTER_NAME}-diags.tgz}

# bz working directories and artifact bucket.
# 'bz init profile -n NAME' creates the profile at <cwd>/NAME, and bz provision/
# install/destroy must run from that dir. Init from $HOME (in a subshell so the
# parent stays at repo root for the relative body_standard.sh call); BZ_HOME=$HOME/NAME.
export BZ_PROFILE_NAME="${BZ_PROFILE_NAME:-${ARGO_WORKFLOW_NAME:-local}-${RANDOM_TOKEN1}}"
export BZ_HOME="${BZ_HOME:-${HOME}/${BZ_PROFILE_NAME}}"
export USE_HASH_RELEASE="${USE_HASH_RELEASE:-true}"
export USE_LATEST_RELEASE="${USE_LATEST_RELEASE:-false}"
export BZ_LOCAL_DIR=${BZ_LOCAL_DIR:-${BZ_HOME}/.local}
export BZ_LOGS_DIR=${BZ_LOGS_DIR:-${HOME}/.bz/logs}
export REPORT_DIR=${REPORT_DIR:-${BZ_LOCAL_DIR}/report/${TEST_TYPE}}
export GS_BUCKET=${GS_BUCKET:-argoci-artifacts}
mkdir -p "${BZ_LOGS_DIR}"   # BZ_HOME + .local are created by "bz init profile"

# --- Install the banzai (bz) CLI: the ArgoCI runner image does not ship it ---
# (Semaphore installed bz the same way; our earlier port wrongly assumed the
#  base image provided it.) BZ_REPO + GITHUB_ACCESS_TOKEN come from banzai-secrets.
export BZ_GLOBAL_BIN="${BZ_GLOBAL_BIN:-${HOME}/.local/bin}"
mkdir -p "${BZ_GLOBAL_BIN}"
export PATH="${BZ_GLOBAL_BIN}:${PATH}"
if ! command -v bz >/dev/null 2>&1; then
  echo "[INFO] bz not on PATH; BZ_REPO=${BZ_REPO:-<UNSET>} GITHUB_ACCESS_TOKEN=$( [ -n "${GITHUB_ACCESS_TOKEN:-}" ] && echo SET || echo EMPTY ) jq=$(command -v jq || echo none) wget=$(command -v wget || echo none)"
  : "${BZ_REPO:?BZ_REPO not set (expected from banzai-secrets)}"
  : "${GITHUB_ACCESS_TOKEN:?GITHUB_ACCESS_TOKEN not set (expected from banzai-secrets)}"
  [[ -n "${BZ_VERSION:-}" ]] && BZ_RELEASE="tags/${BZ_VERSION}" || BZ_RELEASE="latest"
  BZ_ASSET_ID=$(curl --retry 9 --retry-all-errors -H "Authorization: token ${GITHUB_ACCESS_TOKEN}" -H "Accept: application/vnd.github.v3.raw" -s "https://api.github.com/repos/${BZ_REPO}/releases/${BZ_RELEASE}" | jq '.assets[] | select(.name|test("^bz.*linux-amd64"))| .id')
  echo "[INFO] bz asset id=${BZ_ASSET_ID}"
  wget -q --auth-no-challenge --header='Accept:application/octet-stream' "https://${GITHUB_ACCESS_TOKEN}:@api.github.com/repos/${BZ_REPO}/releases/assets/${BZ_ASSET_ID}" -O "${BZ_GLOBAL_BIN}/bz"
  chmod +x "${BZ_GLOBAL_BIN}/bz"
fi
echo "[INFO] bz resolved at $(command -v bz || echo '<none>')"

# --- Ensure pyyaml for bz's provisioner python scripts. bz's destroy path runs
# provisioners/scripts/cleanup.py, which `import yaml`; the ArgoCI runner image's
# system python lacks it, so `bz destroy` fails ("No module named 'yaml'") and
# leaks the cluster (observed on local-kind). Install it if missing. ---
if ! python3 -c 'import yaml' 2>/dev/null; then
  echo "[INFO] installing pyyaml for bz provisioner scripts..."
  python3 -m pip install --quiet pyyaml 2>/dev/null \
    || python3 -m pip install --quiet --break-system-packages pyyaml 2>/dev/null \
    || echo "[WARN] could not install pyyaml; bz destroy for local-kind may fail"
fi

# --- Ensure python3-venv for bz's provisioner venv. bz init/provision runs
# `python3 -m venv` (python3.10 on the ArgoCI runner image), but that image ships
# only python3.7/3.8-venv, so venv creation fails ("No such file: .local/venv/
# include"; "apt install python3.10-venv"). Stopgap until the runner image adds it
# (cc-utils/argoci-images); safe to remove once that lands. ---
if ! python3 -c 'import ensurepip' 2>/dev/null; then
  echo "[INFO] installing python3.10-venv (runner image lacks it)..."
  sudo apt-get install -y python3.10-venv 2>/dev/null \
    || { sudo apt-get update -qq 2>/dev/null && sudo apt-get install -y python3.10-venv 2>/dev/null; } \
    || echo "[WARN] could not install python3.10-venv; bz venv creation may fail"
fi

echo "[INFO] initialising bz profile..."
( cd "${HOME}" && bz init profile -n "${BZ_PROFILE_NAME}" --skip-prompt --secretsPath "${HOME}/secrets" ) \
  |& tee "${BZ_LOGS_DIR}/initialize.log" || true
mkdir -p "${BZ_LOCAL_DIR}" "${REPORT_DIR}" "${BZ_LOCAL_DIR}/config"
# bz provision prereq wants the docker auth at <profile>/.local/config/docker_auth.json
# (the DOCKER_AUTH_FILE env alone does not redirect the prereq check).
if [[ -f "${HOME}/.docker/config.json" ]]; then
  cp "${HOME}/.docker/config.json" "${BZ_LOCAL_DIR}/config/docker_auth.json"
  echo "[INFO] staged docker_auth.json into ${BZ_LOCAL_DIR}/config"
else
  echo "[WARN] ${HOME}/.docker/config.json missing; docker_auth not staged"
fi

echo "[INFO] exiting prologue (PROVISIONER=${PROVISIONER} RELEASE_STREAM=${RELEASE_STREAM} CLUSTER_NAME=${CLUSTER_NAME})"
