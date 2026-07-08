#!/usr/bin/env bash
# Vendored from tigera/banzai-utils ocp-hcp/hcp-init.sh, adapted for ArgoCI.
# Env-driven (BZ_PROFILES_PATH/BZ_SECRETS_PATH/BZ_PATH); the ArgoCI HCP
# wrapper (.argoci/scripts/phases/hcp.sh) + global_prologue.sh set those.

set -e

INTERACTIVE_MODE=${INTERACTIVE_MODE:=false}
CUSTOM_K8S_E2E_IMAGE=${CUSTOM_K8S_E2E_IMAGE:=gcr.io/unique-caldron-775/k8s-e2e:stable}
BZ_HCP_PREFIX=${BZ_HCP_PREFIX:=$USER-bz-$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 4)}

BZ_PROFILES_PATH=${BZ_PROFILES_PATH:=$HOME/bzprofiles}
BZ_SECRETS_PATH=${BZ_SECRETS_PATH:=$HOME/.banzai/secrets}
BZ=${BZ_PATH:=$HOME/.local/bin/bz}
BZ_BRANCH=${BZ_BRANCH}

PRODUCT=${PRODUCT:="calico"}
DATAPLANE=${DATAPLANE:="CalicoIptables"}

HOSTING_K8SVERSION=${HOSTING_K8SVERSION:="stable-1"}
HOSTING_RELEASE_STREAM=${HOSTING_RELEASE_STREAM:="master"}
HOSTING_PROVISIONER=${HOSTING_PROVISIONER:="aws-openshift"}
HOSTING_OPENSHIFT_VERSION=${HOSTING_OPENSHIFT_VERSION:="4.18.24"}

HOSTED_CLUSTERS=${HOSTED_CLUSTERS:-1}
HOSTED_RELEASE_STREAM=${HOSTED_RELEASE_STREAM:=$HOSTING_RELEASE_STREAM}
HOSTED_K8SVERSION=${HOSTED_K8SVERSION:=$HOSTING_K8SVERSION}
HOSTED_PROVISIONER=${HOSTED_PROVISIONER:-$HOSTING_PROVISIONER}
HOSTED_OPENSHIFT_VERSION=${HOSTED_OPENSHIFT_VERSION:=$HOSTING_OPENSHIFT_VERSION}

function configure_cluster () {
  if [[ -z "$1" ]]; then
    echo "[ERROR] Cannot create a profile without a name"
    exit 1
  fi

  if [[ -z "$2" ]]; then
    echo "[ERROR] Cannot provision a cluster without a type"
    exit 1
  elif [[ $2 == "HCP-hosted" ]]; then
     if [[ -z "$9" ]]; then
      echo "[ERROR] Cannot provision a hosted cluster without a hosting kubeconfig"
      exit 1
     fi
  fi

  if [[ $INTERACTIVE_MODE == false ]]; then
      if [[ -z "$3" ]]; then
        echo "[ERROR] Cannot provision a cluster without k8s version"
        exit 1
      fi

      if [[ -z "$4" ]]; then
        echo "[ERROR] Cannot provision a cluster without a release stream"
        exit 1
      fi

      if [[ -z "$5" ]]; then
        echo "[ERROR] Cannot provision a cluster without a provisioner"
        exit 1
      fi

      if [[ -z "$6" ]]; then
        echo "[ERROR] Cannot provision a cluster without openshift version"
        exit 1
      fi

      if [[ -z "$7" ]]; then
          echo "[ERROR] Cannot provision a cluster without product (calico, calient)"
        exit 1
      fi

      if [[ -z "$8" ]]; then
          echo "[ERROR] Cannot provision a cluster without dataplane (CalicoIptables, CalicoBPF, CalicoNftables)"
        exit 1
      fi
  fi

  echo cd "$BZ_PROFILES_PATH"
  cd "$BZ_PROFILES_PATH"

  optionalFlags=""
  # Only set --core-branch if it is explicitly provided as a parameter. This
  # is useful for dev testing when you want to provide your own branch. This
  # should not be set in pipelines for official releases.
  if [[ -n "$BZ_BRANCH" ]]; then
      optionalFlags="${optionalFlags} --core-branch $BZ_BRANCH"
  fi

  # Use hashrelease if release stream is set to "master"
  if [[ "$4" == "master" ]]; then
      optionalFlags="${optionalFlags} --hashrelease"
  fi

  if [[ $INTERACTIVE_MODE == true ]]; then
    echo K8S_E2E_IMAGE=$CUSTOM_K8S_E2E_IMAGE OPENSHIFT_CLUSTER_TYPE="$2" CLUSTER_NAME="$1" "$BZ" init profile -n "$1" $optionalFlags
    K8S_E2E_IMAGE=$CUSTOM_K8S_E2E_IMAGE OPENSHIFT_CLUSTER_TYPE=$2 CLUSTER_NAME="$1" $BZ init profile -n "$1" $optionalFlags
  else
    echo OPENSHIFT_HOSTING_KUBECONFIG="$9" K8S_E2E_IMAGE=$CUSTOM_K8S_E2E_IMAGE OPENSHIFT_VERSION="$6" OPENSHIFT_CLUSTER_TYPE="$2" CLUSTER_NAME="$1" "$BZ" init profile -n "$1" $optionalFlags --k8sversion "$3" --product "$7" --release-stream "$4" --installer operator --provisioner "$5" --dataplane "$8" --secretsPath "$BZ_SECRETS_PATH" --skip-prompt
    OPENSHIFT_HOSTING_KUBECONFIG="$9" K8S_E2E_IMAGE=$CUSTOM_K8S_E2E_IMAGE OPENSHIFT_VERSION="$6" OPENSHIFT_CLUSTER_TYPE="$2" CLUSTER_NAME="$1" $BZ init profile -n "$1" $optionalFlags --k8sversion "$3" --product "$7" --release-stream "$4" --installer operator --provisioner "$5" --dataplane "$8" --secretsPath "$BZ_SECRETS_PATH" --skip-prompt
  fi
  echo cd "$BZ_PROFILES_PATH/$1"
  cd "$BZ_PROFILES_PATH/$1"

  echo cd "$BZ_PROFILES_PATH"
  cd "$BZ_PROFILES_PATH"
}

hosting="$BZ_HCP_PREFIX-hosting"
hosted_prefix="$BZ_HCP_PREFIX-hosted"
echo "[INFO] Starting OCP HCP multicluster provisioning and configuration using prefix hcp id $BZ_HCP_PREFIX in $BZ_PROFILES_PATH"
echo mkdir -p "$BZ_PROFILES_PATH"
mkdir -p "$BZ_PROFILES_PATH"

echo "[INFO] Provision hosting cluster"
configure_cluster "$hosting" HCP-hosting "$HOSTING_K8SVERSION" "$HOSTING_RELEASE_STREAM" "$HOSTING_PROVISIONER" "$HOSTING_OPENSHIFT_VERSION" "$PRODUCT" "$DATAPLANE"
cd "$BZ_PROFILES_PATH/$hosting" || exit 1

for i in $(seq 1 "$HOSTED_CLUSTERS"); do
    echo "[INFO] Provision hosted cluster number $i"
    hosted=$hosted_prefix-$i
    configure_cluster "$hosted" HCP-hosted "$HOSTED_K8SVERSION" "$HOSTED_RELEASE_STREAM" "$HOSTED_PROVISIONER" "$HOSTED_OPENSHIFT_VERSION" "$PRODUCT" "$DATAPLANE" "$BZ_PROFILES_PATH/$hosting/.local/kubeconfig"
    cd "$BZ_PROFILES_PATH/$hosted" || exit 1
done

echo "[INFO] Creating /tmp/hcp-${BZ_HCP_PREFIX}.status file"
printf "hosting: %s\n"  "$hosting" > /tmp/hcp-"$BZ_HCP_PREFIX".status
printf "hosted:" >> /tmp/hcp-"$BZ_HCP_PREFIX".status
for i in $(seq 1 "$HOSTED_CLUSTERS"); do
  printf " %s" "${hosted_prefix}"-"${i}" >> /tmp/hcp-"$BZ_HCP_PREFIX".status
done
printf "\n" >> /tmp/hcp-"$BZ_HCP_PREFIX".status

echo cp /tmp/hcp-"$BZ_HCP_PREFIX".status "$BZ_PROFILES_PATH"
cp /tmp/hcp-"$BZ_HCP_PREFIX".status "$BZ_PROFILES_PATH"
echo "[INFO]  Content of ${BZ_PROFILES_PATH}/hcp-${BZ_HCP_PREFIX}.status"
cat "$BZ_PROFILES_PATH"/hcp-"$BZ_HCP_PREFIX".status
