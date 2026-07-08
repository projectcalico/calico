#!/usr/bin/env bash
# Vendored from tigera/banzai-utils ocp-hcp/hcp-provision.sh, adapted for ArgoCI.
# Env-driven (BZ_PROFILES_PATH/BZ_SECRETS_PATH/BZ_PATH); the ArgoCI HCP
# wrapper (.argoci/scripts/phases/hcp.sh) + global_prologue.sh set those.

set -e

BZ_PROFILES_PATH=${BZ_PROFILES_PATH:=$HOME/bzprofiles}
BZ_SECRETS_PATH=${BZ_SECRETS_PATH:=$HOME/.banzai/secrets}
BZ=${BZ_PATH:=$HOME/.local/bin/bz}
BZ_HCP_STATUS_PATH=${BZ_HCP_STATUS_PATH:=$(find "$BZ_PROFILES_PATH" -maxdepth 1 -type f -name "hcp-*.status" -printf "%T@ %p\n" | sort -rn -k1 | head -n 1 | cut -d" " -f2)}
PRODUCT=${PRODUCT:="calico"}

echo "[INFO] Using $BZ_HCP_STATUS_PATH to extract clusters"
hosting=$(grep "hosting:" "$BZ_HCP_STATUS_PATH" | cut -d: -f2 )
hosted=$(grep "hosted:" "$BZ_HCP_STATUS_PATH" | cut -d: -f2 )
clusters="$hosting $hosted"

if [[ -z "$clusters" ]]; then
  echo "[ERROR] No clusters have been declared to be installed/provisioned"
  exit 1
fi

echo "[INFO] The following clusters: $clusters are declared"

for cluster in $clusters; do
  if [[ -d $BZ_PROFILES_PATH/$cluster ]]; then
    echo "[INFO] Installing $PRODUCT using operator on $cluster"
    pushd "$BZ_PROFILES_PATH/$cluster"
    $BZ provision
    $BZ install
    popd
  fi
done
