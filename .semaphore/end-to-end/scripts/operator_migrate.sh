#!/usr/bin/env bash
set -eo pipefail

# Perform the operator migration following the instructions here:
# https://projectcalico.docs.tigera.io/maintenance/operator-migration
echo "[INFO] starting operator migration..."

# Get the docs site base url
if [[ "${USE_HASH_RELEASE}" == "true" ]]; then
  LATEST_HASHREL="https://latest-os.docs.eng.tigera.net/${RELEASE_STREAM}.txt"
  echo "Checking ${LATEST_HASHREL} for latest hash release url..."
  BASE_URL=$(curl --retry 9 --retry-all-errors -sS ${LATEST_HASHREL})
  echo "Using $BASE_URL for hash release base url"
else
  if [[ "${RELEASE_STREAM}" == "master" ]]; then
    echo "Cannot use latest release on master branch"
    exit 1
  else
    BASE_URL="https://projectcalico.docs.tigera.io/archive/${RELEASE_STREAM}"
  fi
  echo "Not hash release. Using $BASE_URL for base url"
fi

# Apply operator manifest
echo "Applying operator install manifest"
KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl apply --server-side --force-conflicts -f "${BASE_URL}/manifests/tigera-operator.yaml"
sleep 60 # Wait for operator to write CRDs
echo "Creating Installation"
for i in $(seq 10); do
  if KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl create -f - <<EOF
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec: {}
EOF
  then
    break
  fi
  echo "attempt $i, Applying Installation didn't succeed, sleeping a bit before maybe retrying"
  sleep 10
done

echo "Waiting for Calico tigerastatus to exist"
for i in $(seq 10); do
  if KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl get tigerastatus calico; then
    break
  fi
  echo "attempt $i, Calico tigerastatus not found, sleeping a bit"
  sleep 5
done

echo "Waiting for Calico tigerastatus to be Available"
KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl wait --timeout=10m --for condition=available tigerastatus/calico

# Do a sanity check
echo "Bring up test nginx pod and confirm podIPs"
KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl run nginx --image nginx
echo "Waiting for nginx pod to exist"
for i in $(seq 10); do
  if KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl get pod nginx; then
    break
  fi
  echo "attempt $i, nginx pod does not exist, sleeping"
  sleep 5
done
KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl wait --timeout=5m --for condition=Ready pod nginx
KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl get po nginx -oyaml | grep 'cni.projectcalico.org/podIPs'
KUBECONFIG=${BZ_LOCAL_DIR}/kubeconfig kubectl delete pod nginx
