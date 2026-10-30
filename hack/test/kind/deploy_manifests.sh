#!/bin/bash -e

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# deploy_manifests.sh installs Calico on an existing kind cluster from the
# generated manifests, the way a user without the operator does. Every other
# kind lane installs through the operator, which renders its own DaemonSet and
# so cannot catch a manifest that is missing a piece.
#
# It installs the v3-CRD variant because the e2e specs talk to
# projectcalico.org/v3, which the default manifest does not serve.
#
# Required environment variables:
#   REPO_ROOT  - absolute path to the repository root
#   KIND       - path to the kind binary
#   KIND_NAME  - name of the kind cluster
#   KUBECONFIG - kubeconfig for that cluster
#
# Optional environment variables:
#   MANIFEST       - manifest to install (default: the v3-CRD manifest matching
#                    the cluster's MutatingAdmissionPolicy API version)
#   IMAGE_REGISTRY - registry the manifest images are rewritten to (default localhost:5000)
#   IMAGE_PATH     - path under that registry (default calico)
#   IMAGE_TAG      - tag to use (default test-build)

: ${REPO_ROOT:?REPO_ROOT must be set}
: ${KIND:?KIND must be set}
: ${KIND_NAME:?KIND_NAME must be set}
: ${KUBECONFIG:?KUBECONFIG must be set}

: ${kubectl:=${REPO_ROOT}/hack/test/kind/kubectl}

# The manifests ship one v3-CRD file per MutatingAdmissionPolicy API version,
# which is v1 from Kubernetes 1.36 and v1beta1 before it.
if [ -z "${MANIFEST:-}" ]; then
  if ${kubectl} get --raw /apis/admissionregistration.k8s.io/v1 2>/dev/null | grep -q MutatingAdmissionPolicy; then
    MANIFEST=${REPO_ROOT}/manifests/calico-v3-crds.yaml
  else
    MANIFEST=${REPO_ROOT}/manifests/calico-v3-crds-v1beta1.yaml
  fi
fi
IMAGE_REGISTRY=${IMAGE_REGISTRY:-localhost:5000}
IMAGE_PATH=${IMAGE_PATH:-calico}
IMAGE_TAG=${IMAGE_TAG:-test-build}

# The plugins Calico ships and installs onto the host.
CALICO_PLUGINS="portmap host-local loopback tuning flannel"

# The kind node image ships its own copies, which would mask a manifest that
# never installs them.
echo "Deleting the CNI plugins the kind node image ships"
for node in $(${KIND} get nodes --name "${KIND_NAME}"); do
  for plugin in ${CALICO_PLUGINS}; do
    docker exec "${node}" rm -f "/opt/cni/bin/${plugin}"
  done
done

# The webhook server's certificate is the installer's job on a manifest install,
# so mint one the way charts/calico/templates/calico-webhooks.yaml documents.
certs=$(mktemp -d)
trap 'rm -rf "${certs}"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout "${certs}/tls.key" -out "${certs}/tls.crt" \
  -subj "/CN=calico-webhooks.kube-system.svc" \
  -addext "subjectAltName=DNS:calico-webhooks.kube-system.svc" 2>/dev/null

${kubectl} -n kube-system create secret tls calico-webhooks-tls \
  --cert="${certs}/tls.crt" --key="${certs}/tls.key" \
  --dry-run=client -o yaml | ${kubectl} apply -f -

manifest=$(mktemp -t calico-manifest-XXXXXX.yaml)
trap 'rm -rf "${certs}" "${manifest}"' EXIT

sed -E "s|image: [a-zA-Z0-9./:-]+/([a-z0-9-]+):[A-Za-z0-9_.-]+|image: ${IMAGE_REGISTRY}/${IMAGE_PATH}/\1:${IMAGE_TAG}|g" \
  "${MANIFEST}" > "${manifest}"

echo "Installing Calico from ${MANIFEST#${REPO_ROOT}/}"
grep "image:" "${manifest}" | sort -u | sed 's/^/  /'

# The cluster is created with the Calico CRDs already applied, so the manifest's
# copies land on top of them.
${kubectl} apply --server-side --force-conflicts -f "${manifest}"

# The configuration ships with an empty caBundle for the installer to fill in.
ca=$(base64 -w0 < "${certs}/tls.crt")
${kubectl} patch validatingwebhookconfiguration calico-webhooks --type=json \
  -p "[{\"op\": \"replace\", \"path\": \"/webhooks/0/clientConfig/caBundle\", \"value\": \"${ca}\"}]"

${kubectl} -n kube-system rollout status ds/calico-node --timeout=600s
${kubectl} -n kube-system rollout status deploy/calico-kube-controllers --timeout=300s
${kubectl} -n kube-system rollout status deploy/calico-webhooks --timeout=300s
${kubectl} wait --for=condition=Ready nodes --all --timeout=300s

echo "Calico is running."
