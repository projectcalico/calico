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

# upgrade_to_operator.sh installs the operator on a cluster that already runs
# Calico from the manifests, which is how a manifest user adopts the operator.
# The operator reads the kube-system install, derives an Installation from it,
# and moves the components to calico-system a node at a time.
#
# Required environment variables:
#   REPO_ROOT  - absolute path to the repository root
#   KUBECONFIG - kubeconfig for the cluster
#
# Optional environment variables:
#   GIT_VERSION  - version the chart was packaged under (default: git describe)
#   VALUES_FILE  - operator values (default: infra/values-migration.yaml)

: ${REPO_ROOT:?REPO_ROOT must be set}
: ${KUBECONFIG:?KUBECONFIG must be set}

: ${kubectl:=${REPO_ROOT}/hack/test/kind/kubectl}

INFRA_DIR=${REPO_ROOT}/hack/test/kind/infra
GIT_VERSION=${GIT_VERSION:-$(git -C "${REPO_ROOT}" describe --tags --dirty --always --abbrev=12)}
HELM=${REPO_ROOT}/bin/helm
CHART=${REPO_ROOT}/bin/tigera-operator-${GIT_VERSION}.tgz
VALUES_FILE=${VALUES_FILE:-${INFRA_DIR}/values-migration.yaml}

echo "Installing the operator over the manifest install"
${HELM} install calico "${CHART}" -f "${VALUES_FILE}" -n tigera-operator --create-namespace

# The migration moves one node at a time and rolls every component, so give it
# room; a healthy cluster gets there long before the timeout.
echo "Waiting for the migration to move calico-node out of kube-system"
for attempt in $(seq 1 120); do
  if ! ${kubectl} -n kube-system get daemonset calico-node &>/dev/null; then
    break
  fi
  if [ "${attempt}" -eq 120 ]; then
    echo "FAIL: calico-node is still in kube-system after 600s"
    ${kubectl} get tigerastatus 2>&1 || true
    ${kubectl} -n tigera-operator logs -l k8s-app=tigera-operator --tail=100 2>&1 || true
    exit 1
  fi
  sleep 5
done

echo "Waiting for every TigeraStatus to be Available"
for attempt in $(seq 1 120); do
  not_ready=$(${kubectl} get tigerastatus -o jsonpath='{range .items[*]}{.metadata.name}{" "}{range .status.conditions[?(@.type=="Available")]}{.status}{end}{"\n"}{end}' 2>/dev/null \
    | grep -v "True$" || true)
  if [ -z "${not_ready}" ] && [ "$(${kubectl} get tigerastatus --no-headers 2>/dev/null | wc -l)" -ge 1 ]; then
    break
  fi
  if [ "${attempt}" -eq 120 ]; then
    echo "FAIL: TigeraStatus did not become Available after 600s"
    ${kubectl} get tigerastatus 2>&1 || true
    echo "${not_ready}"
    ${kubectl} -n tigera-operator logs -l k8s-app=tigera-operator --tail=100 2>&1 || true
    exit 1
  fi
  sleep 5
done

${kubectl} -n calico-system rollout status ds/calico-node --timeout=600s
${kubectl} get tigerastatus

# The migration removes the webhook server the manifest puts in kube-system,
# along with the configuration aimed at it, which fails closed.
if ${kubectl} -n kube-system get deployment calico-webhooks &>/dev/null; then
  echo "FAIL: the manifest's webhook server is still in kube-system"
  exit 1
fi
if ${kubectl} get validatingwebhookconfiguration calico-webhooks &>/dev/null; then
  echo "FAIL: the manifest's webhook configuration is still there"
  exit 1
fi

echo "Calico is running under the operator."
