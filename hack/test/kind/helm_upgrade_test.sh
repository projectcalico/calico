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

# helm_upgrade_test.sh upgrades the Calico release with a second Helm binary and checks that
# the Installation and the cluster's IP pools came through unchanged. Helm 4 applies
# server-side, which can take over operator-owned fields.

: ${REPO_ROOT:?REPO_ROOT must be set}
: ${KUBECONFIG:?KUBECONFIG must be set}
: ${HELM_UPGRADE:?HELM_UPGRADE must be set to the helm binary to upgrade with}

GIT_VERSION=${GIT_VERSION:-$(git -C "${REPO_ROOT}" describe --tags --dirty --always --abbrev=12)}
INFRA_DIR=${REPO_ROOT}/hack/test/kind/infra
CHART=${REPO_ROOT}/bin/tigera-operator-${GIT_VERSION}.tgz
VALUES_FILE=${VALUES_FILE:-${INFRA_DIR}/values.yaml}

: ${kubectl:=${REPO_ROOT}/hack/test/kind/kubectl}

# Both API groups serve a resource called "ippools", so name the group the cluster is using.
POOL_RESOURCE=ippools.projectcalico.org
if [ "${CALICO_API_GROUP:-projectcalico.org/v3}" = "crd.projectcalico.org/v1" ]; then
  POOL_RESOURCE=ippools.crd.projectcalico.org
fi

function installation_spec() {
  ${kubectl} get installation default -o jsonpath='{.spec}'
}

function pool_cidrs() {
  ${kubectl} get ${POOL_RESOURCE} -o jsonpath='{range .items[*]}{.spec.cidr}{"\n"}{end}' | sort
}

function field_managers() {
  ${kubectl} get installation default -o jsonpath='{range .metadata.managedFields[*]}{.manager}{" "}{.operation}{"\n"}{end}' | sort
}

echo "Release state before the upgrade"
${HELM_UPGRADE} version --short
installation_before=$(installation_spec)
pools_before=$(pool_cidrs)
echo "Installation spec: ${installation_before}"
echo "IP pools: ${pools_before}"
echo "Field managers:"
field_managers

# Pass the same values the install used. --reuse-values would read the release's values
# rather than the chart's, hiding render changes.
helm_values_args=(-f "${VALUES_FILE}")
for extra in ${EXTRA_VALUES_FILES:-}; do
  helm_values_args+=(-f "${extra}")
done

echo "Upgrade the release"
${HELM_UPGRADE} upgrade calico ${CHART} "${helm_values_args[@]}" -n tigera-operator

echo "Wait for Calico to settle after the upgrade"
${kubectl} rollout status ds/calico-node -n calico-system --timeout=300s
${kubectl} wait --for=condition=Available tigerastatus/calico --timeout=300s

installation_after=$(installation_spec)
pools_after=$(pool_cidrs)
echo "Field managers after the upgrade:"
field_managers

rc=0
if [ "${installation_before}" != "${installation_after}" ]; then
  echo "FAIL: the upgrade changed the Installation spec"
  echo "  before: ${installation_before}"
  echo "  after:  ${installation_after}"
  rc=1
fi

if [ "${pools_before}" != "${pools_after}" ]; then
  echo "FAIL: the upgrade changed the cluster's IP pools"
  echo "  before: ${pools_before}"
  echo "  after:  ${pools_after}"
  rc=1
fi

if [ ${rc} -eq 0 ]; then
  echo "PASS: Installation and IP pools survived the upgrade"
fi
exit ${rc}
