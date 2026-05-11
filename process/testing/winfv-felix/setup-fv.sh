#!/bin/bash
# Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

: "${ASO_DIR:=${SCRIPT_DIR}/../aso}"
: "${UTILS_DIR:=${SCRIPT_DIR}/../util}"

. "${UTILS_DIR}/utils.sh"
. "${ASO_DIR}/export-env.sh"
. ${ASO_DIR}/vmss.sh info

: "${KUBECTL:=${ASO_DIR}/bin/kubectl}"
: "${GOMPLATE:=${ASO_DIR}/bin/gomplate}"
: "${FV_TYPE:?Error: FV_TYPE is not set}"

: "${CALICO_HOME:=${SCRIPT_DIR}/../../..}"

: "${KUBECONFIG:=${ASO_DIR}/kubeconfig}"

GIT_VERSION=$(git describe --tags --dirty --long --always --abbrev=12)

function upload_fv_scripts() {
  mkdir -p ./windows
  ${GOMPLATE} --file ./run-fv-felix.ps1 --out ./windows/run-fv.ps1

  ${ASO_DIR}/scp-to-windows.sh 0 ./windows/run-fv.ps1 'c:\k\run-fv.ps1'
  echo "Copied run-fv.ps1 to Windows node"

  make -C "$CALICO_HOME/felix" fv/win-fv.exe

  ${ASO_DIR}/scp-to-windows.sh 0 $CALICO_HOME/felix/fv/win-fv.exe 'c:\k\win-fv.exe'
  echo "Copied win-fv.exe to Windows node"
}

function upload_calico_images(){
  make -C "$CALICO_HOME/node" image-windows WINDOWS_IMAGE=node-windows
  make -C "$CALICO_HOME/cni-plugin" image-windows WINDOWS_IMAGE=cni-windows

  if [[ $WINDOWS_SERVER_VERSION == "windows-2022" ]]; then
    CALICO_NODE_IMAGE="node-windows-$GIT_VERSION-ltsc2022.tar"
    CALICO_CNI_IMAGE="cni-windows-$GIT_VERSION-ltsc2022.tar"
  else # $WINDOWS_SERVER_VERSION == "windows-2019"
    CALICO_NODE_IMAGE="node-windows-$GIT_VERSION-ltsc2019.tar"
    CALICO_CNI_IMAGE="cni-windows-$GIT_VERSION-ltsc2019.tar"
  fi

  ${ASO_DIR}/scp-to-windows.sh 0 "${CALICO_HOME}/node/dist/windows/${CALICO_NODE_IMAGE}" 'c:\calico-node-windows.tar'
  ${ASO_DIR}/scp-to-windows.sh 0 "${CALICO_HOME}/cni-plugin/dist/windows/${CALICO_CNI_IMAGE}" 'c:\calico-cni-plugin-windows.tar'

  #Import images from locally built images
  ${WINDOWS_CONNECT_COMMAND} 'c:\bin\ctr.exe --namespace k8s.io images import --base-name calico/node-windows c:\calico-node-windows.tar --all-platforms'
  ${WINDOWS_CONNECT_COMMAND} 'c:\bin\ctr.exe --namespace k8s.io images import --base-name calico/cni-windows c:\calico-cni-plugin-windows.tar --all-platforms'

  ${KUBECTL} --kubeconfig="${KUBECONFIG}" annotate ds -n calico-system calico-node-windows unsupported.operator.tigera.io/ignore="true"
  ${KUBECTL} --kubeconfig="${KUBECONFIG}" patch ds -n calico-system calico-node-windows --patch-file "${SCRIPT_DIR}/calico-node-windows.yaml"

  echo "Waiting for calico-node-windows to be ready after image replacement..."
  ${KUBECTL} --kubeconfig="${KUBECONFIG}" rollout status ds -n calico-system calico-node-windows --timeout=600s
}

function start_test_infra(){
  # Enable felix debug logging, wait for felixconfiguration to exist first
  timeout --foreground 180 bash -c "while ! ${KUBECTL} --kubeconfig=${KUBECONFIG} wait felixconfiguration default --for=jsonpath='{.spec}' --timeout=30s; do sleep 5; done"
  ${KUBECTL} --kubeconfig="${KUBECONFIG}" patch felixconfiguration default --type merge --patch='{"spec":{"logSeverityScreen":"Debug"}}'

  ${KUBECTL} --kubeconfig="${KUBECONFIG}" create ns demo
  ${KUBECTL} --kubeconfig="${KUBECONFIG}" apply -f "${SCRIPT_DIR}/infra/"

  #Wait for porter pod to be running on windows node
  for i in $(seq 1 40); do
    if [[ $(${KUBECTL} --kubeconfig="${KUBECONFIG}" -n demo get pods porter --no-headers -o custom-columns=NAMESPACE:metadata.namespace,POD:metadata.name,PodIP:status.podIP,READY-true:status.containerStatuses[*].ready | awk -v OFS='\t\t' '{print $4}') = "true" ]] ; then
      echo "Porter is ready after $i tries"
      return
    fi
    echo "Waiting for porter to be ready"
    sleep 30
  done
  echo "Porter windows did not start after $i tries"
  exit 1
}

function run_windows_fv(){
  ${WINDOWS_CONNECT_COMMAND} "c:\\k\\run-fv.ps1"
  echo
}

function get_logs(){
  rm -r ./pod-logs || true
  mkdir -p ./pod-logs

  # Dump cluster state and container logs to stdout as well as files so that
  # when the job's pod-logs/ directory isn't uploaded as an artifact, the
  # diagnostic output is still captured in the main job log.
  local sections=(
    "kubectl get pods -A -o wide"
    "kubectl get nodes -o wide"
    "kubectl describe ds -n calico-system calico-node-windows"
    "kubectl describe pods -n calico-system -l k8s-app=calico-node-windows"
    "kubectl get events -n calico-system --sort-by=.lastTimestamp"
  )
  for cmd in "${sections[@]}"; do
    echo "================ ${cmd} ================"
    ${KUBECTL} --kubeconfig="${KUBECONFIG}" ${cmd#kubectl } || echo "Failed: ${cmd}"
  done

  # Container logs: capture to files (for artifact upload) and stdout (for job log).
  local win_containers=(uninstall-calico install-cni node felix)
  for c in "${win_containers[@]}"; do
    local out="./pod-logs/win-${c}.log"
    ${KUBECTL} --kubeconfig="${KUBECONFIG}" logs -n calico-system -l k8s-app=calico-node-windows -c "${c}" > "${out}" 2>&1 || echo "Failed to get logs for win-${c}"
    echo "================ calico-node-windows container=${c} ================"
    cat "${out}" || true
  done

  ${KUBECTL} --kubeconfig="${KUBECONFIG}" logs -n calico-system -l k8s-app=calico-node -c calico-node > ./pod-logs/linux-calico-node.log 2>&1 || echo "Failed to get logs for linux-calico-node"
  echo "================ calico-node (linux) ================"
  cat ./pod-logs/linux-calico-node.log || true

  # Pull Windows-side service logs from the VM. When calico-node.exe crashes
  # before Kubernetes can capture container logs (e.g., bad argv parsing), the
  # only trace lives in CalicoWindows/logs on the host.
  echo "================ Windows node CalicoWindows logs ================"
  # Use a `foreach` statement rather than the pipeline form (`| ForEach-Object`):
  # the ssh command is handed to cmd.exe on the Windows side, which treats
  # `|` as its own pipe separator before powershell ever sees it.
  ${WINDOWS_CONNECT_COMMAND} 'foreach ($f in (Get-ChildItem c:\CalicoWindows\logs -Recurse -File -ErrorAction SilentlyContinue)) { Write-Host "---- $($f.FullName) ----"; Get-Content $f.FullName -Tail 500 -ErrorAction SilentlyContinue }' || echo "Failed to fetch Windows service logs"
}

# Main execution
# Always collect pod logs on exit so failures during image rollout or test
# infrastructure setup don't leave us without diagnostic data.
trap get_logs EXIT

upload_fv_scripts
upload_calico_images
start_test_infra
run_windows_fv
