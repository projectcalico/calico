#!/bin/bash
# Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

# Common utility functions for testing scripts

# Logging functions with timestamps and colors
function log_info() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[32m[INFO]\033[0m [$timestamp] $*"
}

function log_warning() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[33m[WARNING]\033[0m [$timestamp] $*" >&2
}

function log_fail() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "\033[31m[FAIL]\033[0m [$timestamp] $*" >&2
}

# Alias for backwards compatibility
function log_warn() {
    log_warning "$@"
}

function log_error() {
    log_fail "$@"
}

# Helper function to redirect output based on VERBOSE setting
function redirect_output() {
  if [[ "${VERBOSE}" == "true" ]]; then
    "$@"
  else
    "$@" > /dev/null 2>&1
  fi
}

unset -f retry_command
function retry_command() {
  local RETRY=$(($1/10))
  local CMD=$2
  echo

  for i in $(seq 1 $RETRY); do
    echo "Trying '$CMD', attempt ${i}"
    $CMD && return 0 || sleep 10
  done
  echo "Command '${CMD}' failed after $RETRY attempts"
  return 1
}

# collect_pod_diagnostics writes describe + logs (current and previous) for every
# pod whose Ready condition is not True, plus cluster-wide pod/event/node snapshots.
# Expects KUBECTL and KUBECONFIG in the environment. Safe to call from an EXIT trap;
# every kubectl invocation tolerates failure so we never mask the original exit code.
#
# Args:
#   $1 - output directory (created if missing). Defaults to /tmp/pod-diagnostics.
function collect_pod_diagnostics() {
    local out_dir="${1:-/tmp/pod-diagnostics}"
    local kubectl="${KUBECTL:-kubectl}"

    mkdir -p "${out_dir}"

    echo ""
    echo "========================================"
    echo "Collecting pod diagnostics into ${out_dir}"
    echo "========================================"

    ${kubectl} get pod -A -o wide > "${out_dir}/pods.txt" 2>&1 || true
    ${kubectl} get events -A --sort-by=.lastTimestamp > "${out_dir}/events.txt" 2>&1 || true
    ${kubectl} get nodes -o wide > "${out_dir}/nodes.txt" 2>&1 || true

    local not_ready
    not_ready=$(${kubectl} get pod -A \
        -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.status.phase} {range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\n"}{end}' \
        2>/dev/null \
        | awk '$2 != "Succeeded" && $3 != "True" { print $1 }' || true)

    if [[ -z "${not_ready}" ]]; then
        echo "No non-Ready pods found."
        return 0
    fi

    echo "Non-Ready pods:"
    echo "${not_ready}" | sed 's/^/  /'
    echo ""

    local ns_pod ns pod safe containers c
    for ns_pod in ${not_ready}; do
        ns="${ns_pod%%/*}"
        pod="${ns_pod#*/}"
        safe="${ns}_${pod}"

        ${kubectl} describe pod "${pod}" -n "${ns}" \
            > "${out_dir}/${safe}.describe.txt" 2>&1 || true

        containers=$(${kubectl} get pod "${pod}" -n "${ns}" \
            -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' 2>/dev/null || true)

        echo "--- ${ns_pod} ---"
        for c in ${containers}; do
            ${kubectl} logs "${pod}" -n "${ns}" -c "${c}" --tail=500 \
                > "${out_dir}/${safe}.${c}.log" 2>&1 || true
            ${kubectl} logs "${pod}" -n "${ns}" -c "${c}" --tail=500 --previous \
                > "${out_dir}/${safe}.${c}.previous.log" 2>&1 || true

            echo "  container ${c} (last 20 lines):"
            ${kubectl} logs "${pod}" -n "${ns}" -c "${c}" --tail=20 2>&1 \
                | sed 's/^/    /' || true
        done
        echo ""
    done

    echo "Full diagnostics written to ${out_dir}"
}

unset -f pause-for-debug
function pause-for-debug() {
  # Stop for debug
  echo "Check for pause file..."
  while [ -f "${HOME}/pause-for-debug" ];
  do
    echo "#"
    sleep 30
  done
}
