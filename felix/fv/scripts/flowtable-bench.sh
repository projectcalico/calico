#!/usr/bin/env bash
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
#
# flowtable-bench.sh - throughput benchmark for nftables flowtable offload.
#
# WHAT THIS NEEDS: a real, already-running 2-node Kubernetes cluster with
# Calico in nftables mode, and two long-lived iperf3 pods scheduled on
# DIFFERENT nodes (a "server" pod and a "client" pod). This script does not
# create the cluster or the pods - point it at ones you already have.
#
# WHY IT HAS TO BE A REAL 2-NODE CLUSTER, NOT AN FV CONTAINER: software flow
# offload (the nft "flow offload" statement / nft_flow_offload) speeds up
# forwarding of a flow through the host once the kernel has fast-pathed it -
# i.e. traffic that actually transits a real NIC and gets forwarded between
# interfaces on a node. Two workloads on the same host communicate over a
# pair of veths inside one network namespace hop; there is no NIC-to-NIC
# forwarding decision for the flowtable to shortcut, so a single-node FV
# topology cannot produce a trustworthy offload-vs-no-offload delta. Pods on
# different nodes force the traffic through each node's real host data path,
# which is where offload does its work.
#
# WHAT IT DOES:
#   1. Patches the default FelixConfiguration to disable flowtable offload,
#      waits for Felix to reprogram, then runs an iperf3 client->server test.
#   2. Patches it to enable offload, waits again, then repeats the test.
#   3. Parses sum_received.bits_per_second out of both JSON results and
#      prints the off number, the on number, and the delta.
#
# USAGE:
#   flowtable-bench.sh <server-pod> <client-pod> <server-ip> [duration-seconds]
#
#   server-pod        Name of the pod already running "iperf3 -s" (or that
#                      this script can start it on - see below).
#   client-pod        Name of the pod on the OTHER node that will run the
#                      iperf3 client.
#   server-ip         Pod IP of the server, reachable from the client pod.
#   duration-seconds  Optional. iperf3 test duration in seconds. Default 30.
#
# The server pod must already have iperf3 listening (run
# "kubectl exec <server-pod> -- iperf3 -s -D" beforehand, or start it
# yourself) - this script does not manage the server's lifecycle, only the
# client side of the measurement.
#
# Requires: kubectl (pointed at the target cluster), jq.

set -euo pipefail

exec > >(tee /tmp/flowtable-bench.log) 2>&1

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: $0 <server-pod> <client-pod> <server-ip> [duration-seconds]" >&2
  exit 1
fi

SERVER_POD="$1"
CLIENT_POD="$2"
SERVER_IP="$3"
DURATION="${4:-30}"

REPROGRAM_WAIT_SECS=10

set_offload() {
  local state="$1"
  echo "--- setting nftablesFlowTableOffload=${state} ---"
  kubectl patch felixconfiguration default --type merge \
    -p "{\"spec\":{\"nftablesFlowTableOffload\":\"${state}\"}}"
  echo "--- waiting ${REPROGRAM_WAIT_SECS}s for Felix to reprogram ---"
  sleep "${REPROGRAM_WAIT_SECS}"
}

run_iperf3() {
  local out_file="$1"
  kubectl exec "${CLIENT_POD}" -- iperf3 -c "${SERVER_IP}" -t "${DURATION}" -J \
    | tee "${out_file}"
}

echo "=== offload OFF ==="
set_offload "Disabled"
run_iperf3 /tmp/bench-off.json

echo "=== offload ON ==="
set_offload "Enabled"
run_iperf3 /tmp/bench-on.json

OFF_BPS="$(jq '.end.sum_received.bits_per_second' /tmp/bench-off.json)"
ON_BPS="$(jq '.end.sum_received.bits_per_second' /tmp/bench-on.json)"

if [[ ! "${OFF_BPS}" =~ ^[0-9.eE+-]+$ ]] || [[ "${OFF_BPS}" == "null" ]]; then
  echo "error: could not read a numeric bits_per_second from /tmp/bench-off.json (got '${OFF_BPS}') - check the offload-OFF iperf3 output" >&2
  exit 1
fi

if [[ ! "${ON_BPS}" =~ ^[0-9.eE+-]+$ ]] || [[ "${ON_BPS}" == "null" ]]; then
  echo "error: could not read a numeric bits_per_second from /tmp/bench-on.json (got '${ON_BPS}') - check the offload-ON iperf3 output" >&2
  exit 1
fi

DELTA_BPS="$(jq -n --argjson off "${OFF_BPS}" --argjson on "${ON_BPS}" '$on - $off')"

echo "=== results ==="
echo "off  bits/s: ${OFF_BPS}"
echo "on   bits/s: ${ON_BPS}"
echo "delta bits/s (on - off): ${DELTA_BPS}"
