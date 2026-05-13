#!/bin/bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# galera_repro.sh
# ===============
#
# Reproduction runner for the QoS resync Galera causality bug.
#
# Prerequisite: pxc_setup.sh must have already been run successfully on
# this host (it's called from bootstrap.sh before stack.sh).  This script:
#
#   1. Throttles PXC node 3's CPU (cpulimit) AND injects loopback
#      latency on its wsrep ports (tc/netem), so any read landing on
#      node 3 sees database state ~NETEM_DELAY_MS behind the cluster.
#   2. Runs GaleraQoSResyncTest, which loops a write+verify cycle and
#      asserts on the first iteration where a resync rewrites the WEP
#      without qosControls.
#   3. Cleans up the CPU throttle AND tc qdisc on exit, no matter how
#      the test exits.
#
# Knobs:
#   CALICO_GALERA_ITERATIONS  number of write/verify iterations (default 500)
#   CPU_LIMIT_PCT             percent CPU node 3 is allowed (default 10)
#   NETEM_DELAY_MS            replication-lag injection on node 3 (default 200)
#   DEVSTACK_DIR              devstack root (default /opt/stack/devstack)

set -e

DEVSTACK_DIR=${DEVSTACK_DIR:-/opt/stack/devstack}
ITERATIONS=${CALICO_GALERA_ITERATIONS:-500}
CPU_LIMIT_PCT=${CPU_LIMIT_PCT:-10}
NETEM_DELAY_MS=${NETEM_DELAY_MS:-500}

# Node 3's wsrep base_port and IST port (from pxc_setup.sh).
NODE3_GCOMM_PORT=4767
NODE3_IST_PORT=4768

if ! systemctl is-active --quiet mysql-pxc3; then
    echo "ERROR: mysql-pxc3 is not running.  Run pxc_setup.sh first."
    exit 1
fi

if ! command -v cpulimit >/dev/null 2>&1; then
    sudo apt-get install -y cpulimit
fi

NODE3_PID=$(systemctl show -p MainPID --value mysql-pxc3)
if [ -z "${NODE3_PID}" ] || [ "${NODE3_PID}" = "0" ]; then
    echo "ERROR: could not find MainPID for mysql-pxc3"
    exit 1
fi
echo "Node 3 mysqld PID = ${NODE3_PID}"

# cpulimit throttles by sending SIGSTOP/SIGCONT to the target.  HAProxy's
# basic TCP check stays satisfied because the kernel still accepts the
# connection, but the userspace mysqld apply thread falls behind.
sudo cpulimit -l "${CPU_LIMIT_PCT}" -p "${NODE3_PID}" >/dev/null 2>&1 &
CPULIMIT_PID=$!
echo "cpulimit ${CPULIMIT_PID} throttling node 3 to ${CPU_LIMIT_PCT}% CPU"

# tc/netem: add ${NETEM_DELAY_MS}ms latency to traffic destined for node
# 3's gcomm and IST ports.  Loopback uses a noqueue qdisc by default; we
# replace it with prio so we can filter specific dports onto a netem
# band.  Default traffic stays on band 1 (no delay).
echo "Installing tc/netem ${NETEM_DELAY_MS}ms delay on lo for ports ${NODE3_GCOMM_PORT}/${NODE3_IST_PORT}"
sudo tc qdisc add dev lo root handle 1: prio bands 4 \
    priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
sudo tc qdisc add dev lo parent 1:4 handle 40: \
    netem delay "${NETEM_DELAY_MS}ms"
sudo tc filter add dev lo protocol ip parent 1:0 prio 4 u32 \
    match ip dport ${NODE3_GCOMM_PORT} 0xffff flowid 1:4
sudo tc filter add dev lo protocol ip parent 1:0 prio 4 u32 \
    match ip dport ${NODE3_IST_PORT} 0xffff flowid 1:4

cleanup() {
    echo "Cleaning up: stopping cpulimit, removing tc qdisc, unfreezing node 3"
    sudo kill "${CPULIMIT_PID}" 2>/dev/null || true
    sleep 1
    sudo kill -CONT "${NODE3_PID}" 2>/dev/null || true
    sudo tc qdisc del dev lo root 2>/dev/null || true
}
trap cleanup EXIT

cd "${DEVSTACK_DIR}"
# shellcheck disable=SC1091
source openrc admin admin

export CALICO_GALERA_ITERATIONS="${ITERATIONS}"
export ETCD_HOST=${ETCD_HOST:-${SERVICE_HOST:-127.0.0.1}}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
echo "Running GaleraQoSResyncTest (${ITERATIONS} iterations)..."
python3 "${SCRIPT_DIR}/qos_responsiveness_tests.py" \
    GaleraQoSResyncTest.test_resync_under_galera_churn -v
