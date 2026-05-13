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
#   1. Throttles MariaDB Galera node 3's CPU to widen its apply lag,
#      so reads landing on node 3 are more likely to miss a recently
#      certified write from another node.
#   2. Runs GaleraQoSResyncTest, which loops a write+verify cycle and
#      asserts on the first iteration where a resync rewrites the WEP
#      without qosControls.
#   3. Cleans up the CPU throttle on exit, no matter how the test exits.
#
# Knobs:
#   CALICO_GALERA_ITERATIONS  number of write/verify iterations (default 100)
#   CPU_LIMIT_PCT             percent CPU node 3 is allowed (default 10)
#   DEVSTACK_DIR              devstack root (default /opt/stack/devstack)

set -e

DEVSTACK_DIR=${DEVSTACK_DIR:-/opt/stack/devstack}
ITERATIONS=${CALICO_GALERA_ITERATIONS:-100}
CPU_LIMIT_PCT=${CPU_LIMIT_PCT:-10}

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

cleanup() {
    echo "Cleaning up: stopping cpulimit and ensuring node 3 is unfrozen"
    sudo kill "${CPULIMIT_PID}" 2>/dev/null || true
    sleep 1
    sudo kill -CONT "${NODE3_PID}" 2>/dev/null || true
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
