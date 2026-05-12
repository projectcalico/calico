#!/bin/bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# galera_setup.sh
# ===============
#
# Promotes the single MariaDB instance that DevStack provisioned into a
# 3-node Galera cluster on the same host, fronts it with HAProxy on
# 127.0.0.1:3320, and repoints Neutron's [database]connection at HAProxy.
# All three Galera nodes are MariaDB processes on this same machine, with
# distinct ports, datadirs, sockets, and wsrep base_ports.
#
# Purpose: reproduce the QoS-resync bug a 3.30.7 customer reported, whose
# suspected root cause is causality violations from transactionless reads
# in mech_calico when the Neutron DB is multi-master Galera.
#
# This script is intended to run *after* a successful `./stack.sh`.  It
# leaves every service except Neutron pointed at node 1 directly (port
# 3306), so DevStack's own provisioning isn't disturbed; only Neutron
# reads/writes can land on a different node from a recent write.
#
# Idempotency: re-running this script should be a no-op once Galera is up
# (it short-circuits if mariadb-galera2 is already running).

set -ex

DEVSTACK_DIR=${DEVSTACK_DIR:-/opt/stack/devstack}
NEUTRON_CONF=${NEUTRON_CONF:-/etc/neutron/neutron.conf}
HAPROXY_PORT=${HAPROXY_PORT:-3320}
WSREP_PROVIDER=${WSREP_PROVIDER:-/usr/lib/galera/libgalera_smm.so}
CLUSTER_NAME=${CLUSTER_NAME:-devstack_galera}
CLUSTER_ADDRESS=${CLUSTER_ADDRESS:-gcomm://127.0.0.1:4567,127.0.0.1:4667,127.0.0.1:4767}

# Short-circuit if cluster is already up.
if systemctl is-active --quiet mariadb-galera2 && systemctl is-active --quiet mariadb-galera3; then
    echo "Galera nodes 2 and 3 already active — nothing to do."
    exit 0
fi

# Locate the DATABASE_PASSWORD.  Prefer env, fall back to local.conf.
if [ -z "${DATABASE_PASSWORD:-}" ]; then
    DATABASE_PASSWORD=$(awk -F= '/^DATABASE_PASSWORD=/ {print $2; exit}' \
        "${DEVSTACK_DIR}/local.conf" 2>/dev/null || true)
fi
if [ -z "${DATABASE_PASSWORD:-}" ]; then
    echo "ERROR: DATABASE_PASSWORD not set and not found in ${DEVSTACK_DIR}/local.conf"
    exit 1
fi

# Install Galera library and HAProxy if not already present.
if ! dpkg -s galera-4 >/dev/null 2>&1 || ! dpkg -s haproxy >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y galera-4 haproxy
fi

# -----------------------------------------------------------------------------
# Node 1: convert the existing MariaDB on 3306 into the cluster primary.
# -----------------------------------------------------------------------------

sudo systemctl stop mariadb

sudo tee /etc/mysql/mariadb.conf.d/99-galera.cnf >/dev/null <<EOF
[mysqld]
bind-address = 0.0.0.0
wsrep_on = ON
wsrep_provider = ${WSREP_PROVIDER}
wsrep_cluster_name = ${CLUSTER_NAME}
wsrep_cluster_address = ${CLUSTER_ADDRESS}
wsrep_node_address = 127.0.0.1
wsrep_node_name = galera1
wsrep_provider_options = "base_port=4567"
wsrep_sst_method = rsync
wsrep_sst_receive_address = 127.0.0.1:4444
# Default wsrep_sync_wait = 0 -- causality NOT enforced.  This is the
# real-world default and the configuration that exposes the bug.
wsrep_sync_wait = 0
binlog_format = ROW
default_storage_engine = InnoDB
innodb_autoinc_lock_mode = 2
EOF

# Bring node 1 up as the cluster primary.
sudo galera_new_cluster

# Wait until node 1 is Synced before joining other nodes.
for i in $(seq 1 30); do
    state=$(sudo mysql --protocol=socket -uroot \
        -e "SHOW STATUS LIKE 'wsrep_local_state_comment'" 2>/dev/null \
        | awk '/wsrep_local_state_comment/ {print $2}')
    if [ "${state}" = "Synced" ]; then
        echo "Node 1 Synced."
        break
    fi
    echo "Waiting for node 1 to reach Synced (currently '${state}'), attempt $i/30"
    sleep 2
done
[ "${state}" = "Synced" ] || { echo "Node 1 failed to sync"; exit 1; }

# -----------------------------------------------------------------------------
# Nodes 2 and 3: fresh MariaDB instances joining the cluster via SST.
# -----------------------------------------------------------------------------

for N in 2 3; do
    DATADIR=/var/lib/mysql-galera${N}
    SQL_PORT=$((3305 + N))            # 3307, 3308
    BASE_PORT=$((4467 + N * 100))     # 4667, 4767  -> gcomm; IST = base+1
    SST_PORT=$((4344 + N * 100))      # 4544, 4644
    SOCK=/run/mysqld/mysqld-galera${N}.sock
    PIDFILE=/run/mysqld/mysqld-galera${N}.pid
    CONF=/etc/mysql/galera-node${N}.cnf
    UNIT=mariadb-galera${N}.service

    # Wipe and re-initialise the datadir so the node joins via SST instead
    # of trying to start from stale state.
    sudo systemctl stop ${UNIT} 2>/dev/null || true
    sudo rm -rf "${DATADIR}"
    sudo mkdir -p "${DATADIR}"
    sudo chown mysql:mysql "${DATADIR}"
    sudo mariadb-install-db --user=mysql --datadir="${DATADIR}" >/dev/null

    sudo tee "${CONF}" >/dev/null <<EOF
[mysqld]
user = mysql
datadir = ${DATADIR}
socket = ${SOCK}
port = ${SQL_PORT}
pid-file = ${PIDFILE}
bind-address = 0.0.0.0
log-error = /var/log/mysql/galera${N}.err

wsrep_on = ON
wsrep_provider = ${WSREP_PROVIDER}
wsrep_cluster_name = ${CLUSTER_NAME}
wsrep_cluster_address = ${CLUSTER_ADDRESS}
wsrep_node_address = 127.0.0.1
wsrep_node_name = galera${N}
wsrep_provider_options = "base_port=${BASE_PORT}"
wsrep_sst_method = rsync
wsrep_sst_receive_address = 127.0.0.1:${SST_PORT}
wsrep_sync_wait = 0
binlog_format = ROW
default_storage_engine = InnoDB
innodb_autoinc_lock_mode = 2
EOF

    sudo tee /etc/systemd/system/${UNIT} >/dev/null <<EOF
[Unit]
Description=MariaDB Galera node ${N}
After=network.target mariadb.service

[Service]
Type=simple
User=mysql
Group=mysql
ExecStart=/usr/sbin/mariadbd --defaults-file=${CONF}
TimeoutSec=180
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl start ${UNIT}

    # Wait until the new node finishes its SST and reaches Synced.
    for i in $(seq 1 60); do
        state=$(sudo mysql --protocol=socket -uroot --socket="${SOCK}" \
            -e "SHOW STATUS LIKE 'wsrep_local_state_comment'" 2>/dev/null \
            | awk '/wsrep_local_state_comment/ {print $2}' || true)
        if [ "${state}" = "Synced" ]; then
            echo "Node ${N} Synced."
            break
        fi
        echo "Waiting for node ${N} to reach Synced (currently '${state}'), attempt $i/60"
        sleep 2
    done
    [ "${state}" = "Synced" ] || { echo "Node ${N} failed to sync"; exit 1; }
done

# Sanity: cluster should now have 3 members.
size=$(sudo mysql --protocol=socket -uroot \
    -e "SHOW STATUS LIKE 'wsrep_cluster_size'" \
    | awk '/wsrep_cluster_size/ {print $2}')
echo "wsrep_cluster_size = ${size}"
[ "${size}" = "3" ] || { echo "Expected 3-member cluster"; exit 1; }

# -----------------------------------------------------------------------------
# HAProxy in front of the three Galera nodes, listening on 3320.
# Plain TCP roundrobin -- we intentionally do not use option mysql-check
# because we do NOT want HAProxy to mark a slow-applying node down; the
# whole point is that some reads should land on a node whose apply queue
# hasn't yet caught up.
# -----------------------------------------------------------------------------

sudo tee /etc/haproxy/haproxy.cfg >/dev/null <<EOF
global
    log /dev/log local0
    log /dev/log local1 notice
    user haproxy
    group haproxy
    daemon
    maxconn 4096

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5000ms
    timeout client  50000ms
    timeout server  50000ms

listen galera
    bind 127.0.0.1:${HAPROXY_PORT}
    mode tcp
    balance roundrobin
    option tcpka
    server galera1 127.0.0.1:3306 check inter 5000 fall 3 rise 2
    server galera2 127.0.0.1:3307 check inter 5000 fall 3 rise 2
    server galera3 127.0.0.1:3308 check inter 5000 fall 3 rise 2

# Stats socket for ad-hoc inspection.
listen stats
    bind 127.0.0.1:3321
    mode http
    stats enable
    stats uri /
    stats refresh 5s
EOF

sudo systemctl restart haproxy

# -----------------------------------------------------------------------------
# Repoint Neutron at HAProxy and restart q-svc.
# pool_pre_ping + low pool_recycle force the SQLAlchemy connection pool
# to keep churning connections, so resync's reads can land on a different
# node than the most recent write.
# -----------------------------------------------------------------------------

current=$(sudo crudini --get "${NEUTRON_CONF}" database connection || true)
echo "Existing Neutron DB connection: ${current}"
new="mysql+pymysql://neutron:${DATABASE_PASSWORD}@127.0.0.1:${HAPROXY_PORT}/neutron?charset=utf8"
sudo crudini --set "${NEUTRON_CONF}" database connection "${new}"
sudo crudini --set "${NEUTRON_CONF}" database pool_pre_ping True
sudo crudini --set "${NEUTRON_CONF}" database pool_recycle 1

sudo systemctl restart devstack@q-svc.service

# Wait for Neutron API to come back.
for i in $(seq 1 30); do
    if openstack network list >/dev/null 2>&1; then
        echo "Neutron API responsive on Galera-backed DB."
        break
    fi
    echo "Waiting for Neutron API ($i/30)..."
    sleep 2
done

echo "Galera setup complete."
echo "  - 3 MariaDB Galera nodes on 127.0.0.1:{3306,3307,3308}"
echo "  - HAProxy fronting them on 127.0.0.1:${HAPROXY_PORT}"
echo "  - Neutron repointed at HAProxy; other services still on 3306."
