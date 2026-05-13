#!/bin/bash
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# pxc_setup.sh
# ============
#
# Sets up a 3-node Percona XtraDB Cluster (PXC) on the local host before
# DevStack's stack.sh runs.  All three PXC nodes are mysqld processes on
# this same machine, with distinct ports/datadirs/sockets/wsrep base_ports.
# HAProxy fronts them on 127.0.0.1:${HAPROXY_PORT}; DevStack will then be
# configured (in bootstrap.sh) to point MYSQL_HOST / MYSQL_PORT at HAProxy
# so every OpenStack service uses the cluster from day one.
#
# Why PXC (not vanilla MariaDB Galera): this is the exact product the
# customer reporting the 3.30.7 QoS-resync bug is running.  The suspected
# bug is a Galera-protocol-level causality violation surfaced by mech_calico's
# transactionless reads, so the wsrep-API behaviour is what matters --
# but staying on PXC eliminates a "did our test product differ from theirs?"
# variable.
#
# Inputs:
#   DATABASE_PASSWORD    must be exported by the caller; set as the MySQL
#                        root password and matches what DevStack uses.
#   HAPROXY_PORT         port for HAProxy listener (default 3320).
#
# Idempotent: short-circuits if mysql-pxc2 and mysql-pxc3 are already up.

set -ex

HAPROXY_PORT=${HAPROXY_PORT:-3320}
CLUSTER_NAME=${CLUSTER_NAME:-devstack_pxc}
CLUSTER_ADDRESS=${CLUSTER_ADDRESS:-gcomm://127.0.0.1:4567,127.0.0.1:4667,127.0.0.1:4767}

# Short-circuit if cluster is already up.
if systemctl is-active --quiet mysql-pxc2 && systemctl is-active --quiet mysql-pxc3; then
    echo "PXC nodes 2 and 3 already active — nothing to do."
    exit 0
fi

if [ -z "${DATABASE_PASSWORD:-}" ]; then
    echo "ERROR: DATABASE_PASSWORD must be exported by the caller."
    exit 1
fi

# -----------------------------------------------------------------------------
# Install Percona XtraDB Cluster from Percona's apt repo.
# -----------------------------------------------------------------------------

if ! dpkg -s percona-xtradb-cluster >/dev/null 2>&1; then
    # Pre-seed debconf with the root password so apt-get install doesn't prompt.
    sudo debconf-set-selections <<DEBCONF
percona-server-server percona-server-server/root-pass password ${DATABASE_PASSWORD}
percona-server-server percona-server-server/re-root-pass password ${DATABASE_PASSWORD}
DEBCONF

    sudo apt-get install -y curl lsb-release gnupg
    CODENAME=$(lsb_release -sc)
    if ! dpkg -s percona-release >/dev/null 2>&1; then
        curl -fsSL -o /tmp/percona-release.deb \
            "https://repo.percona.com/apt/percona-release_latest.${CODENAME}_all.deb"
        sudo dpkg -i /tmp/percona-release.deb
    fi
    sudo percona-release setup pxc-80
    # PXC 8.0 no longer supports rsync SST -- it forces xtrabackup-v2 -- so
    # we need percona-xtrabackup-80 as well.  That package lives in the
    # separate pxb-80 repo, which `setup pxc-80` does NOT enable (`setup`
    # is selective: it disables all other Percona repos).  Use `enable` to
    # add pxb-80 alongside.
    sudo percona-release enable pxb-80 release
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        percona-xtradb-cluster percona-xtrabackup-80
fi

# Install HAProxy if not already present (separate from PXC packages).
if ! dpkg -s haproxy >/dev/null 2>&1; then
    sudo apt-get install -y haproxy
fi

# PXC autostarts a single-node service on install.  Stop it; we'll bring it
# back up as the cluster primary once wsrep config is in place.
sudo systemctl stop mysql 2>/dev/null || true

# -----------------------------------------------------------------------------
# Node 1: configure as the cluster primary on the standard ports.
# -----------------------------------------------------------------------------

WSREP_PROVIDER=/usr/lib/galera4/libgalera_smm.so
if [ ! -e "${WSREP_PROVIDER}" ]; then
    echo "ERROR: Galera provider not found at ${WSREP_PROVIDER}"
    echo "Available galera libs:"
    sudo find /usr -name 'libgalera*' 2>/dev/null || true
    exit 1
fi

# Drop-in for node 1.  Goes in conf.d so it's loaded by both the
# main mysql.cnf and the PXC-specific include path.
sudo tee /etc/mysql/conf.d/99-pxc-node1.cnf >/dev/null <<EOF
[mysqld]
bind-address = 0.0.0.0

# Galera / wsrep
wsrep_provider = ${WSREP_PROVIDER}
wsrep_cluster_name = ${CLUSTER_NAME}
wsrep_cluster_address = ${CLUSTER_ADDRESS}
wsrep_node_address = 127.0.0.1
wsrep_node_name = pxc1
wsrep_provider_options = "base_port=4567"
wsrep_sst_method = xtrabackup-v2
wsrep_sst_receive_address = 127.0.0.1:4444

# Note: wsrep_sst_auth was removed in PXC 8.0.34 -- SST now uses the
# auto-provisioned mysql.pxc.sst.user system account, so we don't set
# it here.  Setting it would cause an "unknown variable" abort.

# Default wsrep_sync_wait = 0 -- causality NOT enforced.  This is the
# real-world default and the configuration that exposes the bug.
wsrep_sync_wait = 0

# Required by Galera (and what OpenStack expects anyway).
binlog_format = ROW
default_storage_engine = InnoDB
innodb_autoinc_lock_mode = 2

# PXC strict mode -- relaxed so OpenStack services (which sometimes do
# things PXC considers unsafe, like CREATE TABLE without explicit PK)
# can operate.  TODO: confirm customer's value.
pxc_strict_mode = PERMISSIVE

# PXC 8.0 defaults pxc-encrypt-cluster-traffic = ON, which would require
# pre-shared SSL certs across all 3 nodes.  Without that, each mysqld
# auto-generates its own per-node certs that don't match, so SST fails.
# Disabled for this single-host test setup.  The "loose-" prefix means
# an unrecognised option becomes a warning instead of a fatal abort.
loose-pxc-encrypt-cluster-traffic = OFF
EOF

# Bring node 1 up as the cluster primary using PXC's bootstrap unit.
# If the start command itself fails (e.g. mysqld aborts during config
# parsing), dump diagnostics before the script exits via set -e.
if ! sudo systemctl start mysql@bootstrap.service; then
    echo "mysql@bootstrap.service failed to start.  Diagnostic dumps follow:"
    echo "----- /var/log/mysql/error.log (last 200 lines) -----"
    sudo tail -200 /var/log/mysql/error.log 2>&1 || echo "(no error log)"
    echo "----- systemctl status mysql@bootstrap.service -----"
    sudo systemctl status mysql@bootstrap.service --no-pager -l || true
    echo "----- journalctl -u mysql@bootstrap.service (last 100 lines) -----"
    sudo journalctl -u mysql@bootstrap.service -n 100 --no-pager || true
    exit 1
fi

# Wait for node 1 to be Synced.
for i in $(seq 1 30); do
    state=$(sudo mysql --protocol=socket -uroot \
        -e "SHOW STATUS LIKE 'wsrep_local_state_comment'" 2>/dev/null \
        | awk '/wsrep_local_state_comment/ {print $2}' || true)
    if [ "${state}" = "Synced" ]; then
        echo "Node 1 Synced."
        break
    fi
    echo "Waiting for node 1 to reach Synced (currently '${state}'), attempt $i/30"
    sleep 2
done
if [ "${state}" != "Synced" ]; then
    echo "Node 1 failed to sync.  Diagnostic dumps follow:"
    echo "----- /var/log/mysql/error.log (last 200 lines) -----"
    sudo tail -200 /var/log/mysql/error.log 2>&1 || echo "(no error log)"
    echo "----- systemctl status mysql@bootstrap.service -----"
    sudo systemctl status mysql@bootstrap.service --no-pager -l || true
    exit 1
fi

# Set the root password so DevStack (and HAProxy clients) can authenticate.
# PXC 8 with auth_socket on root@localhost lets us issue this without a
# password from a socket connection.
sudo mysql --protocol=socket -uroot <<SQL
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${DATABASE_PASSWORD}';
CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY '${DATABASE_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;
SQL

# -----------------------------------------------------------------------------
# Nodes 2 and 3: fresh PXC instances joining the cluster via SST.
# -----------------------------------------------------------------------------

for N in 2 3; do
    DATADIR=/var/lib/mysql-pxc${N}
    SQL_PORT=$((3305 + N))            # 3307, 3308
    BASE_PORT=$((4467 + N * 100))     # 4667, 4767  -> gcomm; IST = base+1
    SST_PORT=$((4344 + N * 100))      # 4544, 4644
    SOCK=/run/mysqld/mysqld-pxc${N}.sock
    PIDFILE=/run/mysqld/mysqld-pxc${N}.pid
    CONF=/etc/mysql/pxc-node${N}.cnf
    UNIT=mysql-pxc${N}.service

    # Wipe the datadir; SST will populate it from node 1.
    sudo systemctl stop ${UNIT} 2>/dev/null || true
    sudo rm -rf "${DATADIR}"
    sudo mkdir -p "${DATADIR}"
    sudo chown mysql:mysql "${DATADIR}"

    sudo tee "${CONF}" >/dev/null <<EOF
[mysqld]
user = mysql
datadir = ${DATADIR}
socket = ${SOCK}
port = ${SQL_PORT}
pid-file = ${PIDFILE}
bind-address = 0.0.0.0
log-error = /var/log/mysql/pxc${N}.err

wsrep_provider = ${WSREP_PROVIDER}
wsrep_cluster_name = ${CLUSTER_NAME}
wsrep_cluster_address = ${CLUSTER_ADDRESS}
wsrep_node_address = 127.0.0.1
wsrep_node_name = pxc${N}
wsrep_provider_options = "base_port=${BASE_PORT}"
wsrep_sst_method = xtrabackup-v2
wsrep_sst_receive_address = 127.0.0.1:${SST_PORT}
wsrep_sync_wait = 0

binlog_format = ROW
default_storage_engine = InnoDB
innodb_autoinc_lock_mode = 2
pxc_strict_mode = PERMISSIVE
loose-pxc-encrypt-cluster-traffic = OFF
EOF

    sudo tee /etc/systemd/system/${UNIT} >/dev/null <<EOF
[Unit]
Description=Percona XtraDB Cluster node ${N}
After=network.target mysql.service

[Service]
Type=simple
User=mysql
Group=mysql
ExecStart=/usr/sbin/mysqld --defaults-file=${CONF}
TimeoutSec=300
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl start ${UNIT}

    # Wait until the new node finishes its SST and reaches Synced.
    for i in $(seq 1 60); do
        state=$(sudo mysql --protocol=socket -uroot --socket="${SOCK}" \
            -p"${DATABASE_PASSWORD}" \
            -e "SHOW STATUS LIKE 'wsrep_local_state_comment'" 2>/dev/null \
            | awk '/wsrep_local_state_comment/ {print $2}' || true)
        if [ "${state}" = "Synced" ]; then
            echo "Node ${N} Synced."
            break
        fi
        echo "Waiting for node ${N} to reach Synced (currently '${state}'), attempt $i/60"
        sleep 2
    done
    if [ "${state}" != "Synced" ]; then
        echo "Node ${N} failed to sync.  Diagnostic dumps follow:"
        echo "----- /var/log/mysql/pxc${N}.err (last 200 lines) -----"
        sudo tail -200 "/var/log/mysql/pxc${N}.err" 2>&1 || echo "(no error log)"
        echo "----- systemctl status mysql-pxc${N} -----"
        sudo systemctl status "${UNIT}" --no-pager -l || true
        echo "----- journalctl -u mysql-pxc${N} (last 100 lines) -----"
        sudo journalctl -u "${UNIT}" -n 100 --no-pager || true
        exit 1
    fi
done

# Sanity: cluster should now have 3 members.
size=$(sudo mysql --protocol=socket -uroot -p"${DATABASE_PASSWORD}" \
    -e "SHOW STATUS LIKE 'wsrep_cluster_size'" 2>/dev/null \
    | awk '/wsrep_cluster_size/ {print $2}')
echo "wsrep_cluster_size = ${size}"
[ "${size}" = "3" ] || { echo "Expected 3-member cluster"; exit 1; }

# -----------------------------------------------------------------------------
# Switch node 1 from mysql@bootstrap.service to mysql.service.
#
# This is required so DevStack's `restart_service mysql` works -- PXC's
# startup wrapper refuses to start mysql.service while mysql@bootstrap
# is still active.  We do this *after* nodes 2 and 3 are up, so the
# brief node-1 outage during the swap leaves a quorate 2-member cluster
# and node 1 rejoins via IST (very little to catch up on).
# -----------------------------------------------------------------------------

sudo systemctl stop mysql@bootstrap.service
sudo systemctl start mysql.service

for i in $(seq 1 60); do
    state=$(sudo mysql --protocol=socket -uroot -p"${DATABASE_PASSWORD}" \
        -e "SHOW STATUS LIKE 'wsrep_local_state_comment'" 2>/dev/null \
        | awk '/wsrep_local_state_comment/ {print $2}' || true)
    if [ "${state}" = "Synced" ]; then
        echo "Node 1 rejoined as mysql.service, Synced."
        break
    fi
    echo "Waiting for node 1 to rejoin under mysql.service (currently '${state}'), attempt $i/60"
    sleep 2
done
if [ "${state}" != "Synced" ]; then
    echo "Node 1 failed to rejoin under mysql.service.  Diagnostic dumps follow:"
    echo "----- /var/log/mysql/error.log (last 200 lines) -----"
    sudo tail -200 /var/log/mysql/error.log 2>&1 || echo "(no error log)"
    echo "----- systemctl status mysql.service -----"
    sudo systemctl status mysql.service --no-pager -l || true
    exit 1
fi

# -----------------------------------------------------------------------------
# HAProxy in front of the three PXC nodes, listening on 3320.
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

listen pxc
    bind 127.0.0.1:${HAPROXY_PORT}
    mode tcp
    balance roundrobin
    option tcpka
    server pxc1 127.0.0.1:3306 check inter 5000 fall 3 rise 2
    server pxc2 127.0.0.1:3307 check inter 5000 fall 3 rise 2
    server pxc3 127.0.0.1:3308 check inter 5000 fall 3 rise 2

# Stats socket for ad-hoc inspection.
listen stats
    bind 127.0.0.1:3321
    mode http
    stats enable
    stats uri /
    stats refresh 5s
EOF

sudo systemctl restart haproxy

echo "PXC cluster setup complete."
echo "  - 3 PXC nodes on 127.0.0.1:{3306,3307,3308}"
echo "  - HAProxy fronting them on 127.0.0.1:${HAPROXY_PORT}"
echo "  - DevStack should be configured to use MYSQL_HOST=127.0.0.1, MYSQL_PORT=${HAPROXY_PORT}"
