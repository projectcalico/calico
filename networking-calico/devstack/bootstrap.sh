#!/bin/bash
# Copyright 2015 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

set -ex

sudo pip uninstall -y setuptools
sudo rm -rf /usr/local/lib/python3.8/dist-packages/setuptools-*.dist-info
sudo find / -name "*setuptools*" || true
sudo pip list || true

#------------------------------------------------------------------------------
# IMPORTANT - Review before use!
#
# This script can be used to bootstrap a single or multi-node Calico/DevStack
# cluster.  Please note that it has not been exhaustively reviewed or tested
# for safety, and is designed for use on a fresh Ubuntu Trusty VM, with no data
# that you would care about losing.  We recommend that you review the following
# code, before running the script.
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# Environment Variables
#
# SERVICE_HOST
#
#     If the SERVICE_HOST environment variable is already set when ./stack.sh
#     is run, and is _different_ from the local machine's hostname, the
#     Calico DevStack plugin will interpret that as a request to set
#     up a compute-only node, that points to $SERVICE_HOST as its controller.
#
#     On the other hand, if SERVICE_HOST is not set, or is the _same_ as the
#     local hostname, the plugin will set up a combined controller and compute
#     node.
#
#     Therefore, to bring up a multi-node Calico/DevStack cluster, set and
#     export SERVICE_HOST in the environment, to the hostname for the chosen
#     controller node in your cluster, before invoking this script.
#
#     For a single node Calico/DevStack cluster, the environment should leave
#     SERVICE_HOST unset.
#
# DEVSTACK_BRANCH
#
#     By default this script uses the master branch of devstack.  To use a
#     different branch, set the DEVSTACK_BRANCH environment variable before
#     running this script; for example:
#
#         export DEVSTACK_BRANCH=stable/liberty
#
# TEMPEST
#
#     By default this script is as minimal as possible, so it doesn't include
#     Tempest or the initial network setup that Tempest expects.  If TEMPEST is
#     set to 'true', Tempest will be installed and the required initial
#     networks created, ready for a Tempest run after the stack setup has
#     completed.
#
# NC_PLUGIN_REPO
#
#     Repository for the Calico devstack plugin.  By default this is
#     https://github.com/projectcalico/calico.
#
# NC_PLUGIN_REF
#
#     Git ref for the Calico devstack plugin.  By default this is master.
#
# ------------------------------------------------------------------------------

# Handle branch name transition from "stable/yoga" to "unmaintained/yoga".  The DevStack repo
# internally still uses "stable/yoga" for all its defaults even though all the actual branch names
# have changed to "unmaintained/yoga".
if [ "${DEVSTACK_BRANCH}" = unmaintained/yoga ]; then
    export CINDER_BRANCH=unmaintained/yoga
    export GLANCE_BRANCH=unmaintained/yoga
    export KEYSTONE_BRANCH=unmaintained/yoga
    export NEUTRON_BRANCH=unmaintained/yoga
    export NOVA_BRANCH=unmaintained/yoga
    export PLACEMENT_BRANCH=unmaintained/yoga
    export REQUIREMENTS_BRANCH=unmaintained/yoga
fi

: ${NC_PLUGIN_REPO:=https://github.com/projectcalico/calico}
: ${NC_PLUGIN_REF:=master}

# Assume that we are starting from the home directory of a non-root
# user that can sudo, and hence is suitable for running DevStack.  For
# example, the 'ubuntu' user on Ubuntu.
cd

# Create a directory for DevStack bootstrap and testing.
mkdir -p devstack-bootstrap
cd devstack-bootstrap

# Ensure that Git is installed.
sudo apt-get update
sudo apt-get -y install git

# Enable IPv4 and IPv6 forwarding.
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Clone the DevStack repository (if not already present).
test -e devstack || \
    git clone -b ${DEVSTACK_BRANCH:-master} ${DEVSTACK_REPO:-https://github.com/openstack/devstack} --depth=1
cd devstack

# Prepare DevStack config.
cat > local.conf <<EOF
[[local|localrc]]
SERVICE_HOST=${SERVICE_HOST:-$HOST_IP}
ADMIN_PASSWORD=015133ea2bdc46ed434c
DATABASE_PASSWORD=d0060b07d3f3631ece78
RABBIT_PASSWORD=6366743536a8216bde26
SERVICE_PASSWORD=91eb72bcafb4ddf246ab
SERVICE_TOKEN=c5680feca5e2c9c8f820

enable_plugin calico $NC_PLUGIN_REPO $NC_PLUGIN_REF
disable_service horizon

LOGFILE=stack.log
LOG_COLOR=False

TEMPEST_BRANCH=29.1.0

# Setting to prevent DevStack from configuring a value of dhcp_client that old Tempest code does not
# support.
SCENARIO_IMAGE_TYPE=ignore

# We clone from GitHub because we commonly used to hit GnuTLS errors when git cloning OpenStack
# repos from opendev.org (which is the default server), for example:
#
# Cloning into 'devstack'...
# remote: Enumerating objects: 28788, done.
# remote: Counting objects: 100% (28788/28788), done.
# remote: Compressing objects: 100% (9847/9847), done.
# error: RPC failed; curl 56 GnuTLS recv error (-9): A TLS packet with unexpected length was received.
GIT_BASE=https://github.com

EOF

if ! ${TEMPEST:-false}; then
    cat >> local.conf <<EOF
disable_service tempest

# Devstack by default creates an initial Neutron network topology for VMs to
# attach to: a private tenant network, an external public network, and a
# Neutron router connecting these; and then VMs are attached to the tenant
# network.  This setup works fine with the Calico driver, and it is the setup
# that - for example - Tempest testing expects.  But for a first demonstration
# of Calico we prefer to use a simpler setup with only a public provider
# network: shared and with a 'local' network_type but no segmentation ID.  So
# for that demonstration we tell Devstack not to create those initial networks,
# and instead create a provider network with the 'neutron net-create' and
# 'neutron subnet-create' invocations below.
NEUTRON_CREATE_INITIAL_NETWORKS=False

EOF
fi

# Create stack user.
sudo tools/create-stack-user.sh
cd ..
sudo mkdir -p /opt/stack
sudo mv devstack /opt/stack
sudo chown -R stack:stack /opt/stack
ls -ld /home/
ls -la /home/
ls -la /home/semaphore/
ls -la /home/semaphore/calico

# Allow the stack user to read /home/semaphore.  In the ubuntu2204 image on Semaphore,
# /home/semaphore permissions are "drwxr-x---", which it means it can't be read by users outside the
# "semaphore" group.
sudo adduser stack semaphore

# Stack!
sudo -u stack -H -E bash -x <<'EOF'
ls -la /home/semaphore/calico
ls -ld /opt/stack
ls -la /opt/stack
cd /opt/stack/devstack
export FORCE=yes
./stack.sh
EOF

# We use a fresh `sudo -u stack -H -E bash ...` invocation here, because with
# OpenStack Yoga it appears there is something in the stack.sh setup that
# closes stdin, and that means that bash doesn't read any further commands from
# stdin after the exit of the ./stack.sh line.
sudo -u stack -H -E bash -x <<'EOF'
cd /opt/stack/devstack
if ! ${TEMPEST:-false}; then
    if [ x${SERVICE_HOST:-$HOSTNAME} = x$HOSTNAME ]; then
        # We're not running Tempest tests, and we're on the controller node.
        # Create a Calico network, for demonstration purposes.
        . openrc admin admin
        neutron net-create --shared --provider:network_type local calico
        neutron subnet-create --gateway 10.65.0.1 --enable-dhcp --ip-version 4 --name calico-v4 calico 10.65.0.0/24
    fi
else
    # Run mainline Tempest tests.
    source ../calico/devstack/devstackgaterc
    cd /opt/stack/tempest
    tox -eall -- $DEVSTACK_GATE_TEMPEST_REGEX --concurrency=$TEMPEST_CONCURRENCY
fi

EOF
