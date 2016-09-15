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
#     networking-calico DevStack plugin will interpret that as a request to set
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
# TEST_GERRIT_CHANGE
#
#     By default this script uses the master branch of networking-calico.  To
#     test a networking-calico change in Gerrit that hasn't yet been merged to
#     master, set the TEST_GERRIT_CHANGE environment variable to indicate that
#     change, before running this script; for example:
#
#         export TEST_GERRIT_CHANGE=219646/1
#
# DEVSTACK_BRANCH
#
#     By default this script uses the master branch of devstack.  To use a
#     different branch, set the DEVSTACK_BRANCH environment variable before
#     running this script; for example:
#
#         export DEVSTACK_BRANCH=stable/liberty
# ------------------------------------------------------------------------------

# Assume that we are starting from the home directory of a non-root
# user that can sudo, and hence is suitable for running DevStack.  For
# example, the 'ubuntu' user on Ubuntu.
cd

# Create a directory for Calico stuff.
mkdir -p calico
cd calico

# Ensure that Git is installed.
sudo apt-get update
sudo apt-get -y install git

# Prepare networking-calico tree - the following lines will check out
# the master branch of networking-calico.
git clone https://git.openstack.org/openstack/networking-calico
cd networking-calico

# If TEST_GERRIT_CHANGE has been specified, merge that change from Gerrit.
if [ -n "$TEST_GERRIT_CHANGE" ]; then
    git fetch https://review.openstack.org/openstack/networking-calico \
	refs/changes/${TEST_GERRIT_CHANGE:4:2}/${TEST_GERRIT_CHANGE}
    git checkout FETCH_HEAD
    git checkout -b devstack-test
    git checkout master
    git config user.name "someone"
    git config user.email "someone@someplace.com"
    git merge --no-edit devstack-test
fi

# Remember the current directory.
ncdir=`pwd`
cd ..

# Enable IPv4 and IPv6 forwarding.
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Clone the DevStack repository.
git clone https://git.openstack.org/openstack-dev/devstack
cd devstack

# If DEVSTACK_BRANCH has been specified, check out that branch.  (Otherwise we
# use DevStack's master branch.)
if [ -n "$DEVSTACK_BRANCH" ]; then
    git checkout ${DEVSTACK_BRANCH}
fi

# Prepare DevStack config.
cat > local.conf <<EOF
[[local|localrc]]
SERVICE_HOST=${SERVICE_HOST:-$HOSTNAME}
ADMIN_PASSWORD=015133ea2bdc46ed434c
DATABASE_PASSWORD=d0060b07d3f3631ece78
RABBIT_PASSWORD=6366743536a8216bde26
SERVICE_PASSWORD=91eb72bcafb4ddf246ab
SERVICE_TOKEN=c5680feca5e2c9c8f820

enable_plugin networking-calico $ncdir

LOGFILE=stack.log
LOG_COLOR=False

EOF

# Stack!
./stack.sh

# If we're on the controller node, create a Calico network.
if [ x${SERVICE_HOST:-$HOSTNAME} = x$HOSTNAME ]; then
    . openrc admin admin
    neutron net-create --shared --provider:network_type local calico
    neutron subnet-create --gateway 10.65.0.1 --enable-dhcp --ip-version 4 --name calico-v4 calico 10.65.0.0/24
fi
