#!/bin/bash -ex
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

# Set defaults if not set
: ${OPENSTACK_REL:=cara}

PYTHON_REQUIREMENTS="-r requirements.txt"
if [[ ${OPENSTACK_REL} =~ "cara" ]]; then
    curl -L https://raw.githubusercontent.com/openstack/requirements/refs/heads/unmaintained/2024.1/upper-constraints.txt > cara_constraints.txt
    sed -i 's,paramiko===2.8.1,paramiko===2.9.0,' cara_constraints.txt
    PYTHON_CONSTRAINTS="-c cara_constraints.txt"
else
    echo "Unsupported OpenStack release ${OPENSTACK_REL}"
    exit 1
fi

# Build the environment
python3 -m venv env
source env/bin/activate
# put 'python -m' on the front of this command to avoid problems with path
# length.  See https://github.com/pypa/pip/issues/1773
python3 -m pip install --upgrade pip
python3 -m pip install wheel ${PYTHON_CONSTRAINTS}
python3 -m pip install ${PYTHON_REQUIREMENTS} ${PYTHON_CONSTRAINTS}

# Apply OpenStack QoS packet-rate-limit patches into the freshly-installed
# venv.  The Caracal-suffixed patch variants align with the "cara" constraints
# we just pulled; only "cara" gets past the release check above.
#
# test_qos.py needs these for `openstack network qos rule create --type
# packet-rate-limit`.  Upstream status, as of November 2026:
#
# - openstacksdk: equivalent support merged as
#   https://review.opendev.org/c/openstack/openstacksdk/+/945202 and first
#   released in openstacksdk 4.5.0 (2025.2 Flamingo).  Once we test against
#   Flamingo or later, the openstacksdk patch can be dropped.
#
# - python-openstackclient: proposed as
#   https://review.opendev.org/c/openstack/python-openstackclient/+/944784,
#   which is still open (Work in Progress, and needs a rebase).  Until that
#   merges and we test against a release that has it, the
#   python-openstackclient patch is still needed.
SITE_PACKAGES=$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
PATCH_DIR=patches
patch -p1 -d "$SITE_PACKAGES" < "$PATCH_DIR/packet_rate_limit_rules__openstacksdk_caracal.patch"
patch -p1 -d "$SITE_PACKAGES" < "$PATCH_DIR/packet_rate_limit_rules__python_openstackclient_caracal.patch"
