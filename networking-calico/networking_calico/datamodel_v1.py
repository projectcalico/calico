# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
"""
Shared etcd data-model definitions for version 1 of the data model.

The wider Calico data model is now v3.  The legacy v1 definitions here
are private to networking-calico (i.e. the Neutron driver and the
Calico DHCP agent) and Felix's status-reporting code.  However, when
changing these, we still need to consider upgrading an existing
Calico/OpenStack deployment.
"""

# Key used for leader election by Neutron mechanism drivers.
NEUTRON_ELECTION_KEY = "/calico/openstack/v1/neutron_election"

ENDPOINT_STATUS_UP = "up"
ENDPOINT_STATUS_DOWN = "down"
ENDPOINT_STATUS_ERROR = "error"

# Subtree used by the Neutron driver to pass subnet information to the
# DHCP agent.
SUBNET_DIR = "/calico/dhcp/v1/subnet"
