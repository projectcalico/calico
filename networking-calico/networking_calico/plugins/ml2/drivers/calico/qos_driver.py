# -*- coding: utf-8 -*-
#
# Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

from neutron_lib import constants
from neutron_lib.api.definitions import portbindings
from neutron_lib.db import constants as db_consts
from neutron_lib.services.qos import base
from neutron_lib.services.qos import constants as qos_consts

from oslo_log import log


LOG = log.getLogger(__name__)

DRIVER = None

SUPPORTED_RULES = {
    qos_consts.RULE_TYPE_BANDWIDTH_LIMIT: {
        qos_consts.MAX_KBPS: {"type:range": [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST: {"type:range": [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.DIRECTION: {"type:values": constants.VALID_DIRECTIONS},
    },
    qos_consts.RULE_TYPE_PACKET_RATE_LIMIT: {
        qos_consts.MAX_KPPS: {"type:range": [0, db_consts.DB_INTEGER_MAX_VALUE]},
        qos_consts.MAX_BURST_KPPS: {"type:range": [0, 0]},
        qos_consts.DIRECTION: {"type:values": constants.VALID_DIRECTIONS},
    },
}


class CalicoQoSDriver(base.DriverBase):

    @staticmethod
    def create():
        return CalicoQoSDriver(
            name="calico",
            vif_types=[portbindings.VIF_TYPE_TAP],
            vnic_types=[portbindings.VNIC_NORMAL],
            supported_rules=SUPPORTED_RULES,
            requires_rpc_notifications=False,
        )

    def update_policy(self, context, policy):
        """Update policy invocation.

        This method can be implemented by the specific driver subclass
        to update the backend where necessary.

        :param context: current running context information
        :param policy: a QoSPolicy object being updated.
        """
        LOG.info("update_policy: context=%r policy=%r", context, policy)

        # Find the set N of Networks with this policy in their qos_policy_id field.

        # Find the set P of Ports with this policy in their qos_policy_id field, or with
        # null qos_policy_id and with a Network in set N.

        # For each Port in set P, do what the syncer would do for that Port.


def register():
    """Register the driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = CalicoQoSDriver.create()
    LOG.debug("Calico QoS driver registered")
