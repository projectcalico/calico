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

    def create_policy(self, context, policy):
        """Create policy invocation.

        This method can be implemented by the specific driver subclass
        to update the backend where necessary with the specific policy
        information.

        :param context: current running context information
        :param policy: a QoSPolicy object being created, which will have no
                      rules.
        """
        LOG.info("create_policy: context=%r policy=%r", context, policy)

    def create_policy_precommit(self, context, policy):
        """Create policy precommit.

        This method can be implemented by the specific driver subclass
        to handle the precommit event of a policy that is being created.

        :param context: current running context information
        :param policy: a QoSPolicy object being created, which will have no
                      rules.
        """
        LOG.info("create_policy_precommit: context=%r policy=%r", context, policy)

    def update_policy(self, context, policy):
        """Update policy invocation.

        This method can be implemented by the specific driver subclass
        to update the backend where necessary.

        :param context: current running context information
        :param policy: a QoSPolicy object being updated.
        """
        LOG.info("update_policy: context=%r policy=%r", context, policy)

    def update_policy_precommit(self, context, policy):
        """Update policy precommit.

        This method can be implemented by the specific driver subclass
        to handle update precommit event of a policy that is being updated.

        :param context: current running context information
        :param policy: a QoSPolicy object being updated.
        """
        LOG.info("update_policy_precommit: context=%r policy=%r", context, policy)

    def delete_policy(self, context, policy):
        """Delete policy invocation.

        This method can be implemented by the specific driver subclass
        to delete the backend policy where necessary.

        :param context: current running context information
        :param policy: a QoSPolicy object being deleted
        """
        LOG.info("delete_policy: context=%r policy=%r", context, policy)

    def delete_policy_precommit(self, context, policy):
        """Delete policy precommit.

        This method can be implemented by the specific driver subclass
        to handle delete precommit event of a policy that is being deleted.

        :param context: current running context information
        :param policy: a QoSPolicy object being deleted
        """
        LOG.info("delete_policy_precommit: context=%r policy=%r", context, policy)


def register():
    """Register the driver."""
    global DRIVER
    if not DRIVER:
        DRIVER = CalicoQoSDriver.create()
    LOG.debug("Calico QoS driver registered")
