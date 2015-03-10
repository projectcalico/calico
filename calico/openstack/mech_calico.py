# -*- coding: utf-8 -*-
#
# Copyright (c) 2014, 2015 Metaswitch Networks
# Copyright (c) 2013 OpenStack Foundation
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

# Calico/OpenStack Plugin
#
# This module is the OpenStack-specific implementation of the Plugin component
# of the new Calico architecture (described by the "Felix, the Calico Plugin
# and the Calico ACL Manager" wiki page at
# https://github.com/Metaswitch/calico-docs/wiki).
#
# It is implemented as a Neutron/ML2 mechanism driver.

# OpenStack imports.
from neutron.common import constants
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from neutron import context as ctx
from neutron import manager

# Calico imports.
from calico.openstack.t_zmq import CalicoTransport0MQ

LOG = log.getLogger(__name__)

# An OpenStack agent type name for Felix, the Calico agent component in the new
# architecture.
AGENT_TYPE_FELIX = 'Felix (Calico agent)'


class CalicoMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Neutron/ML2 mechanism driver for Project Calico.

    CalicoMechanismDriver communicates information about endpoints and security
    configuration, over the Endpoint and Network APIs respectively, to the
    other components of the Calico architecture; namely to the Felix instances
    running on each compute host, and to one or more ACL Managers.
    """

    def __init__(self):
        super(CalicoMechanismDriver, self).__init__(
            constants.AGENT_TYPE_DHCP,
            'tap',
            {'port_filter': True})

        # Initialize fields for the database object and context.  We will
        # initialize these properly when we first need them.
        self.db = None

        # Use 0MQ-based transport.
        self.transport = CalicoTransport0MQ(self, LOG)

    def initialize(self):
        self.transport.initialize()

    def _get_db(self):
        if not self.db:
            self.db = manager.NeutronManager.get_plugin()
            LOG.info("db = %s" % self.db)

            # Installer a notifier proxy in order to catch security group
            # changes, if we haven't already.
            if self.db.notifier.__class__ != CalicoNotifierProxy:
                self.db.notifier = CalicoNotifierProxy(self.db.notifier, self)
            else:
                # In case the notifier proxy already exists but the current
                # CalicoMechanismDriver instance has changed, ensure that the
                # notifier proxy will delegate to the current
                # CalicoMechanismDriver instance.
                self.db.notifier.calico_driver = self

    def check_segment_for_agent(self, segment, agent):
        LOG.debug("Checking segment %s with agent %s" % (segment, agent))
        if segment[api.NETWORK_TYPE] in ['local', 'flat']:
            return True
        else:
            return False

    def _port_is_endpoint_port(self, port):
        # Return True if port is a VM port.
        if port['device_owner'].startswith('compute:'):
            return True

        # Otherwise log and return False.
        LOG.debug("Not a VM port: %s" % port)
        return False

    def create_network_postcommit(self, context):
        LOG.info("CREATE_NETWORK_POSTCOMMIT: %s" % context)

    def update_network_postcommit(self, context):
        LOG.info("UPDATE_NETWORK_POSTCOMMIT: %s" % context)

    def delete_network_postcommit(self, context):
        LOG.info("DELETE_NETWORK_POSTCOMMIT: %s" % context)

    def create_subnet_postcommit(self, context):
        LOG.info("CREATE_SUBNET_POSTCOMMIT: %s" % context)

    def update_subnet_postcommit(self, context):
        LOG.info("UPDATE_SUBNET_POSTCOMMIT: %s" % context)

    def delete_subnet_postcommit(self, context):
        LOG.info("DELETE_SUBNET_POSTCOMMIT: %s" % context)

    def add_port_gateways(self, port, context):
        assert self.db
        for ip in port['fixed_ips']:
            subnet = self.db.get_subnet(context, ip['subnet_id'])
            ip['gateway'] = subnet['gateway_ip']

    def add_port_interface_name(self, port):
        port['interface_name'] = 'tap' + port['id'][:11]

    def create_port_postcommit(self, context):
        LOG.info("CREATE_PORT_POSTCOMMIT: %s" % context)
        port = context._port
        if self._port_is_endpoint_port(port):
            LOG.info("Created port: %s" % port)
            self.add_port_gateways(port, context)
            self.add_port_interface_name(port)
            self.transport.endpoint_created(port)
            self._get_db()
            self.db.update_port_status(context._plugin_context,
                                       port['id'],
                                       constants.PORT_STATUS_ACTIVE)

    def update_port_postcommit(self, context):
        LOG.info("UPDATE_PORT_POSTCOMMIT: %s" % context)
        port = context._port
        original = context.original
        if self._port_is_endpoint_port(port):
            LOG.info("Updated port: %s" % port)
            LOG.info("Original: %s" % original)
            if port['binding:vif_type'] == 'unbound':
                # This indicates part 1 of a port being migrated: the port
                # being unbound from its old location.  The old compute host is
                # available from context.original.  We should send an
                # ENDPOINTDESTROYED to the old compute host.
                #
                # Ref: http://lists.openstack.org/pipermail/openstack-dev/
                # 2014-February/027571.html
                LOG.info("Migration part 1")
                self.add_port_gateways(original, context)
                self.transport.endpoint_deleted(original)
            elif original['binding:vif_type'] == 'unbound':
                # This indicates part 2 of a port being migrated: the port
                # being bound to its new location.  We should send an
                # ENDPOINTCREATED to the new compute host.
                #
                # Ref: http://lists.openstack.org/pipermail/openstack-dev/
                # 2014-February/027571.html
                LOG.info("Migration part 2")
                self.add_port_gateways(port, context)
                self.transport.endpoint_created(port)
            elif original['binding:host_id'] != port['binding:host_id']:
                # Migration as implemented in Icehouse.
                LOG.info("Migration as implemented in Icehouse")
                self.add_port_gateways(original, context)
                self.transport.endpoint_deleted(original)
                self.add_port_gateways(port, context)
                self.transport.endpoint_created(port)
            else:
                # This is a non-migration-related update.
                self.add_port_gateways(port, context)
                self.transport.endpoint_updated(port)

    def delete_port_postcommit(self, context):
        LOG.info("DELETE_PORT_POSTCOMMIT: %s" % context)
        port = context._port
        if self._port_is_endpoint_port(port):
            LOG.info("Deleted port: %s" % port)
            self.transport.endpoint_deleted(port)

    def send_sg_updates(self, sgids, db_context):
        for sgid in sgids:
            sg = self.db.get_security_group(db_context, sgid)
            sg['members'] = self._get_members(sg, db_context)
            self.transport.security_group_updated(sg)

    def get_endpoints(self):
        """Return the current set of endpoints.
        """
        # Set up access to the Neutron database, if we haven't already.
        self._get_db()

        # Get a DB context for this query.
        db_context = ctx.get_admin_context()

        # Get current endpoint ports.
        ports = [port for port in self.db.get_ports(db_context)
                 if self._port_is_endpoint_port(port)]

        # Add IP gateways and interface names.
        for port in ports:
            self.add_port_gateways(port, db_context)
            self.add_port_interface_name(port)

        # Return those (augmented) ports.
        return ports

    def get_security_groups(self):
        """Return the current set of security groups.
        """
        # Set up access to the Neutron database, if we haven't already.
        self._get_db()

        # Get a DB context for this query.
        db_context = ctx.get_admin_context()

        # Get current SGs.
        sgs = self.db.get_security_groups(db_context)

        # Add, to each SG, a dict whose keys are the endpoints configured to
        # use that SG, and whose values are the corresponding IP addresses.
        for sg in sgs:
            sg['members'] = self._get_members(sg, db_context)

        # Return those (augmented) security groups.
        return sgs

    def _get_members(self, sg, db_context):
        filters = {'security_group_id': [sg['id']]}
        bindings = self.db._get_port_security_group_bindings(db_context,
                                                             filters)
        endpoints = {}
        for binding in bindings:
            port_id = binding['port_id']
            port = self.db.get_port(db_context, port_id)
            endpoints[port_id] = [ip['ip_address'] for ip in port['fixed_ips']]

        LOG.info("Endpoints for SG %s are %s" % (sg['id'], endpoints))
        return endpoints

    def felix_status(self, hostname, up):
        # Get a DB context for this processing.
        db_context = ctx.get_admin_context()

        if up:
            self.db.create_or_update_agent(db_context,
                                           {'agent_type': AGENT_TYPE_FELIX,
                                            'binary': '',
                                            'host': hostname,
                                            'topic': constants.L2_AGENT_TOPIC})


class CalicoNotifierProxy(object):
    """Proxy pattern class used to intercept security-related notifications
    from the ML2 plugin.
    """

    def __init__(self, ml2_notifier, calico_driver):
        self.ml2_notifier = ml2_notifier
        self.calico_driver = calico_driver

    def __getattr__(self, name):
        return getattr(self.ml2_notifier, name)

    def security_groups_rule_updated(self, context, sgids):
        LOG.info("security_groups_rule_updated: %s %s" % (context, sgids))
        self.calico_driver.send_sg_updates(sgids, context)
        self.ml2_notifier.security_groups_rule_updated(context, sgids)

    def security_groups_member_updated(self, context, sgids):
        LOG.info("security_groups_member_updated: %s %s" % (context, sgids))
        self.calico_driver.send_sg_updates(sgids, context)
        self.ml2_notifier.security_groups_member_updated(context, sgids)
