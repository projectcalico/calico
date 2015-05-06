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
# and the Calico ACL Manager" document at
# http://docs.projectcalico.org/en/latest/arch-felix-and-acl.html).
# TODO: Update reference to new etcd architecture document
#
# It is implemented as a Neutron/ML2 mechanism driver.

# OpenStack imports.
from neutron.common import constants
from neutron.common.exceptions import PortNotFound
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from neutron import context as ctx
from neutron import manager

# Calico imports.
from calico.openstack.t_etcd import CalicoTransportEtcd

LOG = log.getLogger(__name__)

# An OpenStack agent type name for Felix, the Calico agent component in the new
# architecture.
AGENT_TYPE_FELIX = 'Felix (Calico agent)'


class CalicoMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Neutron/ML2 mechanism driver for Project Calico.

    CalicoMechanismDriver communicates information about endpoints and security
    configuration, over the Endpoint and Network APIs respectively, to the
    other components of the Calico architecture; namely to the Felix instances
    running on each compute host.
    """

    def __init__(self):
        super(CalicoMechanismDriver, self).__init__(
            constants.AGENT_TYPE_DHCP,
            'tap',
            {'port_filter': True})

        # Initialize fields for the database object and context.  We will
        # initialize these properly when we first need them.
        self.db = None

        # Use Etcd-based transport.
        self.transport = CalicoTransportEtcd(self, LOG)

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

    # For network and subnet actions we have nothing to do, so we provide these
    # no-op methods.
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

    # Idealised method forms.
    def create_port_postcommit(self, context):
        """
        Called after Neutron has committed a port creation event to the
        database.

        Process this event by taking and holding a database transaction and
        re-reading the port. Once we do that, we know the port will remain
        unchanged while we hold the transaction. We can then write the port to
        etcd, along with any other information we may need (security profiles).
        """
        LOG.info('CREATE_PORT_POSTCOMMIT: %s' % context)
        port = context._port

        # Immediately halt processing if this is not an endpoint port.
        if not self._port_is_endpoint_port(port):
            return

        with context.session.begin(subtransactions=True):
            self._get_db()

            # First, regain the current port. This protects against concurrent
            # writes breaking our state.
            port = self.db.get_port(context, port['id'])

            # Next, fill out other information we need on the port.
            self.add_port_gateways(port, context)
            self.add_port_interface_name(port)

            # Next, we need to work out what security profile applies to this
            # port and grab information about it. This is a fairly expensive
            # operation, but we need to do it to guarantee our sanity.
            # TODO: This method doesn't exist yet!
            profile = self.get_security_profile(context, port)

            # Pass this to the transport layer.
            # Implementation note: we could arguably avoid holding the
            # transaction for this length and instead release it here, then
            # use atomic CAS. The problem there is that we potentially have to
            # repeatedly respin and regain the transaction. Let's not do that
            # for now, and performance test to see if it's a problem later.
            self.transport.endpoint_created(port, profile)

            # Update Neutron that we succeeded.
            self.db.update_port_status(context._plugin_context,
                                       port['id'],
                                       constants.PORT_STATUS_ACTIVE)

    def update_port_postcommit(self, context):
        """
        Called after Neutron has committed a port update event to the
        database.

        This is a tricky event, because it can be called in a number of ways
        during VM migration. We farm out to the appropriate method from here.
        """
        LOG.info('UPDATE_PORT_POSTCOMMIT: %s' % context)
        port = context._port
        original = context.original

        # Abort early if we're manging non-endpoint ports.
        if not self._port_is_endpoint_port(port):
            return

        # Fork execution based on the type of update we're performing.
        if port['binding:vif_type'] == 'unbound':
            self._first_migration_step(context, original)
        elif original['binding:vif_type'] == 'unbound':
            self._second_migration_step(context, port)
        elif original['binding:host_id'] != port['binding:host_id']:
            self._icehouse_migration(context, port, original)
        else:
            self._update_port(context, port)

    def delete_port_postcommit(self, context):
        """
        Called after Neutron has committed a port deletion event to the
        database.

        There's no database row for us to lock on here, so don't bother.
        """
        LOG.info('CREATE_PORT_POSTCOMMIT: %s' % context)
        port = context._port

        # Immediately halt processing if this is not an endpoint port.
        if not self._port_is_endpoint_port(port):
            return

        # Pass this to the transport layer.
        self.transport.endpoint_deleted(port)

    def send_sg_updates(self, sgids, context):
        """
        Called whenever security group rules or membership change.

        We handle this change by taking out a database transaction and
        re-reading the database state. We then write that state straight out
        into the transport layer.
        """
        with context.session.begin(subtransactions=True):
            for sgid in sgids:
                sg = self.db.get_security_group(context, sgid)
                sg['members'] = self._get_members(sg, context)
                self.transport.security_group_updated(sg)

    def _first_migration_step(self, context, port):
        """
        This is called during stage one of port migration, when the port is
        unbound from the old location. At this point we treat it as an endpoint
        deletion.

        For more, see:
        http://lists.openstack.org/pipermail/openstack-dev/2014-February/
        027571.html
        """
        LOG.info("Migration part 1")
        with context.session.begin(subtransactions=True):
            port = self.db.get_port(port['id'])
            self.transport.endpoint_deleted(port)

    def _second_migration_step(self, context, port):
        """
        This is called during stage two of port migration, when the port is
        unbound from the old location. At this point we treat it as an endpoint
        creation event.

        For more, see:
        http://lists.openstack.org/pipermail/openstack-dev/2014-February/
        027571.html
        """
        LOG.info("Migration part 2")
        with context.session.begin(subtransactions=True):
            port = self.db.get_port(port['id'])
            self.add_port_gateways(port, context)
            self.add_port_interface_name(port)
            profile = self.get_security_profile(context, port)
            self.transport.endpoint_created(port, profile)

    def _icehouse_migration_step(self, context, port, original):
        """
        This is called when migrating on Icehouse. Here, we basically just
        perform step one and step two at exactly the same time, but we hold
        a DB lock the entire time.
        """
        LOG.info("Migration as implemented in Icehouse")
        with context.session.begin(subtransactions=True):
            port = self.db.get_port(port['id'])
            original = self.db.get_port(original['id'])

            self.transport.endpoint_deleted(original)
            self.add_port_gateways(port, context._plugin_context)
            self.add_port_interface_name(port)
            profile = self.get_security_profile(context, port)
            self.transport.endpoint_created(port, profile)

    def _update_port(self, context, port):
        """
        Called during port updates that have nothing to do with migration.
        """
        # TODO: There's a lot of redundant code in these methods, with the only
        # key difference being taking out transactions. Come back and shorten
        # these.
        with context.session.begin(subtransactions=True):
            port = self.db.get_port(port['id'])
            self.add_port_gateways(port, context)
            self.add_port_interface_name(port)
            profile = profile = self.get_security_profile(context, port)
            self.transport.endpoint_created(port, profile)

    def add_port_gateways(self, port, context):
        """
        Determine the gateway IP addresses for a given port's IP addresses, and
        adds them to the port dict.

        This method assumes it's being called from within a database
        transaction and does not take out another one.
        """
        for ip in port['fixed_ips']:
            subnet = self.db.get_subnet(context, ip['subnet_id'])
            ip['gateway'] = subnet['gateway_ip']

    def add_port_interface_name(self, port):
        port['interface_name'] = 'tap' + port['id'][:11]

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

    def _get_members(self, sg, context):
        """
        Get the endpoint members of the given security group.

        This method will lock a large number of database rows, be warned.
        """
        # TODO: Can we refactor this to do a single database query for the
        # ports? Otherwise, the cost of this method is O(n) in Python code,
        # which is far worse than whatever the SQL database could do.
        filters = {'security_group_id': [sg['id']]}
        bindings = self.db._get_port_security_group_bindings(context,
                                                             filters)
        endpoints = {}
        for binding in bindings:
            port_id = binding['port_id']
            try:
                port = self.db.get_port(context, port_id)
                endpoints[port_id] = [ip['ip_address'] for
                                          ip in port['fixed_ips']]
            except PortNotFound:
                # The port must have been removed after we loaded the bindings.
                LOG.warning("Port %s not found while looking up members of %s",
                            port_id, sg)

        LOG.info("Endpoints for SG %s are %s" % (sg['id'], endpoints))
        return endpoints

    def felix_status(self, hostname, up, start_flag):
        # Get a DB context for this processing.
        db_context = ctx.get_admin_context()

        if up:
            agent_state = {'agent_type': AGENT_TYPE_FELIX,
                           'binary': '',
                           'host': hostname,
                           'topic': constants.L2_AGENT_TOPIC}
            if start_flag:
                agent_state['start_flag'] = True
            self.db.create_or_update_agent(db_context, agent_state)


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
