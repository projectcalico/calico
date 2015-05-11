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
import eventlet

from collections import namedtuple

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

# The interval between period resyncs, in seconds.
# TODO: Increase this to a longer interval for product code.
RESYNC_INTERVAL_SECS = 60


# A single security profile.
SecurityProfile = namedtuple(
    'SecurityProfile', ['id', 'inbound_rules', 'outbound_rules']
)


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
        self.transport = CalicoTransportEtcd(self)

        # Start our resynchronization process.
        eventlet.spawn(self.periodic_resync_thread)

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
        LOG.info('CREATE_PORT_POSTCOMMIT: %s', context)
        port = context._port

        # Immediately halt processing if this is not an endpoint port.
        if not self._port_is_endpoint_port(port):
            return

        with context._plugin_context.session.begin(subtransactions=True):
            self._get_db()

            # First, regain the current port. This protects against concurrent
            # writes breaking our state.
            port = self.db.get_port(context._plugin_context, port['id'])

            # Next, fill out other information we need on the port.
            self.add_port_gateways(port, context._plugin_context)
            self.add_port_interface_name(port)

            # Next, we need to work out what security profiles apply to this
            # port and grab information about it.
            profiles = self.get_security_profiles(
                context._plugin_context, port
            )

            # Pass this to the transport layer.
            # Implementation note: we could arguably avoid holding the
            # transaction for this length and instead release it here, then
            # use atomic CAS. The problem there is that we potentially have to
            # repeatedly respin and regain the transaction. Let's not do that
            # for now, and performance test to see if it's a problem later.
            self.transport.endpoint_created(port)

            for profile in profiles:
                self.transport.write_profile_to_etcd(profile)

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
        LOG.info('UPDATE_PORT_POSTCOMMIT: %s', context)
        port = context._port
        original = context.original
        self._get_db()

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
        LOG.info('DELETE_PORT_POSTCOMMIT: %s', context)
        port = context._port

        # Immediately halt processing if this is not an endpoint port.
        if not self._port_is_endpoint_port(port):
            return

        # Pass this to the transport layer.
        self.transport.endpoint_deleted(port)

    def send_sg_updates(self, sgids, context):
        """
        Called whenever security group rules or membership change.

        When a security group rule is added, we need to do the following steps:

        1. Reread the security rules from the Neutron DB.
        2. Write the profile to etcd.
        """
        LOG.info("Updating security group IDs %s", sgids)
        self._get_db()
        with context.session.begin(subtransactions=True):
            rules = self.db.get_security_group_rules(
                context, filters={'security_group_id': sgids}
            )

            # For each profile, build its object and send it down.
            # TODO: Sending this to etcd could legitimately fail because of a
            # CAS problem. Come back to handle retries.
            profiles = (
                profile_from_neutron_rules(sgid, rules) for sgid in sgids
            )

            for profile in profiles:
                self.transport.write_profile_to_etcd(profile)

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
        with context._plugin_context.session.begin(subtransactions=True):
            port = self.db.get_port(context._plugin_context, port['id'])
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
        # TODO: Can we avoid re-writing the security profile here? Put another
        # way, does the security profile change during migration steps, or does
        # a separate port update event occur?
        LOG.info("Migration part 2")
        with context._plugin_context.session.begin(subtransactions=True):
            port = self.db.get_port(context._plugin_context, port['id'])
            self.add_port_gateways(port, context._plugin_context)
            self.add_port_interface_name(port)
            profiles = self.get_security_profiles(
                context._plugin_context, port
            )
            self.transport.endpoint_created(port)

            for profile in profiles:
                self.transport.write_profile_to_etcd(profile)

    def _icehouse_migration_step(self, context, port, original):
        """
        This is called when migrating on Icehouse. Here, we basically just
        perform step one and step two at exactly the same time, but we hold
        a DB lock the entire time.
        """
        # TODO: Can we avoid re-writing the security profile here? Put another
        # way, does the security profile change during migration steps, or does
        # a separate port update event occur?
        LOG.info("Migration as implemented in Icehouse")
        with context._plugin_context.session.begin(subtransactions=True):
            port = self.db.get_port(context._plugin_context, port['id'])
            original = self.db.get_port(
                context._plugin_context, original['id']
            )

            self.transport.endpoint_deleted(original)
            self.add_port_gateways(port, context._plugin_context)
            self.add_port_interface_name(port)
            profiles = self.get_security_profiles(
                context._plugin_context, port
            )
            self.transport.endpoint_created(port)

            for profile in profiles:
                self.transport.write_profile_to_etcd(profile)

    def _update_port(self, context, port):
        """
        Called during port updates that have nothing to do with migration.
        """
        # TODO: There's a lot of redundant code in these methods, with the only
        # key difference being taking out transactions. Come back and shorten
        # these.
        LOG.info("Updating port %s", port)
        with context._plugin_context.session.begin(subtransactions=True):
            port = self.db.get_port(context._plugin_context, port['id'])
            self.add_port_gateways(port, context._plugin_context)
            self.add_port_interface_name(port)
            profiles = self.get_security_profiles(
                context._plugin_context, port
            )
            self.transport.endpoint_created(port)

            for profile in profiles:
                self.transport.write_profile_to_etcd(profile)

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

    def get_security_profiles(self, context, port):
        """
        Obtain information about the security profile that applies to a given
        port.

        This method expects to be called from within a database transaction,
        and does not create its own.

        :returns: A generator of ``SecurityProfile`` objects.
        """
        # For each security group get its rules. Given that we don't need
        # anything else about the security group, we can do this as a single
        # query.
        # CB2: I am concerned that this does not adequately prevent new
        # security group rules being added and racing us in.
        sgids = port['security_groups']
        rules = self.db.get_security_group_rules(
            context, filters={'security_group_id': sgids}
        )

        # Now, return a generator that provides profile objects for each
        # profile.
        return (
            profile_from_neutron_rules(sgid, rules) for sgid in sgids
        )

    def periodic_resync_thread(self):
        """
        This method acts as a the periodic resynchronization logic for the
        Calico mechanism driver.

        On a fixed interval, it spins over the entire database and reconciles
        it with etcd, ensuring that the etcd database and Neutron are in
        synchronization with each other.
        """
        self._get_db()

        while True:
            context = ctx.get_admin_context()

            try:
                # First, resync endpoints.
                self.resync_endpoints(context)

                # Second, profiles.
                self.resync_profiles(context)
            except Exception:
                LOG.exception("Error in periodic resync thread.")

            # Reschedule ourselves.
            eventlet.sleep(RESYNC_INTERVAL_SECS)

    def resync_endpoints(self, context):
        """
        Handles periodic resynchronization for endpoints.
        """
        LOG.info("Resyncing endpoints")

        # Work out all the endpoints in etcd. Do this outside a database
        # transaction to try to ensure that anything that gets created is in
        # our Neutron snapshot.
        endpoints = self.transport.get_endpoints()
        endpoint_ids = set(ep.id for ep in endpoints)

        # Then, grab all the ports from Neutron. Quickly work out whether
        # a given port is missing from etcd, or if etcd has too many ports.
        # Then, add all missing ports and remove all extra ones.
        # This explicit with statement is technically unnecessary, but it helps
        # keep our transaction scope really clear.
        with context.session.begin(subtransactions=True):
            ports = [port for port in self.db.get_ports(context)
                     if self._port_is_endpoint_port(port)]

        port_ids = set(port['id'] for port in ports)
        missing_ports = port_ids - endpoint_ids
        extra_ports = endpoint_ids - port_ids

        if missing_ports or extra_ports:
            LOG.info("Missing ports: %s", missing_ports)
            LOG.info("Extra ports: %s", extra_ports)

        # For each missing port, do a quick port creation. This takes out a
        # db transaction and regains all the ports. Note that this transaction
        # is potentially held for quite a while.
        with context.session.begin(subtransactions=True):
            missing_ports = self.db.get_ports(
                context, filters={'id': missing_ports}
            )

            for port in missing_ports:
                # Fill out other information we need on the port and write to
                # etcd.
                self.add_port_gateways(port, context)
                self.add_port_interface_name(port)
                self.transport.endpoint_created(port)

        # Next, handle the extra ports. Each of them needs to be atomically
        # deleted.
        eps_to_delete = (e for e in endpoints if e.id in extra_ports)

        for endpoint in eps_to_delete:
            try:
                self.transport.atomic_delete_endpoint(endpoint)
            except Exception:
                # TODO: Be more specific.
                # If the atomic CAD doesn't successfully delete, that's ok, it
                # means the endpoint was created or updated elsewhere.
                continue

    def resync_profiles(self, context):
        """
        Resynchronize security profiles.
        """
        LOG.info("Resyncing profiles")
        # Work out all the security groups in etcd. Do this outside a database
        # transaction to try to ensure that anything that gets created is in
        # our Neutron snapshot.
        profiles = self.transport.get_profiles()
        profile_ids = set(profile.id for profile in profiles)

        # Next, grab all the security groups from Neutron. Quickly work out
        # whether a given group is missing from etcd, or if etcd has too many
        # groups. Then, add all missing groups and remove all extra ones.
        # This explicit with statement is technically unnecessary, but it helps
        # keep our transaction scope really clear.
        with context.session.begin(subtransactions=True):
            sgs = self.db.get_security_groups(context)

        sgids = set(sg['id'] for sg in sgs)
        missing_groups = sgids - profile_ids
        extra_groups = profile_ids - sgids

        if missing_groups or extra_groups:
            LOG.info("Missing groups: %s", missing_groups)
            LOG.info("Extra groups: %s", extra_groups)

        # For each missing profile, do a quick profile creation. This takes out
        # a db transaction and regains all the rules. Note that this
        # transaction is potentially held for quite a while.
        with context.session.begin(subtransactions=True):
            rules = self.db.get_security_group_rules(
                context, filters={'security_group_id': missing_groups}
            )

            profiles = (
                profile_from_neutron_rules(sgid, rules)
                for sgid in missing_groups
            )

            for profile in profiles:
                self.transport.write_profile_to_etcd(profile)

        # Next, handle the extra profiles. Each of them needs to be atomically
        # deleted.
        profiles_to_delete = (p for p in profiles if p.id in extra_groups)

        for profile in profiles_to_delete:
            try:
                self.transport.atomic_delete_profile(profile)
            except Exception:
                # TODO: Be more specific.
                # If the atomic CAD doesn't successfully delete, that's ok, it
                # means the profile was created or updated elsewhere.
                continue

    def add_port_interface_name(self, port):
        port['interface_name'] = 'tap' + port['id'][:11]

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


def profile_from_neutron_rules(profile_id, rules):
    """
    Given a set of Neutron rules, build them into a ``SecurityProfile`` object.
    """
    # Split the rules based on direction.
    inbound_rules = []
    outbound_rules = []

    # Only use the rules that have the right profile id.
    sg_rules = (r for r in rules if r['security_group_id'] == profile_id)

    for rule in sg_rules:
        if rule['direction'] == 'ingress':
            inbound_rules.append(rule)
        else:
            outbound_rules.append(rule)

    return SecurityProfile(profile_id, inbound_rules, outbound_rules)
