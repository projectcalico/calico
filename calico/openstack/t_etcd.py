# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 Metaswitch Networks
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

# Etcd-based transport for the Calico/OpenStack Plugin.

# Standard Python library imports.
import etcd
import eventlet
import json
import re

# OpenStack imports.
from oslo.config import cfg

# Calico imports.
from calico.datamodel_v1 import (READY_KEY, CONFIG_DIR, TAGS_KEY_RE, HOST_DIR,
                                 key_for_endpoint, PROFILE_DIR,
                                 key_for_profile, key_for_profile_rules,
                                 key_for_profile_tags, key_for_config)
from calico.openstack.transport import CalicoTransport

# Register Calico-specific options.
calico_opts = [
    cfg.StrOpt('etcd_host', default='localhost',
               help="The hostname or IP of the etcd node/proxy"),
    cfg.IntOpt('etcd_port', default=4001,
               help="The port to use for the etcd node/proxy"),
]
cfg.CONF.register_opts(calico_opts, 'calico')

LOG = None
OPENSTACK_ENDPOINT_RE = re.compile(
    r'^' + HOST_DIR +
    r'/(?P<hostname>[^/]+)/.*openstack.*/endpoint/(?P<endpoint_id>[^/]+)')

json_decoder = json.JSONDecoder()

PERIODIC_RESYNC_INTERVAL_SECS = 30


class CalicoTransportEtcd(CalicoTransport):
    """Calico transport implementation based on etcd."""

    def __init__(self, driver, logger):
        super(CalicoTransportEtcd, self).__init__(driver)

        # Initialize logger.
        global LOG
        LOG = logger

    def initialize(self):
        # Prepare client for accessing etcd data.
        self.client = etcd.Client(host=cfg.CONF.calico.etcd_host,
                                  port=cfg.CONF.calico.etcd_port)

        # Spawn a green thread for periodically resynchronizing etcd against
        # the OpenStack database.
        eventlet.spawn(self.periodic_resync_thread)

        # We will remember the OpenStack security group data, between resyncs,
        # so that we can generate profiles when needed for new or updated
        # endpoints.  Start off with an empty set.
        self.sgs = {}

        # Also the set of profile IDs that we need for the current endpoints,
        # so that we can generate the profile data if an underlying security
        # group changes.
        self.needed_profiles = set()

        # This event is used exactly once, at start of day, to delay all
        # endpoint creation events behind security group synchronization.
        # Note that this is a temporary work-around for a more severe problem,
        # and should not be considered good architectural practice.
        # This event has no meaningful return value.
        self.start_of_day_lock = eventlet.event.Event()
        self._start_of_day_complete = False

    def periodic_resync_thread(self):
        while True:
            try:
                # Write non-default config that Felices need.
                self.provide_felix_config()

                # Resynchronize endpoint data.
                self.resync_endpoints()

                # Resynchronize security group data.
                self.resync_security_groups()

                # If this is our first pass through start of day processing, we
                # can now unblock anyone waiting.
                if not self._start_of_day_complete:
                    self.start_of_day_lock.send('complete')
                    self._start_of_day_complete = True
                    LOG.info("Start of day processing complete")

            except:
                LOG.exception("Exception in periodic resync thread")

            # Sleep until time for next resync.
            eventlet.sleep(PERIODIC_RESYNC_INTERVAL_SECS)

    def resync_endpoints(self):
        # Get all current endpoints from the OpenStack database and key them on
        # endpoint ID.
        ports = {}
        for port in self.driver.get_endpoints():
            ports[port['id']] = port

        # As we go through the current endpoints, we'll accumulate the set of
        # security profiles that they need.  Start with an empty set here.
        self.needed_profiles = set()

        # Read all etcd keys under /calico/v1/host.
        try:
            children = self.client.read(HOST_DIR, recursive=True).children
        except etcd.EtcdKeyNotFound:
            children = []
        for child in children:
            LOG.debug("etcd key: %s" % child.key)
            m = OPENSTACK_ENDPOINT_RE.match(child.key)
            if m:
                # We have a key/value pair for an OpenStack endpoint.  Extract
                # the endpoint ID and hostname from the key, and read the JSON
                # data as a dict.
                endpoint_id = m.group("endpoint_id")
                hostname = m.group("hostname")
                data = json_decoder.decode(child.value)
                LOG.debug("Existing etcd endpoint data for %s on %s" % (
                    endpoint_id,
                    hostname
                ))
                if (endpoint_id in ports and
                    hostname == ports[endpoint_id]['binding:host_id'] and
                    data == self.port_etcd_data(ports[endpoint_id])):
                    LOG.debug("Existing etcd endpoint data is correct")
                    # OpenStack still has an endpoint that exactly matches this
                    # etcd key/value.  Remember its security profile.
                    self.needed_profiles.add(data['profile_id'])

                    # No change is needed to the etcd data, and we can delete
                    # the port from the ports dict so as not to unnecessarily
                    # write out its (unchanged) value again below.
                    del ports[endpoint_id]

                elif (endpoint_id not in ports or
                      hostname != ports[endpoint_id]['binding:host_id']):
                    LOG.debug("Existing etcd endpoint key is now invalid")
                    # OpenStack no longer has an endpoint with the ID in the
                    # etcd key; or it does, but the endpoint has migrated to a
                    # different host than the one in the etcd key.  In both
                    # cases the etcd key is no longer valid and should be
                    # deleted.  In the migration case, data will be written
                    # below to an etcd key that incorporates the new hostname.
                    try:
                        self.client.delete(child.key)
                    except etcd.EtcdKeyNotFound:
                        LOG.debug("Key %s, which we were deleting, "
                                  "disappeared", child.key)

        # Now write etcd data for any endpoints remaining in the ports dict;
        # these are new endpoints - i.e. never previously represented in etcd
        # data - or endpoints that have migrated or whose data has changed.
        for port in ports.values():
            data = self.port_etcd_data(port)
            self.client.write(self.port_etcd_key(port), json.dumps(data))

            # Remember the security profile that this port needs.
            self.needed_profiles.add(data['profile_id'])

    def port_etcd_key(self, port):
        return key_for_endpoint(port['binding:host_id'],
                                "openstack",
                                port['device_id'],
                                port['id'])

    def port_etcd_data(self, port):
        # Construct the simpler port data.
        data = {'state': 'active' if port['admin_state_up'] else 'inactive',
                'name': port['interface_name'],
                'mac': port['mac_address'],
                'profile_id': self.port_profile_id(port)}

        # Collect IPv6 and IPv6 addresses.  On the way, also set the
        # corresponding gateway fields.  If there is more than one IPv4 or IPv6
        # gateway, the last one (in port['fixed_ips']) wins.
        ipv4_nets = []
        ipv6_nets = []
        for ip in port['fixed_ips']:
            if ':' in ip['ip_address']:
                ipv6_nets.append(ip['ip_address'] + '/128')
                if ip['gateway'] is not None:
                    data['ipv6_gateway'] = ip['gateway']
            else:
                ipv4_nets.append(ip['ip_address'] + '/32')
                if ip['gateway'] is not None:
                    data['ipv4_gateway'] = ip['gateway']
        data['ipv4_nets'] = ipv4_nets
        data['ipv6_nets'] = ipv6_nets

        # Return that data.
        return data

    def port_profile_id(self, port):
        return '_'.join(port['security_groups'])

    def resync_security_groups(self):
        # Get all current security groups from the OpenStack database and key
        # them on security group ID.
        self.sgs = {}
        for sg in self.driver.get_security_groups():
            self.sgs[sg['id']] = sg

        # As we look at the etcd data, accumulate a set of profile IDs that
        # already have correct data.
        correct_profiles = set()

        # Read all etcd keys directly under /calico/v1/policy/profile.
        try:
            children = self.client.read(PROFILE_DIR, recursive=True).children
        except etcd.EtcdKeyNotFound:
            children = []
        for child in children:
            LOG.debug("etcd key: %s" % child.key)
            m = TAGS_KEY_RE.match(child.key)
            if m:
                # If there are no policies, then read returns the top level
                # node, so we need to check that this really is a profile ID.
                profile_id = m.group("profile_id")
                LOG.debug("Existing etcd profile data for %s" % profile_id)
                try:
                    if profile_id in self.needed_profiles:
                        # This is a profile that we want.  Let's read its rules and
                        # tags, and compare those against the current OpenStack data.
                        rules_key = key_for_profile_rules(profile_id)
                        rules = json_decoder.decode(
                            self.client.read(rules_key).value)
                        tags_key = key_for_profile_tags(profile_id)
                        tags = json_decoder.decode(
                            self.client.read(tags_key).value)

                        if (rules == self.profile_rules(profile_id) and
                            tags == self.profile_tags(profile_id)):
                            # The existing etcd data for this profile is completely
                            # correct.  Remember the profile_id so that we don't
                            # unnecessarily write out its (unchanged) data again below.
                            LOG.debug("Existing etcd profile data is correct")
                            correct_profiles.add(profile_id)
                    else:
                        # We don't want this profile any more, so delete the key.
                        LOG.debug("Existing etcd profile key is now invalid")
                        profile_key = key_for_profile(profile_id)
                        self.client.delete(profile_key, recursive=True)
                except etcd.EtcdKeyNotFound:
                    LOG.info("Etcd data appears to have been reset")

        # Now write etcd data for each profile that we need and that we don't
        # already know to be correct.
        for profile_id in self.needed_profiles.difference(correct_profiles):
            self.write_profile_to_etcd(profile_id)

    def write_profile_to_etcd(self, profile_id):
        self.client.write(key_for_profile_rules(profile_id),
                          json.dumps(self.profile_rules(profile_id)))
        self.client.write(key_for_profile_tags(profile_id),
                          json.dumps(self.profile_tags(profile_id)))

    def profile_rules(self, profile_id):
        inbound = []
        outbound = []
        for sgid in self.profile_tags(profile_id):
            # Be tolerant of a security group not being here. Allow up to 5
            # attempts to get it, waiting a few hundred ms in between: we might
            # just be racing slightly ahead of a security group update.
            rules = None
            retries = 5
            while rules is None:
                try:
                    rules = self.sgs[sgid]['security_group_rules']
                except KeyError:
                    LOG.warning("Missing info for SG %s: waiting.", sgid)
                    retries -= 1

                    if not retries:
                        LOG.error("Gave up waiting for SG %s", sgid)
                        raise

                    # Wait for 200ms
                    eventlet.sleep(0.2)


            for rule in rules:
                LOG.info("Neutron rule  %s : %s", profile_id, rule)
                etcd_rule = _neutron_rule_to_etcd_rule(rule)
                if rule['direction'] == 'ingress':
                    inbound.append(etcd_rule)
                else:
                    outbound.append(etcd_rule)

        return {'inbound_rules': inbound, 'outbound_rules': outbound}

    def profile_tags(self, profile_id):
        return profile_id.split('_')

    def endpoint_created(self, port):
        # Endpoint creation events should not be processed until start of day
        # processing is complete. Note that, if start of day processing never
        # completes, we'll wait for a very long time indeed: for this reason,
        # log if we're going to have to wait for start-of-day processing.
        if not self.start_of_day_lock.ready():
            LOG.warning(
                "Endpoint creation blocked behind start of day processing"
            )
            self.start_of_day_lock.wait()

        # Write etcd data for the new endpoint.
        data = self.port_etcd_data(port)
        self.client.write(self.port_etcd_key(port), json.dumps(data))

        # Get and remember the security profile that this port needs.
        profile_id = data['profile_id']
        self.needed_profiles.add(profile_id)

        # Write etcd data for this profile.
        self.write_profile_to_etcd(profile_id)

    def endpoint_updated(self, port):
        # Do the same as for endpoint_created.
        self.endpoint_created(port)

    def endpoint_deleted(self, port):
        # Delete the etcd key for this endpoint.
        key = self.port_etcd_key(port)
        try:
            self.client.delete(key)
        except etcd.EtcdKeyNotFound:
            # Already gone, treat as success.
            LOG.debug("Key %s, which we were deleting, disappeared", key)

    def security_group_updated(self, sg):
        # Update the data that we're keeping for this security group.
        self.sgs[sg['id']] = sg

        # Identify all the needed profiles that incorporate this security
        # group, and rewrite their data.
        for profile_id in self.needed_profiles:
            if sg['id'] in self.profile_tags(profile_id):
                # Write etcd data for this profile.
                self.write_profile_to_etcd(profile_id)

    def provide_felix_config(self):
        """Specify the prefix of the TAP interfaces that Felix should
        look for and work with.  This config setting does not have a
        default value, because different cloud systems will do
        different things.  Here we provide the prefix that Neutron
        uses.
        """
        # First read the config values, so as to avoid unnecessary
        # writes.
        prefix = None
        ready = None
        iface_pfx_key = key_for_config('InterfacePrefix')
        try:
            prefix = self.client.read(iface_pfx_key).value
            ready = self.client.read(READY_KEY).value
        except etcd.EtcdKeyNotFound:
            LOG.info('%s values are missing', CONFIG_DIR)

        # Now write the values that need writing.
        if prefix != 'tap':
            LOG.info('%s -> tap', iface_pfx_key)
            self.client.write(iface_pfx_key, 'tap')
        if ready != 'true':
            # TODO Set this flag only once we're really ready!
            LOG.info('%s -> true', READY_KEY)
            self.client.write(READY_KEY, 'true')

def _neutron_rule_to_etcd_rule(rule):
    """
    Translate a single Neutron rule dict to a single dict in our
    etcd format.
    """
    ethertype = rule['ethertype']
    etcd_rule = {}
    # Map the ethertype field from Neutron to etcd format.
    etcd_rule['ip_version'] = {'IPv4': 4,
                               'IPv6': 6}[ethertype]
    # Map the protocol field from Neutron to etcd format.
    if rule['protocol'] is None or rule['protocol'] == -1:
        pass
    elif rule['protocol'] == 'icmp':
        etcd_rule['protocol'] = {'IPv4': 'icmp',
                                 'IPv6': 'icmpv6'}[ethertype]
    else:
        etcd_rule['protocol'] = rule['protocol']

    # OpenStack (sometimes) represents 'any IP address' by setting
    # both 'remote_group_id' and 'remote_ip_prefix' to None.  We
    # translate that to an explicit 0.0.0.0/0 (for IPv4) or ::/0
    # (for IPv6).
    net = rule['remote_ip_prefix']
    if not (net or rule['remote_group_id']):
        net = {'IPv4': '0.0.0.0/0',
               'IPv6': '::/0'}[ethertype]
    port_spec = None
    if rule['protocol'] == 'icmp':
        # OpenStack stashes the ICMP match criteria in
        # port_range_min/max.
        icmp_type = rule['port_range_min']
        if icmp_type is not None and icmp_type != -1:
            etcd_rule['icmp_type'] = icmp_type
        icmp_code = rule['port_range_max']
        if icmp_code is not None and icmp_code != -1:
            etcd_rule['icmp_code'] = icmp_code
    else:
        # src/dst_ports is a list in which each entry can be a
        # single number, or a string describing a port range.
        if rule['port_range_min'] == -1:
            port_spec = ['1:65535']
        elif rule['port_range_min'] == rule['port_range_max']:
            if rule['port_range_min'] is not None:
                port_spec = [rule['port_range_min']]
        else:
            port_spec = ['%s:%s' % (rule['port_range_min'],
                                    rule['port_range_max'])]

    # Put it all together and add to either the inbound or the
    # outbound list.
    if rule['direction'] == 'ingress':
        if rule['remote_group_id'] is not None:
            etcd_rule['src_tag'] = rule['remote_group_id']
        if net is not None:
            etcd_rule['src_net'] = net
        if port_spec is not None:
            etcd_rule['dst_ports'] = port_spec
        LOG.info("=> Inbound Calico rule %s" % etcd_rule)
    else:
        if rule['remote_group_id'] is not None:
            etcd_rule['dst_tag'] = rule['remote_group_id']
        if net is not None:
            etcd_rule['dst_net'] = net
        if port_spec is not None:
            etcd_rule['dst_ports'] = port_spec
        LOG.info("=> Outbound Calico rule %s" % etcd_rule)

    return etcd_rule
