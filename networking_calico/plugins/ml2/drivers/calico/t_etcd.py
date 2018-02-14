# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 Metaswitch Networks
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

import collections
import functools
import json
import netaddr
import socket
import uuid
import weakref

from etcd3gw.exceptions import Etcd3Exception
import eventlet
from eventlet.semaphore import Semaphore

from networking_calico.common import config as calico_config
from networking_calico.compat import cfg
from networking_calico.compat import log
from networking_calico import datamodel_v1
from networking_calico import datamodel_v3
from networking_calico import etcdutils
from networking_calico import etcdv3
from networking_calico.plugins.ml2.drivers.calico.election import Elector


# The node hostname is used as the default identity for leader election
_hostname = socket.gethostname()


# Elector configuration;
elector_opt = cfg.StrOpt(
    'elector_name', default=_hostname,
    help="A unique name to identify this node in leader election"
)

# Register Calico related configuration options
calico_config.register_options(cfg.CONF, additional_options=[elector_opt])


LOG = log.getLogger(__name__)

# Set a low refresh interval on the master key.  This reduces the chance of
# the etcd event buffer wrapping while non-masters are waiting for the key to
# be refreshed.
MASTER_REFRESH_INTERVAL = 10
MASTER_TIMEOUT = 60

# Objects for lightly wrapping etcd return values for use in the mechanism
# driver.
# These namedtuples are getting pretty heavyweight at this point. If you find
# yourself wanting to add more fields to them, consider rewriting them as full
# classes. Note that several of the properties of namedtuples are desirable for
# these objects (immutability being the biggest), so if you rewrite as classes
# attempt to preserve those properties.
Endpoint = collections.namedtuple(
    'Endpoint', ['id', 'key', 'mod_revision', 'host', 'data']
)
Profile = collections.namedtuple(
    'Profile',
    [
        'id',                   # Note: _without_ any OPENSTACK_SG_PREFIX.
        'mod_revision',
        'spec',
    ]
)
Subnet = collections.namedtuple(
    'Subnet', ['id', 'mod_revision', 'data']
)


# The ID of every profile that this driver writes into etcd will be prefixed
# with the following, and this driver only regards itself as the owner of
# profiles that begin with this prefix.  Specifically this means that, when
# resyncing the content of the Neutron DB against etcd, it will not clean up
# (or even touch) profiles whose ID does not begin with this prefix.  This
# means that profiles established by this driver can happily coexist with those
# established by other Calico orchestrators.
OPENSTACK_SG_PREFIX = 'openstack-sg-'


def with_openstack_sg_prefix(openstack_sg_id):
    assert not openstack_sg_id.startswith(OPENSTACK_SG_PREFIX)
    return OPENSTACK_SG_PREFIX + openstack_sg_id


def without_openstack_sg_prefix(etcd_sg_id):
    assert etcd_sg_id.startswith(OPENSTACK_SG_PREFIX)
    return etcd_sg_id[len(OPENSTACK_SG_PREFIX):]


def _logging_etcd_exceptions(fn):
    """_logging_etcd_exceptions

    Decorator for methods of CalicoTransportEtcd only; implements some
    common EtcdException handling.
    """
    @functools.wraps(fn)
    def wrapped(self, *args, **kwargs):
        try:
            return fn(self, *args, **kwargs)
        except Etcd3Exception as e:
            LOG.warning("Etcd3Exception, re-raising: %r", e)
            raise
    return wrapped


class CalicoTransportEtcd(object):
    """Calico transport implementation based on etcd."""

    def __init__(self, driver):
        # Explicitly store the driver as a weakreference. This prevents
        # the reference loop between transport and driver keeping the objects
        # alive.
        self.driver = weakref.proxy(driver)

        # Elector, for performing leader election.
        self.elector = None

        # Lock prevents concurrent re-initialisations which could leave us with
        # inconsistent client and elector.
        self._init_lock = Semaphore()
        self._init_count = 0
        self._initialise()

    def _initialise(self):
        # Optimisation: only run the most recently scheduled _initialise()
        # call. This increment and copy is atomic because there are no yield
        # points.  The lock prevents inconsistency anyway.
        self._init_count += 1
        expected_count = self._init_count

        with self._init_lock:
            if self._init_count != expected_count:
                LOG.info("Skipping duplicate _initialise() call.")
                return
            LOG.info("(Re)initialising the etcd transport.")
            if self.elector:
                LOG.warning("There was already an elector, shutting it down.")
                self.elector.stop()
            self.elector = Elector(
                server_id=cfg.CONF.calico.elector_name,
                election_key=datamodel_v1.NEUTRON_ELECTION_KEY,
                interval=MASTER_REFRESH_INTERVAL,
                ttl=MASTER_TIMEOUT,
            )

    @property
    def is_master(self):
        """Whether this node is currently the Neutron master."""
        return self.elector.master()

    @_logging_etcd_exceptions
    def write_profile_to_etcd(self, profile, mod_revision=None):
        """Convert and write a SecurityProfile to etcdv3."""
        LOG.debug("Writing profile %s", profile)
        name = with_openstack_sg_prefix(profile.id)
        return datamodel_v3.put("Profile",
                                name,
                                profile_spec(profile),
                                mod_revision=mod_revision)

    @_logging_etcd_exceptions
    def subnet_created(self, subnet, mod_revision=None):
        """Write data to etcd to describe a DHCP-enabled subnet."""
        LOG.info("Write subnet %s %s to etcd", subnet['id'], subnet['cidr'])
        data = subnet_etcd_data(subnet)
        return etcdv3.put(datamodel_v1.key_for_subnet(subnet['id']),
                          json.dumps(data),
                          mod_revision=mod_revision)

    @_logging_etcd_exceptions
    def subnet_deleted(self, subnet_id):
        """Delete data from etcd for a subnet that is no longer wanted."""
        LOG.info("Deleting subnet %s", subnet_id)
        # Delete the etcd key for this subnet.
        key = datamodel_v1.key_for_subnet(subnet_id)
        if not etcdv3.delete(key):
            # Already gone, treat as success.
            LOG.debug("Key %s, which we were deleting, disappeared", key)

    @_logging_etcd_exceptions
    def provide_felix_config(self):
        """provide_felix_config

        Specify the prefix of the TAP interfaces that Felix should
        look for and work with.  This config setting does not have a
        default value, because different cloud systems will do
        different things.  Here we provide the prefix that Neutron
        uses.
        """
        LOG.info("Providing Felix configuration")

        rewrite_cluster_info = True
        while rewrite_cluster_info:
            # Get existing global ClusterInformation.  We will add to this,
            # rather than trampling on anything that may already be there, and
            # will also take care to avoid an overlapping write with some other
            # orchestrator.
            try:
                cluster_info, ci_mod_revision = datamodel_v3.get(
                    "ClusterInformation",
                    "default")
            except etcdv3.KeyNotFound:
                cluster_info = {}
                ci_mod_revision = 0
            rewrite_cluster_info = False
            LOG.info("Read ClusterInformation %s mod_revision %r",
                     cluster_info,
                     ci_mod_revision)

            # Generate a cluster GUID if there isn't one already.
            if not cluster_info.get(datamodel_v3.CLUSTER_GUID):
                cluster_info[datamodel_v3.CLUSTER_GUID] = \
                    uuid.uuid4().get_hex()
                rewrite_cluster_info = True

            # Add "openstack" to the cluster type, unless there already.
            cluster_type = cluster_info.get(datamodel_v3.CLUSTER_TYPE, "")
            if cluster_type:
                if "openstack" not in cluster_type:
                    cluster_info[datamodel_v3.CLUSTER_TYPE] = \
                        cluster_type + ",openstack"
                    rewrite_cluster_info = True
            else:
                cluster_info[datamodel_v3.CLUSTER_TYPE] = "openstack"
                rewrite_cluster_info = True

            # Note, we don't touch the Calico version field here, as we don't
            # know it.  (With other orchestrators, it is calico/node's
            # responsibility to set the Calico version.  But we don't run
            # calico/node in Calico for OpenStack.)

            # Set the datastore to ready, if the datastore readiness state
            # isn't already set at all.  This field is intentionally tri-state,
            # i.e. it can be explicitly True, explicitly False, or not set.  If
            # it has been set explicitly to False, that is probably because
            # another orchestrator is doing an upgrade or wants for some other
            # reason to suspend processing of the Calico datastore.
            if datamodel_v3.DATASTORE_READY not in cluster_info:
                cluster_info[datamodel_v3.DATASTORE_READY] = True
                rewrite_cluster_info = True

            # Rewrite ClusterInformation, if we changed anything above.
            if rewrite_cluster_info:
                LOG.info("New ClusterInformation: %s", cluster_info)
                if datamodel_v3.put("ClusterInformation",
                                    "default",
                                    cluster_info,
                                    mod_revision=ci_mod_revision):
                    rewrite_cluster_info = False
                else:
                    # Short sleep to avoid a tight loop.
                    eventlet.sleep(1)

        rewrite_felix_config = True
        while rewrite_felix_config:
            # Get existing global FelixConfiguration.  We will add to this,
            # rather than trampling on anything that may already be there, and
            # will also take care to avoid an overlapping write with some other
            # orchestrator.
            try:
                felix_config, fc_mod_revision = datamodel_v3.get(
                    "FelixConfiguration",
                    "default")
            except etcdv3.KeyNotFound:
                felix_config = {}
                fc_mod_revision = 0
            rewrite_felix_config = False
            LOG.info("Read FelixConfiguration %s mod_revision %r",
                     felix_config,
                     fc_mod_revision)

            # Enable endpoint reporting.
            if not felix_config.get(datamodel_v3.ENDPOINT_REPORTING_ENABLED,
                                    False):
                felix_config[datamodel_v3.ENDPOINT_REPORTING_ENABLED] = True
                rewrite_felix_config = True

            # Ensure that interface prefixes include 'tap'.
            interface_prefix = felix_config.get(datamodel_v3.INTERFACE_PREFIX)
            prefixes = interface_prefix.split(',') if interface_prefix else []
            if 'tap' not in prefixes:
                prefixes.append('tap')
                felix_config[datamodel_v3.INTERFACE_PREFIX] = \
                    ','.join(prefixes)
                rewrite_felix_config = True

            # Rewrite FelixConfiguration, if we changed anything above.
            if rewrite_felix_config:
                LOG.info("New FelixConfiguration: %s", felix_config)
                if datamodel_v3.put("FelixConfiguration",
                                    "default",
                                    felix_config,
                                    mod_revision=fc_mod_revision):
                    rewrite_felix_config = False
                else:
                    # Short sleep to avoid a tight loop.
                    eventlet.sleep(1)

    @_logging_etcd_exceptions
    def get_subnets(self):
        """Get information about every subnet in etcd.

        Returns a generator of ``Subnet`` objects.
        """
        LOG.info("Scanning etcd for all subnets")

        results = etcdv3.get_prefix(datamodel_v1.SUBNET_DIR)
        for result in results:
            key, value, mod_revision = result
            subnet_id = key.split("/")[-1]
            LOG.debug("Found subnet %s", subnet_id)
            yield Subnet(
                id=subnet_id,
                mod_revision=mod_revision,
                data=value,
            )

    @_logging_etcd_exceptions
    def atomic_delete_subnet(self, subnet):
        """Atomically delete a given subnet.

        This method tolerates attempting to delete keys that are already
        missing, otherwise allows exceptions from etcd to bubble up.
        """
        LOG.info(
            "Atomically deleting subnet id %s, modified %s",
            subnet.id,
            subnet.mod_revision
        )

        if not etcdv3.delete(datamodel_v1.key_for_subnet(subnet.id),
                             mod_revision=subnet.mod_revision):
            # Trying to delete stuff that doesn't exist is ok, but log it.
            LOG.info("Subnet %s was already deleted, nothing to do", subnet.id)

    @_logging_etcd_exceptions
    def get_profiles(self):
        """get_profiles

        Gets every OpenStack profile in etcdv3. Returns a generator of
        ``Profile`` objects.
        """
        LOG.info("Scanning etcdv3 for all profiles")

        for result in datamodel_v3.get_all("Profile"):
            name, spec, mod_revision = result
            if name.startswith(OPENSTACK_SG_PREFIX):
                LOG.debug("Found profile %s", name)
                yield Profile(
                    id=without_openstack_sg_prefix(name),
                    mod_revision=mod_revision,
                    spec=spec,
                )

    @_logging_etcd_exceptions
    def atomic_delete_profile(self, profile):
        """atomic_delete_profile

        Atomically delete a profile.
        """
        LOG.info(
            "Deleting profile %s, modified %s",
            profile.id,
            profile.mod_revision,
        )
        name = with_openstack_sg_prefix(profile.id)

        return datamodel_v3.delete("Profile", name)

    def stop(self):
        LOG.info("Stopping transport %s", self)
        self.elector.stop()


class StatusWatcher(etcdutils.EtcdWatcher):
    """A class that watches our status-reporting subtree.

    Status events use the Calico v1 data model, under
    datamodel_v1.FELIX_STATUS_DIR, but are written and read over etcdv3.

    This class parses events within that subtree and passes corresponding
    updates to the mechanism driver.

    Entrypoints:
    - StatusWatcher(calico_driver) (constructor)
    - watcher.start()
    - watcher.stop()

    Callbacks (from the thread of watcher.start()):
    - calico_driver.on_port_status_changed
    - calico_driver.on_felix_alive
    """

    def __init__(self, calico_driver):
        super(StatusWatcher, self).__init__(datamodel_v1.FELIX_STATUS_DIR)
        self.calico_driver = calico_driver

        # Track the set of endpoints that are on each host so we can generate
        # endpoint notifications if a Felix goes down.
        self._endpoints_by_host = collections.defaultdict(set)

        # Track the hosts with a live Felix.
        self._hosts_with_live_felix = set()

        # Register for felix uptime updates.
        self.register_path(datamodel_v1.FELIX_STATUS_DIR +
                           "/<hostname>/status",
                           on_set=self._on_status_set,
                           on_del=self._on_status_del)
        # Register for per-port status updates.
        self.register_path(datamodel_v1.FELIX_STATUS_DIR +
                           "/<hostname>/workload/openstack/"
                           "<workload>/endpoint/<endpoint>",
                           on_set=self._on_ep_set,
                           on_del=self._on_ep_delete)
        LOG.info("StatusWatcher created")

    def _pre_snapshot_hook(self):
        # Save off current endpoint status, then reset current state, so we
        # will be able to identify any changes in the new snapshot.
        old_endpoints_by_host = self._endpoints_by_host
        self._hosts_with_live_felix = set()
        self._endpoints_by_host = collections.defaultdict(set)
        return old_endpoints_by_host

    def _post_snapshot_hook(self, old_endpoints_by_host):
        # Collect hosts for each old endpoint status.  For each of those hosts
        # we will check if we now have a Felix status.
        all_hosts_with_endpoint_status = set()
        for hostname in old_endpoints_by_host.keys():
            all_hosts_with_endpoint_status.add(hostname)

        # There might be new endpoint statuses with new hosts, for which we
        # should also check if we also have Felix status for those hosts.
        for hostname in self._endpoints_by_host.keys():
            all_hosts_with_endpoint_status.add(hostname)

        # For each of those hosts...
        for hostname in all_hosts_with_endpoint_status:
            LOG.info("host: %s", hostname)
            if hostname not in self._hosts_with_live_felix:
                # Status for a Felix has disappeared in the new snapshot.
                # Signal port status None for both the endpoints that we had
                # for that Felix _before_ the snapshot, _and_ those that we
                # have in the new snapshot.
                LOG.info("has disappeared")
                for ep_id in (old_endpoints_by_host[hostname] |
                              self._endpoints_by_host[hostname]):
                    LOG.info("signal None for %s", ep_id.endpoint)
                    self.calico_driver.on_port_status_changed(
                        hostname,
                        ep_id.endpoint,
                        None)
            else:
                # Felix is still there, but we should check for particular
                # endpoints that have disappeared, and signal those.
                LOG.info("is still alive")
                for ep_id in (old_endpoints_by_host[hostname] -
                              self._endpoints_by_host[hostname]):
                    LOG.info("signal None for %s", ep_id.endpoint)
                    self.calico_driver.on_port_status_changed(
                        hostname,
                        ep_id.endpoint,
                        None)

    def _on_status_set(self, response, hostname):
        """Called when a felix uptime report is inserted/updated."""
        try:
            value = json.loads(response.value)
            new = bool(value.get("first_update"))
        except (ValueError, TypeError):
            LOG.warning("Bad JSON data for key %s: %s",
                        response.key, response.value)
        else:
            self._hosts_with_live_felix.add(hostname)
            self.calico_driver.on_felix_alive(
                hostname,
                new=new,
            )

    def _on_status_del(self, response, hostname):
        """Called when Felix's status key expires.  Implies felix is dead."""
        LOG.error("Felix on host %s failed to check in.  Marking the "
                  "ports it was managing as in-error.", hostname)
        self._hosts_with_live_felix.discard(hostname)
        for endpoint_id in self._endpoints_by_host[hostname]:
            # Flag all the ports as being in error.  They're no longer
            # receiving security updates.
            self.calico_driver.on_port_status_changed(
                hostname,
                endpoint_id.endpoint,
                None,
            )
        # Then discard our cache of endpoints.  If felix comes back up, it will
        # repopulate.
        self._endpoints_by_host.pop(hostname)

    def _on_ep_set(self, response, hostname, workload, endpoint):
        """Called when the status key for a particular endpoint is updated.

        Reports the status to the driver and caches the existence of the
        endpoint.
        """
        ep_id = datamodel_v1.get_endpoint_id_from_key(response.key)
        if not ep_id:
            LOG.error("Failed to extract endpoint ID from: %s.  Ignoring "
                      "update!", response.key)
            return
        self._report_status(ep_id, response.value)

    def _report_status(self, endpoint_id, raw_json):
        try:
            status = json.loads(raw_json)
        except (ValueError, TypeError):
            LOG.error("Bad JSON data for %s: %s", endpoint_id, raw_json)
            status = None  # Report as error
            self._endpoints_by_host[endpoint_id.host].discard(endpoint_id)
            if not self._endpoints_by_host[endpoint_id.host]:
                del self._endpoints_by_host[endpoint_id.host]
        else:
            self._endpoints_by_host[endpoint_id.host].add(endpoint_id)
        LOG.debug("Port %s updated to status %s", endpoint_id, status)
        self.calico_driver.on_port_status_changed(
            endpoint_id.host,
            endpoint_id.endpoint,
            status,
        )

    def _on_ep_delete(self, response, hostname, workload, endpoint):
        """Called when the status key for an endpoint is deleted.

        This typically means the endpoint has been deleted.  Reports
        the deletion to the driver.
        """
        LOG.debug("Port %s/%s/%s deleted", hostname, workload, endpoint)
        endpoint_id = datamodel_v1.get_endpoint_id_from_key(response.key)
        self._endpoints_by_host[hostname].discard(endpoint_id)
        if not self._endpoints_by_host[hostname]:
            del self._endpoints_by_host[hostname]
        self.calico_driver.on_port_status_changed(
            hostname,
            endpoint,
            None,
        )


def _neutron_rule_to_etcd_rule(rule):
    """_neutron_rule_to_etcd_rule

    Translate a single Neutron rule dict to a single dict in our
    etcd format.
    """
    ethertype = rule['ethertype']
    etcd_rule = {'action': 'Allow'}
    # Map the ethertype field from Neutron to etcd format.
    etcd_rule['ipVersion'] = {'IPv4': 4,
                              'IPv6': 6}[ethertype]
    # Map the protocol field from Neutron to etcd format.
    if rule['protocol'] is None or rule['protocol'] == -1:
        pass
    elif rule['protocol'] == 'icmp':
        etcd_rule['protocol'] = {'IPv4': 'ICMP',
                                 'IPv6': 'ICMPv6'}[ethertype]
    elif isinstance(rule['protocol'], int):
        etcd_rule['protocol'] = rule['protocol']
    else:
        etcd_rule['protocol'] = rule['protocol'].upper()

    port_spec = None
    if rule['protocol'] == 'icmp':
        # OpenStack stashes the ICMP match criteria in
        # port_range_min/max.
        icmp_fields = {}
        icmp_type = rule['port_range_min']
        if icmp_type is not None and icmp_type != -1:
            icmp_fields['type'] = icmp_type
        icmp_code = rule['port_range_max']
        if icmp_code is not None and icmp_code != -1:
            icmp_fields['code'] = icmp_code
        if icmp_fields:
            etcd_rule['icmp'] = icmp_fields
    else:
        # src/dst_ports is a list in which each entry can be a
        # single number, or a string describing a port range.
        if rule['port_range_min'] == -1:
            port_spec = None
        elif rule['port_range_min'] == rule['port_range_max']:
            if rule['port_range_min'] is not None:
                port_spec = [rule['port_range_min']]
        else:
            port_spec = ['%s:%s' % (rule['port_range_min'],
                                    rule['port_range_max'])]

    entity_rule = {}
    if rule['remote_group_id'] is not None:
        entity_rule['selector'] = 'has(%s)' % rule['remote_group_id']
    if rule['remote_ip_prefix'] is not None:
        entity_rule['nets'] = [rule['remote_ip_prefix']]
    LOG.debug("=> Entity rule %s" % entity_rule)

    # Store in source or destination field of the overall rule.
    if entity_rule:
        if rule['direction'] == 'ingress':
            etcd_rule['source'] = entity_rule
            if port_spec is not None:
                etcd_rule['destination'] = {'ports': port_spec}
        else:
            if port_spec is not None:
                entity_rule['ports'] = port_spec
            etcd_rule['destination'] = entity_rule

    LOG.debug("=> %s Calico rule %s" % (rule['direction'], etcd_rule))

    return etcd_rule


def subnet_etcd_data(subnet):
    data = {'network_id': subnet['network_id'],
            'cidr': str(netaddr.IPNetwork(subnet['cidr'])),
            'host_routes': subnet['host_routes'],
            'gateway_ip': subnet['gateway_ip']}
    if subnet['dns_nameservers']:
        data['dns_servers'] = subnet['dns_nameservers']
    return data


def profile_spec(profile):
    """profile_spec

    Generate JSON ProfileSpec for the given SecurityProfile.
    """
    inbound_rules = [
        _neutron_rule_to_etcd_rule(rule) for rule in profile.inbound_rules
    ]
    outbound_rules = [
        _neutron_rule_to_etcd_rule(rule) for rule in profile.outbound_rules
    ]
    labels_to_apply = {}
    for tag in profile.id.split('_'):
        labels_to_apply[tag] = ''

    return {
        'ingress': inbound_rules,
        'egress': outbound_rules,
        'labelsToApply': labels_to_apply,
    }
