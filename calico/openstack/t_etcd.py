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
from collections import namedtuple
import functools
import httplib
import json
import re
import socket
import weakref

from socket import timeout as SocketTimeout
from urllib3.exceptions import ReadTimeoutError

# OpenStack imports.
from calico.etcdutils import EtcdWatcher

try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg
from neutron import context as ctx

try:  # Icehouse, Juno
    from neutron.openstack.common import log
except ImportError:  # Kilo
    from oslo_log import log

# Calico imports.
from eventlet.semaphore import Semaphore
import etcd
import urllib3.exceptions
from calico.datamodel_v1 import (READY_KEY, CONFIG_DIR, TAGS_KEY_RE, HOST_DIR,
                                 key_for_endpoint, PROFILE_DIR, RULES_KEY_RE,
                                 key_for_profile, key_for_profile_rules,
                                 key_for_profile_tags, key_for_config,
                                 NEUTRON_ELECTION_KEY, FELIX_STATUS_DIR,
                                 hostname_from_status_key,
                                 hostname_from_uptime_key)
from calico.election import Elector


# The node hostname is used as the default identity for leader election
_hostname = socket.gethostname()

# The amount of time in seconds to wait for etcd responses.
ETCD_TIMEOUT = 5

# Register Calico-specific options.
calico_opts = [
    cfg.StrOpt('etcd_host', default='localhost',
               help="The hostname or IP of the etcd node/proxy"),
    cfg.IntOpt('etcd_port', default=4001,
               help="The port to use for the etcd node/proxy"),
    cfg.StrOpt('elector_name', default=_hostname,
               help="A unique name to identify this node in leader election"),
]
cfg.CONF.register_opts(calico_opts, 'calico')

OPENSTACK_ENDPOINT_RE = re.compile(
    r'^' + HOST_DIR +
    r'/(?P<hostname>[^/]+)/.*openstack.*/endpoint/(?P<endpoint_id>[^/]+)')

LOG = log.getLogger(__name__)


# Objects for lightly wrapping etcd return values for use in the mechanism
# driver.
# These namedtuples are getting pretty heavyweight at this point. If you find
# yourself wanting to add more fields to them, consider rewriting them as full
# classes. Note that several of the properties of namedtuples are desirable for
# these objects (immutability being the biggest), so if you rewrite as classes
# attempt to preserve those properties.
Endpoint = namedtuple(
    'Endpoint', ['id', 'key', 'modified_index', 'host', 'data']
)
Profile = namedtuple(
    'Profile',
    [
        'id',
        'tags_modified_index',
        'rules_modified_index',
        'tags_data',
        'rules_data',
    ]
)


def _handling_etcd_exceptions(fn):
    """
    Decorator for methods of CalicoTransportEtcd only; implements some
    common EtcdException handling.
    """
    @functools.wraps(fn)
    def wrapped(self, *args, **kwargs):
        try:
            return fn(self, *args, **kwargs)
        except (etcd.EtcdException,
                urllib3.exceptions.HTTPError,
                httplib.HTTPException,
                socket.error):
            LOG.exception("Request to etcd failed. This will cause the "
                          "current API call to fail.")
            self._on_etcd_request_failed()
            raise
    return wrapped


class CalicoTransportEtcd(object):
    """Calico transport implementation based on etcd."""

    def __init__(self, driver):
        # Explicitly store the driver as a weakreference. This prevents
        # the reference loop between transport and driver keeping the objects
        # alive.
        self.driver = weakref.proxy(driver)

        # Prepare clients for accessing etcd data.
        self.client = None
        self.status_client = None
        self.next_etcd_index = 0

        # Elector, for performing leader election.
        self.elector = None

        # Lock prevents concurrent re-initialisations which could leave us with
        # inconsistent client and elector.
        self._init_lock = Semaphore()
        self._init_count = 0
        self._initialise()

    def _on_etcd_request_failed(self):
        LOG.warning("Request to etcd failed, reinitialising our connection.")
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
            client = etcd.Client(host=cfg.CONF.calico.etcd_host,
                                 port=cfg.CONF.calico.etcd_port)
            elector = Elector(
                client=client,
                server_id=cfg.CONF.calico.elector_name,
                election_key=NEUTRON_ELECTION_KEY
            )
            # Since normal reading threads don't take the lock, save the
            # client and elector off together atomically.  This is atomic
            # because we're in a green thread.
            self.client = client
            self.elector = elector

    @property
    def is_master(self):
        """
        Whether this node is currently the Neutron master.
        """
        return self.elector.master()

    @_handling_etcd_exceptions
    def write_profile_to_etcd(self,
                              profile,
                              prev_rules_index=None,
                              prev_tags_index=None):
        """
        Write a single security profile into etcd.
        """
        LOG.debug("Writing profile %s", profile)

        # python-etcd is stupid about the prevIndex keyword argument, so we
        # need to explicitly filter out None-y values ourselves.
        rules_kwargs = {}
        if prev_rules_index is not None:
            rules_kwargs['prevIndex'] = prev_rules_index

        tags_kwargs = {}
        if prev_tags_index is not None:
            tags_kwargs['prevIndex'] = prev_tags_index

        self.client.write(
            key_for_profile_rules(profile.id),
            json.dumps(profile_rules(profile)),
            **rules_kwargs
        )

        self.client.write(
            key_for_profile_tags(profile.id),
            json.dumps(profile_tags(profile)),
            **tags_kwargs
        )

    @_handling_etcd_exceptions
    def endpoint_created(self, port):
        """
        Write appropriate data to etcd for an endpoint creation event.
        """
        # Write etcd data for the new endpoint.
        self.write_port_to_etcd(port)

    @_handling_etcd_exceptions
    def endpoint_deleted(self, port):
        """
        Delete data from etcd for an endpoint deleted event.
        """
        LOG.info("Deleting port %s", port)
        # TODO: What do we do about profiles here?
        # Delete the etcd key for this endpoint.
        key = port_etcd_key(port)
        try:
            self.client.delete(key)
        except etcd.EtcdKeyNotFound:
            # Already gone, treat as success.
            LOG.debug("Key %s, which we were deleting, disappeared", key)

        self._cleanup_workload_tree(key)

    @_handling_etcd_exceptions
    def write_port_to_etcd(self, port, prev_index=None):
        """
        Writes a given port dictionary to etcd.
        """
        LOG.info("Write port %s to etcd", port)
        data = port_etcd_data(port)

        # python-etcd doesn't keyword argument properly.
        kwargs = {}
        if prev_index is not None:
            kwargs['prevIndex'] = prev_index

        self.client.write(
            port_etcd_key(port), json.dumps(data), **kwargs
        )

    @_handling_etcd_exceptions
    def provide_felix_config(self):
        """Specify the prefix of the TAP interfaces that Felix should
        look for and work with.  This config setting does not have a
        default value, because different cloud systems will do
        different things.  Here we provide the prefix that Neutron
        uses.
        """
        LOG.info("Providing Felix configuration")

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

    @_handling_etcd_exceptions
    def get_endpoint_data(self, endpoint):
        """
        Get data for an endpoint out of etcd. This should be used on endpoints
        returned from functions like ``get_endpoints``.

        :param endpoint: An ``Endpoint`` class.
        :return: A ``Endpoint`` class with ``data`` not None.
        """
        LOG.debug("Getting endpoint %s", endpoint.id)

        result = self.client.read(endpoint.key, timeout=ETCD_TIMEOUT)

        return Endpoint(
            id=endpoint.id,
            key=endpoint.key,
            modified_index=result.modifiedIndex,
            host=endpoint.host,
            data=result.value,
        )

    @_handling_etcd_exceptions
    def get_endpoints(self):
        """
        Gets information about every endpoint in etcd. Returns a generator of
        ``Endpoint`` objects.
        """
        LOG.info("Scanning etcd for all endpoints")

        try:
            result = self.client.read(
                HOST_DIR, recursive=True, timeout=ETCD_TIMEOUT
            )
        except etcd.EtcdKeyNotFound:
            # No key yet, which is totally fine: just exit.
            LOG.info("No endpoint key present.")
            return

        nodes = result.children

        for node in nodes:
            match = OPENSTACK_ENDPOINT_RE.match(node.key)
            if match is None:
                continue

            endpoint_id = match.group('endpoint_id')
            host = match.group('hostname')

            LOG.debug("Found endpoint %s", endpoint_id)
            yield Endpoint(
                id=endpoint_id,
                key=node.key,
                modified_index=node.modifiedIndex,
                host=host,
                data=None,
            )

    @_handling_etcd_exceptions
    def atomic_delete_endpoint(self, endpoint):
        """
        Atomically delete a given endpoint.

        This method tolerates attempting to delete keys that are already
        missing, otherwise allows exceptions from etcd to bubble up.

        This also attempts to clean up the containing directory, but doesn't
        worry too much if it fails.
        """
        LOG.info(
            "Atomically deleting endpoint id %s, modified %s",
            endpoint.id,
            endpoint.modified_index
        )

        try:
            self.client.delete(
                endpoint.key,
                prevIndex=endpoint.modified_index,
                timeout=ETCD_TIMEOUT,
            )
        except etcd.EtcdKeyNotFound:
            # Trying to delete stuff that doesn't exist is ok, but log it.
            LOG.info(
                "Key %s was already deleted, nothing to do.",
                endpoint.key
            )

        self._cleanup_workload_tree(endpoint.key)

    @_handling_etcd_exceptions
    def get_profile_data(self, profile):
        """
        Get data for a profile out of etcd. This should be used on profiles
        returned from functions like ``get_profiles``.

        :param profile: A ``Profile`` class.
        :return: A ``Profile`` class with tags and rules data present.
        """
        LOG.debug("Getting profile %s", profile.id)

        tags_result = self.client.read(
            key_for_profile_tags(profile.id), timeout=ETCD_TIMEOUT
        )
        rules_result = self.client.read(
            key_for_profile_rules(profile.id), timeout=ETCD_TIMEOUT
        )

        return Profile(
            id=profile.id,
            tags_modified_index=tags_result.modifiedIndex,
            rules_modified_index=rules_result.modifiedIndex,
            tags_data=tags_result.value,
            rules_data=rules_result.value,
        )

    @_handling_etcd_exceptions
    def get_profiles(self):
        """
        Gets information about every profile in etcd. Returns a generator of
        ``Profile`` objects.
        """
        LOG.info("Scanning etcd for all profiles")

        try:
            result = self.client.read(
                PROFILE_DIR, recursive=True, timeout=ETCD_TIMEOUT
            )
        except etcd.EtcdKeyNotFound:
            # No key yet, which is totally fine: just exit.
            LOG.info("No profiles key present")
            return

        nodes = result.children

        tag_indices = {}
        rules_indices = {}

        for node in nodes:
            # All groups have both tags and rules, and we need the
            # modifiedIndex for both.
            tags_match = TAGS_KEY_RE.match(node.key)
            rules_match = RULES_KEY_RE.match(node.key)
            if tags_match:
                profile_id = tags_match.group('profile_id')
                tag_indices[profile_id] = node.modifiedIndex
            elif rules_match:
                profile_id = rules_match.group('profile_id')
                rules_indices[profile_id] = node.modifiedIndex
            else:
                continue

            # Check whether we have a complete set. If we do, remove them and
            # yield.
            if profile_id in tag_indices and profile_id in rules_indices:
                tag_modified = tag_indices.pop(profile_id)
                rules_modified = rules_indices.pop(profile_id)

                LOG.debug("Found profile id %s", profile_id)
                yield Profile(
                    id=profile_id,
                    tags_modified_index=tag_modified,
                    rules_modified_index=rules_modified,
                    tags_data=None,
                    rules_data=None,
                )

        # Quickly confirm that the tag and rule indices are empty (they should
        # be).
        if tag_indices or rules_indices:
            LOG.warning(
                "Imbalanced profile tags and rules! "
                "Extra tags %s, extra rules %s", tag_indices, rules_indices
            )

    @_handling_etcd_exceptions
    def atomic_delete_profile(self, profile):
        """
        Atomically delete a profile. This occurs in two stages: first the tag,
        then the rules. Abort if the first stage fails, as we can assume that
        someone else is trying to replace the profile.

        Tolerates attempting to delete keys that are already deleted.

        This will also attempt to clean up the directory, but isn't overly
        bothered if that fails.
        """
        LOG.info(
            "Deleting profile %s, tags modified %s, rules modified %s",
            profile.id,
            profile.tags_modified_index,
            profile.rules_modified_index
        )

        # Try to delete tags and rules. We don't care if we can't, but we
        # should log in case it's symptomatic of a wider problem.
        try:
            self.client.delete(
                key_for_profile_tags(profile.id),
                prevIndex=profile.tags_modified_index,
                timeout=ETCD_TIMEOUT
            )
        except etcd.EtcdKeyNotFound:
            LOG.info(
                "Profile %s tags already deleted, nothing to do.", profile.id
            )

        try:
            self.client.delete(
                key_for_profile_rules(profile.id),
                prevIndex=profile.rules_modified_index,
                timeout=ETCD_TIMEOUT
            )
        except etcd.EtcdKeyNotFound:
            LOG.info(
                "Profile %s rules already deleted, nothing to do.", profile.id
            )

        # Strip the endpoint specific part of the key.
        profile_key = key_for_profile(profile.id)

        try:
            self.client.delete(profile_key, dir=True, timeout=ETCD_TIMEOUT)
        except etcd.EtcdException as e:
            LOG.debug("Failed to delete %s (%r), giving up.", profile_key, e)

    def _cleanup_workload_tree(self, endpoint_key):
        """
        Attempts to delete any remaining etcd directories after an endpoint has
        been deleted. This needs to recurse up the tree until the workload
        level to ensure that all directories really are pruned.
        """
        key_parts = endpoint_key.split('/')

        # This will return [-1, -2], which means we'll attempt to delete two
        # directories above the endpoint key. That means we'll clean up the
        # workload directory.
        for i in range(-1, -3, -1):
            delete_key = '/'.join(key_parts[:i])
            try:
                self.client.delete(delete_key, dir=True, timeout=ETCD_TIMEOUT)
            except etcd.EtcdException as e:
                LOG.debug("Failed to delete %s (%r), skipping.", delete_key, e)

    def stop(self):
        LOG.info("Stopping transport %s", self)
        self.elector.stop()
    
    
class CalicoEtcdWatcher(EtcdWatcher):
    """
    An EtcdWatcher that watches our status-reporting subtree.

    Responsible for parsing the events and passing the updates to the
    mechanism driver.

    We deliberately do not share an etcd client with the transport.
    The reason is that, if we share a client then managing the lifecycle
    of the client becomes an awkward shared responsibility (complicated
    by the EtcdClusterIdChanged exception, which is only thrown once).
    """
    
    def __init__(self, calico_driver):
        super(CalicoEtcdWatcher, self).__init__(cfg.CONF.calico.etcd_host +
                                                ":" +
                                                cfg.CONF.calico.etcd_port,
                                                FELIX_STATUS_DIR)
        self.calico_driver = calico_driver

        # Register for felix uptime updates.
        self.register_path(FELIX_STATUS_DIR + "/<hostname>/uptime",
                           on_set=self._on_uptime_set)

    def _on_snapshot_loaded(self, etcd_snapshot_response):
        """
        Called whenever a snapshot is loaded from etcd.

        Updates the driver with the current state.
        """
        for etcd_node in etcd_snapshot_response.leaves():
            key = etcd_node.key
            felix_hostname = hostname_from_uptime_key(key)
            if felix_hostname:
                self.calico_driver.on_felix_alive(felix_hostname, new=False)

    def _on_uptime_set(self, response, hostname):
        """
        Called when a felix uptime report is inserted/updated.
        """
        self.calico_driver.on_felix_alive(hostname)


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
        LOG.debug("=> Inbound Calico rule %s" % etcd_rule)
    else:
        if rule['remote_group_id'] is not None:
            etcd_rule['dst_tag'] = rule['remote_group_id']
        if net is not None:
            etcd_rule['dst_net'] = net
        if port_spec is not None:
            etcd_rule['dst_ports'] = port_spec
        LOG.debug("=> Outbound Calico rule %s" % etcd_rule)

    return etcd_rule


def port_etcd_key(port):
    """
    Determine what the etcd key is for a port.
    """
    return key_for_endpoint(port['binding:host_id'],
                            "openstack",
                            port['device_id'],
                            port['id'])


def port_etcd_data(port):
    """
    Build the dictionary of data that will be written into etcd for a port.
    """
    # Construct the simpler port data.
    data = {'state': 'active' if port['admin_state_up'] else 'inactive',
            'name': port['interface_name'],
            'mac': port['mac_address'],
            'profile_ids': port['security_groups']}
            # MD4 TODO Check the old version writes 'profile_id' in a form that
            # translation code in common.validate_endpoint() will work.

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


def profile_tags(profile):
    """
    Get the tags from a given security profile.
    """
    # TODO: This is going to be a no-op now, so consider removing it.
    return profile.id.split('_')


def profile_rules(profile):
    """
    Get a dictionary of profile rules, ready for writing into etcd as JSON.
    """
    inbound_rules = [
        _neutron_rule_to_etcd_rule(rule) for rule in profile.inbound_rules
    ]
    outbound_rules = [
        _neutron_rule_to_etcd_rule(rule) for rule in profile.outbound_rules
    ]

    return {'inbound_rules': inbound_rules, 'outbound_rules': outbound_rules}
