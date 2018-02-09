# -*- coding: utf-8 -*-
#
# Copyright (c) 2015, 2018 Metaswitch Networks
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
import re
import socket
import uuid
import weakref

import etcd
import eventlet
from eventlet.semaphore import Semaphore

from networking_calico.common import config as calico_config
from networking_calico.compat import cfg
from networking_calico.compat import log
from networking_calico import datamodel_v1
from networking_calico import datamodel_v3
from networking_calico import etcdutils
from networking_calico.monotonic import monotonic_time
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


# The amount of time in seconds to wait for etcd responses.
ETCD_TIMEOUT = 5

OPENSTACK_ENDPOINT_RE = re.compile(
    r'^' + datamodel_v1.HOST_DIR +
    r'/(?P<hostname>[^/]+)/.*openstack.*/endpoint/(?P<endpoint_id>[^/]+)')

LOG = log.getLogger(__name__)

# Set a low refresh interval on the master key.  This reduces the chance of
# the etcd event buffer wrapping while non-masters are waiting for the key to
# be refreshed.
MASTER_REFRESH_INTERVAL = 10
MASTER_TIMEOUT = 60
WATCH_TIMEOUT_SECS = 10

# Objects for lightly wrapping etcd return values for use in the mechanism
# driver.
# These namedtuples are getting pretty heavyweight at this point. If you find
# yourself wanting to add more fields to them, consider rewriting them as full
# classes. Note that several of the properties of namedtuples are desirable for
# these objects (immutability being the biggest), so if you rewrite as classes
# attempt to preserve those properties.
Endpoint = collections.namedtuple(
    'Endpoint', ['id', 'key', 'modified_index', 'host', 'data']
)
Profile = collections.namedtuple(
    'Profile',
    [
        'id',                   # Note: _without_ any OPENSTACK_SG_PREFIX.
        'modified_index',
        'spec',
    ]
)
Subnet = collections.namedtuple(
    'Subnet', ['id', 'modified_index', 'data']
)
Response = collections.namedtuple(
    'Response', ['action', 'key', 'value']
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


def _handling_etcd_exceptions(fn):
    """_handling_etcd_exceptions

    Decorator for methods of CalicoTransportEtcd only; implements some
    common EtcdException handling.
    """
    @functools.wraps(fn)
    def wrapped(self, *args, **kwargs):
        try:
            return fn(self, *args, **kwargs)
        except (etcd.EtcdCompareFailed,
                etcd.EtcdKeyError,
                etcd.EtcdValueError) as e:
            # The caller should be expecting this, re-raise it.
            LOG.warning("Expected etcd error, re-raising: %r", e)
            raise
        except etcd.EtcdException:
            # Other exceptions we can't be sure about, so be defensive and
            # reconnect.
            LOG.exception("Request to etcd failed, refreshing our connection.")
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

        # Prepare client for accessing etcd data.
        self.client = None

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
            calico_cfg = cfg.CONF.calico
            tls_config_params = [
                calico_cfg.etcd_key_file,
                calico_cfg.etcd_cert_file,
                calico_cfg.etcd_ca_cert_file,
            ]
            if any(tls_config_params):
                LOG.info("TLS to etcd is enabled with key file %s; "
                         "cert file %s; CA cert file %s", *tls_config_params)
                # Etcd client expects cert and key as a tuple.
                tls_cert = (calico_cfg.etcd_cert_file,
                            calico_cfg.etcd_key_file)
                tls_ca_cert = calico_cfg.etcd_ca_cert_file
                protocol = "https"
            else:
                LOG.info("TLS disabled, using HTTP to connect to etcd.")
                tls_cert = None
                tls_ca_cert = None
                protocol = "http"
            client = etcd.Client(host=calico_cfg.etcd_host,
                                 port=calico_cfg.etcd_port,
                                 protocol=protocol,
                                 cert=tls_cert,
                                 ca_cert=tls_ca_cert)
            elector = Elector(
                client=client,
                server_id=calico_cfg.elector_name,
                election_key=datamodel_v1.NEUTRON_ELECTION_KEY,
                interval=MASTER_REFRESH_INTERVAL,
                ttl=MASTER_TIMEOUT,
            )
            # Since normal reading threads don't take the lock, save the
            # client and elector off together atomically.  This is atomic
            # because we're in a green thread.
            self.client = client
            self.elector = elector

    @property
    def is_master(self):
        """Whether this node is currently the Neutron master."""
        return self.elector.master()

    @_handling_etcd_exceptions
    def write_profile_to_etcd(self, profile, mod_revision=None):
        """Convert and write a SecurityProfile to etcdv3."""
        LOG.debug("Writing profile %s", profile)
        name = with_openstack_sg_prefix(profile.id)
        datamodel_v3.put("Profile",
                         name,
                         profile_spec(profile),
                         mod_revision=mod_revision)

    @_handling_etcd_exceptions
    def subnet_created(self, subnet, prev_index=None):
        """Write data to etcd to describe a DHCP-enabled subnet."""
        LOG.info("Write subnet %s %s to etcd", subnet['id'], subnet['cidr'])
        data = subnet_etcd_data(subnet)

        # python-etcd doesn't keyword argument properly.
        kwargs = {}
        if prev_index is not None:
            kwargs['prevIndex'] = prev_index

        self.client.write(datamodel_v1.key_for_subnet(subnet['id']),
                          json.dumps(data),
                          **kwargs)

    @_handling_etcd_exceptions
    def subnet_deleted(self, subnet_id):
        """Delete data from etcd for a subnet that is no longer wanted."""
        LOG.info("Deleting subnet %s", subnet_id)
        # Delete the etcd key for this subnet.
        key = datamodel_v1.key_for_subnet(subnet_id)
        try:
            self.client.delete(key)
        except etcd.EtcdKeyNotFound:
            # Already gone, treat as success.
            LOG.debug("Key %s, which we were deleting, disappeared", key)

    @_handling_etcd_exceptions
    def endpoint_created(self, port):
        """Write appropriate data to etcd for an endpoint creation event."""
        # Write etcd data for the new endpoint.
        self.write_port_to_etcd(port)

    @_handling_etcd_exceptions
    def endpoint_deleted(self, port):
        """Delete data from etcd for an endpoint deleted event."""
        LOG.info("Deleting port %s", port)
        # TODO(nj): What do we do about profiles here?
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
        """Writes a given port dictionary to etcd."""
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
                cluster_info, ci_mod_revision = \
                    datamodel_v3.get_with_mod_revision("ClusterInformation",
                                                       "default")
            except etcd.EtcdKeyNotFound:
                cluster_info = {}
                ci_mod_revision = 0
            rewrite_cluster_info = False
            LOG.info("Read ClusterInformation: %s", cluster_info)

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
                felix_config, fc_mod_revision = \
                    datamodel_v3.get_with_mod_revision("FelixConfiguration",
                                                       "default")
            except etcd.EtcdKeyNotFound:
                felix_config = {}
                fc_mod_revision = 0
            rewrite_felix_config = False
            LOG.info("Read FelixConfiguration: %s", felix_config)

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

    @_handling_etcd_exceptions
    def get_subnet_data(self, subnet):
        """Get data for an subnet out of etcd.

        This should be used on subnets returned from functions like
        ``get_subnets``.

        :param subnet: A ``Subnet`` class.
        :return: A ``Subnet`` class with ``data`` not None.
        """
        LOG.debug("Getting subnet %s", subnet.id)

        result = self.client.read(datamodel_v1.key_for_subnet(subnet.id),
                                  timeout=ETCD_TIMEOUT)
        return Subnet(
            id=subnet.id,
            modified_index=result.modifiedIndex,
            data=result.value,
        )

    @_handling_etcd_exceptions
    def get_subnets(self):
        """Get information about every subnet in etcd.

        Returns a generator of ``Subnet`` objects.
        """
        LOG.info("Scanning etcd for all subnets")

        try:
            result = self.client.read(
                datamodel_v1.SUBNET_DIR, recursive=True, timeout=ETCD_TIMEOUT
            )
        except etcd.EtcdKeyNotFound:
            # No key yet, which is totally fine: just exit.
            LOG.info("No subnet key present.")
            return

        nodes = result.children

        for node in nodes:
            subnet_id = node.key.split("/")[-1]
            LOG.debug("Found subnet %s", subnet_id)
            yield Subnet(
                id=subnet_id,
                modified_index=node.modifiedIndex,
                data=None,
            )

    @_handling_etcd_exceptions
    def atomic_delete_subnet(self, subnet):
        """Atomically delete a given subnet.

        This method tolerates attempting to delete keys that are already
        missing, otherwise allows exceptions from etcd to bubble up.
        """
        LOG.info(
            "Atomically deleting subnet id %s, modified %s",
            subnet.id,
            subnet.modified_index
        )

        try:
            self.client.delete(
                datamodel_v1.key_for_subnet(subnet.id),
                prevIndex=subnet.modified_index,
                timeout=ETCD_TIMEOUT,
            )
        except etcd.EtcdKeyNotFound:
            # Trying to delete stuff that doesn't exist is ok, but log it.
            LOG.info(
                "Subnet %s was already deleted, nothing to do.",
                subnet.id
            )

    @_handling_etcd_exceptions
    def get_endpoint_data(self, endpoint):
        """get_endpoint_data

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
        """get_endpoints

        Gets information about every endpoint in etcd. Returns a generator of
        ``Endpoint`` objects.
        """
        LOG.info("Scanning etcd for all endpoints")

        try:
            result = self.client.read(
                datamodel_v1.HOST_DIR, recursive=True, timeout=ETCD_TIMEOUT
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
        """Atomically delete a given endpoint.

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
                    modified_index=mod_revision,
                    spec=spec,
                )

    @_handling_etcd_exceptions
    def atomic_delete_profile(self, profile):
        """atomic_delete_profile

        Atomically delete a profile.
        """
        LOG.info(
            "Deleting profile %s, modified %s",
            profile.id,
            profile.modified_index,
        )
        name = with_openstack_sg_prefix(profile.id)

        datamodel_v3.delete("Profile", name)

    def _cleanup_workload_tree(self, endpoint_key):
        """_cleanup_workload_tree

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


class StatusWatcher(object):
    """A class that watches our status-reporting subtree.

    Status events use the Calico v1 data model, under
    datamodel_v1.FELIX_STATUS_DIR, but are written and read over etcdv3.

    This class parses events within that subtree and passes corresponding
    updates to the mechanism driver.

    Entrypoints:
    - StatusWatcher(calico_driver) (constructor)
    - watcher.loop()
    - watcher.stop()

    Callbacks (from the thread of watcher.loop()):
    - calico_driver.on_port_status_changed
    - calico_driver.on_felix_alive
    """

    def __init__(self, calico_driver):
        LOG.info("StatusWatcher created")
        self.calico_driver = calico_driver
        self.cancel = None
        self.dispatcher = etcdutils.PathDispatcher()

        # Track the set of endpoints that are on each host so we can generate
        # endpoint notifications if a Felix goes down.
        self._endpoints_by_host = collections.defaultdict(set)

        # Track the hosts with a live Felix.
        self._hosts_with_live_felix = set()

        # Register for felix uptime updates.
        self.dispatcher.register(datamodel_v1.FELIX_STATUS_DIR +
                                 "/<hostname>/status",
                                 on_set=self._on_status_set,
                                 on_del=self._on_status_del)
        # Register for per-port status updates.
        self.dispatcher.register(datamodel_v1.FELIX_STATUS_DIR +
                                 "/<hostname>/workload/openstack/"
                                 "<workload>/endpoint/<endpoint>",
                                 on_set=self._on_ep_set,
                                 on_del=self._on_ep_delete)
        self._stopped = False

    def loop(self):
        LOG.info("Start watching status tree")
        self._stopped = False

        while not self._stopped:
            # Get the current etcdv3 revision, so we know when to start
            # watching from.
            last_revision = int(datamodel_v3.get_current_revision())
            LOG.info("Current etcdv3 revision is %d", last_revision)

            # Save off current endpoint status, then reset current state, so we
            # will be able to identify any changes in the new snapshot.
            old_endpoints_by_host = self._endpoints_by_host
            self._hosts_with_live_felix = set()
            self._endpoints_by_host = collections.defaultdict(set)

            # Report any existing values.
            for result in datamodel_v3.get_prefix(
                    datamodel_v1.FELIX_STATUS_DIR):
                key, value = result
                # Convert to what the dispatcher expects - see below.
                response = Response(
                    action='set',
                    key=key,
                    value=value,
                )
                LOG.info("status event: %s", response)
                self.dispatcher.handle_event(response)

            # Collect hosts for each old endpoint status.  For each of those
            # hosts we will check if we now have a Felix status.
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
                    # Signal port status None for both the endpoints that we
                    # had for that Felix _before_ the snapshot, _and_ those
                    # that we have in the new snapshot.
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

            # Now watch for any changes, starting after the revision above.
            while not self._stopped:
                # Start a watch from just after the last known revision.
                try:
                    event_stream, cancel = \
                        datamodel_v3.watch_subtree(
                            datamodel_v1.FELIX_STATUS_DIR,
                            str(last_revision + 1))
                except Exception:
                    # Log and handle by breaking out to the wider loop, which
                    # means we'll get the tree again and then try watching
                    # again.  E.g. it could be that the DB has just been
                    # compacted and so the revision is no longer available that
                    # we asked to start watching from.
                    LOG.exception("Exception watching status tree")
                    break

                # Record time of last activity on the successfully created
                # watch.  (This is updated below as we see watch events.)
                last_event_time = monotonic_time()

                def _cancel_watch_if_inactive():
                    # Loop until we should cancel the watch, either because of
                    # inactivity or because of stop() having been called.
                    while not self._stopped:
                        time_to_next_timeout = (last_event_time +
                                                WATCH_TIMEOUT_SECS -
                                                monotonic_time())
                        LOG.debug("Time to next timeout is %ds",
                                  time_to_next_timeout)
                        if time_to_next_timeout < 1:
                            break
                        else:
                            # Sleep until when we might next have to cancel
                            # (but won't if a watch event has occurred in the
                            # meantime).
                            eventlet.sleep(time_to_next_timeout)

                    # Cancel the watch
                    cancel()
                    return

                # Spawn a greenlet to cancel the watch if it's inactive, or if
                # stop() is called.  Cancelling the watch adds None to the
                # event stream, so the following for loop will see that.
                eventlet.spawn(_cancel_watch_if_inactive)

                for event in event_stream:
                    LOG.debug("status event: %s", event)
                    last_event_time = monotonic_time()

                    # If the StatusWatcher has been stopped, return from the
                    # whole loop.
                    if self._stopped:
                        LOG.info("StatusWatcher has been stopped")
                        return

                    # Otherwise a None event means that the watch has been
                    # cancelled owing to inactivity.  In that case we break out
                    # from this loop, and the watch will be restarted.
                    if event is None:
                        LOG.debug("Watch cancelled owing to inactivity")
                        break

                    # Convert v3 event to form that the dispatcher expects;
                    # namely an object response, with:
                    # - response.key giving the etcd key
                    # - response.action being "set" or "delete"
                    # - whole response being passed on to the handler method.
                    # Handler methods here expect
                    # - response.key
                    # - response.value
                    response = Response(
                        action=event.get('type', 'SET').lower(),
                        key=event['kv']['key'],
                        value=event['kv'].get('value', ''),
                    )
                    LOG.info("status event: %s", response)
                    self.dispatcher.handle_event(response)

                    # Update last known revision.
                    mod_revision = int(event['kv'].get('mod_revision', '0'))
                    if mod_revision > last_revision:
                        last_revision = mod_revision
                        LOG.info("Last known revision is now %d",
                                 last_revision)

    """
    Example status events:

    status event: {u'kv': {
        u'mod_revision': u'4',
        u'value': '{
            "time":"2017-12-31T14:09:29Z",
            "uptime":392.5231995,
            "first_update":true
        }',
        u'create_revision': u'4',
        u'version': u'1',
        u'key': '/calico/felix/v1/host/ubuntu-xenial-rax-dfw-0001640133/status'
    }}

    status event: {u'type': u'DELETE',
                   u'kv': {
        u'mod_revision': u'88',
        u'key': '/calico/felix/v1/host/ubuntu-xenial-rax-dfw-0001640133/' +
                'workload/openstack/' +
                'openstack%2f84a5e464-c2be-4bfd-926b-96030421999d/endpoint/' +
                '84a5e464-c2be-4bfd-926b-96030421999d'
    }}

    status event: {u'kv': {
        u'mod_revision': u'113',
        u'value': '{"status":"down"}',
        u'create_revision': u'113',
        u'version': u'1',
        u'key': '/calico/felix/v1/host/ubuntu-xenial-rax-dfw-0001640133/' +
                'workload/openstack/' +
                'openstack%2f8ae2181b-8aab-4b49-8242-346f6a0b21e5/endpoint/' +
                '8ae2181b-8aab-4b49-8242-346f6a0b21e5'
    }}
    """

    def stop(self):
        LOG.info("Stop watching status tree")
        self._stopped = True

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


def port_etcd_key(port):
    """Determine what the etcd key is for a port."""
    return datamodel_v1.key_for_endpoint(port['binding:host_id'],
                                         "openstack",
                                         port['device_id'],
                                         port['id'])


def port_etcd_data(port):
    """port_etcd_data

    Build the dictionary of data that will be written into etcd for a port.
    """

    # Construct the simpler port data.
    data = {'state': 'active' if port['admin_state_up'] else 'inactive',
            'name': port['interface_name'],
            'mac': port['mac_address'],
            'profile_ids': [with_openstack_sg_prefix(sg_id)
                            for sg_id in port['security_groups']]}
    # TODO(MD4) Check the old version writes 'profile_id' in a form
    # that translation code in common.validate_endpoint() will work.

    # Collect IPv4 and IPv6 addresses and subnet IDs.  On the way, also set the
    # corresponding gateway fields.  If there is more than one IPv4 or IPv6
    # gateway, the last one (in port['fixed_ips']) wins.
    ipv4_nets = []
    ipv6_nets = []
    ipv4_subnet_ids = []
    ipv6_subnet_ids = []
    for ip in port['fixed_ips']:
        if ':' in ip['ip_address']:
            ipv6_nets.append(ip['ip_address'] + '/128')
            ipv6_subnet_ids.append(ip['subnet_id'])
            if ip['gateway'] is not None:
                data['ipv6_gateway'] = ip['gateway']
        else:
            ipv4_nets.append(ip['ip_address'] + '/32')
            ipv4_subnet_ids.append(ip['subnet_id'])
            if ip['gateway'] is not None:
                data['ipv4_gateway'] = ip['gateway']
    data['ipv4_nets'] = ipv4_nets
    data['ipv6_nets'] = ipv6_nets
    data['ipv4_subnet_ids'] = ipv4_subnet_ids
    data['ipv6_subnet_ids'] = ipv6_subnet_ids

    # Propagate the port's FQDN.
    dns_assignment = port.get('dns_assignment')
    if dns_assignment:
        # Note: the Neutron server generates a list of assignment entries, one
        # for each fixed IP, but all with the same FQDN, for slightly
        # historical reasons.  We're fine getting the FQDN from the first
        # entry.
        data['fqdn'] = dns_assignment[0]['fqdn']

    ipv4_nat = []
    ipv6_nat = []
    for ip in port['floating_ips']:
        if ':' in ip['int_ip']:
            ipv6_nat.append(ip)
        else:
            ipv4_nat.append(ip)
    if ipv4_nat:
        data['ipv4_nat'] = ipv4_nat
    if ipv6_nat:
        data['ipv6_nat'] = ipv6_nat

    # Return that data.
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
