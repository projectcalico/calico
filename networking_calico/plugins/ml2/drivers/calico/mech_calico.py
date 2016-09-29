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
# of the new Calico architecture (described by the "Calico Architecture"
# document at http://docs.projectcalico.org/en/latest/architecture.html).
#
# It is implemented as a Neutron/ML2 mechanism driver.
from collections import namedtuple
import contextlib
from functools import wraps
import inspect
import json
import os

# OpenStack imports.
import eventlet
from eventlet.semaphore import Semaphore
from neutron.agent import rpc as agent_rpc
from neutron.common import constants
from neutron.common.exceptions import PortNotFound
from neutron.common.exceptions import SubnetNotFound
from neutron.common import topics
from neutron import context as ctx
from neutron.db import l3_db
from neutron.db import models_v2
from neutron import manager
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from sqlalchemy import exc as sa_exc

# Monkeypatch import
import neutron.plugins.ml2.rpc as rpc

# OpenStack imports.
try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg

try:  # Icehouse, Juno
    from neutron.openstack.common import log
except ImportError:  # Kilo
    from oslo_log import log

try:
    # Icehouse.
    from neutron.openstack.common.db import exception as db_exc
except ImportError:
    try:
        # Juno.
        from oslo.db import exception as db_exc
    except ImportError:
        # Later.
        from oslo_db import exception as db_exc

try:
    # Icehouse/Juno.
    from neutron.openstack.common import lockutils
except ImportError:
    # Later.
    from oslo_concurrency import lockutils

# Calico imports.
import etcd
from networking_calico import datamodel_v1
from networking_calico.logutils import logging_exceptions
from networking_calico.monotonic import monotonic_time

from networking_calico.plugins.ml2.drivers.calico import t_etcd

LOG = log.getLogger(__name__)

calico_opts = [
    cfg.IntOpt('num_port_status_threads', default=4,
               help="Number of threads to use for writing port status "
                    "updates to the database."),
]
cfg.CONF.register_opts(calico_opts, 'calico')

# In order to rate limit warning logs about queue lengths, we check if we've
# already logged within this interval (seconds) before logging.
QUEUE_WARN_LOG_INTERVAL_SECS = 10

# An OpenStack agent type name for Felix, the Calico agent component in the new
# architecture.
AGENT_TYPE_FELIX = 'Calico per-host agent (felix)'
AGENT_ID_FELIX = 'calico-felix'

# Mapping from our endpoint status to neutron's port status.
PORT_STATUS_MAPPING = {
    datamodel_v1.ENDPOINT_STATUS_UP: constants.PORT_STATUS_ACTIVE,
    datamodel_v1.ENDPOINT_STATUS_DOWN: constants.PORT_STATUS_DOWN,
    datamodel_v1.ENDPOINT_STATUS_ERROR: constants.PORT_STATUS_ERROR,
}

# The interval between period resyncs, in seconds.
# TODO(nj): Increase this to a longer interval for product code.
RESYNC_INTERVAL_SECS = 60
# When we're not the master, how often we check if we have become the master.
MASTER_CHECK_INTERVAL_SECS = 5
# Delay before retrying a failed port status update to the Neutron DB.
PORT_UPDATE_RETRY_DELAY_SECS = 5

# We wait for a short period of time before we initialize our state to avoid
# problems with Neutron forking.
STARTUP_DELAY_SECS = 10

# A single security profile.  Although we call this a profile it is still a
# representation of security data that is closer to Neutron than to the Calico
# data model: it simply collects the Neutron-format inbound and outbound rules
# for a security group, together with that group's ID, and it has no
# representation for Calico profile tags.  Specifically, its 'id' is just the
# Neutron security group ID, _without_ the prefix for OpenStack that we add
# when writing into etcd.
SecurityProfile = namedtuple(
    'SecurityProfile', ['id', 'inbound_rules', 'outbound_rules']
)


# This terrible global variable points to the running instance of the
# Calico Mechanism Driver. This variable relies on the basic assertion that
# any Neutron process, forked or not, should only ever have *one* Calico
# Mechanism Driver in it. It's used by our monkeypatch of the
# security_groups_rule_updated method below to locate the mechanism driver.
# TODO(nj): Let's not do this any more. Please?
mech_driver = None


def requires_state(f):
    """requires_state

    This decorator is used to ensure that any method that requires that
    state be initialized will do that. This is to make sure that, if a user
    attempts an action before STARTUP_DELAY_SECS have passed, they don't
    have to wait.

    This decorator only needs to be applied to top-level functions of the
    CalicoMechanismDriver class: specifically, those that are called directly
    from Neutron.
    """
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        self._init_state()
        return f(self, *args, **kwargs)

    return wrapper


def retry_on_cluster_id_change(f):
    """retry_on_cluster_id_change

    This decorator ensures that the appropriate methods will retry if an
    etcd EtcdClusterIdChanged exception is raised. This ensures that if etcd
    is moved under their feet these methods don't fail, but instead do their
    best to succeed.

    To avoid infinite loops, however, these methods attempt to retry a finite
    number of times before abandoning the attempt.

    This decorator can only be applied to functions of the
    CalicoMechanismDriver.
    """
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        retries = 5
        while True:
            try:
                return f(self, *args, **kwargs)
            except etcd.EtcdClusterIdChanged:
                LOG.info("etcd cluster moved, retrying")
                retries -= 1
                if not retries:
                    raise

    return wrapper


class CalicoMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Neutron/ML2 mechanism driver for Project Calico.

    CalicoMechanismDriver communicates information about endpoints and security
    configuration, over the Endpoint and Network APIs respectively, to the
    other components of the Calico architecture; namely to the Felix instances
    running on each compute host.
    """

    def __init__(self):
        super(CalicoMechanismDriver, self).__init__(
            AGENT_TYPE_FELIX,
            'tap',
            {'port_filter': True,
             'mac_address': '00:61:fe:ed:ca:fe'})
        # Lock to prevent concurrent initialisation.
        self._init_lock = Semaphore()
        # Initialize fields for the database object and transport.  We will
        # initialize these properly when we first need them.
        self.db = None
        self._agent_update_context = None
        self.transport = None
        self._etcd_watcher = None
        self._etcd_watcher_thread = None
        self._my_pid = None
        self._epoch = 0
        self.in_resync = False
        # Mapping from (hostname, port-id) to Calico's status for a port.  The
        # hostname is included to disambiguate between multiple copies of a
        # port, which may exist during a migration or a re-schedule.
        self._port_status_cache = {}
        # Queue used to fan out port status updates to worker threads.  Notes:
        # * we bound the queue so that, at some level of sustained overload
        #   we'll be forced to resync with etcd
        # * we don't recreate the queue in _init_state() so that we can't
        #   possibly lose updates that had already been queued.
        self._port_status_queue = eventlet.Queue(maxsize=10000)
        # RPC client for fanning out agent state reports.
        self.state_report_rpc = None
        # Whether the version of update_port_status() available in this version
        # of OpenStack has the host argument.  computed on first use.
        self._cached_update_port_status_has_host_param = None
        # Last time we logged about a long port-status queue.  Used for rate
        # limiting.  Note: monotonic_time() uses its own epoch so it's only
        # safe to compare this with other values returned by monotonic_time().
        self._last_status_queue_log_time = monotonic_time()

        # Tell the monkeypatch where we are.
        global mech_driver
        assert mech_driver is None
        mech_driver = self

        # Make sure we initialise even if we don't see any API calls.
        eventlet.spawn_after(STARTUP_DELAY_SECS, self._init_state)

    @logging_exceptions(LOG)
    def _init_state(self):
        """_init_state

        Creates the connection state required for talking to the Neutron DB
        and to etcd. This is a no-op if it has been executed before.

        This is split out from __init__ to allow us to defer this
        initialisation until after Neutron has forked off its worker
        children.  If we initialise the DB and etcd connections before
        the fork (as would happen in __init__()) then the workers
        would share sockets incorrectly.
        """
        with self._init_lock:
            current_pid = os.getpid()
            if self._my_pid == current_pid:
                # We've initialised our PID and it hasn't changed since last
                # time, nothing to do.
                return
            # else: either this is the first call or our PID has changed:
            # (re)initialise.

            if self._my_pid is not None:
                # This is unexpected but we can deal with it: Neutron should
                # fork before we trigger the first call to _init_state().
                LOG.warning("PID changed from %s to %s; unexpected fork after "
                            "initialisation?  Reinitialising Calico driver.",
                            self._my_pid, current_pid)
            else:
                LOG.info("Doing Calico mechanism driver initialisation in"
                         "process %s", current_pid)

            # (Re)init the DB.
            self.db = None
            self._get_db()

            # Admin context used by (only) the thread that updates Felix agent
            # status.
            self._agent_update_context = ctx.get_admin_context()

            # Get RPC connection for fanning out Felix state reports.
            try:
                state_report_topic = topics.REPORTS
            except AttributeError:
                # Older versions of OpenStack share the PLUGIN topic.
                state_report_topic = topics.PLUGIN
            self.state_report_rpc = agent_rpc.PluginReportStateAPI(
                state_report_topic
            )

            # Use Etcd-based transport.
            if self.transport:
                # If we've been forked then the old transport will incorrectly
                # share file handles with the other process.
                LOG.warning("Shutting down previous transport instance.")
                self.transport.stop()
            self.transport = t_etcd.CalicoTransportEtcd(self)

            self._my_pid = current_pid

            # Start our resynchronization process and status updating. Just in
            # case we ever get two same threads running, use an epoch counter
            # to tell the old thread to die.
            # We deliberately do this last, to ensure that all of the setup
            # above is complete before we start running.
            self._epoch += 1
            eventlet.spawn(self.periodic_resync_thread, self._epoch)
            eventlet.spawn(self._status_updating_thread, self._epoch)
            for _ in xrange(cfg.CONF.calico.num_port_status_threads):
                eventlet.spawn(self._loop_writing_port_statuses, self._epoch)
            LOG.info("Calico mechanism driver initialisation done in process "
                     "%s", current_pid)

    @logging_exceptions(LOG)
    def _status_updating_thread(self, expected_epoch):
        """_status_updating_thread

        This method acts as a status updates handler logic for the
        Calico mechanism driver. Watches for felix updates in etcd
        and passes info to Neutron database.
        """
        LOG.info("Status updating thread started.")
        while self._epoch == expected_epoch:
            # Only handle updates if we are the master node.
            if self.transport.is_master:
                if self._etcd_watcher is None:
                    LOG.info("Became the master, starting CalicoEtcdWatcher")
                    self._etcd_watcher = t_etcd.CalicoEtcdWatcher(self)
                    self._etcd_watcher_thread = eventlet.spawn(
                        self._etcd_watcher.loop
                    )
                    LOG.info("Started %s as %s",
                             self._etcd_watcher, self._etcd_watcher_thread)
                elif not self._etcd_watcher_thread:
                    LOG.error("CalicoEtcdWatcher %s died", self._etcd_watcher)
                    self._etcd_watcher.stop()
                    self._etcd_watcher = None
            else:
                if self._etcd_watcher is not None:
                    LOG.warning("No longer the master, stopping "
                                "CalicoEtcdWatcher")
                    self._etcd_watcher.stop()
                    self._etcd_watcher = None
                # Short sleep interval before we check if we've become
                # the master.
            eventlet.sleep(MASTER_CHECK_INTERVAL_SECS)
        else:
            LOG.warning("Unexpected: epoch changed. "
                        "Handling status updates thread exiting.")

    def on_felix_alive(self, felix_hostname, new):
        LOG.info("Felix on host %s is alive; fanning out status report",
                 felix_hostname)
        # Rather than writing directly to the database, we use the RPC
        # mechanism to fan out the request to another process.  This
        # distributes the DB write load and avoids turning the db-access lock
        # into a bottleneck.
        agent_state = felix_agent_state(felix_hostname, start_flag=new)
        self.state_report_rpc.report_state(self._agent_update_context,
                                           agent_state,
                                           use_call=False)

    def on_port_status_changed(self, hostname, port_id, status_dict):
        """Called when etcd tells us that a port status has changed.

        :param hostname: hostname of the host containing the port.
        :param port_id: the port ID.
        :param status_dict: new status dict for the port or None if the
               status was deleted.
        """
        port_status_key = (intern(hostname.encode("utf8")), port_id)
        # Unwrap the dict around the actual status.
        if status_dict is not None:
            # Update.
            calico_status = status_dict.get("status")
        else:
            # Deletion.
            calico_status = None
        if self._port_status_cache.get(port_status_key) != calico_status:
            LOG.info("Status of port %s on host %s changed to %s",
                     port_status_key, hostname, calico_status)
            # We write the update to our in-memory cache, which is shared with
            # the DB writer threads.  This means that the next write for a
            # particular key always goes directly to the correct state.
            # Python's dict is thread-safe for set and get, which is what we
            # need.
            if calico_status is not None:
                if calico_status in PORT_STATUS_MAPPING:
                    # Intern the status to avoid keeping thousands of copies
                    # of the status strings.  We know the .encode() is safe
                    # because we just checked this was one of our expected
                    # strings.
                    interned_status = intern(calico_status.encode("utf8"))
                    self._port_status_cache[port_status_key] = interned_status
                else:
                    LOG.error("Unknown port status: %r", calico_status)
                    self._port_status_cache.pop(port_status_key, None)
            else:
                self._port_status_cache.pop(port_status_key, None)
            # Defer the actual update to the background thread so that we don't
            # hold up reading from etcd.  In particular, we don't want to block
            # Felix status updates while we wait on the DB.
            self._port_status_queue.put(port_status_key)
            if self._port_status_queue.qsize() > 10:
                now = monotonic_time()
                if (now - self._last_status_queue_log_time >
                        QUEUE_WARN_LOG_INTERVAL_SECS):
                    LOG.warning("Port status update queue length is high: %s",
                                self._port_status_queue.qsize())
                    self._last_status_queue_log_time = now
                # Queue is getting large, make sure the DB writer threads
                # get CPU.
                eventlet.sleep()

    @logging_exceptions(LOG)
    def _loop_writing_port_statuses(self, expected_epoch):
        LOG.info("Port status write thread started epoch=%s", expected_epoch)
        admin_context = ctx.get_admin_context()
        while self._epoch == expected_epoch:
            # Wait for work to do.
            port_status_key = self._port_status_queue.get()
            # Actually do the update.
            self._try_to_update_port_status(admin_context, port_status_key)

    def _try_to_update_port_status(self, admin_context, port_status_key):
        """Attempts to update the given port status.

        :param admin_context: Admin context to pass to Neutron.  Should be
               unique for each thread.
        :param port_status_key: tuple of hostname, port_id.
        """
        hostname, port_id = port_status_key
        calico_status = self._port_status_cache.get(port_status_key)
        if calico_status:
            neutron_status = PORT_STATUS_MAPPING[calico_status]
            LOG.info("Updating port %s status to %s", port_id, neutron_status)
        else:
            # Report deletion as error.  Either the port has genuinely been
            # deleted, in which case this update is ignored by
            # update_port_status() or the port still exists but we disagree,
            # which is an error.
            neutron_status = constants.PORT_STATUS_ERROR
            LOG.info("Reporting port %s deletion", port_id)

        try:
            if self._update_port_status_has_host_param():
                # Later OpenStack versions support passing the hostname.
                LOG.debug("update_port_status() supports host parameter")
                self.db.update_port_status(admin_context,
                                           port_id,
                                           neutron_status,
                                           host=hostname)
            else:
                # Older versions don't have a way to specify the hostname so
                # we do our best.
                LOG.debug("update_port_status() missing host parameter")
                self.db.update_port_status(admin_context,
                                           port_id,
                                           neutron_status)
        except (db_exc.DBError,
                sa_exc.SQLAlchemyError) as e:
            # Defensive: pre-Liberty, it was easy to cause deadlocks here if
            # any code path (in another loaded plugin, say) failed to take
            # the db-access lock.  Post-Liberty, we shouldn't see any
            # exceptions here because update_port_status() is wrapped with a
            # retry decorator in the neutron code.
            LOG.warning("Failed to update port status for %s due to %r.",
                        port_id, e)
            # Queue up a retry after a delay.
            eventlet.spawn_after(PORT_UPDATE_RETRY_DELAY_SECS,
                                 self._retry_port_status_update,
                                 port_status_key)
        else:
            LOG.debug("Updated port status for %s", port_id)

    @logging_exceptions(LOG)
    def _retry_port_status_update(self, port_status_key):
        LOG.info("Retrying update to port %s", port_status_key)
        # Queue up the update so that we'll go via the normal writer threads.
        # They will re-read the current state of the port from the cache.
        self._port_status_queue.put(port_status_key)

    def _update_port_status_has_host_param(self):
        """Check whether update_port_status() supports the host parameter."""
        if self._cached_update_port_status_has_host_param is None:
            args, _, varkw, _ = inspect.getargspec(self.db.update_port_status)
            has_host_param = varkw or "host" in args
            self._cached_update_port_status_has_host_param = has_host_param
            LOG.info("update_port_status() supports host arg: %s",
                     has_host_param)
        return self._cached_update_port_status_has_host_param

    def _get_db(self):
        if not self.db:
            self.db = manager.NeutronManager.get_plugin()
            LOG.info("db = %s" % self.db)

            # Update the reference to ourselves.
            global mech_driver
            mech_driver = self

    def bind_port(self, context):
        """bind_port

        Checks that the DHCP agent is alive on the host and then defers
        to the superclass, which will check that felix is alive and then
        call back into our check_segment_for_agent() method, which does
        further checks.
        """
        # FIXME: Actually for now we don't check for a DHCP agent,
        # because we haven't yet worked out the future architecture
        # for this.  The key point is that we don't want to do this
        # via the Neutron database and RPC mechanisms, because that is
        # what causes the scaling problem that led us to switch to an
        # etcd-driven DHCP agent.
        return super(CalicoMechanismDriver, self).bind_port(context)

    def check_segment_for_agent(self, segment, agent):
        LOG.debug("Checking segment %s with agent %s" % (segment, agent))
        if segment[api.NETWORK_TYPE] in ['local', 'flat']:
            return True
        else:
            LOG.warning(
                "Calico does not support network type %s, on network %s",
                segment[api.NETWORK_TYPE],
                segment[api.ID],
            )
            return False

    def get_allowed_network_types(self, agent=None):
        return ('local', 'flat')

    def get_mappings(self, agent):
        # We override this primarily to satisfy the ABC checker: this method
        # never actually gets called because we also override
        # check_segment_for_agent.
        assert False

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

    @retry_on_cluster_id_change
    @requires_state
    def create_subnet_postcommit(self, context):
        LOG.info("CREATE_SUBNET_POSTCOMMIT: %s" % context)

        # Re-read the subnet from the DB.  This ensures that a change to the
        # same subnet can't be processed by another controller process while
        # we're writing the effects of this call into etcd.
        subnet = context.current
        plugin_context = context._plugin_context
        with self._txn_from_context(plugin_context, tag="create-subnet"):
            subnet = self.db.get_subnet(plugin_context, subnet['id'])
            if subnet['enable_dhcp']:
                # Pass relevant subnet info to the transport layer.
                self.transport.subnet_created(subnet)

    @retry_on_cluster_id_change
    @requires_state
    def update_subnet_postcommit(self, context):
        LOG.info("UPDATE_SUBNET_POSTCOMMIT: %s" % context)

        # Re-read the subnet from the DB.  This ensures that a change to the
        # same subnet can't be processed by another controller process while
        # we're writing the effects of this call into etcd.
        subnet = context.current
        plugin_context = context._plugin_context
        with self._txn_from_context(plugin_context, tag="update-subnet"):
            subnet = self.db.get_subnet(plugin_context, subnet['id'])
            if subnet['enable_dhcp']:
                # Pass relevant subnet info to the transport layer.
                self.transport.subnet_created(subnet)
            else:
                # Tell transport layer that subnet has been deleted.
                self.transport.subnet_deleted(subnet['id'])

    @retry_on_cluster_id_change
    @requires_state
    def delete_subnet_postcommit(self, context):
        LOG.info("DELETE_SUBNET_POSTCOMMIT: %s" % context)

        # Pass on to the transport layer.
        self.transport.subnet_deleted(context.current['id'])

    # Idealised method forms.
    @retry_on_cluster_id_change
    @requires_state
    def create_port_postcommit(self, context):
        """create_port_postcommit

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

        # If the port binding VIF type is 'unbound', this port doesn't actually
        # need to be networked yet. We can simply return immediately.
        if port['binding:vif_type'] == 'unbound':
            LOG.info("Creating unbound port: no work required.")
            return

        plugin_context = context._plugin_context
        with self._txn_from_context(plugin_context, tag="create-port"):
            # First, regain the current port. This protects against concurrent
            # writes breaking our state.
            port = self.db.get_port(plugin_context, port['id'])

            # Next, fill out other information we need on the port.
            port = self.add_extra_port_information(
                plugin_context, port
            )

            # Next, we need to work out what security profiles apply to this
            # port and grab information about them.
            profiles = self.get_security_profiles(
                plugin_context, port
            )

            # Write data for those profiles into etcd.
            for profile in profiles:
                self.transport.write_profile_to_etcd(profile)

            # Pass this to the transport layer.
            # Implementation note: we could arguably avoid holding the
            # transaction for this length and instead release it here, then
            # use atomic CAS. The problem there is that we potentially have to
            # repeatedly respin and regain the transaction. Let's not do that
            # for now, and performance test to see if it's a problem later.
            self.transport.endpoint_created(port)

    @retry_on_cluster_id_change
    @requires_state
    def update_port_postcommit(self, context):
        """update_port_postcommit

        Called after Neutron has committed a port update event to the
        database.

        This is a tricky event, because it can be called in a number of ways
        during VM migration. We farm out to the appropriate method from here.
        """
        LOG.info('UPDATE_PORT_POSTCOMMIT: %s', context)
        port = context._port
        original = context.original

        # Abort early if we're managing non-endpoint ports.
        if not self._port_is_endpoint_port(port):
            return

        # If this port update is purely for a status change, don't do anything:
        # we don't care about port statuses.
        if port_status_change(port, original):
            LOG.info('Called for port status change, no action.')
            return

        # Now, re-read the port.
        plugin_context = context._plugin_context
        with self._txn_from_context(plugin_context, tag="update-port"):
            port = self.db.get_port(plugin_context, port['id'])

            # Now, fork execution based on the type of update we're performing.
            # There are a few:
            # - a port becoming bound (binding vif_type from unbound to bound);
            # - a port becoming unbound (binding vif_type from bound to
            #   unbound);
            # - an Icehouse migration (binding host id changed and port bound);
            # - an update (port bound at all times);
            # - a change to an unbound port (which we don't care about, because
            #   we do nothing with unbound ports).
            if port_bound(port) and not port_bound(original):
                self._port_bound_update(context, port)
            elif port_bound(original) and not port_bound(port):
                self._port_unbound_update(context, original)
            elif original['binding:host_id'] != port['binding:host_id']:
                LOG.info("Icehouse migration")
                self._icehouse_migration_step(context, port, original)
            elif port_bound(original) and port_bound(port):
                LOG.info("Port update")
                self._update_port(plugin_context, port)
            else:
                LOG.info("Update on unbound port: no action")
                pass

    @retry_on_cluster_id_change
    @requires_state
    def update_floatingip(self, plugin_context):
        """update_floatingip

        Called after a Neutron floating IP has been associated or
        disassociated from a port.
        """
        LOG.info('UPDATE_FLOATINGIP: %s', plugin_context)

        with self._txn_from_context(plugin_context, tag="update_floatingip"):
            port = self.db.get_port(plugin_context,
                                    plugin_context.fip_update_port_id)
            self._update_port(plugin_context, port)

    @retry_on_cluster_id_change
    @requires_state
    def delete_port_postcommit(self, context):
        """delete_port_postcommit

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

    @retry_on_cluster_id_change
    @requires_state
    def send_sg_updates(self, sgids, context):
        """Called whenever security group rules or membership change.

        When a security group rule is added, we need to do the following steps:

        1. Reread the security rules from the Neutron DB.
        2. Write the profile to etcd.
        """
        LOG.info("Updating security group IDs %s", sgids)
        with self._txn_from_context(context, tag="sg-update"):
            rules = self.db.get_security_group_rules(
                context, filters={'security_group_id': sgids}
            )

            # For each profile, build its object and send it down.
            #
            # TODO(nj): Sending this to etcd could legitimately fail because of
            # a CAS problem. Come back to handle retries.
            profiles = (
                profile_from_neutron_rules(sgid, rules) for sgid in sgids
            )

            for profile in profiles:
                self.transport.write_profile_to_etcd(profile)

    @contextlib.contextmanager
    def _txn_from_context(self, context, tag="<unset>"):
        """Context manager: opens a DB transaction against the given context.

        If required, this also takes the Neutron-wide db-access semaphore.

        :return: context manager for use with with:.
        """
        session = context.session
        conn_url = str(session.connection().engine.url).lower()
        if (conn_url.startswith("mysql:") or
                conn_url.startswith("mysql+mysqldb:")):
            # Neutron is using the mysqldb driver for accessing the database.
            # This has a known incompatibility with eventlet that leads to
            # deadlock.  Take the neutron-wide db-access lock as a workaround.
            # See https://bugs.launchpad.net/oslo.db/+bug/1350149 for a
            # description of the issue.
            LOG.debug("Waiting for db-access lock tag=%s...", tag)
            try:
                with lockutils.lock('db-access'):
                    LOG.debug("...acquired db-access lock tag=%s", tag)
                    with context.session.begin(subtransactions=True) as txn:
                        yield txn
            finally:
                LOG.debug("Released db-access lock tag=%s", tag)
        else:
            # Liberty or later uses an eventlet-safe mysql library.  (Or, we're
            # not using mysql at all.)
            LOG.debug("Not using mysqldb driver, skipping db-access lock")
            with context.session.begin(subtransactions=True) as txn:
                yield txn

    def _port_unbound_update(self, context, port):
        """_port_unbound_update

        This is called when a port is unbound during a port update. This
        destroys the port in etcd.
        """
        LOG.info("Port becoming unbound: destroy.")
        self.transport.endpoint_deleted(port)

    def _port_bound_update(self, context, port):
        """_port_bound_update

        This is called when a port is bound during a port update. This creates
        the port in etcd.

        This method expects to be called from within a database transaction,
        and does not create one itself.
        """
        # TODO(nj): Can we avoid re-writing the security profile here? Put
        # another way, does the security profile change during migration steps,
        # or does a separate port update event occur?
        LOG.info("Port becoming bound: create.")
        plugin_context = context._plugin_context
        port = self.db.get_port(plugin_context, port['id'])
        port = self.add_extra_port_information(plugin_context, port)

        # Get the security profiles for this port.
        profiles = self.get_security_profiles(plugin_context, port)

        # Write data for those profiles into etcd.
        for profile in profiles:
            self.transport.write_profile_to_etcd(profile)

        # Now write the new endpoint data for the port.
        self.transport.endpoint_created(port)

    def _icehouse_migration_step(self, context, port, original):
        """_icehouse_migration_step

        This is called when migrating on Icehouse. Here, we basically just
        perform an unbinding and a binding at exactly the same time, but we
        hold a DB lock the entire time.

        This method expects to be called from within a database transaction,
        and does not create one itself.
        """
        # TODO(nj): Can we avoid re-writing the security profile here? Put
        # another way, does the security profile change during migration steps,
        # or does a separate port update event occur?
        LOG.info("Migration as implemented in Icehouse")
        self._port_unbound_update(context, original)
        self._port_bound_update(context, port)

    def _update_port(self, plugin_context, port):
        """_update_port

        Called during port updates that have nothing to do with migration.

        This method assumes it's being called from within a database
        transaction and does not take out another one.
        """
        # TODO(nj): There's a lot of redundant code in these methods, with the
        # only key difference being taking out transactions. Come back and
        # shorten these.
        LOG.info("Updating port %s", port)

        # If the binding VIF type is unbound, we consider this port 'disabled',
        # and should attempt to delete it. Otherwise, the port is enabled:
        # re-process it.
        port_disabled = port['binding:vif_type'] == 'unbound'
        if not port_disabled:
            LOG.info("Port enabled, attempting to update.")

            port = self.db.get_port(plugin_context, port['id'])
            port = self.add_extra_port_information(plugin_context, port)

            # Get the security profiles for this port.
            profiles = self.get_security_profiles(plugin_context, port)

            # Write data for those profiles into etcd.
            for profile in profiles:
                self.transport.write_profile_to_etcd(profile)

            # Now write the new endpoint data for the port.
            self.transport.endpoint_created(port)
        else:
            # Port unbound, attempt to delete.
            LOG.info("Port disabled, attempting delete if needed.")
            self.transport.endpoint_deleted(port)

    def add_port_gateways(self, port, context):
        """add_port_gateways

        Determine the gateway IP addresses for a given port's IP addresses, and
        adds them to the port dict.

        This method assumes it's being called from within a database
        transaction and does not take out another one.
        """
        for ip in port['fixed_ips']:
            subnet = self.db.get_subnet(context, ip['subnet_id'])
            ip['gateway'] = subnet['gateway_ip']

    def get_security_profiles(self, context, port):
        """get_security_profiles

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

    def periodic_resync_thread(self, expected_epoch):
        """periodic_resync_thread

        This method acts as a the periodic resynchronization logic for the
        Calico mechanism driver.

        On a fixed interval, it spins over the entire database and reconciles
        it with etcd, ensuring that the etcd database and Neutron are in
        synchronization with each other.
        """
        try:
            LOG.info("Periodic resync thread started")
            while self._epoch == expected_epoch:
                # Only do the resync logic if we're actually the master node.
                if self.transport.is_master:
                    LOG.info("I am master: doing periodic resync")
                    # Since this thread is not associated with any particular
                    # request, we use our own admin context for accessing the
                    # database.
                    admin_context = ctx.get_admin_context()

                    try:
                        # First, resync subnets.
                        self.resync_subnets(admin_context)

                        # Next, resync profiles as far as to create any that
                        # are missing from etcd, and to update any that are in
                        # etcd but whose Neutron data differs from etcd.  After
                        # this step, etcd will have correct data for all
                        # profiles that an endpoint can be using; that's why we
                        # do this part of the resync before resyncing the
                        # endpoints.
                        #
                        # The call also returns a set of profiles that are in
                        # etcd but no longer wanted (because there is now no
                        # corresponding Neutron data for them).  We will delete
                        # these after resyncing the endpoints, because right
                        # now there could still be endpoints referencing some
                        # of those profiles.
                        profiles_to_delete = self.resync_profiles(
                            admin_context
                        )

                        # Next, resync endpoints.
                        self.resync_endpoints(admin_context)

                        # Now delete the profiles that are no longer wanted.
                        self._resync_deleted_profiles(profiles_to_delete)

                        # Now, set the config flags.
                        self.transport.provide_felix_config()
                    except Exception:
                        LOG.exception("Error in periodic resync thread.")
                    # Reschedule ourselves.
                    eventlet.sleep(RESYNC_INTERVAL_SECS)
                else:
                    # Shorter sleep interval before we check if we've become
                    # the master.  Avoids waiting a whole RESYNC_INTERVAL_SECS
                    # if we just miss the master update.
                    eventlet.sleep(MASTER_CHECK_INTERVAL_SECS)
        except Exception:
            # TODO(nj) Should we tear down the process.
            LOG.exception("Periodic resync thread died!")
            if self.transport:
                # Stop the transport so that we give up the mastership.
                self.transport.stop()
            raise
        else:
            LOG.warning("Periodic resync thread exiting.")

    def resync_subnets(self, context):
        """Handles periodic resynchronization for subnets."""
        LOG.info("Resyncing subnets")

        # Work out all the subnets in etcd. Do this outside a database
        # transaction to try to ensure that anything that gets created is in
        # our Neutron snapshot.
        etcd_subnets = list(self.transport.get_subnets())
        etcd_ids = set(ep.id for ep in etcd_subnets)

        # Then, grab all the DHCP-enabled subnets from Neutron.
        with self._txn_from_context(context, "resync-subnets"):
            neutron_ids = set([subnet['id']
                               for subnet in self.db.get_subnets(context)
                               if subnet['enable_dhcp']])

        missing_ids = neutron_ids - etcd_ids
        extra_ids = etcd_ids - neutron_ids
        common_ids = etcd_ids & neutron_ids

        if missing_ids or extra_ids:
            LOG.warning("Missing subnets: %s", missing_ids)
            LOG.warning("Extra subnets: %s", extra_ids)

        # First, handle the extra subnets.
        subnets_to_delete = [s for s in etcd_subnets if s.id in extra_ids]
        self._resync_extra_subnets(subnets_to_delete)

        # Next, the missing subnets.
        self._resync_missing_subnets(context, missing_ids)

        # Finally, scan each of the subnets in common_ids. Work out if there
        # are any differences. If there are, write out to etcd.
        common_subnets = (s for s in etcd_subnets if s.id in common_ids)
        self._resync_changed_subnets(context, common_subnets)

    def _resync_extra_subnets(self, subnets_to_delete):
        """Atomically delete subnets that are in etcd, but shouldn't be.

        :param subnets_to_delete: An iterable of Subnet objects to be
            deleted.
        :returns: Nothing.
        """
        for subnet in subnets_to_delete:
            try:
                self.transport.atomic_delete_subnet(subnet)
            except (etcd.EtcdCompareFailed, etcd.EtcdKeyNotFound):
                # If the atomic CAD doesn't successfully delete, that's ok, it
                # means the subnet was created or updated elsewhere.
                LOG.info('Subnet %s was deleted elsewhere', subnet)
                continue

    def _resync_missing_subnets(self, context, missing_subnet_ids):
        """Resync missing subnets.

        For each missing subnet, do a quick subnet creation. This takes out a
        DB transaction and regains all the subnets. Note that this transaction
        is potentially held for quite a while.

        :param context: A Neutron DB context.
        :param missing_subnet_ids: A set of IDs for subnets missing from etcd.
        :returns: Nothing.
        """
        with self._txn_from_context(context, tag="resync-subnet-missing"):
            missing_subnets = self.db.get_subnets(
                context, filters={'id': missing_subnet_ids}
            )

            for subnet in missing_subnets:
                # Fill out other information we need on the subnet and write to
                # etcd.
                self.transport.subnet_created(subnet)

    def _resync_changed_subnets(self, context, common_subnets):
        """_resync_changed_subnets

        Reconcile all changed subnets by checking whether Neutron and etcd
        agree.

        :param context: A Neutron DB context.
        :param common_subnets: An iterable of Subnet objects that should
            be checked for changes.
        :returns: Nothing.
        """
        for subnet in common_subnets:
            # Get the subnet data from etcd.
            try:
                etcd_subnet = self.transport.get_subnet_data(subnet)
            except etcd.EtcdKeyNotFound:
                # The subnet is gone. That's fine.
                LOG.info("Failed to resync deleted subnet %s", subnet.id)
                continue

            with self._txn_from_context(context, tag="resync-subnets-changed"):
                try:
                    neutron_subnet = self.db.get_subnet(context, subnet.id)
                except SubnetNotFound:
                    # The subnet got deleted.
                    LOG.info("Failed to resync deleted subnet %s", subnet.id)
                    continue

            # Get the data for both.
            try:
                etcd_data = json.loads(etcd_subnet.data)
            except (ValueError, TypeError):
                # If the JSON data is bad, we need to fix it up. Set a value
                # that is impossible for Neutron to be returning: nothing at
                # all.
                LOG.warning("Bad JSON data for subnet %s", subnet.id)
                etcd_data = None

            neutron_data = t_etcd.subnet_etcd_data(neutron_subnet)

            if etcd_data != neutron_data:
                # Write to etcd.
                LOG.warning("etcd copy of subnet %s inconsistent with " +
                            "Neutron DB, resyncing", subnet.id)
                try:
                    self.transport.subnet_created(
                        neutron_subnet,
                        prev_index=subnet.modified_index
                    )
                except (etcd.EtcdCompareFailed, etcd.EtcdKeyNotFound):
                    # If someone wrote to etcd they probably have more recent
                    # data than us, let it go.
                    LOG.info("Atomic CAS failed, no action.")
                    continue

    def resync_endpoints(self, context):
        """Handles periodic resynchronization for endpoints."""
        LOG.info("Resyncing endpoints")

        # Work out all the endpoints in etcd. Do this outside a database
        # transaction to try to ensure that anything that gets created is in
        # our Neutron snapshot.
        endpoints = list(self.transport.get_endpoints())
        endpoint_ids = set(ep.id for ep in endpoints)

        # Then, grab all the ports from Neutron.
        # TODO(lukasa): We can reduce the amount of data we load from Neutron
        # here by filtering in the get_ports call.
        with self._txn_from_context(context, "resync-port"):
            ports = dict((port['id'], port)
                         for port in self.db.get_ports(context)
                         if self._port_is_endpoint_port(port))

        port_ids = set(ports.keys())
        missing_ports = port_ids - endpoint_ids
        extra_ports = endpoint_ids - port_ids
        changes_ports = set()

        # We need to do one more check: are any ports in the wrong place? The
        # way we handle this is to treat this as a port that is both missing
        # and extra, where the old version is extra and the new version is
        # missing.
        #
        # While we're here, anything that's not extra, missing, or in the wrong
        # place should be added to the list of ports to check for changes.
        for endpoint in endpoints:
            try:
                port = ports[endpoint.id]
            except KeyError:
                # Port already in extra_ports.
                continue

            if endpoint.host != port['binding:host_id']:
                LOG.info(
                    "Port %s is incorrectly on %s, should be %s",
                    endpoint.id,
                    endpoint.host,
                    port['binding:host_id']
                )
                missing_ports.add(endpoint.id)
                extra_ports.add(endpoint.id)
            else:
                # Port is common to both: add to changes_ports.
                changes_ports.add(endpoint.id)

        if missing_ports or extra_ports:
            LOG.warning("Missing ports: %s", missing_ports)
            LOG.warning("Extra ports: %s", extra_ports)

        # First, handle the extra ports.
        eps_to_delete = (e for e in endpoints if e.id in extra_ports)
        self._resync_extra_ports(eps_to_delete)

        # Next, the missing ports.
        self._resync_missing_ports(context, missing_ports)

        # Finally, scan each of the ports in changes_ports. Work out if there
        # are any differences. If there are, write out to etcd.
        common_endpoints = (e for e in endpoints if e.id in changes_ports)
        self._resync_changed_ports(context, common_endpoints)

    def _resync_missing_ports(self, context, missing_port_ids):
        """_resync_missing_ports

        For each missing port, do a quick port creation. This takes out a DB
        transaction and regains all the ports. Note that this transaction is
        potentially held for quite a while.

        :param context: A Neutron DB context.
        :param missing_port_ids: A set of IDs for ports missing from etcd.
        :returns: Nothing.
        """
        with self._txn_from_context(context, tag="resync-port-missing"):
            missing_ports = self.db.get_ports(
                context, filters={'id': missing_port_ids}
            )

            for port in missing_ports:
                # Fill out other information we need on the port and write to
                # etcd.
                port = self.add_extra_port_information(context, port)
                self.transport.endpoint_created(port)

    def _resync_extra_ports(self, ports_to_delete):
        """Atomically delete ports that are in etcd, but shouldn't be.

        :param ports_to_delete: An iterable of Endpoint objects to be
            deleted.
        :returns: Nothing.
        """
        for endpoint in ports_to_delete:
            try:
                self.transport.atomic_delete_endpoint(endpoint)
            except (etcd.EtcdCompareFailed, etcd.EtcdKeyNotFound):
                # If the atomic CAD doesn't successfully delete, that's ok, it
                # means the endpoint was created or updated elsewhere.
                LOG.info('Endpoint %s was deleted elsewhere', endpoint)
                continue

    def _resync_changed_ports(self, context, common_endpoints):
        """_resync_changed_ports

        Reconcile all changed ports by checking whether Neutron and etcd agree.

        :param context: A Neutron DB context.
        :param common_endpoints: An iterable of Endpoint objects that should
            be checked for changes.
        :returns: Nothing.
        """
        for endpoint in common_endpoints:
            # Get the endpoint data from etcd.
            try:
                endpoint = self.transport.get_endpoint_data(endpoint)
            except etcd.EtcdKeyNotFound:
                # The endpoint is gone. That's fine.
                LOG.info("Failed to update deleted endpoint %s", endpoint.id)
                continue

            with self._txn_from_context(context, tag="resync-ports-changed"):
                try:
                    port = self.db.get_port(context, endpoint.id)
                except PortNotFound:
                    # The endpoint got deleted.
                    LOG.info("Failed to update deleted port %s", endpoint.id)
                    continue

            # Get the data for both.
            try:
                etcd_data = json.loads(endpoint.data)
            except (ValueError, TypeError):
                # If the JSON data is bad, we need to fix it up. Set a value
                # that is impossible for Neutron to be returning: nothing at
                # all.
                LOG.warning("Bad JSON data in key %s", endpoint.key)
                etcd_data = None

            port = self.add_extra_port_information(context, port)
            neutron_data = t_etcd.port_etcd_data(port)

            if etcd_data != neutron_data:
                # Write to etcd.
                LOG.warning("Resolving error in port %s", endpoint.id)
                try:
                    self.transport.write_port_to_etcd(
                        port, prev_index=endpoint.modified_index
                    )
                except (etcd.EtcdCompareFailed, etcd.EtcdKeyNotFound):
                    # If someone wrote to etcd they probably have more recent
                    # data than us, let it go.
                    LOG.info("Atomic CAS failed, no action.")
                    continue

    def resync_profiles(self, context):
        """Resynchronize security profiles."""
        LOG.info("Resyncing profiles")

        # Work out all the security groups in etcd. Do this outside a database
        # transaction to try to ensure that anything that gets created is in
        # our Neutron snapshot.
        profiles = list(self.transport.get_profiles())
        profile_ids = set(profile.id for profile in profiles)

        # Next, grab all the security groups from Neutron. Quickly work out
        # whether a given group is missing from etcd, or if etcd has too many
        # groups. Then, add all missing groups and remove all extra ones.
        # Anything not in either group is added to the 'reconcile' set.
        # This explicit with statement is technically unnecessary, but it helps
        # keep our transaction scope really clear.
        with self._txn_from_context(context, tag="resync-prof"):
            sgs = self.db.get_security_groups(context)

        sgids = set(sg['id'] for sg in sgs)
        missing_groups = sgids - profile_ids
        extra_groups = profile_ids - sgids
        reconcile_groups = profile_ids & sgids

        if missing_groups or extra_groups:
            LOG.warning("Missing groups: %s", missing_groups)
            LOG.warning("Extra groups: %s", extra_groups)

        # First, create the missing security profiles.
        self._resync_missing_profiles(context, missing_groups)

        # Next, reconcile existing security profiles. This involves looping
        # over them, grabbing their data, and then comparing that to what
        # Neutron has.
        profiles_to_reconcile = (
            p for p in profiles if p.id in reconcile_groups
        )
        self._resync_changed_profiles(context, profiles_to_reconcile)

        # Finally, return the set of extra profiles, i.e. those that need to be
        # atomically deleted.
        return (p for p in profiles if p.id in extra_groups)

    def _resync_missing_profiles(self, context, missing_group_ids):
        """_resync_missing_profiles

        For each missing profile, do a quick profile creation. This takes out a
        db transaction and regains all the rules. Note that this transaction is
        potentially held for quite a while.

        :param context: A Neutron DB context.
        :param missing_group_ids: The IDs of the missing security groups.
        :returns: Nothing.
        """
        with self._txn_from_context(context, tag="resync-prof-missing"):
            rules = self.db.get_security_group_rules(
                context, filters={'security_group_id': missing_group_ids}
            )

            profiles_to_write = (
                profile_from_neutron_rules(sgid, rules)
                for sgid in missing_group_ids
            )

            for profile in profiles_to_write:
                self.transport.write_profile_to_etcd(profile)

    def _resync_deleted_profiles(self, profiles_to_delete):
        """Atomically delete profiles that are in etcd, but shouldn't be.

        :param profiles_to_delete: An iterable of profile objects to be
            deleted.
        :returns: Nothing.
        """
        for profile in profiles_to_delete:
            try:
                self.transport.atomic_delete_profile(profile)
            except (etcd.EtcdCompareFailed, etcd.EtcdKeyNotFound):
                # If the atomic CAD doesn't successfully delete, that's ok, it
                # means the profile was created or updated elsewhere.
                continue

    def _resync_changed_profiles(self, context, profiles_to_reconcile):
        """_resync_changed_profiles

        Reconcile all changed profiles by checking whether Neutron and etcd
        agree.
        """
        for etcd_profile in profiles_to_reconcile:
            # Get the data from etcd.
            try:
                etcd_profile = self.transport.get_profile_data(etcd_profile)
            except etcd.EtcdKeyNotFound:
                # The profile is gone. That's fine.
                LOG.info(
                    "Failed to update deleted profile %s", etcd_profile.id
                )
                continue

            # Get the data from Neutron.
            with self._txn_from_context(context, tag="resync-prof-changed"):
                rules = self.db.get_security_group_rules(
                    context, filters={'security_group_id': [etcd_profile.id]}
                )

            # Do the same conversion for the Neutron profile.
            neutron_profile = profile_from_neutron_rules(
                etcd_profile.id, rules
            )

            if not profiles_match(etcd_profile, neutron_profile):
                # Write to etcd.
                LOG.warning("Resolving error in profile %s", etcd_profile.id)

                try:
                    self.transport.write_profile_to_etcd(
                        neutron_profile,
                        prev_rules_index=etcd_profile.rules_modified_index,
                        prev_tags_index=etcd_profile.tags_modified_index,
                    )
                except (etcd.EtcdCompareFailed, etcd.EtcdKeyNotFound):
                    # If someone wrote to etcd they probably have more recent
                    # data than us, let it go.
                    LOG.info("Atomic CAS failed, no action.")
                    continue

    def add_port_interface_name(self, port):
        port['interface_name'] = 'tap' + port['id'][:11]

    def get_security_groups_for_port(self, context, port):
        """Checks which security groups apply for a given port.

        Frustratingly, the port dict provided to us when we call get_port may
        actually be out of date, and I don't know why. This change ensures that
        we get the most recent information.
        """
        filters = {'port_id': [port['id']]}
        bindings = self.db._get_port_security_group_bindings(
            context, filters=filters
        )
        return [binding['security_group_id'] for binding in bindings]

    def get_fixed_ips_for_port(self, context, port):
        """Obtains a complete list of fixed IPs for a port.

        Much like with security groups, for some insane reason we're given an
        out of date port dictionary when we call get_port. This forces an
        explicit query of the IPAllocation table to get the right data out of
        Neutron.
        """
        return [
            {'subnet_id': ip['subnet_id'], 'ip_address': ip['ip_address']}
            for ip in context.session.query(
                models_v2.IPAllocation
            ).filter_by(
                port_id=port['id']
            )
        ]

    def get_floating_ips_for_port(self, context, port):
        """Obtains a list of floating IPs for a port."""
        return [
            {'int_ip': ip['fixed_ip_address'],
             'ext_ip': ip['floating_ip_address']}
            for ip in context.session.query(
                l3_db.FloatingIP
            ).filter_by(
                fixed_port_id=port['id']
            )
        ]

    def add_extra_port_information(self, context, port):
        """add_extra_port_information

        Gets extra information for a port that is needed before sending it to
        etcd.
        """
        port['fixed_ips'] = self.get_fixed_ips_for_port(
            context, port
        )
        port['floating_ips'] = self.get_floating_ips_for_port(
            context, port
        )
        port['security_groups'] = self.get_security_groups_for_port(
            context, port
        )
        self.add_port_gateways(port, context)
        self.add_port_interface_name(port)
        return port


# This section monkeypatches the AgentNotifierApi.security_groups_rule_updated
# method to ensure that the Calico driver gets told about security group
# updates at all times. This is a deeply unpleasant hack. Please, do as I say,
# not as I do.
#
# For more info, please see issues #635 and #641.
original_sgr_updated = rpc.AgentNotifierApi.security_groups_rule_updated


def security_groups_rule_updated(self, context, sgids):
    LOG.info("security_groups_rule_updated: %s %s" % (context, sgids))
    mech_driver.send_sg_updates(sgids, context)
    original_sgr_updated(self, context, sgids)


rpc.AgentNotifierApi.security_groups_rule_updated = (
    security_groups_rule_updated
)


def profile_from_neutron_rules(profile_id, rules):
    """Build a set of Neutron rules into a ``SecurityProfile`` object."""
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


def port_status_change(port, original):
    """port_status_change

    Checks whether a port update is being called for a port status change
    event.

    Port activation events are triggered by our own action: if the only change
    in the port dictionary is activation state, we don't want to do any
    processing.
    """
    # Be defensive here: if Neutron is going to use these port dicts later we
    # don't want to have taken away data they want. Take copies.
    port = port.copy()
    original = original.copy()

    port.pop('status')
    original.pop('status')

    if port == original:
        return True
    else:
        return False


def port_bound(port):
    """Returns true if the port is bound."""
    return port['binding:vif_type'] != 'unbound'


def profiles_match(etcd_profile, neutron_profile):
    """profiles_match

    Given a set of Neutron security group rules and a Profile read from etcd,
    compare if they're the same.

    :param etcd_profile: A Profile object from etcd.
    :param neutron_profile: A SecurityProfile object from Neutron.
    :returns: True if the rules are identical, False otherwise.
    """
    # Convert the etcd data into in-memory data structures.
    try:
        etcd_rules = json.loads(etcd_profile.rules_data)
        etcd_tags = json.loads(etcd_profile.tags_data)
    except (ValueError, TypeError):
        # If the JSON data is bad, log it then treat this as not matching
        # Neutron.
        LOG.exception("Bad JSON data in key %s", etcd_profile.key)
        return False

    # Do the same conversion for the Neutron profile.
    neutron_group_rules = t_etcd.profile_rules(neutron_profile)
    neutron_group_tags = t_etcd.profile_tags(neutron_profile)

    return (
        (etcd_rules == neutron_group_rules) and
        (etcd_tags == neutron_group_tags)
    )


def felix_agent_state(hostname, start_flag=False):
    """felix_agent_state

    :param bool start_flag: True if this is a new felix, that is starting up.
           False if this is a refresh of an existing felix.
    :returns dict: agent status dict appropriate for inserting into Neutron DB.
    """
    state = {'agent_type': AGENT_TYPE_FELIX,
             'binary': AGENT_ID_FELIX,
             'host': hostname,
             'topic': constants.L2_AGENT_TOPIC}
    if start_flag:
        # Felix has told us that it has only just started, report that to
        # neutron, which will use it to reset its view of the uptime.
        state['start_flag'] = True
    return state
