# -*- coding: utf-8 -*-
#
# Copyright (c) 2014, 2015 Metaswitch Networks
# Copyright (c) 2013 OpenStack Foundation
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

# Calico/OpenStack Plugin
#
# This module is the OpenStack-specific implementation of the Plugin component
# of the new Calico architecture (described by the "Calico Architecture"
# document at http://docs.projectcalico.org/en/latest/architecture.html).
#
# It is implemented as a Neutron/ML2 mechanism driver.
import contextlib
from functools import wraps
import inspect
import os
import re
import uuid

# OpenStack imports.
import eventlet
from eventlet.queue import PriorityQueue
from eventlet.semaphore import Semaphore
from neutron.agent import rpc as agent_rpc

try:
    from neutron_lib.agent import topics
except ImportError:
    # Neutron code prior to d996758fb4 (13th March 2018).
    from neutron.common import topics
try:
    from neutron_lib import context as ctx
except ImportError:
    # Neutron code prior to ca751a1486 (6th March 2017).
    from neutron import context as ctx
try:
    from neutron_lib.plugins.ml2 import api
except ImportError:
    # Neutron code prior to a2c36d7e (10th November 2017).
    from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from sqlalchemy import exc as sa_exc

# Monkeypatch import
import neutron.plugins.ml2.rpc as rpc

# Calico imports.
from networking_calico.common import config as calico_config
from networking_calico.common import intern_string
from networking_calico.compat import cfg
from networking_calico.compat import constants
from networking_calico.compat import db_exc
from networking_calico.compat import lockutils
from networking_calico.compat import log
from networking_calico.compat import n_exc
from networking_calico.compat import plugin_dir
from networking_calico import datamodel_v1
from networking_calico import datamodel_v2
from networking_calico import datamodel_v3
from networking_calico import etcdv3
from networking_calico.logutils import logging_exceptions
from networking_calico.monotonic import monotonic_time
from networking_calico.plugins.ml2.drivers.calico.election import Elector
from networking_calico.plugins.ml2.drivers.calico.endpoints import \
    _port_is_endpoint_port
from networking_calico.plugins.ml2.drivers.calico.endpoints import \
    WorkloadEndpointSyncer
from networking_calico.plugins.ml2.drivers.calico.policy import PolicySyncer
from networking_calico.plugins.ml2.drivers.calico.status import StatusWatcher
from networking_calico.plugins.ml2.drivers.calico.subnets import SubnetSyncer

# Imports for a Keystone client.
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3.client import Client as KeystoneClient

LOG = log.getLogger(__name__)

calico_opts = [
    cfg.IntOpt('num_port_status_threads', default=4,
               help="Number of threads to use for writing port status "
                    "updates to the database."),
    cfg.IntOpt('etcd_compaction_period_mins', default=60,
               help="Interval in minutes between periodic etcd compactions. "
                    "A setting of 0 tells this Calico driver not to request "
                    "any etcd compaction; in that case the deployment must "
                    "take its own steps to prevent the etcd database from "
                    "growing without any disk usage bound."),
    cfg.IntOpt('etcd_compaction_min_revisions', default=1000,
               help="The minimum number of revisions to keep when requesting "
                    "an etcd compaction.  We also keep at least the history "
                    "of the previous etcd_compaction_period_mins interval."),
    cfg.IntOpt('project_name_cache_max', default=100,
               help="The maximum allowed size of our cache of project names."),
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

# Set a low refresh interval on the master key.  This reduces the chance of
# the etcd event buffer wrapping while non-masters are waiting for the key to
# be refreshed.
MASTER_REFRESH_INTERVAL = 10
MASTER_TIMEOUT = 60

PRIORITY_HIGH = 0
PRIORITY_LOW = 1
PRIORITY_RETRY = 2

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
        self._post_fork_init()
        return f(self, *args, **kwargs)

    return wrapper


class CalicoMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Neutron/ML2 mechanism driver for Project Calico.

    CalicoMechanismDriver communicates information about endpoints and security
    configuration, via etcd, to the Felix and DHCP agent instances running on
    each compute host.
    """

    def __init__(self):
        super(CalicoMechanismDriver, self).__init__(
            AGENT_TYPE_FELIX,
            'tap',
            {'port_filter': True,
             'mac_address': '00:61:fe:ed:ca:fe'})
        # Lock to prevent concurrent initialisation.
        self._init_lock = Semaphore()
        # Generally initialize attributes to nil values.  They get initialized
        # properly, as needed, in _post_fork_init().
        self.db = None
        self.elector = None
        self._agent_update_context = None
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
        # * we don't recreate the queue in _post_fork_init() so that we can't
        #   possibly lose updates that had already been queued.
        # * the queue contains tuples (priority, <status key>); we use a
        #   higher priority for events and a lower priority for snapshot
        #   keys, so that current data skips the queue.
        self._port_status_queue = PriorityQueue()
        self._port_status_queue_too_long = False

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
        eventlet.spawn_after(STARTUP_DELAY_SECS, self._post_fork_init)
        LOG.info("Created Calico mechanism driver %s", self)

    @logging_exceptions(LOG)
    def _post_fork_init(self):
        """_post_fork_init

        Creates the connection state required for talking to the Neutron DB
        and to etcd. This is a no-op if it has been executed before.

        This is split out from __init__ to allow us to defer this
        initialisation until after Neutron has forked off its worker
        children.  If we initialise the DB and etcd connections before
        the fork (as would happen in __init__()) then the workers
        would share sockets incorrectly.
        """
        # The self._init_lock semaphore mediates if two or more eventlet
        # threads call _post_fork_init at the same time, within the same
        # Neutron server fork.  This can happen if the timed initialization
        # (after STARTUP_DELAY_SECS) coincides with the handling of a Neutron
        # API request, or if this fork processes multiple Neutron API requests
        # at the same time.
        with self._init_lock:
            current_pid = os.getpid()
            if self._my_pid == current_pid:
                # We've initialised our PID and it hasn't changed since last
                # time, nothing to do.
                LOG.info("Calico state already initialised for PID %s",
                         current_pid)
                return
            # else: either this is the first call or our PID has changed:
            # (re)initialise.

            if self._my_pid is not None:
                # This is unexpected but we can deal with it: Neutron should
                # fork before we trigger the first call to _post_fork_init!().
                LOG.warning("PID changed from %s to %s; unexpected fork after "
                            "initialisation?  Reinitialising Calico driver.",
                            self._my_pid, current_pid)
            else:
                LOG.info("Doing Calico mechanism driver initialisation in"
                         " process %s", current_pid)

            # (Re)init the DB.
            self.db = None
            self._get_db()

            # Create a Keystone client.
            authcfg = cfg.CONF.keystone_authtoken
            LOG.debug("authcfg = %r", authcfg)
            for key in authcfg:
                if 'password' in key:
                    LOG.debug("authcfg[%s] = %s", key, '***')
                else:
                    LOG.debug("authcfg[%s] = %s", key, authcfg[key])

            # Compatibility with older versions of openstack [mitaka and below]
            try:
                user_domain_name = authcfg.user_domain_name
            except cfg.NoSuchOptError:
                user_domain_name = 'Default'
                LOG.debug("authcfg[user_domain_name] fallback = %s",
                          user_domain_name)

            try:
                username = authcfg.username
            except cfg.NoSuchOptError:
                username = authcfg.admin_user
                LOG.debug("authcfg[username] fallback[admin_user] = %s",
                          username)

            try:
                password = authcfg.password
            except cfg.NoSuchOptError:
                password = authcfg.admin_password
                LOG.debug("authcfg[password] fallback[admin_password] = %s",
                          '***')

            try:
                project_domain_name = authcfg.project_domain_name
            except cfg.NoSuchOptError:
                project_domain_name = 'Default'
                LOG.debug("authcfg[project_domain_name] fallback = %s",
                          project_domain_name)

            try:
                project_name = authcfg.project_name
            except cfg.NoSuchOptError:
                project_name = authcfg.admin_tenant_name
                LOG.debug("authcfg[project_name] fallback[admin_tenant_name]"
                          " = %s", project_name)

            try:
                auth_url = authcfg.auth_url
            except cfg.NoSuchOptError:
                auth_url = authcfg.identity_uri
                LOG.debug("authcfg[auth_url] fallback[identity_uri] = %s",
                          auth_url)

            auth = v3.Password(user_domain_name=user_domain_name,
                               username=username,
                               password=password,
                               project_domain_name=project_domain_name,
                               project_name=project_name,
                               auth_url=re.sub(r'/v3/?$', '', auth_url) +
                               '/v3')
            sess = session.Session(auth=auth)
            keystone_client = KeystoneClient(session=sess)
            LOG.debug("Keystone client = %r", keystone_client)

            # Create syncers.
            self.subnet_syncer = \
                SubnetSyncer(self.db, self._txn_from_context)
            self.policy_syncer = \
                PolicySyncer(self.db, self._txn_from_context)
            self.endpoint_syncer = \
                WorkloadEndpointSyncer(self.db,
                                       self._txn_from_context,
                                       self.policy_syncer,
                                       keystone_client)

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

            # Elector, for performing leader election.
            self.elector = Elector(cfg.CONF.calico.elector_name,
                                   datamodel_v2.neutron_election_key(
                                       calico_config.get_region_string()),
                                   old_key=datamodel_v1.NEUTRON_ELECTION_KEY,
                                   interval=MASTER_REFRESH_INTERVAL,
                                   ttl=MASTER_TIMEOUT)

            self._my_pid = current_pid

            # Start our resynchronization process and status updating. Just in
            # case we ever get two same threads running, use an epoch counter
            # to tell the old thread to die.
            # We deliberately do this last, to ensure that all of the setup
            # above is complete before we start running.
            self._epoch += 1
            eventlet.spawn(self.periodic_resync_thread, self._epoch)
            eventlet.spawn(self._status_updating_thread, self._epoch)
            for _ in range(cfg.CONF.calico.num_port_status_threads):
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
            if self.elector.master():
                if self._etcd_watcher is None:
                    LOG.info("Became the master, starting StatusWatcher")
                    self._etcd_watcher = StatusWatcher(self)
                    self._etcd_watcher_thread = eventlet.spawn(
                        self._etcd_watcher.start
                    )
                    LOG.info("Started %s as %s",
                             self._etcd_watcher, self._etcd_watcher_thread)
                elif not self._etcd_watcher_thread:
                    LOG.error("StatusWatcher %s died", self._etcd_watcher)
                    self._etcd_watcher.stop()
                    self._etcd_watcher = None
            else:
                if self._etcd_watcher is not None:
                    LOG.warning("No longer master, stopping StatusWatcher")
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

    def on_port_status_changed(self, hostname, port_id, status_dict,
                               priority="low"):
        """Called when etcd tells us that a port status has changed.

        :param hostname: hostname of the host containing the port.
        :param port_id: the port ID.
        :param status_dict: new status dict for the port or None if the
               status was deleted.
        """
        port_status_key = (intern_string(hostname), port_id)
        # Unwrap the dict around the actual status.
        if status_dict is not None:
            # Update.
            calico_status = status_dict.get("status")
        else:
            # Deletion.
            calico_status = None

        # Check whether this update gives us new information to pass to
        # Neutron.  "high" priority updates come from changes spotted by Felix,
        # including interface flaps caused by, for example, VM rebuild.  In
        # those cases, we may be out-of-sync with Neutron because the
        # port can be marked as down/removed by another component.
        #
        # "low" priority updates come from datastore resyncs.  In those cases
        # we rely on our cache of port status to avoid spamming Neutron with
        # many no-op updates.  It _is_ possible for our cache to be out of
        # sync in the resync case too; however,
        #
        # - the impact on the database of sending port status updates to
        #   Neutron for all ports is significant (we do have to do it as
        #   start-of-day, because our cache is empty)
        #
        # - the impact of an incorrect port status for a normal, live VM is
        #   minimal (and it shouldn't get out of sync unless another component
        #   updates the port anyway, in which case they'll have updated the
        #   database)
        #
        # - the impact of missing an update for a VM that is being (re)built
        #   is that the VM (re)build fails; but if we're doing a resync then
        #   we must have been disconnected from the datastore and that means
        #   the (re)build is already likely to fail due to the disconnection.
        if (priority == "high" or
                self._port_status_cache.get(port_status_key) != calico_status):
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
                    interned_status = intern_string(calico_status)
                    self._port_status_cache[port_status_key] = interned_status
                else:
                    LOG.error("Unknown port status: %r", calico_status)
                    self._port_status_cache.pop(port_status_key, None)
            else:
                self._port_status_cache.pop(port_status_key, None)
            # Defer the actual update to the background thread so that we don't
            # hold up reading from etcd.  In particular, we don't want to block
            # Felix status updates while we wait on the DB.
            sortable_priority = (
                PRIORITY_HIGH if priority == "high" else PRIORITY_LOW,
                monotonic_time(),
            )
            self._port_status_queue.put((sortable_priority, port_status_key))
            qsize = self._port_status_queue.qsize()
            if qsize > 10:
                now = monotonic_time()
                if (now - self._last_status_queue_log_time >
                        QUEUE_WARN_LOG_INTERVAL_SECS):
                    LOG.warning("Port status update queue length is high: %s",
                                qsize)
                    self._last_status_queue_log_time = now
                    self._port_status_queue_too_long = True
                # Queue is getting large, make sure the DB writer threads
                # get CPU.
                eventlet.sleep()
            elif self._port_status_queue_too_long and qsize < 5:
                self._port_status_queue_too_long = False
                LOG.warning("Port status update queue back to normal: %s",
                            qsize)

    @logging_exceptions(LOG)
    def _loop_writing_port_statuses(self, expected_epoch):
        LOG.info("Port status write thread started epoch=%s", expected_epoch)
        admin_context = ctx.get_admin_context()
        while self._epoch == expected_epoch:
            # Wait for work to do.
            _, port_status_key = self._port_status_queue.get()
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
        except db_exc.DBError as e:
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
        except sa_exc.SQLAlchemyError as e:
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
        self._port_status_queue.put(((PRIORITY_RETRY, monotonic_time()),
                                     port_status_key))

    def _update_port_status_has_host_param(self):
        """Check whether update_port_status() supports the host parameter."""
        if self._cached_update_port_status_has_host_param is None:
            full_arg_spec = inspect.getfullargspec(
                self.db.update_port_status
            )
            args = full_arg_spec.args
            varkw = full_arg_spec.varkw
            has_host_param = varkw or "host" in args
            self._cached_update_port_status_has_host_param = has_host_param
            LOG.info("update_port_status() supports host arg: %s",
                     has_host_param)
        return self._cached_update_port_status_has_host_param

    def _get_db(self):
        if not self.db:
            self.db = plugin_dir.get_plugin()
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

    # For network and subnet actions we have nothing to do, so we provide these
    # no-op methods.
    def create_network_postcommit(self, context):
        LOG.info("CREATE_NETWORK_POSTCOMMIT: %s" % context)

    def update_network_postcommit(self, context):
        LOG.info("UPDATE_NETWORK_POSTCOMMIT: %s" % context)

    def delete_network_postcommit(self, context):
        LOG.info("DELETE_NETWORK_POSTCOMMIT: %s" % context)

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
                self.subnet_syncer.subnet_created(subnet, context)

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
                self.subnet_syncer.subnet_created(subnet, context)
            else:
                self.subnet_syncer.subnet_deleted(subnet['id'])

    @requires_state
    def delete_subnet_postcommit(self, context):
        LOG.info("DELETE_SUBNET_POSTCOMMIT: %s" % context)
        self.subnet_syncer.subnet_deleted(context.current['id'])

    # Idealised method forms.
    @requires_state
    def create_port_postcommit(self, context):
        """create_port_postcommit

        Called after Neutron has committed a port creation event to the
        database.

        Process this event by taking and holding a database transaction and
        re-reading the port. Once we do that, we know the port will remain
        unchanged while we hold the transaction. We can then write the port to
        etcd, along with any other information we may need.
        """
        LOG.info('CREATE_PORT_POSTCOMMIT: %s', context)
        port = context._port

        # Ignore if this is not an endpoint port.
        if not _port_is_endpoint_port(port):
            return

        # Ignore if the port binding VIF type is 'unbound'; then this port
        # doesn't need to be networked yet.
        if port['binding:vif_type'] == 'unbound':
            LOG.info("Creating unbound port: no work required.")
            return

        plugin_context = context._plugin_context
        with self._txn_from_context(plugin_context, tag="create-port"):
            self.endpoint_syncer.write_endpoint(port, plugin_context)

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
        if not _port_is_endpoint_port(port):
            return

        # If this port update is purely for a status change, don't do anything:
        # we don't care about port statuses.
        if port_status_change(port, original):
            LOG.info(' port status changed from %s to %s, no action.',
                     original.get("status"), port.get("status"))
            return

        # Re-read the port; we do this to guarantee correctly ordered handling
        # of multiple updates to the same port, when there are multiple Neutron
        # servers and so different updates could be processed on different
        # servers.  Imagine an update that changes KEY1=NEW1, and a following
        # update that changes KEY2=NEW2.  So the first update_port_postcommit
        # callback will have KEY1=NEW1 KEY2=OLD2 and the second callback will
        # have KEY1=NEW1 KEY2=NEW2.  Now suppose the 'second' callback executes
        # first, and in particular that its write hits the etcd datastore first.
        # Then the 'first' callback's write hits second and we can end up with
        # data in the datastore that corresponds to KEY1=NEW1 KEY2=OLD2.
        #
        # To eliminate that possibility of writing stale data, take a Neutron DB
        # transaction, re-read the latest available port data, and write
        # corresponding data into etcd while still holding the Neutron DB
        # transaction.
        plugin_context = context._plugin_context
        with self._txn_from_context(plugin_context, tag="update-port"):

            # If the port was previously bound, the endpoint should already
            # exist.
            endpoint_should_already_exist = port_bound(original)

            # Check for migration so that we can reliably delete the
            # WorkloadEndpoint on the old host.
            if original['binding:host_id'] != port['binding:host_id']:
                LOG.info("Migration, delete WorkloadEndpoint on old host %s",
                         original['binding:host_id'])
                self.endpoint_syncer.delete_endpoint(original)
                endpoint_should_already_exist = False

            try:
                port = self.db.get_port(plugin_context, port['id'])
            except n_exc.PortNotFound:
                LOG.info("Port no longer exists")
                return

            # Now, fork execution based on the type of update we're performing.
            # There are a few:
            # - a pre live-migration notice (binding profile has a migrating_to
            #   key with the future nova-compute host as the value), which we
            #   do nothing with right now.
            # - a port becoming bound (binding vif_type from unbound to bound);
            # - a port becoming unbound (binding vif_type from bound to
            #   unbound);
            # - an update (port bound at all times);
            # - a change to an unbound port (which we don't care about, because
            #   we do nothing with unbound ports).
            if port.get('binding:profile', {}).get('migrating_to') is not None:
                LOG.debug("Pre-live-migration notification message: no action")
            elif port_bound(port):
                if endpoint_should_already_exist:
                    LOG.info("Port update")
                    self.endpoint_syncer.write_endpoint(port,
                                                        plugin_context,
                                                        must_update=True)
                else:
                    LOG.info("Port becoming bound: create.")
                    self.endpoint_syncer.write_endpoint(port,
                                                        plugin_context)
            elif endpoint_should_already_exist:
                LOG.info("Port becoming unbound: destroy.")
                self.endpoint_syncer.delete_endpoint(original)
            else:
                LOG.info("Update on unbound port: no action")

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
        if not _port_is_endpoint_port(port):
            return

        self.endpoint_syncer.delete_endpoint(port)

    @requires_state
    def send_sg_updates(self, sgids, context):
        """Called whenever security group rules or membership change.

        When a security group rule is added, we need to do the following steps:

        1. Reread the security rules from the Neutron DB.
        2. Write the updated policy to etcd.
        """
        LOG.info("Updating security group IDs %s", sgids)
        with self._txn_from_context(context, tag="sg-update"):
            self.policy_syncer.write_sgs_to_etcd(sgids, context)

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

    def _update_port(self, plugin_context, port):
        """_update_port

        This method assumes it's being called from within a database
        transaction and does not take out another one.
        """
        LOG.info("Updating port %s", port)

        if port_bound(port):
            LOG.info("Port bound, attempting to update.")
            self.endpoint_syncer.write_endpoint(port,
                                                plugin_context,
                                                must_update=True)
        else:
            LOG.info("Port unbound, attempting delete if needed.")
            self.endpoint_syncer.delete_endpoint(port)

    def periodic_resync_thread(self, expected_epoch):
        """Periodic Neutron DB -> etcd resynchronization logic.

        On a fixed interval, spin over relevant Neutron DB objects and
        reconcile them with etcd, ensuring that the etcd database and Neutron
        are in synchronization with each other.
        """
        try:
            LOG.info("Periodic resync thread started")
            while self._epoch == expected_epoch:
                # Only do the resync logic if we're actually the master node.
                if self.elector.master():
                    LOG.info("I am master: doing periodic resync")

                    # Since this thread is not associated with any particular
                    # request, we use our own admin context for accessing the
                    # database.
                    admin_context = ctx.get_admin_context()

                    try:
                        # Resync subnets.
                        self.subnet_syncer.resync(admin_context)

                        # Resync policies.  Do this before endpoints because
                        # it's worse to have incorrect or missing policy for a
                        # known endpoint, than it is to have a briefly
                        # incorrect or missing endpoint.
                        self.policy_syncer.resync(admin_context)

                        # Resync endpoints.
                        self.endpoint_syncer.resync(admin_context)

                        # Resync ClusterInformation and FelixConfiguration.
                        self.provide_felix_config()

                        # Possibly request an etcd compaction.
                        check_request_etcd_compaction()
                    except Exception:
                        LOG.exception("Error in periodic resync thread.")
                    # Reschedule ourselves.
                    eventlet.sleep(RESYNC_INTERVAL_SECS)
                else:
                    # Shorter sleep interval before we check if we've become
                    # the master.  Avoids waiting a whole RESYNC_INTERVAL_SECS
                    # if we just miss the master update.
                    LOG.debug("I am not master")
                    eventlet.sleep(MASTER_CHECK_INTERVAL_SECS)
        except Exception:
            # TODO(nj) Should we tear down the process.
            LOG.exception("Periodic resync thread died!")
            if self.elector:
                # Stop the elector so that we give up the mastership.
                self.elector.stop()
            raise
        else:
            LOG.warning("Periodic resync thread exiting.")

    @etcdv3.logging_exceptions
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
                    uuid.uuid4().hex
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
                                    datamodel_v3.NOT_NAMESPACED,
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
                                    datamodel_v3.NOT_NAMESPACED,
                                    "default",
                                    felix_config,
                                    mod_revision=fc_mod_revision):
                    rewrite_felix_config = False
                else:
                    # Short sleep to avoid a tight loop.
                    eventlet.sleep(1)


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


COMPACTION_PREFIX = "/calico/compaction/v1/"
COMPACTION_TRIGGER_KEY = COMPACTION_PREFIX + "trigger"
COMPACTION_LAST_KEY = COMPACTION_PREFIX + "last"


def check_request_etcd_compaction():
    """Possibly request an etcd compaction.

    Without any compaction, etcd's disk usage will grow without bound because
    of it retaining previous revisions for all known keys.  Compaction, at a
    particular revision, tells etcd to forget the detailed information for all
    revisions before that, and so keeps etcd memory usage in check.

    By default, therefore, networking-calico requests an etcd compaction every
    60 minutes.  This period is controlled by the etcd_compaction_period_mins
    config setting, and requesting compaction can be disabled by setting that
    to 0.

    Each time we consider a compaction, we ensure that we retain history for
    the previous etcd_compaction_period_mins interval, and also for at least
    the last etcd_compaction_min_revisions revisions.

    We piggyback on the master election infrastructure so that only one thread
    of the Neutron server requests compaction, each time that it becomes due.
    """
    # If periodic etcd compaction is disabled, do nothing here.
    if cfg.CONF.calico.etcd_compaction_period_mins == 0:
        return

    try:
        # Try to read the compaction trigger key.
        try:
            _, _, lease = etcdv3.get(COMPACTION_TRIGGER_KEY, with_lease=True)

            # No exception, so the key still exists.  Check that it still has a
            # lease and TTL as expected.  (For example, the lease could be
            # missing or have an unreasonably large TTL, if the etcd cluster
            # has been restarted after restoring from an incomplete or corrupt
            # backup.)
            if lease is None:
                # Start from scratch as though neither of the compaction keys
                # is present.
                LOG.warning("Compaction key has lost its lease; rewriting")
                write_compaction_keys(0)
                return

            # We're now going to sanity check the lease, but that involves
            # further requests to the etcd server, and it's possible for those
            # to fail if the lease is expiring _right now_.  We will catch that
            # and handle it the same as if the key was not there.
            try:
                ttl = lease.ttl()
                if ttl > cfg.CONF.calico.etcd_compaction_period_mins * 60:
                    # Start from scratch as though neither of the compaction
                    # keys is present.
                    LOG.warning("Unreasonably large lease TTL (%r)", ttl)
                    write_compaction_keys(0)
                    return

                # Lease is there and TTL is reasonable: just wait for more time
                # to pass then.
                LOG.info("Compaction trigger TTL is %r", ttl)
                return
            except (etcdv3.Etcd3Exception, KeyError) as e:
                # Etcd3Exception "Not Found" is expected if the lease has just
                # expired and been removed.  We can also get KeyError 'TTL'
                # because of JSON missing the 'TTL' field; for example here's
                # what we see if we create a lease with TTL 5s and then query
                # it every 0.5s:
                #
                # {..., 'grantedTTL': '5', 'ID': '75...', 'TTL': '4'}
                # {..., 'grantedTTL': '5', 'ID': '75...', 'TTL': '4'}
                # {..., 'grantedTTL': '5', 'ID': '75...', 'TTL': '3'}
                # {..., 'grantedTTL': '5', 'ID': '75...', 'TTL': '3'}
                # {..., 'grantedTTL': '5', 'ID': '75...', 'TTL': '2'}
                # {..., 'grantedTTL': '5', 'ID': '75...', 'TTL': '2'}
                # {..., 'grantedTTL': '5', 'ID': '75...', 'TTL': '1'}
                # {..., 'grantedTTL': '5', 'ID': '75...', 'TTL': '1'}
                # {..., 'ID': '75...', 'grantedTTL': '5'}
                # {..., 'ID': '75...', 'grantedTTL': '5'}
                # {..., 'ID': '75...', 'grantedTTL': '5'}
                # {..., 'ID': '75...', 'TTL': '-1'}
                # {..., 'ID': '75...', 'TTL': '-1'}
                # {..., 'ID': '75...', 'TTL': '-1'}
                #
                # Strange but true!
                LOG.info("Lease expired as we were checking it: %r", e)

                # Now fall through to the code below to consider requesting a
                # compaction.

        except etcdv3.KeyNotFound:
            # The key has timed out, so etcd_compaction_period_mins has passed
            # since the last time we considered compaction.  (Or else the key
            # has never existed yet.)
            pass

        # Find out when the last compaction happened, and what the current
        # revision was etcd_compaction_period_mins ago.
        try:
            last_compaction_rev, last_check_rev = etcdv3.get(
                COMPACTION_LAST_KEY
            )
            last_compaction_rev = int(last_compaction_rev)
            last_check_rev = int(last_check_rev)
            LOG.info("Last compaction %r, last check %r",
                     last_compaction_rev, last_check_rev)
        except etcdv3.KeyNotFound:
            # This is the first time we've checked for compaction.  No
            # possibility of compacting this time, because we always want to
            # keep history for at least one etcd_compaction_period_mins
            # interval, and we can't yet tell what that means.  Write the keys
            # so that we will be able to tell this next time round.
            LOG.info("First check")
            write_compaction_keys(0)
            return

        # Get the current revision.
        _, current_revision = etcdv3.get_status()
        current_revision = int(current_revision)
        LOG.info("Current etcd revision is %r", current_revision)

        # Defensive sanity check that the read last_compaction_rev is less than
        # the current revision.  Conceivably a user could restore from backup
        # and throw off the revisions.  In that case, rewrite the keys with
        # last_compaction 0 and returning without compacting.  (Note: it isn't
        # possible for last_check_rev to be similarly bogus, because it is
        # current etcd cluster metadata from the same source as
        # current_revision.)
        if last_compaction_rev > current_revision:
            LOG.info("Bogus last compaction revision (%r > %r)",
                     last_compaction_rev,
                     current_revision)
            write_compaction_keys(0)
            return

        # We must keep at least etcd_compaction_min_revisions of history.  If
        # there aren't that many yet, we can't compact.
        if current_revision <= cfg.CONF.calico.etcd_compaction_min_revisions:
            LOG.info("Not enough revisions to compact yet (%r <= %r)",
                     current_revision,
                     cfg.CONF.calico.etcd_compaction_min_revisions)
            # Note: there could still be a non-zero last_compaction_rev here,
            # if the Neutron server has been restarted with an increased value
            # of etcd_compaction_min_revisions.
            write_compaction_keys(last_compaction_rev)
            return

        # Calculate the amount of history to keep.  This must be at least
        # etcd_compaction_min_revisions.
        keep_revisions = cfg.CONF.calico.etcd_compaction_min_revisions
        # But must also be at least the history of the whole previous
        # etcd_compaction_period_mins interval.
        if keep_revisions < (current_revision - last_check_rev):
            keep_revisions = current_revision - last_check_rev

        # So that would mean compacting at:
        compact_revision = current_revision - keep_revisions

        if compact_revision <= last_compaction_rev:
            # We've already compacted at or after that revision.  Wait for more
            # time to pass, or history to accumulate.
            LOG.info("No compactable history yet (%r <= %r)",
                     compact_revision, last_compaction_rev)
            write_compaction_keys(last_compaction_rev)
            return

        # Request compaction at that revision.
        LOG.info("Request compaction at %r", compact_revision)
        try:
            etcdv3.request_compaction(compact_revision)
        except etcdv3.Etcd3Exception as e3e:
            # An exception here most likely means that the revision we're
            # asking to compact at has already been compacted - which means
            # that there is some other service in the deployment which is also
            # taking some responsibility for etcd compaction.  (For example, it
            # could be libcalico-go.)
            #
            # In that case, and given that it isn't straightforward for us to
            # discover exactly what the current compacted revision is, just
            # imagine that it's the same as the current revision.  That means
            # that this code won't consider compacting again until another
            # etcd_compaction_min_revisions revisions and
            # etcd_compaction_period_mins minutes have passed.
            #
            # (On the other hand, if the exception is for some other reason
            # such as connectivity to the etcd cluster, the following write
            # will hit that too, and that will be handled below.)
            LOG.info("Someone else has requested etcd compaction:\n%s",
                     e3e.detail_text)
            write_compaction_keys(current_revision)
            return

        # Record the new compaction revision.
        write_compaction_keys(compact_revision)
    except Exception:
        # Something wrong with etcd connectivity; clearly then we can't do any
        # compaction.  Just log, and we'll try again on the next resync.
        LOG.exception("Failed to check/request compaction")


def write_compaction_keys(compaction_revision):
    # Write the last key to record the last compaction and check revisions (the
    # latter implicitly, as mod_revision).
    if not etcdv3.put(COMPACTION_LAST_KEY, str(compaction_revision)):
        # Writing should always succeed; but in case it doesn't we will retry
        # as part of the next resync, so just a warning is sufficient here.
        LOG.warning("Failed to write %s", COMPACTION_LAST_KEY)

    # Write the trigger key, with TTL such that it will disappear again after
    # etcd_compaction_period_mins.
    lease = etcdv3.get_lease(
        cfg.CONF.calico.etcd_compaction_period_mins * 60
    )
    if not etcdv3.put(COMPACTION_TRIGGER_KEY, str(os.getpid()), lease=lease):
        # Writing should always succeed; but in case it doesn't we will retry
        # as part of the next resync, so just a warning is sufficient here.
        LOG.warning("Failed to write %s", COMPACTION_TRIGGER_KEY)
