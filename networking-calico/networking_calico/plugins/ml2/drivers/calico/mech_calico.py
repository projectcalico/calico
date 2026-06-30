# -*- coding: utf-8 -*-
#
# Copyright (c) 2014, 2015 Metaswitch Networks
# Copyright (c) 2013 OpenStack Foundation
# Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.
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
import inspect
import multiprocessing
import os
import threading
import time

import eventlet
from eventlet.queue import PriorityQueue

from neutron.agent import rpc as agent_rpc
from neutron.conf.agent import common as config
from neutron.objects import ports as ports_object
from neutron.objects.qos import policy as policy_object
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2.drivers import mech_agent

from neutron_lib import constants
from neutron_lib import context as ctx
from neutron_lib import exceptions as n_exc
from neutron_lib.agent import topics
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.plugins import directory as plugin_dir
from neutron_lib.plugins.ml2 import api

from oslo_config import cfg

import oslo_context

from oslo_db import exception as db_exc
from oslo_db import options as oslo_db_options

from oslo_log import log

from sqlalchemy import exc as sa_exc

from networking_calico import datamodel_v1
from networking_calico import datamodel_v2
from networking_calico import datamodel_v3
from networking_calico import etcdv3
from networking_calico.common import config as calico_config
from networking_calico.common import intern_string
from networking_calico.logutils import logging_exceptions
from networking_calico.monotonic import monotonic_time
from networking_calico.plugins.ml2.drivers.calico import qos_driver
from networking_calico.plugins.ml2.drivers.calico.election import Elector
from networking_calico.plugins.ml2.drivers.calico.endpoints import (
    WorkloadEndpointSyncer,
    _port_is_endpoint_port,
    endpoint_name,
)
from networking_calico.plugins.ml2.drivers.calico.policy import PolicySyncer
from networking_calico.plugins.ml2.drivers.calico.status import (
    AgentStatusWatcher,
    EndpointStatusWatcher,
)
from networking_calico.plugins.ml2.drivers.calico.subnets import SubnetSyncer
from networking_calico.plugins.ml2.drivers.calico.workers import (
    CalicoStartupResyncWorker,
    CalicoManagerWorker,
    CalicoAgentStatusWatcherWorker,
    CalicoEndpointStatusWatcherWorker,
)
from networking_calico.resync import scope as resync


# Register [AGENT] options, which we need in order to successfully use
# PluginReportStateAPI.
config.register_agent_state_opts_helper(cfg.CONF)

LOG = log.getLogger(__name__)


calico_opts = [
    cfg.IntOpt(
        "num_port_status_threads",
        default=4,
        help=(
            "Number of threads to use for writing port status updates to the database."
        ),
    ),
    cfg.IntOpt(
        "etcd_compaction_period_mins",
        default=60,
        help=(
            "Interval in minutes between periodic etcd compactions. "
            "A setting of 0 tells this Calico driver not to request "
            "any etcd compaction; in that case the deployment must "
            "take its own steps to prevent the etcd database from "
            "growing without any disk usage bound."
        ),
    ),
    cfg.IntOpt(
        "etcd_compaction_min_revisions",
        default=1000,
        help=(
            "The minimum number of revisions to keep when requesting "
            "an etcd compaction.  We also keep at least the history "
            "of the previous etcd_compaction_period_mins interval."
        ),
    ),
    cfg.IntOpt(
        "project_name_cache_max",
        default=100,
        help="The maximum allowed size of our cache of project names.",
    ),
    cfg.StrOpt(
        "startup_resync",
        default="always",
        choices=["always", "never"],
        help=(
            "Whether the driver should run a full Neutron DB -> etcd "
            "resync when neutron-server starts.  Note that a resync "
            "can also be run on demand using the calico-resync CLI."
        ),
    ),
    cfg.IntOpt(
        "resync_interval_secs",
        default=0,
        deprecated_for_removal=True,
        deprecated_reason=(
            "The driver no longer runs a periodic resync thread. "
            "Resync is now driven once on startup and on demand "
            "via the calico-resync CLI.  This option has no effect."
        ),
        help="Deprecated and unused.  Retained to avoid neutron.conf errors.",
    ),
    cfg.IntOpt(
        "resync_max_interval_secs",
        default=0,
        deprecated_for_removal=True,
        deprecated_reason=(
            "The driver no longer runs a periodic resync thread, so "
            "there is no inter-resync interval to police.  This option "
            "has no effect."
        ),
        help="Deprecated and unused.  Retained to avoid neutron.conf errors.",
    ),
    cfg.BoolOpt(
        "fairy_gc_diagnostics",
        default=False,
        help=(
            "DIAGNOSTIC: install SQLAlchemy event listeners that "
            "capture a stack trace at every connection-pool checkout "
            "and detect when a connection-checkin (typically fired by "
            "GC of a session) is happening in the eventlet hub "
            "greenlet -- a failure mode in which oslo.db's "
            "_thread_yield listener calls time.sleep(0) -> "
            "hub.switch() and deadlocks because the hub greenlet "
            "cannot switch to itself.  When the in-hub case is "
            "detected, the originating-checkout stack is logged at "
            "WARNING so the leaking code path can be identified.  See "
            "the module docstring in "
            "networking_calico/plugins/ml2/drivers/calico/"
            "fairy_gc_diagnostics.py for the full failure-mode "
            "explanation.  Default off because the per-checkout stack "
            "capture adds non-trivial overhead at high "
            "connection-churn rates; enable when investigating a "
            "suspected occurrence."
        ),
    ),
    cfg.IntOpt(
        "startup_resync_inject_per_item_delay_ms",
        default=0,
        min=0,
        help=(
            "TEST-ONLY: when non-zero, the start-of-day resync sleeps "
            "this many milliseconds between every step of its endpoints "
            "compare loop.  Used by the resync-concurrency test "
            "(CORE-12037) to stretch the resync to a known duration "
            "while dynamic operations are timed against it.  Never set "
            "this in production."
        ),
    ),
]
cfg.CONF.register_opts(calico_opts, "calico")

# In order to rate limit warning logs about queue lengths, we check if we've
# already logged within this interval (seconds) before logging.
QUEUE_WARN_LOG_INTERVAL_SECS = 10

# An OpenStack agent type name for Felix, the Calico agent component in the new
# architecture.
AGENT_TYPE_FELIX = "Calico per-host agent (felix)"
AGENT_ID_FELIX = "calico-felix"

# Mapping from our endpoint status to neutron's port status.
PORT_STATUS_MAPPING = {
    datamodel_v1.ENDPOINT_STATUS_UP: constants.PORT_STATUS_ACTIVE,
    datamodel_v1.ENDPOINT_STATUS_DOWN: constants.PORT_STATUS_DOWN,
    datamodel_v1.ENDPOINT_STATUS_ERROR: constants.PORT_STATUS_ERROR,
}

# When we're not the master, how often we check if we have become the master.
MASTER_CHECK_INTERVAL_SECS = 5
# Delay before retrying a failed port status update to the Neutron DB.
PORT_UPDATE_RETRY_DELAY_SECS = 5

# Set a low refresh interval on the master key.  This reduces the chance of
# the etcd event buffer wrapping while non-masters are waiting for the key to
# be refreshed.
MASTER_REFRESH_INTERVAL = 10
MASTER_TIMEOUT = 60

PRIORITY_HIGH = 0
PRIORITY_LOW = 1
PRIORITY_RETRY = 2


def _close_session_safely(context):
    """Close the session on an admin context, swallowing any error.

    Background threads (currently just _loop_writing_port_statuses)
    create their own admin contexts and are responsible for cleaning
    up the session when they're done with it for this cycle.  If we
    leave it open, GC may eventually trigger a rollback on the
    eventlet hub greenlet -- which raises an AssertionError from
    eventlet because the hub is not allowed to do blocking I/O.
    """
    try:
        session = getattr(context, "session", None)
        if session is not None:
            session.close()
    except Exception:
        LOG.exception("Failed to close admin context session; ignoring.")


def _check_mysql_driver():
    """One-shot validation that the configured MySQL driver is acceptable.

    Reads [database] connection from oslo.config directly so the check works
    before any context/session exists.  Since 2015 it has been expected
    that anyone using MySQL also uses the PyMySQL driver, to avoid the
    problem described in https://bugs.launchpad.net/oslo.db/+bug/1350149.

    Call once per process at start of day -- from
    CalicoMechanismDriver.initialize() for the driver path, and from
    networking_calico.resync.cli.main() / Scope.run() for the resync path.
    """
    # Ensure the [database] option group is registered.  In neutron-server's
    # startup, ML2 ``mechanism_manager.initialize()`` runs during plugin
    # __init__, before anything has imported oslo.db's enginefacade -- which
    # is what would otherwise side-effect-register this group.  Registering
    # the opts ourselves is idempotent and decouples us from Neutron's
    # startup ordering.
    cfg.CONF.register_opts(oslo_db_options.database_opts, "database")
    conn_url = (cfg.CONF.database.connection or "").lower()
    if conn_url.startswith("mysql:") or conn_url.startswith("mysql+mysqldb:"):
        msg = (
            "Unsupported MySQL driver detected in [database] connection: %s.  "
            "Use the 'mysql+pymysql' driver -- see "
            "https://bugs.launchpad.net/oslo.db/+bug/1350149 for details." % conn_url
        )
        LOG.error(msg)
        raise RuntimeError(msg)


def _trigger_class(trigger):
    """Class of the bound-method ``trigger`` argument that Neutron passes to the
    AFTER_INIT callback.  Returns None for non-method triggers.

    Borrowed from neutron.common.ovn.utils; replicated here to avoid pulling in
    the ovn package as a dependency.
    """
    if not inspect.ismethod(trigger):
        return None
    return trigger.__self__.__class__


# The execution model of the Neutron server is complex.  It runs as multiple OS
# processes, each of which has only one OS thread, but each process uses eventlet to run
# multiple green threads in parallel.  In the near-ish future eventlet will be removed
# and there will be multiple OS threads instead.  The Calico driver code (which,
# broadly, maps between configuration in the Neutron DB and corresponding Calico data in
# the etcd datastore) runs as part of the Neutron server, and so its entry points can be
# called from any of those contexts: from multiple OS processes, or from multiple
# threads within the same OS process, or from multiple green threads within the same OS
# thread.  And the processing for such calls can be interleaved - e.g. one thread or
# green thread yields for a while and allows others to run.  This makes it difficult to
# follow through logs - for example, to tell if a given log line is part of an
# UPDATE_PORT_POSTCOMMIT for port A or an earlier UPDATE_PORT_POSTCOMMIT for port B, or
# some other trigger into our code.
#
# Happily OpenStack upstream has a solution for this kind of problem in its logging and
# 'context' libraries (oslo_log and oslo_context).  Logging honours format strings, for
# each log line, that include arbitrary keys (like `%(key)s`) and the context library
# permits setting thread-local values for those keys, where 'thread' means either OS
# thread or green thread, whichever of those is in use.  We can set values meaningful to
# us by creating an instance of oslo_context.context.RequestContext (or subclass) at the
# start of each of our driver entry points.
#
# But there are practical constraints:
#
# - We can't add a Calico-specific key, and customize the format strings to include
#   that, because the format strings apply to the whole of the Neutron server, and any
#   non-Calico context will be missing that key when it tries to log.  (Resulting in
#   tracebacks throughout the log file.)
#
# - Anyway, it's more convenient to piggy-back on a key that is already in the default
#   format strings, so that we don't need to customize those.
#
# Therefore we arrange for our RequestContext subclass to add Calico-specific context to
# the existing `request_id` key.  This then appears in all of the logs that are emitted
# within the processing of a Calico driver entry point, including common Neutron code as
# well as Calico-specific code.  For example:
#
# .. 14:19:44 ..INFO networking_calico.plugins.ml2.drivers.calico.subnets \
#                                           [None CALICO:2:CREATE_SUBNET_POSTCOMMIT ...
# .. 14:19:44 ..DEBUG networking_calico.etcdv3 \
#                                           [None CALICO:2:CREATE_SUBNET_POSTCOMMIT ...
# .. 14:19:44 ..DEBUG neutron.pecan_wsgi.hooks.policy_enforcement \
#                                           [None CALICO:2:CREATE_SUBNET_POSTCOMMIT ...
# .. 14:19:44 ..DEBUG neutron_lib.callbacks.manager \
#                                           [None CALICO:2:CREATE_SUBNET_POSTCOMMIT ...
#
# This helps to see that `CALICO:2:CREATE_SUBNET_POSTCOMMIT` is a different entry point
# than a later operation such as `CALICO:3:CREATE_SUBNET_POSTCOMMIT`, or than processing
# in a different thread such as `CALICO:3:RESYNC`.

task_id_lock = threading.Lock()
last_task_id = 0


class TrackTask(oslo_context.context.RequestContext):
    def __init__(self, log_string):
        super(TrackTask, self).__init__(overwrite=True)
        with task_id_lock:
            global last_task_id
            last_task_id += 1
            task_id = last_task_id
        self.log_string = f"CALICO:{task_id}:{log_string}"

    def get_logging_values(self):
        d = super(TrackTask, self).get_logging_values()
        if "request_id" in d:
            d["request_id"] = self.log_string + " " + d["request_id"]
        else:
            d["request_id"] = self.log_string
        return d


class CalicoMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Neutron/ML2 mechanism driver for Project Calico.

    CalicoMechanismDriver communicates information about endpoints and security
    configuration, via etcd, to the Felix and DHCP agent instances running on
    each compute host.
    """

    def __init__(self):
        super(CalicoMechanismDriver, self).__init__(
            AGENT_TYPE_FELIX,
            "tap",
            {"port_filter": True, "mac_address": "00:61:fe:ed:ca:fe"},
        )
        qos_driver.register(self)
        # Generally initialize attributes to nil values.  They get initialized
        # properly, as needed, in post_fork_initialize().
        self.db = None
        self.elector = None
        self._agent_update_context = None
        self._etcd_watcher = None
        self._etcd_watcher_thread = None
        self._my_pid = None
        # Variable shared across all processes that are forked for the
        # current Neutron server. Tracks whether or not this Neutron server
        # is the master for its OpenStack region.
        # "d" = double. Used for storing time.time(). See
        # https://docs.python.org/3/library/array.html#module-array
        self._is_master = multiprocessing.Value("d", 0)

        # RPC client for fanning out agent state reports.
        self.state_report_rpc = None

        # Last time we logged about a long port-status queue.  Used for rate
        # limiting.  Note: monotonic_time() uses its own epoch so it's only
        # safe to compare this with other values returned by monotonic_time().
        self._last_status_queue_log_time = monotonic_time()

        # Flag for telling workers to stop. Only applicable to the
        # calico worker processes and currently used for unit tests
        # only.
        self._stop_worker = False

        LOG.info("Created Calico mechanism driver %s", self)

    def initialize(self):
        """Called once by ML2 in the parent process, before any forks.

        We use this hook to subscribe to Neutron's process-AFTER_INIT callback so that
        we get a chance to run code in each worker process we own (see ``get_workers``)
        once it has been forked.

        Also validate the configured MySQL driver up front so a bad
        ``[database] connection`` fails the worker at startup rather than
        on the first port operation.
        """
        super(CalicoMechanismDriver, self).initialize()
        _check_mysql_driver()
        if cfg.CONF.calico.fairy_gc_diagnostics:
            # Install once in the parent process before workers are forked.
            # The listeners attach to the SQLAlchemy Pool class; each forked
            # worker inherits them as part of its post-fork memory image, so
            # we do not need to re-install in each child.
            from networking_calico.plugins.ml2.drivers.calico import (
                fairy_gc_diagnostics,
            )

            fairy_gc_diagnostics.install()
        registry.subscribe(
            self.post_fork_initialize,
            resources.PROCESS,
            events.AFTER_INIT,
            cancellable=True,
        )

    def get_workers(self):
        """Workers that neutron-server should fork on our behalf.

        Returns a list of ``neutron_lib.worker.BaseWorker`` instances, each of which
        becomes one OS process.

        Mastership architecture
        -----------------------
        Three of the four workers run continuous loops where "who is doing this work
        right now?" is decided dynamically by leader election against an etcd key (see
        ``Elector`` in election.py):

        * ``CalicoManagerWorker`` runs the elector itself, plus the periodic etcd
          compaction loop (compaction is gated on ``is_master()``).

        * ``CalicoAgentStatusWatcherWorker`` watches Felix uptime keys, gated on
          ``is_master()``.

        * ``CalicoEndpointStatusWatcherWorker`` watches per-port status keys, gated on
          ``is_master()``.

        Election is the right fit for these because failover matters: if the current
        master process dies, another neutron-server should automatically pick up the
        continuous work.

        The fourth worker is different:

        * ``CalicoStartupResyncWorker`` runs the one-shot Neutron-DB-to-etcd resync on
          process start, then idles.  There is no continuous loop to fail over, the
          resync runs exactly once per process lifetime, and we want each operator to
          consciously decide whether their deployment topology requires a startup resync
          at all.  The decision is therefore a static config switch (``[calico]
          startup_resync = always|never``) rather than dynamic election.  ``[calico]
          startup_resync = never`` suppresses the worker entirely so the operator can
          take responsibility for resync themselves -- typically by running
          ``calico-resync`` from a CD pipeline, or by leaving ``always`` set on exactly
          one neutron-server in the deployment.
        """
        # CalicoManagerWorker gets a back-reference to the driver so its
        # stop() can reach self.elector and step down cleanly on graceful
        # shutdown -- otherwise the elector greenlet is killed without
        # running its finally _attempt_step_down, the election key stays
        # in etcd until the lease expires, and the next neutron-server
        # restart has to wait out that TTL before anyone can win.
        services = [
            CalicoManagerWorker(driver=self),
            CalicoAgentStatusWatcherWorker(),
            CalicoEndpointStatusWatcherWorker(),
        ]

        if cfg.CONF.calico.startup_resync != "never":
            services.append(CalicoStartupResyncWorker())

        return services

    def post_fork_initialize(self, resource, event, trigger, payload=None):
        """Per-worker-process initialisation, fired by Neutron after fork.

        ``trigger`` is the worker instance (its bound ``start`` method, in practice).
        We dispatch on the worker's class so each worker process runs only the code
        it's responsible for:

        * ``CalicoStartupResyncWorker`` -> just the one-shot resync.

        * ``neutron.wsgi.WorkerService`` -> indicates an API worker process.
          Per PR #11580, API workers must never run master-only jobs, because their
          primary job is to serve API requests quickly: getting tied up running the
          master-only background threads (status watcher, port-status writers,
          periodic compaction) would hurt API response latency, and the resync work
          specifically now lives in ``CalicoStartupResyncWorker`` anyway.

        * Anything else (RPC / state-report / similar) -> connection state plus the
          elector and master-only background threads.
        """
        trigger_cls = _trigger_class(trigger)

        # ResyncWorker is special-cased because the function can be called by CLI as
        # well. Thus, all necessary init will happen in the _do_startup_resync
        # function.
        if trigger_cls is CalicoStartupResyncWorker:
            self._init_start_calico_resource_syncer()
            return

        self._post_fork_init()

        worker_mapping = {
            CalicoManagerWorker: self._init_start_calico_manager,
            CalicoAgentStatusWatcherWorker: self._init_start_agent_status_watcher,
            CalicoEndpointStatusWatcherWorker: (
                self._init_start_endpoint_status_watcher
            ),
        }

        if trigger_cls in worker_mapping:
            self._stop_worker = False
            worker_mapping[trigger_cls]()

        LOG.info(
            "Calico mechanism driver initialisation done for class %s",
            trigger_cls.__name__ if trigger_cls else trigger_cls,
        )

    def is_master(self):
        """Check whether the current instance of neutron-server is the master.

        In order for a neutron-server to be considered as a master, it needs
        to aquire the election key and actively maintain it.
        """
        if self._is_master.value <= 0:
            # We were not elected. We are not the master.
            return False

        # Else, let's check if we refresh the time within timeout.
        time_since_last_refreshed = time.time() - self._is_master.value
        refreshed_in_time = time_since_last_refreshed < MASTER_TIMEOUT

        # If not, there is something wrong with elector!!
        if not refreshed_in_time:
            LOG.warning(
                "The elector hasn't refreshed the lease in "
                f"{time_since_last_refreshed}s."
            )

        return refreshed_in_time

    def _post_fork_init(self):
        """Common post fork initialization.

        Creates the connection state required for talking to the Neutron DB
        and to etcd.
        """
        # Init the DB.
        self.db = None
        self._get_db()

        # Create syncers.
        self.subnet_syncer = SubnetSyncer(self.db)
        self.policy_syncer = PolicySyncer(self.db)
        self.endpoint_syncer = WorkloadEndpointSyncer(self.db, self.policy_syncer)

    def _init_start_calico_resource_syncer(self):
        self.start_up_resync_thread = eventlet.spawn(self._do_startup_resync)

    def _init_start_calico_manager(self):
        self.elector = Elector(
            cfg.CONF.calico.elector_name,
            datamodel_v2.neutron_election_key(calico_config.get_region_string()),
            self._is_master,
            old_key=datamodel_v1.NEUTRON_ELECTION_KEY,
            interval=MASTER_REFRESH_INTERVAL,
            ttl=MASTER_TIMEOUT,
        )

        self.election_thread = self.elector.start()

        if cfg.CONF.calico.etcd_compaction_period_mins > 0:
            self.periodic_compaction_thread = eventlet.spawn(
                self.do_periodic_compaction
            )

    def _init_start_agent_status_watcher(self):
        # Admin context used by (only) the thread that updates Felix agent
        # status.
        self._agent_update_context = ctx.get_admin_context()

        # Get RPC connection for fanning out Felix state reports.
        try:
            state_report_topic = topics.REPORTS
        except AttributeError:
            # Older versions of OpenStack share the PLUGIN topic.
            state_report_topic = topics.PLUGIN
        self.state_report_rpc = agent_rpc.PluginReportStateAPI(state_report_topic)

        self.agent_status_watch_thread = eventlet.spawn(
            self.watch_status_updates, AgentStatusWatcher
        )

    def _init_start_endpoint_status_watcher(self):
        # Mapping from (hostname, port-id) to Calico's status for a port.  The
        # hostname is included to disambiguate between multiple copies of a
        # port, which may exist during a migration or a re-schedule.
        self._port_status_cache = {}
        # Queue used to fan out port status updates to worker threads.  Notes:
        # * the queue contains tuples (priority, <status key>); we use a
        #   higher priority for events and a lower priority for snapshot
        #   keys, so that current data skips the queue.
        self._port_status_queue = PriorityQueue()
        self._port_status_queue_too_long = False

        self.endpoint_status_watch_thread = eventlet.spawn(
            self.watch_status_updates, EndpointStatusWatcher
        )

        self.port_status_update_threads = []
        for _ in range(cfg.CONF.calico.num_port_status_threads):
            self.port_status_update_threads.append(
                eventlet.spawn(self._loop_writing_port_statuses)
            )

    @logging_exceptions(LOG)
    def watch_status_updates(self, watcher):
        """watch_status_updates

        This method acts as a status updates handler logic for the
        Calico mechanism driver. Watches for felix updates in etcd
        and passes info to Neutron database.

        :param watcher: Watcher class to created to watch and update status.
        """
        TrackTask("STATUS_UPDATING")
        LOG.info("Status updating thread started for %s.", watcher.__name__)

        while not self._stop_worker:
            # Only handle updates if we are the master node.
            if self.is_master():
                if self._etcd_watcher is None:
                    LOG.info(
                        "Became the master, starting %s",
                        watcher.__name__,
                    )
                    self._etcd_watcher = watcher(self)

                    def start_etcd_watcher():
                        TrackTask("STATUS_ETCD_WATCHER")
                        self._etcd_watcher.start()

                    self._etcd_watcher_thread = eventlet.spawn(start_etcd_watcher)
                    LOG.info(
                        "Started %s as %s",
                        self._etcd_watcher,
                        self._etcd_watcher_thread,
                    )
                elif not self._etcd_watcher_thread:
                    LOG.error(
                        "StatusWatcher %s died: %s",
                        self._etcd_watcher,
                        watcher.__name__,
                    )
                    self._etcd_watcher.stop()
                    self._etcd_watcher = None
            else:
                if self._etcd_watcher is not None:
                    LOG.warning(
                        "No longer master, stopping StatusWatcher: %s.",
                        watcher.__name__,
                    )
                    self._etcd_watcher.stop()
                    self._etcd_watcher = None
                # Short sleep interval before we check if we've become
                # the master.
            eventlet.sleep(MASTER_CHECK_INTERVAL_SECS)

    def on_felix_alive(self, felix_hostname, new):
        LOG.info("Felix on host %s is alive; fanning out status report", felix_hostname)
        # Rather than writing directly to the database, we use the RPC
        # mechanism to fan out the request to another process.  This
        # distributes the DB write load and avoids turning the db-access lock
        # into a bottleneck.
        agent_state = felix_agent_state(felix_hostname, start_flag=new)
        self.state_report_rpc.report_state(
            self._agent_update_context, agent_state, use_call=False
        )

    def on_port_status_changed(self, hostname, port_id, status_dict, priority="low"):
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
        #   Neutron for all ports is significant (we do have to do it on
        #   startup, because our cache is empty)
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
        if (
            priority == "high"
            or self._port_status_cache.get(port_status_key) != calico_status
        ):
            LOG.info(
                "Status of port %s on host %s changed to %s",
                port_status_key,
                hostname,
                calico_status,
            )
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
                if (
                    now - self._last_status_queue_log_time
                    > QUEUE_WARN_LOG_INTERVAL_SECS
                ):
                    LOG.warning("Port status update queue length is high: %s", qsize)
                    self._last_status_queue_log_time = now
                    self._port_status_queue_too_long = True
                # Queue is getting large, make sure the DB writer threads
                # get CPU.
                eventlet.sleep()
            elif self._port_status_queue_too_long and qsize < 5:
                self._port_status_queue_too_long = False
                LOG.warning("Port status update queue back to normal: %s", qsize)

    @logging_exceptions(LOG)
    def _loop_writing_port_statuses(self):
        TrackTask("PORT_STATUS_WRITE")
        LOG.info("Port status write thread started")
        admin_context = ctx.get_admin_context()
        try:
            while not self._stop_worker:
                # Wait for work to do.
                _, port_status_key = self._port_status_queue.get()
                # Actually do the update.  Catch all exceptions to avoid
                # terminating this long-lived loop.
                try:
                    self._try_to_update_port_status(admin_context, port_status_key)
                except Exception:
                    LOG.exception(
                        "Unexpected error updating port status for %s",
                        port_status_key,
                    )
                finally:
                    # Close the session after each update so that its
                    # connection is returned to the pool promptly.  This
                    # avoids the GC-on-hub rollback path; the next call
                    # transparently gets a fresh session from the pool.
                    _close_session_safely(admin_context)
        finally:
            _close_session_safely(admin_context)

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
            self.db.update_port_status(
                admin_context, port_id, neutron_status, host=hostname
            )
        except db_exc.DBError as e:
            # Defensive: pre-Liberty, it was easy to cause deadlocks here if
            # any code path (in another loaded plugin, say) failed to take
            # the db-access lock.  Post-Liberty, we shouldn't see any
            # exceptions here because update_port_status() is wrapped with a
            # retry decorator in the neutron code.
            LOG.warning("Failed to update port status for %s due to %r.", port_id, e)
            # Queue up a retry after a delay.
            eventlet.spawn_after(
                PORT_UPDATE_RETRY_DELAY_SECS,
                self._retry_port_status_update,
                port_status_key,
            )
        except sa_exc.SQLAlchemyError as e:
            # Defensive: pre-Liberty, it was easy to cause deadlocks here if
            # any code path (in another loaded plugin, say) failed to take
            # the db-access lock.  Post-Liberty, we shouldn't see any
            # exceptions here because update_port_status() is wrapped with a
            # retry decorator in the neutron code.
            LOG.warning("Failed to update port status for %s due to %r.", port_id, e)
            # Queue up a retry after a delay.
            eventlet.spawn_after(
                PORT_UPDATE_RETRY_DELAY_SECS,
                self._retry_port_status_update,
                port_status_key,
            )
        else:
            LOG.debug("Updated port status for %s", port_id)
            if calico_status == datamodel_v1.ENDPOINT_STATUS_UP:
                port = self.db.get_port(admin_context, port_id)
                migrating_to = port.get("binding:profile", {}).get("migrating_to")
                if migrating_to == hostname:
                    dest_port = port.copy()
                    dest_port["binding:host_id"] = migrating_to
                    dest_wep_name = endpoint_name(dest_port)
                    namespace = self.endpoint_syncer.namespace
                    migration_uid = datamodel_v3.get_uid(
                        "LiveMigration", namespace, dest_wep_name
                    )
                    LOG.info(
                        "Live migration %s: destination port %s "
                        "active on %s, notifying Nova",
                        migration_uid,
                        port_id,
                        hostname,
                    )
                    # notify_port_active_direct expects a db
                    # model (not a dict), matching the pattern
                    # used by OVN and ML2 RPC callers.
                    # TODO: verify that db_port has the correct
                    # binding:host_id for the destination host at
                    # this point in the migration lifecycle, and
                    # that this interacts correctly with Nova's
                    # live_migration_wait_for_vif_plug mechanism.
                    db_port = ml2_db.get_port(admin_context, port_id)
                    if db_port:
                        self.db.nova_notifier.notify_port_active_direct(db_port)

    @logging_exceptions(LOG)
    def _retry_port_status_update(self, port_status_key):
        TrackTask("RETRY_PORT_STATUS_UPDATE")
        LOG.info("Retrying update to port %s", port_status_key)
        # Queue up the update so that we'll go via the normal writer threads.
        # They will re-read the current state of the port from the cache.
        self._port_status_queue.put(
            ((PRIORITY_RETRY, monotonic_time()), port_status_key)
        )

    def _get_db(self):
        if not self.db:
            self.db = plugin_dir.get_plugin()
            LOG.info("db = %s" % self.db)

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
        if segment[api.NETWORK_TYPE] in ["local", "flat"]:
            return True
        else:
            LOG.warning(
                "Calico does not support network type %s, on network %s",
                segment[api.NETWORK_TYPE],
                segment[api.ID],
            )
            return False

    def get_allowed_network_types(self, agent=None):
        return ("local", "flat")

    def get_mappings(self, agent):
        # We override this primarily to satisfy the ABC checker: this method
        # never actually gets called because we also override
        # check_segment_for_agent.
        assert False

    def create_network_postcommit(self, context):
        LOG.info("CREATE_NETWORK_POSTCOMMIT: %s" % context)
        # Nothing else needed here.  There cannot yet be any ports on a network that has
        # only just been created.

    def update_network_postcommit(self, context):
        TrackTask("UPDATE_NETWORK_POSTCOMMIT")
        LOG.info("UPDATE_NETWORK_POSTCOMMIT: %s" % context)

        # Determine if qos_policy_id is changing.  If not, no-op.
        old_qos_policy_id = context.original.get("qos_policy_id", None)
        new_qos_policy_id = context.current.get("qos_policy_id", None)
        if old_qos_policy_id == new_qos_policy_id:
            return

        network_id = context.current["id"]
        LOG.info(
            "qos_policy_id for network %r changing from %r to %r",
            network_id,
            old_qos_policy_id,
            new_qos_policy_id,
        )

        # Update the existing ports for this network and which don't have their own
        # qos_policy_id.  We do NOT wrap this in a writer/reader context: each upstream
        # call (``get_ports``, ``get_security_group_rules`` via the endpoint syncer,
        # etc.) is already decorated with ``@db_api.retry_if_session_inactive`` and
        # manages its own transaction plus retry.  Holding an outer writer here disables
        # that retry -- documented as an anti-pattern in Neutron's contributor devref:
        # "the retry context would be always called from inside an active transaction
        # making it useless."
        plugin_context = context._plugin_context
        ports = self.db.get_ports(
            plugin_context,
            filters={
                "network_id": [network_id],
            },
        )
        self.update_existing_ports(
            [p for p in ports if not p["qos_policy_id"]],
            plugin_context,
            "network changing qos_policy_id",
        )

    def update_existing_ports(self, ports, plugin_context, reason):
        # For each port, recompute and emit the WorkloadEndpoint for that port.
        LOG.info("Update %d port(s) for %s", len(ports), reason)
        for p in ports:
            if _port_is_endpoint_port(p):
                self.endpoint_syncer.write_endpoint(p, plugin_context, must_update=True)

    def handle_qos_policy_update(self, context, policy_id):
        TrackTask("HANDLE_QOS_POLICY_UPDATE")
        LOG.info("HANDLE_QOS_POLICY_UPDATE: %s %s", context, policy_id)

        # No outer writer/reader context here -- see the comment in
        # update_network_postcommit above for rationale.
        policy = policy_object.QosPolicy.get_policy_obj(context, policy_id)

        # Find ports whose network use this QoS policy and that don't have a
        # port-specific QoS policy.
        networks_ids = policy.get_bound_networks()
        ports_with_net_policy = (
            ports_object.Port.get_objects(context, network_id=networks_ids)
            if networks_ids
            else []
        )
        ports = [
            port.to_dict()
            for port in ports_with_net_policy
            if port.qos_policy_id is None
        ]

        # Add the ports that directly use this QoS policy.
        port_ids = policy.get_bound_ports()
        if port_ids:
            ports.extend(
                [
                    p.to_dict()
                    for p in ports_object.Port.get_objects(context, id=port_ids)
                ]
            )

        self.update_existing_ports(ports, context, "network QoS policy rules changing")

    def delete_network_postcommit(self, context):
        LOG.info("DELETE_NETWORK_POSTCOMMIT: %s" % context)
        # Nothing else needed here.  If there were ports on this network, we would have
        # got separate callbacks for those ports being deleted.

    def create_subnet_postcommit(self, context):
        TrackTask("CREATE_SUBNET_POSTCOMMIT")
        LOG.info("CREATE_SUBNET_POSTCOMMIT: %s" % context)

        # Re-read the subnet from the DB so we pick up the latest state, rather than the
        # (potentially slightly stale) ``context.current`` snapshot taken in the
        # precommit phase.  ``self.db.get_subnet`` is
        # ``@retry_if_session_inactive``-decorated and manages its own reader
        # transaction; we deliberately do NOT wrap it in our own writer/reader -- see
        # update_network_postcommit for rationale.
        subnet = context.current
        plugin_context = context._plugin_context
        subnet = self.db.get_subnet(plugin_context, subnet["id"])
        if subnet["enable_dhcp"]:
            self.subnet_syncer.write_subnet(subnet, context)

    def update_subnet_postcommit(self, context):
        TrackTask("UPDATE_SUBNET_POSTCOMMIT")
        LOG.info("UPDATE_SUBNET_POSTCOMMIT: %s" % context)

        # Re-read the subnet (see create_subnet_postcommit for the rationale behind the
        # re-read and against wrapping in a writer context).
        subnet = context.current
        plugin_context = context._plugin_context
        subnet = self.db.get_subnet(plugin_context, subnet["id"])
        if subnet["enable_dhcp"]:
            self.subnet_syncer.write_subnet(subnet, context)
        else:
            self.subnet_syncer.delete_subnet(subnet["id"])

    def delete_subnet_postcommit(self, context):
        TrackTask("DELETE_SUBNET_POSTCOMMIT")
        LOG.info("DELETE_SUBNET_POSTCOMMIT: %s" % context)
        self.subnet_syncer.delete_subnet(context.current["id"])

    # Idealised method forms.
    def create_port_postcommit(self, context):
        """create_port_postcommit

        Called after Neutron has committed a port creation event to the database.

        Process this event by writing the corresponding WorkloadEndpoint (and any side
        data such as security-group policies) to etcd.  We deliberately do not wrap this
        in a writer/reader context: the inner calls into ``self.db.get_*`` are already
        ``@db_api.retry_if_session_inactive``-decorated and manage their own
        transactions plus retry behaviour.  Holding an outer writer here disables that
        retry -- see ``update_network_postcommit`` for the devref reference and PR
        #12898 for the regression history this avoids.
        """
        TrackTask("CREATE_PORT_POSTCOMMIT")
        LOG.info("CREATE_PORT_POSTCOMMIT: %s", context)
        port = context._port

        # Ignore if this is not an endpoint port.
        if not _port_is_endpoint_port(port):
            return

        # Ignore if the port binding VIF type is 'unbound'; then this port
        # doesn't need to be networked yet.
        if port["binding:vif_type"] == "unbound":
            LOG.info("Creating unbound port: no work required.")
            return

        plugin_context = context._plugin_context
        self.endpoint_syncer.write_endpoint(port, plugin_context)

    def update_port_postcommit(self, context):
        """update_port_postcommit

        Called after Neutron has committed a port update event to the
        database.

        This is a tricky event, because it can be called in a number of ways
        during VM migration. We farm out to the appropriate method from here.
        """
        TrackTask("UPDATE_PORT_POSTCOMMIT")
        LOG.info("UPDATE_PORT_POSTCOMMIT: %s", context)
        port = context._port
        original = context.original

        # Abort early if we're managing non-endpoint ports.
        if not _port_is_endpoint_port(port):
            return

        # If this port update is purely for a status change, don't do anything:
        # we don't care about port statuses.
        if port_status_change(port, original):
            LOG.info(
                " port status changed from %s to %s, no action.",
                original.get("status"),
                port.get("status"),
            )
            return

        LOG.debug("Old = %r", original)
        LOG.debug("New = %r", port)

        # Re-read the port to pick up the latest available data rather than relying on
        # ``context._port`` which is a snapshot taken earlier in the API call.
        # ``self.db.get_port`` is ``@db_api.retry_if_session_inactive``-decorated and
        # manages its own reader transaction; we deliberately do NOT wrap this body in
        # our own writer/reader context -- see ``create_port_postcommit`` for rationale
        # and PR #12898 for the regression history.
        #
        # The re-read is a best-effort hedge against two fast-paired updates to the same
        # port being routed to different API workers and arriving at postcommit in the
        # opposite order to the API call order.  If the second-in-time update has
        # already committed to the Neutron DB by the time we get here, this re-read
        # picks up both changes and we write a consistent superset to etcd.  If the
        # other order obtains (we re-read before the other worker's DB commit, then race
        # on the etcd write), the etcd state can transiently revert to the older
        # update's view.  A writer transaction here would not help: a Neutron writer txn
        # in our session does not row-lock the port and does not order against other
        # workers' sessions or etcd writes, and the etcd write below is not CAS-guarded
        # (``mod_revision`` is ``None`` in ``endpoints.write_endpoint`` for the dynamic
        # path).  Persistent drift, if it happens, is repaired on the next
        # neutron-server restart by the startup resync; there is no longer a periodic
        # resync.  Tightening this -- e.g. CAS-against-mod_revision on dynamic writes
        # with retry-on-conflict -- is a known follow-up.
        plugin_context = context._plugin_context

        # If the port was previously bound, the endpoint should already exist.
        endpoint_should_already_exist = port_bound(original)

        # Detect live migration ending (migrating_to was set, now cleared).
        orig_migrating_to = original.get("binding:profile", {}).get("migrating_to")
        curr_migrating_to = port.get("binding:profile", {}).get("migrating_to")

        if orig_migrating_to is not None and curr_migrating_to is None:
            # Live migration ended — clean up LiveMigration resource
            # and, if the migration failed, the destination WEP.
            # Source WEP deletion for the success case is handled by
            # the host-change block below, which covers both cold
            # and live migration.
            namespace = self.endpoint_syncer.namespace
            dest_port = original.copy()
            dest_port["binding:host_id"] = orig_migrating_to
            dest_wep_name = endpoint_name(dest_port)
            migration_uid = datamodel_v3.get_uid(
                "LiveMigration", namespace, dest_wep_name
            )
            self.endpoint_syncer.delete_live_migration(dest_wep_name)

            if port["binding:host_id"] == original["binding:host_id"]:
                # Migration FAILED — host didn't change, delete
                # destination WEP.
                LOG.info(
                    "Live migration %s: failed, port %s remains on %s",
                    migration_uid,
                    port["id"],
                    port["binding:host_id"],
                )
                self.endpoint_syncer.delete_endpoint(dest_port)
            else:
                LOG.info(
                    "Live migration %s: succeeded, port %s migrated from %s to %s",
                    migration_uid,
                    port["id"],
                    original["binding:host_id"],
                    port["binding:host_id"],
                )

        # Check for migration (cold or live) so that we can reliably
        # delete the WorkloadEndpoint on the old host.
        if original["binding:host_id"] != port["binding:host_id"]:
            LOG.info(
                "Migration, delete WorkloadEndpoint on old host %s",
                original["binding:host_id"],
            )
            self.endpoint_syncer.delete_endpoint(original)
            endpoint_should_already_exist = False

        try:
            port = self.db.get_port(plugin_context, port["id"])
        except n_exc.PortNotFound:
            LOG.info("Port no longer exists")
            return

        # Now, fork execution based on the type of update we're performing.
        # There are a few:
        # - a pre live-migration notice (binding profile has a migrating_to
        #   key with the future nova-compute host as the value), where we
        #   create a destination WEP and LiveMigration resource;
        # - a port becoming bound (binding vif_type from unbound to bound);
        # - a port becoming unbound (binding vif_type from bound to
        #   unbound);
        # - an update (port bound at all times);
        # - a change to an unbound port (which we don't care about, because
        #   we do nothing with unbound ports).
        if port.get("binding:profile", {}).get("migrating_to") is not None:
            dest_host = port["binding:profile"]["migrating_to"]

            dest_port = port.copy()
            dest_port["binding:host_id"] = dest_host

            # Create LiveMigration resource BEFORE the destination
            # WEP, so that Felix has the migration context before it
            # sees the new endpoint.  (In etcd, write ordering is
            # preserved per-client.)
            migration_uid = self.endpoint_syncer.write_live_migration(port, dest_port)

            # Create destination WEP after the LiveMigration resource.
            # Skip DB re-read because this is a synthetic port dict
            # with the destination host.
            self.endpoint_syncer.write_endpoint(dest_port, plugin_context, reread=False)

            LOG.info(
                "Live migration %s: pre-migrate port %s from %s to %s",
                migration_uid,
                port["id"],
                port["binding:host_id"],
                dest_host,
            )
        elif port_bound(port):
            if endpoint_should_already_exist:
                LOG.info("Port update")
                self.endpoint_syncer.write_endpoint(
                    port, plugin_context, must_update=True
                )
            else:
                LOG.info("Port becoming bound: create.")
                self.endpoint_syncer.write_endpoint(port, plugin_context)
        elif endpoint_should_already_exist:
            LOG.info("Port becoming unbound: destroy.")
            self.endpoint_syncer.delete_endpoint(original)
        else:
            LOG.info("Update on unbound port: no action")

    def update_floatingip(self, plugin_context):
        """update_floatingip

        Called after a Neutron floating IP has been associated or
        disassociated from a port.
        """
        TrackTask("UPDATE_FLOATINGIP")
        LOG.info("UPDATE_FLOATINGIP: %s", plugin_context)

        # No outer writer/reader context here -- see create_port_postcommit for
        # rationale.
        port = self.db.get_port(plugin_context, plugin_context.fip_update_port_id)
        self._update_port(plugin_context, port)

    def delete_port_postcommit(self, context):
        """delete_port_postcommit

        Called after Neutron has committed a port deletion event to the
        database.

        There's no database row for us to lock on here, so don't bother.
        """
        TrackTask("DELETE_PORT_POSTCOMMIT")
        LOG.info("DELETE_PORT_POSTCOMMIT: %s", context)
        port = context._port

        # Immediately halt processing if this is not an endpoint port.
        if not _port_is_endpoint_port(port):
            return

        # If port is being deleted during live migration, clean up the
        # destination WEP and LiveMigration resource too.
        migrating_to = port.get("binding:profile", {}).get("migrating_to")
        if migrating_to is not None:
            namespace = self.endpoint_syncer.namespace
            dest_port = port.copy()
            dest_port["binding:host_id"] = migrating_to
            dest_wep_name = endpoint_name(dest_port)
            migration_uid = datamodel_v3.get_uid(
                "LiveMigration", namespace, dest_wep_name
            )
            LOG.info(
                "Live migration %s: port %s deleted during migration, cleaning up",
                migration_uid,
                port["id"],
            )
            datamodel_v3.delete("LiveMigration", namespace, dest_wep_name)
            self.endpoint_syncer.delete_endpoint(dest_port)

        # Delete source WEP.
        self.endpoint_syncer.delete_endpoint(port)

    def security_groups_rule_updated(self, context):
        """Called whenever security group rules or membership change.

        When a security group rule is added, we need to do the following steps:

        1. Reread the security rules from the Neutron DB.
        2. Write the updated policy to etcd.
        """
        TrackTask("SECURITY_GROUPS_RULE_UPDATED")
        LOG.info("SECURITY_GROUPS_RULE_UPDATED: %s", context)

        # No outer writer/reader context here -- see create_port_postcommit for
        # rationale.  ``write_sgs_to_etcd`` calls ``self.db.get_security_group_rules``,
        # which is ``@retry_if_session_inactive``-decorated and triggers upstream
        # ``_ensure_default_security_group``'s race recovery when called without an
        # outer writer.
        self.policy_syncer.write_sgs_to_etcd(context.sgids, context.plugin_context)

    def _update_port(self, plugin_context, port):
        """_update_port

        This method assumes it's being called from within a database
        transaction and does not take out another one.
        """
        LOG.info("Updating port %s", port)

        if port_bound(port):
            LOG.info("Port bound, attempting to update.")
            self.endpoint_syncer.write_endpoint(port, plugin_context, must_update=True)
        else:
            LOG.info("Port unbound, attempting delete if needed.")
            self.endpoint_syncer.delete_endpoint(port)

    @logging_exceptions(LOG)
    def _do_startup_resync(self):
        """Run one-shot resync.

        Called from ``post_fork_initialize`` inside the dedicated
        ``CalicoStartupResyncWorker`` process when ``[calico] startup_resync`` is
        ``always`` (the default).  Also called from the test framework to simulate the
        worker's behaviour.

        Failures are logged loudly but not retried.  Operators can drive a retry by
        running ``calico-resync`` (with no scope flags, which means resync everything)
        or by restarting neutron-server.
        """
        TrackTask("RESYNC")
        LOG.info("One-shot resync starting")

        # (Re)init the DB.  The resync worker is its own OS process and doesn't share
        # connection state with the API/RPC forks.  Scope.run() builds its own
        # subnet/policy/endpoint syncers from the DB; we don't need to set the
        # driver's syncer attributes here because nothing else in this worker
        # process uses them.
        self.db = None
        self._get_db()

        result = resync.Scope(
            self.db,
            inject_per_item_delay_ms=(
                cfg.CONF.calico.startup_resync_inject_per_item_delay_ms
            ),
        ).run()
        if result.ok:
            LOG.info("One-shot resync done: %s", result.to_dict())
        else:
            LOG.error(
                "One-shot resync FAILED: %s.  "
                "Run `calico-resync` (with no scope flags) to retry, or "
                "restart neutron-server.",
                result.to_dict(),
            )

    def do_periodic_compaction(self):
        """Periodic etcd compaction logic.

        On a fixed interval, requests etcd compaction to prevent unbounded disk usage
        growth.  Only the master node performs compaction.
        """
        TrackTask("COMPACTION")
        try:
            LOG.info("Periodic compaction thread started")
            while not self._stop_worker:
                # Only do the compaction if we are the master node.
                if self.is_master():
                    LOG.info("I am master: doing periodic compaction")

                    try:
                        # Possibly request an etcd compaction.
                        check_request_etcd_compaction()
                    except Exception:
                        LOG.exception("Error in periodic compaction thread")

                    # Reschedule ourselves.
                    eventlet.sleep(60 * cfg.CONF.calico.etcd_compaction_period_mins)
                else:
                    # Shorter sleep interval before we check if we've become the master.
                    # Avoids waiting a whole etcd_compaction_period_mins if we just miss
                    # the master update.
                    LOG.debug("I am not master")
                    eventlet.sleep(MASTER_CHECK_INTERVAL_SECS)
        except Exception:
            # TODO(nj) Should we tear down the process.
            LOG.exception("Periodic compaction thread died!")
            if self.elector:
                # Stop the elector so that we give up the mastership.
                self.elector.stop()
            raise
        else:
            LOG.warning("Periodic compaction thread exiting.")


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

    for ignore_field in ["status", "updated_at", "revision_number"]:
        port.pop(ignore_field, None)
        original.pop(ignore_field, None)

    if port == original:
        return True
    else:
        return False


def port_bound(port):
    """Returns true if the port is bound."""
    return port["binding:vif_type"] != "unbound"


def felix_agent_state(hostname, start_flag=False):
    """felix_agent_state

    :param bool start_flag: True if this is a new felix, that is starting up.
           False if this is a refresh of an existing felix.
    :returns dict: agent status dict appropriate for inserting into Neutron DB.
    """
    state = {
        "agent_type": AGENT_TYPE_FELIX,
        "binary": AGENT_ID_FELIX,
        "host": hostname,
        "topic": constants.L2_AGENT_TOPIC,
    }
    if start_flag:
        # Felix has told us that it has only just started, report that to
        # neutron, which will use it to reset its view of the uptime.
        state["start_flag"] = True
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
            last_compaction_rev, last_check_rev = etcdv3.get(COMPACTION_LAST_KEY)
            last_compaction_rev = int(last_compaction_rev)
            last_check_rev = int(last_check_rev)
            LOG.info(
                "Last compaction %r, last check %r", last_compaction_rev, last_check_rev
            )
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
            LOG.info(
                "Bogus last compaction revision (%r > %r)",
                last_compaction_rev,
                current_revision,
            )
            write_compaction_keys(0)
            return

        # We must keep at least etcd_compaction_min_revisions of history.  If
        # there aren't that many yet, we can't compact.
        if current_revision <= cfg.CONF.calico.etcd_compaction_min_revisions:
            LOG.info(
                "Not enough revisions to compact yet (%r <= %r)",
                current_revision,
                cfg.CONF.calico.etcd_compaction_min_revisions,
            )
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
            LOG.info(
                "No compactable history yet (%r <= %r)",
                compact_revision,
                last_compaction_rev,
            )
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
            LOG.info("Someone else has requested etcd compaction:\n%s", e3e.detail_text)
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
    lease = etcdv3.get_lease(cfg.CONF.calico.etcd_compaction_period_mins * 60)
    if not etcdv3.put(COMPACTION_TRIGGER_KEY, str(os.getpid()), lease=lease):
        # Writing should always succeed; but in case it doesn't we will retry
        # as part of the next resync, so just a warning is sufficient here.
        LOG.warning("Failed to write %s", COMPACTION_TRIGGER_KEY)
