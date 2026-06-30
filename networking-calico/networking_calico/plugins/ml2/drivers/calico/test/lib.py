# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
# Copyright (c) 2018-2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
networking_calico.plugins.ml2.drivers.calico.test.lib
~~~~~~~~~~~

Common code for Neutron driver UT.
"""
import contextlib
import logging
import sys
from types import SimpleNamespace

import eventlet
import mock

# When you're working on a test and need to see logging - both from the test
# code and the code _under_ test - uncomment the following line.
#
# logging.basicConfig(level=logging.DEBUG)

_log = logging.getLogger(__name__)

# Note, we use MagicMock here, instead of Mock, when some of the objects from within the
# relevant package need to be iterable, or to be context managers, or to have any of the
# other magic Python methods that MagicMock generates for us.
sys.modules["neutron"] = m_neutron = mock.MagicMock()
sys.modules["neutron.agent"] = m_neutron.agent
sys.modules["neutron.agent.rpc"] = m_neutron.agent.rpc
sys.modules["neutron.common"] = m_neutron.common
sys.modules["neutron.common.exceptions"] = m_neutron.common.exceptions
sys.modules["neutron.conf"] = m_neutron.conf
sys.modules["neutron.conf.agent"] = m_neutron.conf.agent
sys.modules["neutron.db"] = m_neutron.db
sys.modules["neutron.db.models"] = m_neutron.db.models
sys.modules["neutron.db.models.l3"] = m_neutron.db.models.l3
sys.modules["neutron.db.qos"] = m_neutron.db.qos
sys.modules["neutron.objects"] = m_neutron.objects
sys.modules["neutron.objects.qos"] = m_neutron.objects.qos
sys.modules["neutron.openstack"] = m_neutron.openstack
sys.modules["neutron.openstack.common"] = m_neutron.openstack.common
sys.modules["neutron.openstack.common.db"] = m_neutron.openstack.common.db
sys.modules["neutron.plugins"] = m_neutron.plugins
sys.modules["neutron.plugins.ml2"] = m_neutron.plugins.ml2
sys.modules["neutron.plugins.ml2.drivers"] = m_neutron.plugins.ml2.drivers
sys.modules["neutron.plugins.ml2.rpc"] = m_neutron.plugins.ml2.rpc
sys.modules["neutron.wsgi"] = m_neutron.wsgi
sys.modules["neutron_lib"] = m_neutron_lib = mock.MagicMock()
sys.modules["neutron_lib.agent"] = m_neutron_lib.agent
sys.modules["neutron_lib.callbacks"] = m_neutron_lib.callbacks
sys.modules["neutron_lib.callbacks.events"] = m_neutron_lib.callbacks.events
sys.modules["neutron_lib.callbacks.registry"] = m_neutron_lib.callbacks.registry
sys.modules["neutron_lib.callbacks.resources"] = m_neutron_lib.callbacks.resources
sys.modules["neutron_lib.db"] = m_neutron_lib.db
sys.modules["neutron_lib.constants"] = m_neutron_lib.constants
sys.modules["neutron_lib.plugins"] = m_neutron_lib.plugins
sys.modules["neutron_lib.plugins.ml2"] = m_neutron_lib.plugins.ml2
sys.modules["neutron_lib.worker"] = m_neutron_lib.worker
sys.modules["oslo_concurrency"] = m_oslo_concurrency = mock.Mock()
sys.modules["oslo_config"] = m_oslo_config = mock.MagicMock()
sys.modules["oslo_context"] = m_oslo_context = mock.Mock()
sys.modules["oslo_db"] = m_oslo_db = mock.Mock()
sys.modules["oslo_log"] = m_oslo_log = mock.Mock()
sys.modules["sqlalchemy"] = m_sqlalchemy = mock.Mock()
sys.modules["sqlalchemy.orm"] = m_sqlalchemy.orm
sys.modules["sqlalchemy.orm.exc"] = m_sqlalchemy.orm.exc
sys.modules["networking_calico.plugins.ml2.drivers.calico.qos_driver"] = (
    m_qos_driver
) = mock.Mock()

# Set up some IP protocol mappings to test.  (Unfortunately, importing
# the real IP_PROTOCOL_MAP from neutron_lib.constants tries to pull in
# too much other stuff.)
m_neutron_lib.constants.IP_PROTOCOL_MAP = {
    "esp": 50,
    "ah": 51,
    "rsvp": 46,
}

port1 = {
    "binding:vif_type": "tap",
    "binding:host_id": "felix-host-1",
    "id": "DEADBEEF-1234-5678",
    "tenant_id": "jane3",
    "network_id": "calico-network-id",
    "device_id": "instance-1",
    "device_owner": "compute:nova",
    "fixed_ips": [{"subnet_id": "subnet-id-10.65.0--24", "ip_address": "10.65.0.2"}],
    "mac_address": "00:11:22:33:44:55",
    "admin_state_up": True,
    "security_groups": ["SGID-default"],
    "status": "ACTIVE",
    "allowed_address_pairs": [
        {"ip_address": "23.23.23.2", "mac_address": "fa:16:3e:c4:cd:3f"}
    ],
}

port2 = {
    "binding:vif_type": "tap",
    "binding:host_id": "felix-host-1",
    "id": "FACEBEEF-1234-5678",
    "tenant_id": "jane3",
    "network_id": "calico-network-id",
    "device_id": "instance-2",
    "device_owner": "compute:nova",
    "fixed_ips": [{"subnet_id": "subnet-id-10.65.0--24", "ip_address": "10.65.0.3"}],
    "mac_address": "00:11:22:33:44:66",
    "admin_state_up": True,
    "security_groups": ["SGID-default"],
    "status": "ACTIVE",
    "allowed_address_pairs": [],
}

# Port with an IPv6 address.
port3 = {
    "binding:vif_type": "tap",
    "binding:host_id": "felix-host-2",
    "id": "HELLO-1234-5678",
    "tenant_id": "jane3",
    "network_id": "calico-network-id",
    "device_id": "instance-3",
    "device_owner": "compute:nova",
    "fixed_ips": [
        {
            "subnet_id": "subnet-id-2001:db8:a41:2--64",
            "ip_address": "2001:db8:a41:2::12",
        }
    ],
    "mac_address": "00:11:22:33:44:66",
    "admin_state_up": True,
    "security_groups": ["SGID-default"],
    "status": "ACTIVE",
    "allowed_address_pairs": [],
}

floating_ports = [
    {
        "fixed_port_id": "DEADBEEF-1234-5678",
        "fixed_ip_address": "10.65.0.2",
        "floating_ip_address": "192.168.0.1",
    }
]

network1 = {
    "id": "calico-network-id",
    "name": "calico-network-name",
    "status": "ACTIVE",
    "admin_state_up": True,
    "shared": True,
    "mtu": 9000,
    "project_id": "jane3",
}

network2 = {
    "id": "calico-other-network-id",
    "name": "my-first-network",
    "status": "ACTIVE",
    "admin_state_up": True,
    "shared": True,
    "mtu": 9000,
    "project_id": "jane3",
}


class EtcdKeyNotFound(Exception):
    pass


class DBError(Exception):
    pass


m_oslo_db.exception.DBError = DBError


class NoResultFound(Exception):
    pass


m_sqlalchemy.orm.exc.NoResultFound = NoResultFound


class PortNotFound(Exception):

    def __init__(self, port_id=None):
        super(PortNotFound, self).__init__()
        self.port_id = port_id


m_neutron_lib.exceptions.PortNotFound = PortNotFound


# Define a stub class, that we will use as the base class for
# CalicoMechanismDriver.
class DriverBase(object):
    def __init__(self, agent_type, vif_type, vif_details):
        pass


# Define another stub class that mocks out leader election: assume we're always
# the leader. This is a fake elector: it never votes (get it!?).
class GrandDukeOfSalzburg(object):
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        pass

    def master(self):
        return True

    def stop(self):
        pass


# Replace Neutron's SimpleAgentMechanismDriverBase - which is the base class
# that CalicoMechanismDriver inherits from - with this stub class.
m_neutron.plugins.ml2.drivers.mech_agent.SimpleAgentMechanismDriverBase = DriverBase

# Import all modules used by the mechanism driver so we can hook their logging.
from networking_calico import datamodel_v3
from networking_calico import etcdutils
from networking_calico import etcdv3
from networking_calico.plugins.calico.context import SGUpdateContext
from networking_calico.plugins.ml2.drivers.calico import election
from networking_calico.plugins.ml2.drivers.calico import endpoints
from networking_calico.plugins.ml2.drivers.calico import mech_calico
from networking_calico.plugins.ml2.drivers.calico import policy
from networking_calico.plugins.ml2.drivers.calico import status
from networking_calico.plugins.ml2.drivers.calico import subnets
from networking_calico.plugins.ml2.drivers.calico import syncer
from networking_calico.resync import scope

# Replace the elector.
mech_calico.Elector = GrandDukeOfSalzburg


# Mock the Keystone client.
def mock_projects_list():
    mock_project = mock.Mock()
    mock_project.id = "jane3"
    mock_project.name = "pname+%s" % mock_project.id
    mock_project.parent_id = "gibson"
    return [mock_project]


keystone_client = mock.Mock()
keystone_client.projects.list.side_effect = mock_projects_list
endpoints.make_keystone_client = mock.Mock(return_value=keystone_client)
mech_calico.TrackTask = mock.Mock()
mech_calico.TrackTask.return_value = None

REAL_EVENTLET_SLEEP_TIME = 0.01

# Value used to indicate 'timeout' in poll and sleep processing.
TIMEOUT_VALUE = object()


class _AttrDict(dict):
    """dict subclass that also supports attribute access.

    Used to mock SQLAlchemy row objects returned from bulk queries: the
    driver code reads these via both r["col"] (dict style) and r.col
    (attribute style), so the mock must support both.  An optional set
    of kwargs can be passed to extend the base dict with additional
    virtual columns (e.g. qos_policy_id).
    """

    def __init__(self, base=None, **extra):
        super(_AttrDict, self).__init__(base or {})
        for k, v in extra.items():
            self[k] = v

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


class Lib(object):

    # Ports to return when the driver asks the OpenStack database for all
    # current ports.
    osdb_ports = []

    # Subnets that the OpenStack database knows about.
    osdb_subnets = []

    # Networks that the OpenStack database knows about.
    osdb_networks = []

    qos_policies = {
        # Example from
        # https://docs.openstack.org/api-ref/network/v2/index.html#id695.
        "1": {
            "project_id": "8d4c70a21fed4aeba121a1a429ba0d04",
            "tenant_id": "8d4c70a21fed4aeba121a1a429ba0d04",
            "id": "46ebaec0-0570-43ac-82f6-60d2b03168c4",
            "is_default": False,
            "name": "10Mbit",
            "description": "This policy limits the ports to 10Mbit max.",
            "revision_number": 3,
            "created_at": "2018-04-03T21:26:39Z",
            "updated_at": "2018-04-03T21:26:39Z",
            "shared": False,
            "rules": [
                {
                    "id": "5f126d84-551a-4dcf-bb01-0e9c0df0c793",
                    "qos_policy_id": "46ebaec0-0570-43ac-82f6-60d2b03168c4",
                    "max_kbps": 10000,
                    "max_burst_kbps": 0,
                    "type": "bandwidth_limit",
                },
                {
                    "id": "5f126d84-551a-4dcf-bb01-0e9c0df0c794",
                    "qos_policy_id": "46ebaec0-0570-43ac-82f6-60d2b03168c4",
                    "dscp_mark": 26,
                    "type": "dscp_marking",
                },
            ],
            "tags": ["tag1,tag2"],
        },
        # A policy that will set all possible fields.
        "2": {
            "id": "2",
            "rules": [
                {
                    "max_kbps": 1,
                    "max_burst_kbps": 2,
                    "direction": "ingress",
                    "type": "bandwidth_limit",
                },
                {
                    "max_kbps": 3,
                    "max_burst_kbps": 4,
                    "direction": "egress",
                    "type": "bandwidth_limit",
                },
                {"max_kpps": 5, "direction": "ingress", "type": "packet_rate_limit"},
                {"max_kpps": 6, "direction": "egress", "type": "packet_rate_limit"},
            ],
        },
    }

    def setUp(self):
        # Announce the current test case.
        _log.info("TEST CASE: %s", self.id())

        # Mock calls to sys.exit.
        self.sys_exit_p = mock.patch("sys.exit")
        self.sys_exit_p.start()

        # Hook eventlet.
        self.setUp_eventlet()

        # Hook logging.
        self.setUp_logging()

        # If an arg mismatch occurs, we want to see the complete diff of it.
        self.maxDiff = None

        # Create an instance of CalicoMechanismDriver.
        self.driver = mech_calico.CalicoMechanismDriver()

        # Hook the (mock) Neutron database.
        self.db = mech_calico.plugin_dir.get_plugin()
        self.db_context = mech_calico.ctx.get_admin_context()
        self.db_context.to_dict.return_value = {}
        self.db_context.session.query.side_effect = self.db_query

        # Arrange what the DB's get_ports will return.
        self.db.get_ports.side_effect = self.get_ports
        self.db.get_port.side_effect = self.get_port

        # Arrange DB's get_subnet and get_subnets calls.
        self.db.get_subnet.side_effect = self.get_subnet
        self.db.get_subnets.side_effect = self.get_subnets

        # Arrange DB's get_network and get_networks calls
        self.db.get_network.side_effect = self.get_network
        self.db.get_networks.side_effect = self.get_networks

        # Arrange what the DB's get_security_groups query will return (the
        # default SG).
        self.db.get_security_groups.return_value = [
            {
                "id": "SGID-default",
                "name": "My default SG",
                "security_group_rules": [
                    {
                        "remote_group_id": "SGID-default",
                        "remote_ip_prefix": None,
                        "protocol": -1,
                        "direction": "ingress",
                        "ethertype": "IPv4",
                        "port_range_min": -1,
                    },
                    {
                        "remote_group_id": "SGID-default",
                        "remote_ip_prefix": None,
                        "protocol": -1,
                        "direction": "ingress",
                        "ethertype": "IPv6",
                        "port_range_min": -1,
                    },
                    {
                        "remote_group_id": None,
                        "remote_ip_prefix": None,
                        "protocol": -1,
                        "direction": "egress",
                        "ethertype": "IPv4",
                        "port_range_min": -1,
                    },
                    {
                        "remote_group_id": None,
                        "remote_ip_prefix": None,
                        "protocol": -1,
                        "direction": "egress",
                        "ethertype": "IPv6",
                        "port_range_min": -1,
                    },
                ],
            }
        ]
        self.db.get_security_group_rules.return_value = [
            {
                "remote_group_id": "SGID-default",
                "remote_ip_prefix": None,
                "protocol": -1,
                "direction": "ingress",
                "ethertype": "IPv4",
                "security_group_id": "SGID-default",
                "port_range_min": -1,
            },
            {
                "remote_group_id": "SGID-default",
                "remote_ip_prefix": None,
                "protocol": -1,
                "direction": "ingress",
                "ethertype": "IPv6",
                "security_group_id": "SGID-default",
                "port_range_min": -1,
            },
            {
                "remote_group_id": None,
                "remote_ip_prefix": None,
                "protocol": -1,
                "direction": "egress",
                "ethertype": "IPv4",
                "security_group_id": "SGID-default",
                "port_range_min": -1,
            },
            {
                "remote_group_id": None,
                "remote_ip_prefix": None,
                "protocol": -1,
                "direction": "egress",
                "security_group_id": "SGID-default",
                "ethertype": "IPv6",
                "port_range_min": -1,
            },
        ]

        self.db._get_port_security_group_bindings.side_effect = (
            self.get_port_security_group_bindings
        )

        self.port_security_group_bindings = [
            {"port_id": "DEADBEEF-1234-5678", "security_group_id": "SGID-default"},
            {"port_id": "FACEBEEF-1234-5678", "security_group_id": "SGID-default"},
            {"port_id": "HELLO-1234-5678", "security_group_id": "SGID-default"},
        ]

    def setUp_eventlet(self):
        """setUp_eventlet

        Setup to intercept sleep calls made by the code under test, and hence
        to (i) control when those expire, and (ii) allow time to appear to pass
        (to the code under test) without actually having to wait for that time.
        """
        # Reset the list of spawned eventlet threads.
        self.threads = []

        # Replacement for eventlet.sleep.  For the testing that uses this Lib class we
        # only expect calls with no arg, i.e. to yield to other green threads.
        def simulated_sleep(secs=None):
            assert secs is None
            if secs is None:
                # Thread just wants to yield to any other waiting thread.
                self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)
                return

        # Replacement for eventlet.spawn: track spawned threads so that we can
        # kill them all when a test case ends.
        def simulated_spawn(*args):

            # Do the real spawn.
            thread = self.real_eventlet_spawn(*args)

            # Remember this thread.
            self.threads.append(thread)
            _log.info("New thread %s", thread)

            # Also return it.
            return thread

        def simulated_spawn_after(secs, fn, *args, **kwargs):
            def sleep_then_run():
                simulated_sleep(secs)
                fn(*args, **kwargs)

            return simulated_spawn(sleep_then_run)

        # Hook sleeping.
        self.real_eventlet_sleep = eventlet.sleep
        eventlet.sleep = simulated_sleep

        # Similarly hook spawning.
        self.real_eventlet_spawn = eventlet.spawn
        eventlet.spawn = simulated_spawn

        self.real_eventlet_spawn_after = eventlet.spawn_after
        eventlet.spawn_after = simulated_spawn_after

    def setUp_logging(self):
        """Setup to intercept and display logging by the code under test.

        To see this logging, you also need to uncomment the logging.basicConfig
        call near the top of this file.
        """
        import logging

        for module in [
            election,
            endpoints,
            mech_calico,
            policy,
            status,
            subnets,
            scope,
            syncer,
            datamodel_v3,
            etcdutils,
            etcdv3,
        ]:
            module.LOG = logging.getLogger("\t%-15s\t" % module.__name__.split(".")[-1])

    # Tear down after each test case.
    def tearDown(self):
        _log.info("Clean up remaining green threads...")

        for thread in self.threads:
            _log.info("Kill thread %s", thread)
            thread.kill()
        _log.info("All threads killed")

        # Stop hooking eventlet.
        self.tearDown_eventlet()

        # Stop mocking sys.exit.
        self.sys_exit_p.stop()

    def tearDown_eventlet(self):
        # Restore the real eventlet.sleep and eventlet.spawn.
        eventlet.sleep = self.real_eventlet_sleep
        eventlet.spawn = self.real_eventlet_spawn
        eventlet.spawn_after = self.real_eventlet_spawn_after

    def do_post_fork_actions(self, uuid_str=None):
        """Simulate the post-fork actions that Neutron runs in production.

        In production the Neutron server comprises (at least) three processes:

        - an "API worker" process, responsible for Neutron API requests, i.e. dynamic
          CRUD of ports and other networking resources

        - an "RPC worker" process, which is designed for RPC between the Neutron server
          and compute node agents, but which we use for other work that is not driven
          from the Neutron API, including port and agent status reporting and periodic
          etcd compaction

        - a "Calico resync" process, whose purpose is to sync from the Neutron DB to the
          Calico datastore following Neutron server startup.

        In UT there is only one process, and we want to get the effects of all those in
        the one UT process, which means:

        - Do the same startup preparations - DB connection etc. - that the API worker
          process would do.  These are all coded in ``_post_fork_init()``.
          This allows tests to later call driver entrypoints like
          ``update_port_postcommit()``, similarly as production Neutron would.

        - Spawn the threads for "other work" (as above) as the RPC worker process would
          do.  This is achieved by calling ``_post_fork_init()``.

        - Do the startup resync that the Calico resync process would do.  This is coded
          in ``_do_startup_resync()``.

        ``uuid_str`` controls the UUID generated during init (used for
        ClusterInformation's clusterGUID).
        """
        cm = FixedUUID(uuid_str) if uuid_str else contextlib.nullcontext()
        with cm:
            self.driver._post_fork_init()
            if mech_calico.cfg.CONF.calico.startup_resync == "always":
                self.driver._do_startup_resync()

    def check_update_port_status_called(self, context):
        self.db.update_port_status.assert_called_once_with(
            context._plugin_context,
            context._port["id"],
            mech_calico.constants.PORT_STATUS_ACTIVE,
        )
        self.db.update_port_status.reset_mock()

    def get_port(self, context, port_id):
        try:
            return self.get_ports(context, filters={"id": [port_id]})[0]
        except IndexError:
            raise PortNotFound(port_id=port_id)

    def get_ports(self, context, filters=None):
        if filters is None:
            return self.osdb_ports

        if "id" in filters:
            allowed = set(filters["id"])
            return [p for p in self.osdb_ports if p["id"] in allowed]
        if "network_id" in filters:
            allowed = set(filters["network_id"])
            return [p for p in self.osdb_ports if p["network_id"] in allowed]
        raise AssertionError("unsupported get_ports filter: %s" % filters)

    def get_subnet(self, context, id):
        matches = [s for s in self.osdb_subnets if s["id"] == id]
        if matches and len(matches) == 1:
            return matches[0]
        elif ":" in id:
            return {"gateway_ip": "2001:db8:a41:2::1"}
        else:
            return {"gateway_ip": "10.65.0.1"}

    def get_subnets(self, context, filters=None):
        # NB: unknown subnet IDs are filtered out (return list contains only
        # IDs present in osdb_subnets).  Don't synthesise a "minimal" subnet
        # to make this match get_subnet()'s fallback -- the narrow-resync
        # delete-when-gone path needs an empty list for missing IDs to
        # trigger the delete branch.  The bulk-prefetch in
        # WorkloadEndpointSyncer already tolerates absent entries via
        # ``subnets_by_id.get(...)``.
        if not filters:
            return list(self.osdb_subnets)
        if "id" in filters:
            allowed = set(filters["id"])
            return [s for s in self.osdb_subnets if s["id"] in allowed]
        if "network_id" in filters:
            allowed = set(filters["network_id"])
            return [s for s in self.osdb_subnets if s["network_id"] in allowed]
        raise AssertionError("unsupported get_subnets filter: %s" % filters)

    def get_network(self, context, id):
        return self.get_networks(context, filters={"id": [id]})[0]

    def get_networks(self, context, filters=None):
        if filters is None:
            return self.osdb_networks

        assert list(filters.keys()) == ["id"]
        allowed_ids = set(filters["id"])

        return [p for p in self.osdb_networks if p["id"] in allowed_ids]

    def notify_security_group_update(self, id, rules, port, type):
        """Notify a new or changed security group definition."""
        # Prep appropriate responses for next get_security_group and
        # _get_port_security_group_bindings calls.
        self.db.get_security_group.return_value = {
            "id": id,
            "security_group_rules": rules,
        }
        if port is None:
            self.db._get_port_security_group_bindings.return_value = []
        else:
            self.db._get_port_security_group_bindings.return_value = [
                {"port_id": port["id"]}
            ]
            self.db.get_port.return_value = port

        if type == "rule":
            # Call security_groups_updated with the new or changed ID.
            self.driver.security_groups_updated(SGUpdateContext(mock.MagicMock(), [id]))

    def get_port_security_group_bindings(self, context, filters):
        if filters is None:
            return self.port_security_group_bindings

        assert list(filters.keys()) == ["port_id"]
        allowed_ids = set(filters["port_id"])

        return [
            b for b in self.port_security_group_bindings if b["port_id"] in allowed_ids
        ]

    def db_query(self, model, **kw):
        m = mock.MagicMock()
        # Set up both filter_by (per-port, legacy) and filter (bulk,
        # IN-clause) side effects.  The bulk path returns all relevant
        # rows across all ports/policies; the caller groups them by the
        # relevant id (port_id, qos_policy_id, ...) and looks up per
        # item.  Returning more rows than strictly needed is harmless.
        if "IPAllocation" in str(model.name):
            m.filter_by.side_effect = self.db_query_ip_allocation
            m.filter.side_effect = self.db_query_ip_allocation_bulk
            return m
        if "FloatingIP" in str(model.name):
            m.filter_by.side_effect = self.db_query_floating_ip
            m.filter.side_effect = self.db_query_floating_ip_bulk
            return m
        if "Network" in str(model.name):
            m.filter_by.side_effect = self.db_query_network
            m.filter.side_effect = self.db_query_network_bulk
            return m
        if "QosBandwidthLimitRule" in str(model.name):
            m.filter_by.side_effect = self.db_query_qos_policy_bw_rule
            m.filter.side_effect = self.db_query_qos_policy_bw_rule_bulk
            return m
        if "QosPacketRateLimitRule" in str(model.name):
            m.filter_by.side_effect = self.db_query_qos_policy_pr_rule
            m.filter.side_effect = self.db_query_qos_policy_pr_rule_bulk
            return m
        raise Exception("db_query model=%r kw=%r" % (model, kw))

    def db_query_ip_allocation(self, **kw):
        # 'port_id' query key for IPAllocations
        for port in self.osdb_ports:
            if port["id"] == kw["port_id"]:
                return port["fixed_ips"]

    def db_query_floating_ip(self, **kw):
        fips = []
        for fip in floating_ports:
            if fip["fixed_port_id"] == kw["fixed_port_id"]:
                fips.append(fip)
        return fips

    def db_query_network(self, **kw):
        # 'id' query key for Networks
        for network in self.osdb_networks:
            if network["id"] == kw["id"]:
                network_mock = mock.MagicMock()
                network_mock.first.return_value = network
                return network_mock
        return None

    def db_query_qos_policy_bw_rule(self, **kw):
        policy = self.qos_policies[kw["qos_policy_id"]]
        if policy:
            return [r for r in policy["rules"] if r["type"] == "bandwidth_limit"]
        return []

    def db_query_qos_policy_pr_rule(self, **kw):
        policy = self.qos_policies[kw["qos_policy_id"]]
        if policy:
            return [r for r in policy["rules"] if r["type"] == "packet_rate_limit"]
        return []

    # Bulk-filter (IN-clause) variants used by the resync prefetch.  Each
    # returns all rows for the corresponding model; the real code then
    # groups them by the relevant id.  SimpleNamespace is used so that
    # attribute-style access (row.port_id, row.name, ...) works as it
    # would on a real SQLAlchemy model row.
    def db_query_ip_allocation_bulk(self, _expr):
        return [
            SimpleNamespace(
                port_id=p["id"],
                subnet_id=ip["subnet_id"],
                ip_address=ip["ip_address"],
            )
            for p in self.osdb_ports
            for ip in p["fixed_ips"]
        ]

    def db_query_floating_ip_bulk(self, _expr):
        return [
            SimpleNamespace(
                fixed_port_id=fip["fixed_port_id"],
                fixed_ip_address=fip["fixed_ip_address"],
                floating_ip_address=fip["floating_ip_address"],
            )
            for fip in floating_ports
        ]

    def db_query_network_bulk(self, _expr):
        return [SimpleNamespace(id=n["id"], name=n["name"]) for n in self.osdb_networks]

    def db_query_qos_policy_bw_rule_bulk(self, _expr):
        return [
            _AttrDict(r, qos_policy_id=policy_id)
            for policy_id, policy in self.qos_policies.items()
            for r in policy.get("rules", [])
            if r.get("type") == "bandwidth_limit"
        ]

    def db_query_qos_policy_pr_rule_bulk(self, _expr):
        return [
            _AttrDict(r, qos_policy_id=policy_id)
            for policy_id, policy in self.qos_policies.items()
            for r in policy.get("rules", [])
            if r.get("type") == "packet_rate_limit"
        ]


class FixedUUID(object):

    def __init__(self, uuid):
        self.uuid = uuid
        self.uuid4_p = mock.patch("uuid.uuid4")

    def __enter__(self):
        guid = mock.MagicMock()
        guid.hex = self.uuid
        guid.__str__.return_value = self.uuid
        uuid4 = self.uuid4_p.start()
        uuid4.return_value = guid

    def __exit__(self, type, value, traceback):
        self.uuid4_p.stop()
