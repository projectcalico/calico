# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
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
import eventlet
import eventlet.queue
import inspect
import logging
import mock
import sys

# When you're working on a test and need to see logging - both from the test
# code and the code _under_ test - uncomment the following line.
#
# logging.basicConfig(level=logging.INFO)

_log = logging.getLogger(__name__)

sys.modules['etcd'] = m_etcd = mock.MagicMock()
sys.modules['neutron'] = m_neutron = mock.MagicMock()
sys.modules['neutron.agent'] = m_neutron.agent
sys.modules['neutron.agent.rpc'] = m_neutron.agent.rpc
sys.modules['neutron.common'] = m_neutron.common
sys.modules['neutron.common.constants'] = m_constants = \
    m_neutron.common.constants
sys.modules['neutron.common.exceptions'] = m_neutron.common.exceptions
sys.modules['neutron.db'] = m_neutron.db
sys.modules['neutron.openstack'] = m_neutron.openstack
sys.modules['neutron.openstack.common'] = m_neutron.openstack.common
sys.modules['neutron.openstack.common.db'] = m_neutron.openstack.common.db
sys.modules['neutron.openstack.common.db.exception'] = \
    m_neutron.openstack.common.db.exception
sys.modules['neutron.plugins'] = m_neutron.plugins
sys.modules['neutron.plugins.ml2'] = m_neutron.plugins.ml2
sys.modules['neutron.plugins.ml2.drivers'] = m_neutron.plugins.ml2.drivers
sys.modules['neutron.plugins.ml2.rpc'] = m_neutron.plugins.ml2.rpc
sys.modules['oslo'] = m_oslo = mock.Mock()
sys.modules['oslo.config'] = m_oslo.config
sys.modules['sqlalchemy'] = m_sqlalchemy = mock.Mock()
sys.modules['sqlalchemy.orm'] = m_sqlalchemy.orm
sys.modules['sqlalchemy.orm.exc'] = m_sqlalchemy.orm.exc

port1 = {'binding:vif_type': 'tap',
         'binding:host_id': 'felix-host-1',
         'id': 'DEADBEEF-1234-5678',
         'device_id': 'instance-1',
         'device_owner': 'compute:nova',
         'fixed_ips': [{'subnet_id': 'subnet-id-10.65.0--24',
                        'ip_address': '10.65.0.2'}],
         'mac_address': '00:11:22:33:44:55',
         'admin_state_up': True,
         'security_groups': ['SGID-default'],
         'status': 'ACTIVE'}

port2 = {'binding:vif_type': 'tap',
         'binding:host_id': 'felix-host-1',
         'id': 'FACEBEEF-1234-5678',
         'device_id': 'instance-2',
         'device_owner': 'compute:nova',
         'fixed_ips': [{'subnet_id': 'subnet-id-10.65.0--24',
                        'ip_address': '10.65.0.3'}],
         'mac_address': '00:11:22:33:44:66',
         'admin_state_up': True,
         'security_groups': ['SGID-default'],
         'status': 'ACTIVE'}

# Port with an IPv6 address.
port3 = {'binding:vif_type': 'tap',
         'binding:host_id': 'felix-host-2',
         'id': 'HELLO-1234-5678',
         'device_id': 'instance-3',
         'device_owner': 'compute:nova',
         'fixed_ips': [{'subnet_id': 'subnet-id-2001:db8:a41:2--64',
                        'ip_address': '2001:db8:a41:2::12'}],
         'mac_address': '00:11:22:33:44:66',
         'admin_state_up': True,
         'security_groups': ['SGID-default'],
         'status': 'ACTIVE'}

floating_ports = [{'fixed_port_id': 'DEADBEEF-1234-5678',
                   'fixed_ip_address': '10.65.0.2',
                   'floating_ip_address': '192.168.0.1'}]


class EtcdException(Exception):
    pass


class EtcdKeyNotFound(EtcdException):
    pass


class EtcdClusterIdChanged(EtcdException):
    pass


class EtcdEventIndexCleared(EtcdException):
    pass


class EtcdValueError(EtcdException):
    pass


class EtcdDirNotEmpty(EtcdValueError):
    pass


m_etcd.EtcdException = EtcdException
m_etcd.EtcdKeyNotFound = EtcdKeyNotFound
m_etcd.EtcdClusterIdChanged = EtcdClusterIdChanged
m_etcd.EtcdEventIndexCleared = EtcdEventIndexCleared
m_etcd.EtcdValueError = EtcdValueError
m_etcd.EtcdDirNotEmpty = EtcdDirNotEmpty


class DBError(Exception):
    pass


m_neutron.openstack.common.db.exception.DBError = DBError


class NoResultFound(Exception):
    pass


m_sqlalchemy.orm.exc.NoResultFound = NoResultFound


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

    def master(self):
        return True

    def stop(self):
        pass


# Replace Neutron's SimpleAgentMechanismDriverBase - which is the base class
# that CalicoMechanismDriver inherits from - with this stub class.
m_neutron.plugins.ml2.drivers.mech_agent.SimpleAgentMechanismDriverBase = \
    DriverBase

# Replace the elector.

import networking_calico.plugins.ml2.drivers.calico.mech_calico as mech_calico
import networking_calico.plugins.ml2.drivers.calico.t_etcd as t_etcd
t_etcd.Elector = GrandDukeOfSalzburg

REAL_EVENTLET_SLEEP_TIME = 0.01

# Value used to indicate 'timeout' in poll and sleep processing.
TIMEOUT_VALUE = object()


class Lib(object):

    # Ports to return when the driver asks the OpenStack database for all
    # current ports.
    osdb_ports = []

    # Subnets that the OpenStack database knows about.
    osdb_subnets = []

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
        mech_calico.mech_driver = None
        self.driver = mech_calico.CalicoMechanismDriver()

        # Hook the (mock) Neutron database.
        self.db = mech_calico.manager.NeutronManager.get_plugin()
        self.db_context = mech_calico.ctx.get_admin_context()

        self.db_context.session.query.return_value.filter_by.side_effect = (
            self.port_query
        )

        # Arrange what the DB's get_ports will return.
        self.db.get_ports.side_effect = self.get_ports
        self.db.get_port.side_effect = self.get_port

        # Arrange DB's get_subnet and get_subnets calls.
        self.db.get_subnet.side_effect = self.get_subnet
        self.db.get_subnets.side_effect = self.get_subnets

        # Arrange what the DB's get_security_groups query will return (the
        # default SG).
        self.db.get_security_groups.return_value = [
            {'id': 'SGID-default',
             'security_group_rules': [
                 {'remote_group_id': 'SGID-default',
                  'remote_ip_prefix': None,
                  'protocol': -1,
                  'direction': 'ingress',
                  'ethertype': 'IPv4',
                  'port_range_min': -1},
                 {'remote_group_id': 'SGID-default',
                  'remote_ip_prefix': None,
                  'protocol': -1,
                  'direction': 'ingress',
                  'ethertype': 'IPv6',
                  'port_range_min': -1},
                 {'remote_group_id': None,
                  'remote_ip_prefix': None,
                  'protocol': -1,
                  'direction': 'egress',
                  'ethertype': 'IPv4',
                  'port_range_min': -1},
                 {'remote_group_id': None,
                  'remote_ip_prefix': None,
                  'protocol': -1,
                  'direction': 'egress',
                  'ethertype': 'IPv6',
                  'port_range_min': -1}
             ]}
        ]
        self.db.get_security_group_rules.return_value = [
            {'remote_group_id': 'SGID-default',
             'remote_ip_prefix': None,
             'protocol': -1,
             'direction': 'ingress',
             'ethertype': 'IPv4',
             'security_group_id': 'SGID-default',
             'port_range_min': -1},
            {'remote_group_id': 'SGID-default',
             'remote_ip_prefix': None,
             'protocol': -1,
             'direction': 'ingress',
             'ethertype': 'IPv6',
             'security_group_id': 'SGID-default',
             'port_range_min': -1},
            {'remote_group_id': None,
             'remote_ip_prefix': None,
             'protocol': -1,
             'direction': 'egress',
             'ethertype': 'IPv4',
             'security_group_id': 'SGID-default',
             'port_range_min': -1},
            {'remote_group_id': None,
             'remote_ip_prefix': None,
             'protocol': -1,
             'direction': 'egress',
             'security_group_id': 'SGID-default',
             'ethertype': 'IPv6',
             'port_range_min': -1}
        ]

        self.db._get_port_security_group_bindings.side_effect = (
            self.get_port_security_group_bindings
        )

        self.port_security_group_bindings = [
            {'port_id': 'DEADBEEF-1234-5678',
             'security_group_id': 'SGID-default'},
            {'port_id': 'FACEBEEF-1234-5678',
             'security_group_id': 'SGID-default'},
            {'port_id': 'HELLO-1234-5678',
             'security_group_id': 'SGID-default'},
        ]

    def setUp_eventlet(self):
        """setUp_eventlet

        Setup to intercept sleep calls made by the code under test, and hence
        to (i) control when those expire, and (ii) allow time to appear to pass
        (to the code under test) without actually having to wait for that time.
        """
        # Reset the simulated time (in seconds) that has passed since the
        # beginning of the test.
        self.current_time = 0

        # Make time.time() return current_time.
        self.old_time = sys.modules['time'].time
        sys.modules['time'].time = lambda: self.current_time

        # Reset the dict of current sleepers.  In each dict entry, the key is
        # an eventlet.Queue object and the value is the time at which the sleep
        # should complete.
        self.sleepers = {}

        # Reset the list of spawned eventlet threads.
        self.threads = []

        # Replacement for eventlet.sleep: sleep for some simulated passage of
        # time (as directed by simulated_time_advance), instead of for real
        # elapsed time.
        def simulated_time_sleep(secs=None):
            if secs is None:
                # Thread just wants to yield to any other waiting thread.
                self.give_way()
                return
            # Create a new queue.
            queue = eventlet.Queue(1)
            queue.stack = inspect.stack()[1][3]

            # Add it to the dict of sleepers, together with the waking up time.
            self.sleepers[queue] = self.current_time + secs

            _log.info("T=%s: %s: Start sleep for %ss until T=%s",
                      self.current_time,
                      queue.stack,
                      secs,
                      self.sleepers[queue])

            # Do a zero time real sleep, to allow other threads to run.
            self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

            # Block until something is posted to the queue.
            queue.get(True)

            # Wake up.
            return None

        # Replacement for eventlet.spawn: track spawned threads so that we can
        # kill them all when a test case ends.
        def simulated_spawn(*args):

            # Do the real spawn.
            thread = self.real_eventlet_spawn(*args)

            # Remember this thread.
            self.threads.append(thread)

            # Also return it.
            return thread

        def simulated_spawn_after(secs, fn, *args):
            def sleep_then_run():
                simulated_time_sleep(secs)
                fn(*args)

            return simulated_spawn(sleep_then_run)

        # Hook sleeping.
        self.real_eventlet_sleep = eventlet.sleep
        eventlet.sleep = simulated_time_sleep

        # Similarly hook spawning.
        self.real_eventlet_spawn = eventlet.spawn
        eventlet.spawn = simulated_spawn

        self.real_eventlet_spawn_after = eventlet.spawn_after
        eventlet.spawn_after = simulated_spawn_after

    def setUp_logging(self):
        """Setup to intercept and display logging by the code under test."""
        import logging
        mech_calico.LOG = logging.getLogger(
            'networking_calico.plugins.ml2.drivers.calico.mech_calico'
        )
        t_etcd.LOG = logging.getLogger(
            'networking_calico.plugins.ml2.drivers.calico.t_etcd'
        )

    # Tear down after each test case.
    def tearDown(self):

        _log.info("Clean up remaining green threads...")

        for thread in self.threads:
            thread.kill()

        # Stop hooking eventlet.
        self.tearDown_eventlet()

        # Stop mocking sys.exit.
        self.sys_exit_p.stop()

    def tearDown_eventlet(self):

        # Restore the real eventlet.sleep and eventlet.spawn.
        eventlet.sleep = self.real_eventlet_sleep
        eventlet.spawn = self.real_eventlet_spawn
        eventlet.spawn_after = self.real_eventlet_spawn_after

        # Repair time.time()
        sys.modules['time'].time = self.old_time

    # Method for the test code to call when it wants to advance the simulated
    # time.
    def simulated_time_advance(self, secs):

        while (secs > 0):
            _log.info("T=%s: Want to advance by %s", self.current_time, secs)

            # Determine the time to advance to in this iteration: either the
            # full time that we've been asked for, or the time at which the
            # next sleeper should wake up, whichever of those is earlier.
            wake_up_time = self.current_time + secs
            for queue in self.sleepers.keys():
                if self.sleepers[queue] < wake_up_time:
                    # This sleeper will wake up before the time that we've been
                    # asked to advance to.
                    wake_up_time = self.sleepers[queue]

            # Advance to the determined time.
            secs -= (wake_up_time - self.current_time)
            self.current_time = wake_up_time
            _log.info("T=%s", self.current_time)

            # Wake up all sleepers that should now wake up.
            for queue in self.sleepers.keys():
                if self.sleepers[queue] <= self.current_time:
                    _log.info("T=%s >= %s: %s: Wake up!",
                              self.current_time,
                              self.sleepers[queue],
                              queue.stack)
                    del self.sleepers[queue]
                    queue.put_nowait(TIMEOUT_VALUE)

            # Allow woken (and possibly other) threads to run.
            self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

    def give_way(self):
        """give_way

        Method for test code to call when it wants to allow other eventlet
        threads to run.
        """
        self.real_eventlet_sleep(REAL_EVENTLET_SLEEP_TIME)

    def check_update_port_status_called(self, context):
        self.db.update_port_status.assert_called_once_with(
            context._plugin_context,
            context._port['id'],
            mech_calico.constants.PORT_STATUS_ACTIVE)
        self.db.update_port_status.reset_mock()

    def get_port(self, context, port_id):
        return self.get_ports(context, filters={'id': [port_id]})[0]

    def get_ports(self, context, filters=None):
        if filters is None:
            return self.osdb_ports

        assert filters.keys() == ['id']
        allowed_ids = set(filters['id'])

        return [p for p in self.osdb_ports if p['id'] in allowed_ids]

    def get_subnet(self, context, id):
        matches = [s for s in self.osdb_subnets if s['id'] == id]
        if matches and len(matches) == 1:
            return matches[0]
        elif ':' in id:
            return {'gateway_ip': '2001:db8:a41:2::1'}
        else:
            return {'gateway_ip': '10.65.0.1'}

    def get_subnets(self, context, filters=None):
        if filters:
            self.assertTrue('id' in filters)
            matches = [s for s in self.osdb_subnets
                       if s['id'] in filters['id']]
        else:
            matches = [s for s in self.osdb_subnets]
        return matches

    def notify_security_group_update(self, id, rules, port, type):
        """Notify a new or changed security group definition."""
        # Prep appropriate responses for next get_security_group and
        # _get_port_security_group_bindings calls.
        self.db.get_security_group.return_value = {
            'id': id,
            'security_group_rules': rules
        }
        if port is None:
            self.db._get_port_security_group_bindings.return_value = []
        else:
            self.db._get_port_security_group_bindings.return_value = [
                {'port_id': port['id']}
            ]
            self.db.get_port.return_value = port

        if type == 'rule':
            # Call security_groups_rule_updated with the new or changed ID.
            mech_calico.security_groups_rule_updated(
                mock.MagicMock(), mock.MagicMock(), [id]
            )

    def get_port_security_group_bindings(self, context, filters):
        if filters is None:
            return self.port_security_group_bindings

        assert filters.keys() == ['port_id']
        allowed_ids = set(filters['port_id'])

        return [b for b in self.port_security_group_bindings
                if b['port_id'] in allowed_ids]

    def port_query(self, **kw):
        if kw.get('port_id', None):
            for port in self.osdb_ports:
                if port['id'] == kw['port_id']:
                    return port['fixed_ips']
        elif kw.get('fixed_port_id', None):
            fips = []
            for fip in floating_ports:
                if fip['fixed_port_id'] == kw['fixed_port_id']:
                    fips.append(fip)
            return fips
        else:
            raise Exception("port_query doesn't know how to handle kw=%r" % kw)

        return None


class FixedUUID(object):

    def __init__(self, uuid):
        self.uuid = uuid
        self.uuid4_p = mock.patch('uuid.uuid4')

    def __enter__(self):
        guid = mock.MagicMock()
        guid.get_hex.return_value = self.uuid
        uuid4 = self.uuid4_p.start()
        uuid4.return_value = guid

    def __exit__(self, type, value, traceback):
        self.uuid4_p.stop()
