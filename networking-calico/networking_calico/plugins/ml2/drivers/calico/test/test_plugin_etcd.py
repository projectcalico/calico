# -*- coding: utf-8 -*-
# Copyright 2015 Metaswitch Networks
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
networking_calico.plugins.ml2.drivers.calico.test.test_plugin_etcd
~~~~~~~~~~~

Unit test for the Calico/OpenStack Plugin using etcd transport.
"""
import copy
import json
import unittest

from etcd3gw.utils import _decode
import eventlet
import logging
import mock

import networking_calico.plugins.ml2.drivers.calico.test.lib as lib

from networking_calico.common import config as calico_config
from networking_calico import datamodel_v1
from networking_calico import datamodel_v2
from networking_calico import etcdv3
from networking_calico.monotonic import monotonic_time
from networking_calico.plugins.ml2.drivers.calico import mech_calico
from networking_calico.plugins.ml2.drivers.calico import policy
from networking_calico.plugins.ml2.drivers.calico import status

_log = logging.getLogger(__name__)
logging.getLogger().addHandler(logging.NullHandler())


class _TestEtcdBase(lib.Lib, unittest.TestCase):

    def setUp(self):
        """Setup before each test case."""
        super(_TestEtcdBase, self).setUp()

        # Start with an empty etcd database.
        self.etcd_data = {}

        # Insinuate a mock etcd3gw client.
        etcdv3._client = self.clientv3 = mock.Mock()
        self.clientv3.put.side_effect = self.etcd3gw_client_put
        self.clientv3.transaction.side_effect = self.etcd3gw_client_transaction
        self.clientv3.delete.side_effect = self.etcd3gw_client_delete
        self.clientv3.get.side_effect = self.etcd3gw_client_get
        self.clientv3.get_prefix.side_effect = self.etcd3gw_client_get_prefix
        self.clientv3.delete_prefix.side_effect = self.etcd3gw_client_delete_prefix
        self.clientv3.status.return_value = {
            'header': {'revision': '10', 'cluster_id': '1234abcd'},
        }

        # Start with an empty set of recent writes and deletes.
        self.recent_writes = {}
        self.recent_deletes = set()

        # Reset the counter for when we'll reset the etcd database.
        self.reset_etcd_after = None
        self.assert_etcd_writes_deletes = True

    def tearDown(self):
        etcdv3._client = None
        super(_TestEtcdBase, self).tearDown()

    def maybe_reset_etcd(self):
        if self.reset_etcd_after is not None:
            self.reset_etcd_after -= 1
            if self.reset_etcd_after == 0:
                self.etcd_data = {}
                self.reset_etcd_after = None
                _log.info("etcd reset")
                self.assert_etcd_writes_deletes = False

    def etcd3gw_client_put(self, key, value, **kwargs):
        """etcd3gw_client_put

        Print each etcd write as it occurs, and save into the accumulated etcd
        database.
        """
        self.maybe_reset_etcd()

        # Confirm that, if prevIndex is provided, its value is not None.
        self.assertTrue(kwargs.get('prevIndex', 0) is not None)

        # Check if this key is already in etcd.  If it is, and if it represents
        # a Calico v3 resource, we want to check that its metadata is not
        # changed by the new write.
        existing_v3_metadata = None
        if key in self.etcd_data:
            try:
                existing = json.loads(self.etcd_data[key])
                existing_v3_metadata = existing.get('metadata')
            except ValueError:
                pass

        _log.info("etcd write: %s = %s", key, value)
        self.etcd_data[key] = value
        try:
            self.recent_writes[key] = json.loads(value)
        except ValueError:
            self.recent_writes[key] = value

        if 'metadata' in self.recent_writes[key]:
            # If this is an update, check that the metadata, other than labels
            # and annotations, is unchanged.
            if existing_v3_metadata:
                if 'labels' in self.recent_writes[key]['metadata']:
                    existing_v3_metadata['labels'] = \
                        self.recent_writes[key]['metadata']['labels']
                if 'annotations' in self.recent_writes[key]['metadata']:
                    existing_v3_metadata['annotations'] = \
                        self.recent_writes[key]['metadata']['annotations']
                self.assertEqual(existing_v3_metadata,
                                 self.recent_writes[key]['metadata'])
            # Now delete not-easily-predictable metadata fields from the data
            # that test code checks against.
            if 'creationTimestamp' in self.recent_writes[key]['metadata']:
                del self.recent_writes[key]['metadata']['creationTimestamp']
            if 'uid' in self.recent_writes[key]['metadata']:
                del self.recent_writes[key]['metadata']['uid']

        return True

    def check_etcd_delete(self, key, **kwargs):
        """Print each etcd delete as it occurs."""
        self.maybe_reset_etcd()
        _log.info("etcd delete: %s", key)
        if kwargs.get('recursive', False):
            keylen = len(key) + 1
            for k in self.etcd_data.keys():
                if k == key or k[:keylen] == key + '/':
                    del self.etcd_data[k]
            self.recent_deletes.add(key + '(recursive)')
        else:
            try:
                del self.etcd_data[key]
            except KeyError:
                raise lib.EtcdKeyNotFound()
            self.recent_deletes.add(key)

    def assertEtcdWrites(self, expected):
        if self.assert_etcd_writes_deletes:
            self.assertEqual(expected, self.recent_writes)
        self.recent_writes = {}

    def assertEtcdDeletes(self, expected):
        if self.assert_etcd_writes_deletes:
            self.assertEqual(expected, self.recent_deletes)
        self.recent_deletes = set()

    def etcd3gw_client_get(
        self,
        key,
        metadata=False,
        range_end=None,
        sort_target=None,
        sort_order=None,
        limit=None,
        revision=None,
    ):
        self.maybe_reset_etcd()

        if range_end is not None:
            # Ranged get...
            decoded_end = _decode(range_end).decode()
            _log.info("Ranged get %s...%s", key, decoded_end)
            assert revision is not None
            keys = list(self.etcd_data.keys())
            keys.sort()
            if sort_order == "descend":
                keys.reverse()
            result = []
            keys_in_range = [k for k in keys if key <= k < decoded_end]
            for k in keys_in_range:
                result.append((self.etcd_data[k].encode(),
                               {'key': k.encode(), 'mod_revision': '10'}))
                if limit is not None and len(result) >= limit:
                    break
            return result

        if key in self.etcd_data:
            value = self.etcd_data[key]

            # Print and return the result.
            _log.info("etcd3 get: %s; value: %s", key, value)
            if metadata:
                item = {'key': key.encode(), 'mod_revision': '10'}
                return [(value.encode(), item)]
            else:
                return [value.encode()]
        else:
            return []

    def etcd3gw_client_get_prefix(self, prefix):
        self.maybe_reset_etcd()
        results = []
        for key, value in self.etcd_data.items():
            if key.startswith(prefix):
                result = (value.encode(),
                          {'mod_revision': 0, 'key': key.encode()})
                results.append(result)

        # Print and return the result.
        _log.info("etcd3 get_prefix: %s; results: %s", prefix, results)
        return results

    def etcd3gw_client_delete(self, key, **kwargs):
        try:
            self.check_etcd_delete(key, **kwargs)
            return True
        except lib.EtcdKeyNotFound:
            return False

    def etcd3gw_client_delete_prefix(self, prefix):
        _log.info("etcd3 delete prefix: %s", prefix)
        for key, value in list(self.etcd_data.items()):
            if key.startswith(prefix):
                del self.etcd_data[key]
                _log.info("etcd3 deleted %s", key)
                self.recent_deletes.add(key)

    def etcd3gw_client_transaction(self, txn):
        for txc in txn['compare']:
            _log.info("etcd3 txn compare = %r", txc)
            if txc['target'] == 'VERSION' and txc['version'] == 0:
                key = _decode(txc['key']).decode()
                if txc['result'] == 'EQUAL':
                    # Transaction requires that the etcd entry does not already exist.
                    if key in self.etcd_data:
                        _log.error("etcd3 txn MUST_CREATE failed")
                        return {'succeeded': False}
                if txc['result'] == 'NOT_EQUAL':
                    # Transaction requires that the etcd entry does already exist.
                    if key not in self.etcd_data:
                        _log.error("etcd3 txn MUST_UPDATE failed")
                        return {'succeeded': False}
        if 'request_put' in txn['success'][0]:
            put_request = txn['success'][0]['request_put']
            succeeded = self.etcd3gw_client_put(
                _decode(put_request['key']).decode(),
                _decode(put_request['value']).decode())
        elif 'request_delete_range' in txn['success'][0]:
            del_request = txn['success'][0]['request_delete_range']
            succeeded = self.etcd3gw_client_delete(_decode(del_request['key']).decode())
        return {'succeeded': succeeded}

    def etcd_read(self, key, wait=False, waitIndex=None, recursive=False,
                  timeout=None):
        """Read from the accumulated etcd database."""
        self.maybe_reset_etcd()

        # Slow down reading from etcd status subtree to allow threads to run
        # more often
        if wait and key == datamodel_v2.felix_status_dir():
            eventlet.sleep(30)
            self.driver.db.create_or_update_agent = mock.Mock()

        self.etcd_data[datamodel_v2.felix_status_dir() +
                       "/vm1/status"] = \
            json.dumps({
                "time": "2015-08-14T10:37:54"
            })

        # Prepare a read result object.
        read_result = mock.Mock()
        read_result.modifiedIndex = 123
        read_result.key = key
        read_result.etcd_index = 0

        # Set the object's value - i.e. the value, if any, of exactly the
        # specified key.
        if key in self.etcd_data:
            read_result.value = self.etcd_data[key]
        else:
            read_result.value = None
            if not recursive:
                raise lib.EtcdKeyNotFound()

        # Print and return the result object.
        _log.info("etcd read: %s; value: %s", key, read_result.value)

        if recursive:
            # Also see if this key has any children, and read those.
            read_result.children = []
            read_result.leaves = []
            keylen = len(key) + 1
            for k in self.etcd_data.keys():
                if k[:keylen] == key + '/':
                    child = mock.Mock()
                    child.key = k
                    child.value = self.etcd_data[k]
                    read_result.children.append(child)
                    read_result.leaves.append(child)
            if read_result.value is None and read_result.children == []:
                raise lib.EtcdKeyNotFound(self.etcd_data)
            # Actual direct children of the dir in etcd response.
            # Needed for status_dir, where children are dirs and
            # needs to be iterated.
            read_result._children = []
            list_of_statuses = [{"key": K} for K in self.etcd_data.keys()]
            read_result._children.append({"nodes": list_of_statuses})
        else:
            read_result.children = None

        return read_result


class TestPluginEtcdBase(_TestEtcdBase):

    def setUp_region(self):
        self.region = None
        self.region_string = "no-region"
        self.namespace = "openstack"

    def setUp(self):
        """Setup before each test case."""
        self.setUp_region()
        _log.info("Region %r string %r", self.region, self.region_string)

        # Do common plugin test setup.
        lib.m_compat.cfg.CONF.core_plugin = 'ml2'
        super(TestPluginEtcdBase, self).setUp()

        # Mock out the status updating thread.  These tests were originally
        # written before that was added and they do not support the interleaved
        # requests from the status thread.  The status-reporting thread is
        # tested separately.
        self.driver._status_updating_thread = mock.Mock(
            spec=self.driver._status_updating_thread
        )

        # Mock out config.
        lib.m_compat.cfg.CONF.calico.etcd_host = "localhost"
        lib.m_compat.cfg.CONF.calico.etcd_port = 2379
        lib.m_compat.cfg.CONF.calico.etcd_cert_file = None
        lib.m_compat.cfg.CONF.calico.etcd_ca_cert_file = None
        lib.m_compat.cfg.CONF.calico.etcd_key_file = None
        lib.m_compat.cfg.CONF.calico.num_port_status_threads = 4
        lib.m_compat.cfg.CONF.calico.etcd_compaction_period_mins = 0
        lib.m_compat.cfg.CONF.calico.project_name_cache_max = 0
        lib.m_compat.cfg.CONF.calico.openstack_region = self.region
        lib.m_compat.cfg.CONF.calico.max_ingress_connections_per_port = 0
        lib.m_compat.cfg.CONF.calico.max_egress_connections_per_port = 0
        calico_config._reset_globals()
        datamodel_v2._reset_globals()

        # This value needs to be a string:
        lib.m_compat.cfg.CONF.keystone_authtoken.auth_url = ""

        self.sg_default_key_v3 = (
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            self.namespace + '/ossg.default.SGID-default')
        self.sg_default_value_v3 = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'NetworkPolicy',
            'metadata': {
                'namespace': self.namespace,
                'name': 'ossg.default.SGID-default'
            },
            'spec': {
                'egress': [
                    {'action': 'Allow',
                     'ipVersion': 4},
                    {'action': 'Allow',
                     'ipVersion': 6}],
                'ingress': [
                    {'action': 'Allow',
                     'ipVersion': 4,
                     'source': {
                         'selector':
                         'has(sg.projectcalico.org/openstack-SGID-default)'}},
                    {'action': 'Allow',
                     'ipVersion': 6,
                     'source': {
                         'selector':
                         'has(sg.projectcalico.org/openstack-SGID-default)'}}
                ],
                'selector':
                'has(sg.projectcalico.org/openstack-SGID-default)'}}

        self.initial_etcd3_writes = {
            '/calico/resources/v3/projectcalico.org/' +
            'clusterinformations/default': {
                'apiVersion': 'projectcalico.org/v3',
                'kind': 'ClusterInformation',
                'metadata': {'name': 'default'},
                'spec': {'clusterGUID': 'uuid-start-no-ports',
                         'clusterType': 'openstack',
                         'datastoreReady': True}},
            '/calico/resources/v3/projectcalico.org/' +
            'felixconfigurations/default': {
                'apiVersion': 'projectcalico.org/v3',
                'kind': 'FelixConfiguration',
                'metadata': {'name': 'default'},
                'spec': {'endpointReportingEnabled': True,
                         'interfacePrefix': 'tap'}},
            self.sg_default_key_v3: self.sg_default_value_v3
        }

    def make_context(self):
        context = mock.MagicMock()
        context._plugin_context.to_dict.return_value = {}
        return context

    def test_start_two_ports(self):
        """Startup with two existing ports but no existing etcd data."""
        # Provide two Neutron ports.
        self.osdb_networks = [lib.network1, lib.network2]
        self.osdb_ports = [lib.port1, lib.port2]

        # Allow the etcd transport's resync thread to run.
        with lib.FixedUUID('uuid-start-two-ports'):
            self.give_way()
            self.simulated_time_advance(31)

        ep_deadbeef_key_v3 = (
            '/calico/resources/v3/projectcalico.org/workloadendpoints/' +
            self.namespace + '/felix--host--1-openstack-' +
            'instance--1-DEADBEEF--1234--5678')
        ep_facebeef_key_v3 = (
            '/calico/resources/v3/projectcalico.org/workloadendpoints/' +
            self.namespace + '/felix--host--1-openstack-' +
            'instance--2-FACEBEEF--1234--5678')
        ep_deadbeef_value_v3 = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'WorkloadEndpoint',
            'metadata': {
                'annotations': {
                    'openstack.projectcalico.org/network-id':
                    'calico-network-id'
                },
                'name': ('felix--host--1-openstack-instance' +
                         '--1-DEADBEEF--1234--5678'),
                'namespace': self.namespace,
                'labels': {
                    'sg.projectcalico.org/openstack-SGID-default':
                    'My_default_SG',
                    'sg-name.projectcalico.org/openstack-My_default_SG':
                    'SGID-default',
                    'projectcalico.org/namespace': self.namespace,
                    'projectcalico.org/openstack-project-id': 'jane3',
                    'projectcalico.org/openstack-project-name': 'pname_jane3',
                    'projectcalico.org/openstack-project-parent-id': 'gibson',
                    'projectcalico.org/orchestrator': 'openstack',
                    'projectcalico.org/openstack-network-name':
                    'calico-network-name'
                }
            },
            'spec': {'endpoint': 'DEADBEEF-1234-5678',
                     'interfaceName': 'tapDEADBEEF-12',
                     'ipNATs': [{'externalIP': '192.168.0.1',
                                 'internalIP': '10.65.0.2'}],
                     'ipNetworks': ['10.65.0.2/32',
                                    '23.23.23.2/32'],
                     'allowedIps': ['23.23.23.2/32'],
                     'ipv4Gateway': '10.65.0.1',
                     'mac': '00:11:22:33:44:55',
                     'node': 'felix-host-1',
                     'orchestrator': 'openstack',
                     'workload': 'instance-1'}}
        ep_facebeef_value_v3 = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'WorkloadEndpoint',
            'metadata': {
                'annotations': {
                    'openstack.projectcalico.org/network-id':
                    'calico-network-id'
                },
                'name': ('felix--host--1-openstack-instance' +
                         '--2-FACEBEEF--1234--5678'),
                'namespace': self.namespace,
                'labels': {
                    'sg.projectcalico.org/openstack-SGID-default':
                    'My_default_SG',
                    'sg-name.projectcalico.org/openstack-My_default_SG':
                    'SGID-default',
                    'projectcalico.org/namespace': self.namespace,
                    'projectcalico.org/openstack-project-id': 'jane3',
                    'projectcalico.org/openstack-project-name': 'pname_jane3',
                    'projectcalico.org/openstack-project-parent-id': 'gibson',
                    'projectcalico.org/orchestrator': 'openstack',
                    'projectcalico.org/openstack-network-name':
                    'calico-network-name'
                }
            },
            'spec': {'endpoint': 'FACEBEEF-1234-5678',
                     'interfaceName': 'tapFACEBEEF-12',
                     'ipNetworks': ['10.65.0.3/32'],
                     'allowedIps': [],
                     'ipv4Gateway': '10.65.0.1',
                     'mac': '00:11:22:33:44:66',
                     'node': 'felix-host-1',
                     'orchestrator': 'openstack',
                     'workload': 'instance-2'}}

        expected_writes = copy.deepcopy(self.initial_etcd3_writes)
        expected_writes[
            '/calico/resources/v3/projectcalico.org/clusterinformations/' +
            'default']['spec']['clusterGUID'] = 'uuid-start-two-ports'
        expected_writes.update({
            ep_deadbeef_key_v3: ep_deadbeef_value_v3,
            ep_facebeef_key_v3: ep_facebeef_value_v3,
        })
        self.assertEtcdWrites(expected_writes)

        # Allow it to run again, this time auditing against the etcd data that
        # was written on the first iteration.
        _log.info("Resync with existing etcd data")
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set())

        # Delete lib.port1.
        context = self.make_context()
        context._port = lib.port1
        context._plugin_context.session.query.side_effect = self.db_query
        self.driver.delete_port_postcommit(context)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set([ep_deadbeef_key_v3]))

        # Now process an update for the same port and check that it doesn't cause the etcd
        # resource to be recreated.  This simulates an update and delete racing with each
        # other and being handled on different Neutron servers or on different threads of
        # the same server.  The key point is that the update shouldn't accidentally
        # recreate an etcd resource that has just been deleted.
        self.osdb_ports = [lib.port2]
        self.driver.update_port_postcommit(context)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set())

        # Do another resync - expect no changes to the etcd data.
        _log.info("Resync with existing etcd data")
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set())

        # Add lib.port1 back again.
        self.osdb_ports = [lib.port1, lib.port2]
        self.driver.create_port_postcommit(context)
        self.assertEtcdWrites({
            ep_deadbeef_key_v3: ep_deadbeef_value_v3,
            self.sg_default_key_v3: self.sg_default_value_v3,
        })
        self.assertEtcdDeletes(set())

        # Migrate port1 to a different host.
        context._port = lib.port1.copy()
        context.original = lib.port1.copy()
        context._port['binding:host_id'] = 'new-host'
        self.osdb_ports[0]['binding:host_id'] = 'new-host'
        self.driver.update_port_postcommit(context)

        self.assertEtcdDeletes(set([ep_deadbeef_key_v3]))
        ep_deadbeef_key_v3 = ep_deadbeef_key_v3.replace('felix--host--1',
                                                        'new--host')
        ep_deadbeef_value_v3['metadata']['name'] = \
            ep_deadbeef_value_v3['metadata']['name'].replace('felix--host--1',
                                                             'new--host')
        ep_deadbeef_value_v3['spec']['node'] = \
            ep_deadbeef_value_v3['spec']['node'].replace('felix-host-1',
                                                         'new-host')
        self.assertEtcdWrites({
            ep_deadbeef_key_v3: ep_deadbeef_value_v3,
            self.sg_default_key_v3: self.sg_default_value_v3,
        })

        # Now resync again, moving self.osdb_ports to move port 1 back to the
        # old host felix-host-1.  The effect will be as though we've
        # missed a further update that moved port1 back to felix-host-1; this
        # resync will now discover that.
        _log.info("Resync with existing etcd data")
        self.osdb_ports[0]['binding:host_id'] = 'felix-host-1'
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)

        self.assertEtcdDeletes(set([ep_deadbeef_key_v3]))
        ep_deadbeef_key_v3 = ep_deadbeef_key_v3.replace('new--host',
                                                        'felix--host--1')
        ep_deadbeef_value_v3['metadata']['name'] = \
            ep_deadbeef_value_v3['metadata']['name'].replace('new--host',
                                                             'felix--host--1')
        ep_deadbeef_value_v3['spec']['node'] = \
            ep_deadbeef_value_v3['spec']['node'].replace('new-host',
                                                         'felix-host-1')
        self.assertEtcdWrites({
            ep_deadbeef_key_v3: ep_deadbeef_value_v3,
        })

        # Add another port with an IPv6 address.
        context._port = copy.deepcopy(lib.port3)
        self.osdb_ports.append(context._port)
        self.driver.create_port_postcommit(context)

        ep_hello_key_v3 = (
            '/calico/resources/v3/projectcalico.org/workloadendpoints/' +
            self.namespace + '/felix--host--2-openstack-' +
            'instance--3-HELLO--1234--5678')
        ep_hello_value_v3 = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'WorkloadEndpoint',
            'metadata': {
                'annotations': {
                    'openstack.projectcalico.org/network-id':
                    'calico-network-id'
                },
                'name': ('felix--host--2-openstack-instance' +
                         '--3-HELLO--1234--5678'),
                'namespace': self.namespace,
                'labels': {
                    'sg.projectcalico.org/openstack-SGID-default':
                    'My_default_SG',
                    'sg-name.projectcalico.org/openstack-My_default_SG':
                    'SGID-default',
                    'projectcalico.org/namespace': self.namespace,
                    'projectcalico.org/openstack-project-id': 'jane3',
                    'projectcalico.org/openstack-project-name': 'pname_jane3',
                    'projectcalico.org/openstack-project-parent-id': 'gibson',
                    'projectcalico.org/orchestrator': 'openstack',
                    'projectcalico.org/openstack-network-name':
                    'calico-network-name'
                }
            },
            'spec': {'endpoint': 'HELLO-1234-5678',
                     'interfaceName': 'tapHELLO-1234-',
                     'ipNetworks': ['2001:db8:a41:2::12/128'],
                     'allowedIps': [],
                     'ipv6Gateway': '2001:db8:a41:2::1',
                     'mac': '00:11:22:33:44:66',
                     'node': 'felix-host-2',
                     'orchestrator': 'openstack',
                     'workload': 'instance-3'}}

        expected_writes = {
            ep_hello_key_v3: ep_hello_value_v3,
            self.sg_default_key_v3: self.sg_default_value_v3,
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())
        self.osdb_ports = [lib.port1, lib.port2, context._port]

        # Create a new security group.
        # Update what the DB's queries should now return.
        self.db.get_security_groups.return_value = [
            {'id': 'SGID-default',
             'name': 'My default SG',
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
             ]},
            {'id': 'SG-1',
             'name': 'My first SG',
             'security_group_rules': [
                 {'remote_group_id': 'SGID-default',
                  'remote_ip_prefix': None,
                  'protocol': -1,
                  'direction': 'ingress',
                  'ethertype': 'IPv4',
                  'port_range_min': 5060,
                  'port_range_max': 5061}
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
             'port_range_min': -1},
            {'remote_group_id': 'SGID-default',
             'remote_ip_prefix': None,
             'protocol': -1,
             'direction': 'ingress',
             'ethertype': 'IPv4',
             'security_group_id': 'SG-1',
             'port_range_min': 5060,
             'port_range_max': 5061}
        ]

        # Then, send in an update.
        self.notify_security_group_update(
            'SG-1',
            [
                {'remote_group_id': 'SGID-default',
                 'remote_ip_prefix': None,
                 'protocol': -1,
                 'direction': 'ingress',
                 'ethertype': 'IPv4',
                 'port_range_min': 5060,
                 'port_range_max': 5061}
            ],
            None,
            'rule'
        )

        sg_1_key_v3 = (
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            self.namespace + '/ossg.default.SG-1')
        sg_1_value_v3 = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'NetworkPolicy',
            'metadata': {
                'namespace': self.namespace,
                'name': 'ossg.default.SG-1'
            },
            'spec': {
                'egress': [],
                'ingress': [{
                    'action': 'Allow',
                    'destination': {'ports': ['5060:5061']},
                    'ipVersion': 4,
                    'source': {
                        'selector':
                        'has(sg.projectcalico.org/openstack-SGID-default)'}
                }],
                'selector': 'has(sg.projectcalico.org/openstack-SG-1)'}}

        self.assertEtcdWrites({sg_1_key_v3: sg_1_value_v3})

        # Now change the security group for that port.
        context.original = copy.deepcopy(context._port)
        context.original['security_groups'] = ['SGID-default']
        context._port['security_groups'] = ['SG-1']
        self.port_security_group_bindings.pop(2)
        self.port_security_group_bindings.append({
            'port_id': 'HELLO-1234-5678', 'security_group_id': 'SG-1'
        })
        self.driver.update_port_postcommit(context)

        del ep_hello_value_v3['metadata']['labels'][
            'sg.projectcalico.org/openstack-SGID-default'
        ]
        del ep_hello_value_v3['metadata']['labels'][
            'sg-name.projectcalico.org/openstack-My_default_SG'
        ]
        ep_hello_value_v3['metadata']['labels'][
            'sg.projectcalico.org/openstack-SG-1'] = 'My_first_SG'
        ep_hello_value_v3['metadata']['labels'][
            'sg-name.projectcalico.org/openstack-My_first_SG'] = 'SG-1'
        expected_writes = {
            ep_hello_key_v3: ep_hello_value_v3,
            sg_1_key_v3: sg_1_value_v3
        }
        self.assertEtcdWrites(expected_writes)

        # Resync with all latest data - expect no etcd writes or deletes.
        _log.info("Resync with existing etcd data")
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set([]))

        # Change SG-1 to allow only port 5060.
        self.db.get_security_groups.return_value[-1] = {
            'id': 'SG-1',
            'name': 'My first SG',
            'security_group_rules': [
                {'remote_group_id': 'SGID-default',
                 'remote_ip_prefix': None,
                 'protocol': -1,
                 'direction': 'ingress',
                 'ethertype': 'IPv4',
                 'port_range_min': 5060,
                 'port_range_max': 5061}]
        }
        self.db.get_security_group_rules.return_value[-1] = {
            'remote_group_id': 'SGID-default',
            'remote_ip_prefix': None,
            'protocol': -1,
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'security_group_id': 'SG-1',
            'port_range_min': 5060,
            'port_range_max': 5060
        }
        self.notify_security_group_update(
            'SG-1',
            [
                {'remote_group_id': 'SGID-default',
                 'remote_ip_prefix': None,
                 'protocol': -1,
                 'direction': 'ingress',
                 'ethertype': 'IPv4',
                 'port_range_min': 5060,
                 'port_range_max': 5060}
            ],
            None,
            'rule'
        )

        # Expect an etcd write
        sg_1_value_v3['spec']['ingress'][0]['destination']['ports'] = [5060]
        self.assertEtcdWrites({
            sg_1_key_v3: sg_1_value_v3
        })

        # Resync with only the last port.  Expect the first two ports to be
        # cleaned up.
        self.osdb_ports = [context.original]
        _log.info("Resync with existing etcd data")
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set([
            ep_deadbeef_key_v3,
            ep_facebeef_key_v3,
        ]))

        # Change a small amount of information about the port and the security
        # group. Expect a resync to fix it up.
        self.db.get_security_groups.return_value[-1] = {
            'id': 'SG-1',
            'name': 'My first SG',
            'security_group_rules': [
                {'remote_group_id': 'SGID-default',
                 'remote_ip_prefix': None,
                 'protocol': -1,
                 'direction': 'ingress',
                 'ethertype': 'IPv4',
                 'port_range_min': 5070,
                 'port_range_max': 5071}]
        }
        self.db.get_security_group_rules.return_value[-1] = {
            'remote_group_id': 'SGID-default',
            'remote_ip_prefix': None,
            'protocol': -1,
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'security_group_id': 'SG-1',
            'port_range_min': 5070,
            'port_range_max': 5070
        }
        old_ips = self.osdb_ports[0]['fixed_ips']
        self.osdb_ports[0]['fixed_ips'] = [
            {'subnet_id': 'subnet-id-10.65.0--24',
             'ip_address': '10.65.0.188'}
        ]
        _log.info("Resync with edited data")
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)

        ep_hello_value_v3['spec']['ipNetworks'] = ["10.65.0.188/32"]
        ep_hello_value_v3['spec']['ipv4Gateway'] = "10.65.0.1"
        del ep_hello_value_v3['spec']['ipv6Gateway']
        sg_1_value_v3['spec']['ingress'][0]['destination']['ports'] = [5070]
        expected_writes = {
            ep_hello_key_v3: ep_hello_value_v3,
            sg_1_key_v3: sg_1_value_v3,
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())

        # Change network used
        _log.info("Change network used by endpoint HELLO")
        context._port['network_id'] = 'calico-other-network-id'
        self.osdb_ports[0]['network_id'] = 'calico-other-network-id'
        self.driver.update_port_postcommit(context)

        # Expected changes
        ep_hello_value_v3['metadata']['labels'][
            'projectcalico.org/openstack-network-name'] = 'my-first-network'
        ep_hello_value_v3['metadata']['annotations'][
            'openstack.projectcalico.org/network-id'] = \
            'calico-other-network-id'
        expected_writes = {
            ep_hello_key_v3: ep_hello_value_v3,
            sg_1_key_v3: sg_1_value_v3,
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())

        # Add a QoS policy.
        context._port['qos_policy_id'] = '1'
        self.osdb_ports[0]['qos_policy_id'] = '1'
        self.driver.update_port_postcommit(context)

        # Expected changes
        ep_hello_value_v3['spec']['qosControls'] = {
            'egressBandwidth': 10000000,
        }
        expected_writes = {
            ep_hello_key_v3: ep_hello_value_v3,
            sg_1_key_v3: sg_1_value_v3,
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())

        # Add configuration for max connections.
        lib.m_compat.cfg.CONF.calico.max_ingress_connections_per_port = 10
        lib.m_compat.cfg.CONF.calico.max_egress_connections_per_port = 20
        self.driver.update_port_postcommit(context)

        # Expected changes
        ep_hello_value_v3['spec']['qosControls'] = {
            'egressBandwidth': 10000000,
            'ingressMaxConnections': 10,
            'egressMaxConnections': 20,
        }
        expected_writes = {
            ep_hello_key_v3: ep_hello_value_v3,
            sg_1_key_v3: sg_1_value_v3,
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())

        # Change to a QoS policy that will set all possible settings.
        context._port['qos_policy_id'] = '2'
        self.osdb_ports[0]['qos_policy_id'] = '2'
        self.driver.update_port_postcommit(context)

        # Expected changes
        ep_hello_value_v3['spec']['qosControls'] = {
            'ingressBandwidth': 1000,
            'egressBandwidth': 3000,
            'ingressBurst': 2000,
            'egressBurst': 4000,
            'ingressPacketRate': 5000,
            'egressPacketRate': 6000,
            'ingressMaxConnections': 10,
            'egressMaxConnections': 20,
        }
        expected_writes = {
            ep_hello_key_v3: ep_hello_value_v3,
            sg_1_key_v3: sg_1_value_v3,
        }
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())

        # Reset for future tests.
        lib.m_compat.cfg.CONF.calico.max_ingress_connections_per_port = 0
        lib.m_compat.cfg.CONF.calico.max_egress_connections_per_port = 0
        del self.osdb_ports[0]['qos_policy_id']

        # Reset the state for safety.
        self.osdb_ports[0]['fixed_ips'] = old_ips

        self.db.get_security_groups.return_value[-1] = {
            'id': 'SG-1',
            'name': 'My first SG',
            'security_group_rules': [
                {'remote_group_id': 'SGID-default',
                 'remote_ip_prefix': None,
                 'protocol': -1,
                 'direction': 'ingress',
                 'ethertype': 'IPv4',
                 'port_range_min': 5060,
                 'port_range_max': 5061}]
        }
        self.db.get_security_group_rules.return_value[-1] = {
            'remote_group_id': 'SGID-default',
            'remote_ip_prefix': None,
            'protocol': -1,
            'direction': 'ingress',
            'ethertype': 'IPv4',
            'security_group_id': 'SG-1',
            'port_range_min': 5060,
            'port_range_max': 5060
        }


class TestPluginEtcd(TestPluginEtcdBase):
    # Tests for the Calico mechanism driver.  This covers the mainline function
    # and the periodic resync thread.

    def test_start_no_ports(self):
        """Startup with no ports or existing etcd data."""
        # Allow the etcd transport's resync thread to run. The last thing it
        # does is write the Felix config, so let it run three reads.

        with lib.FixedUUID('uuid-start-no-ports'):
            self.give_way()
            self.simulated_time_advance(31)

        self.assertEtcdWrites(self.initial_etcd3_writes)

    def test_etcd_reset(self):
        for n in range(1, 20):
            _log.info("Reset etcd data after %s reads/writes/deletes", n)
            self.reset_etcd_after = n
            self.test_start_two_ports()
            self.etcd_data = {}

    def test_noop_entry_points(self):
        """test_noop_entry_points

        Call the mechanism driver entry points that are currently
        implemented as no-ops (because Calico function does not need
        them).
        """
        self.driver.update_network_postcommit(None)
        self.driver.delete_network_postcommit(None)
        self.driver.create_network_postcommit(None)
        self.driver.update_network_postcommit(None)

    def test_subnet_hooks(self):
        """Test subnet creation, update and deletion hooks."""

        # Simulate some legacy (pre-multi-region) subnet data.
        self.etcd_data = {
            '/calico/dhcp/v1/subnet/subnet-id-10.65.0--24': json.dumps({
                'network_id': 'net-id-1',
                'cidr': '10.65.0.0/24',
                'gateway_ip': '10.65.0.1',
                'host_routes': [{'destination': '11.11.0.0/16',
                                 'nexthop': '10.65.0.1'}]
            }),
        }

        # Allow the etcd transport's resync thread to run.  Expect the usual
        # writes.
        with lib.FixedUUID('uuid-subnet-hooks'):
            self.give_way()
            self.simulated_time_advance(31)

        expected_writes = copy.deepcopy(self.initial_etcd3_writes)
        expected_writes[
            '/calico/resources/v3/projectcalico.org/clusterinformations/' +
            'default']['spec']['clusterGUID'] = 'uuid-subnet-hooks'
        self.assertEtcdWrites(expected_writes)

        # Check that the legacy data has been cleaned up.
        self.assertEtcdDeletes(set([
            '/calico/dhcp/v1/subnet/subnet-id-10.65.0--24',
        ]))

        # Define two subnets.
        subnet1 = {'network_id': 'net-id-1',
                   'enable_dhcp': True,
                   'id': 'subnet-id-10.65.0--24',
                   'cidr': '10.65.0/24',
                   'gateway_ip': '10.65.0.1',
                   'host_routes': [{'destination': '11.11.0.0/16',
                                    'nexthop': '10.65.0.1'}],
                   'dns_nameservers': []}
        subnet2 = {'network_id': 'net-id-2',
                   'enable_dhcp': False,
                   'id': 'subnet-id-10.28.0--24',
                   'cidr': '10.28.0/24',
                   'gateway_ip': '10.28.0.1',
                   'host_routes': [],
                   'dns_nameservers': ['172.18.10.55']}
        self.osdb_subnets = [subnet1, subnet2]

        # Notify creation of subnet1, and expect corresponding etcd write.
        context = self.make_context()
        context.current = subnet1
        self.driver.create_subnet_postcommit(context)
        self.assertEtcdWrites({
            '/calico/dhcp/v2/no-region/subnet/subnet-id-10.65.0--24': {
                'network_id': 'net-id-1',
                'cidr': '10.65.0.0/24',
                'gateway_ip': '10.65.0.1',
                'host_routes': [{'destination': '11.11.0.0/16',
                                 'nexthop': '10.65.0.1'}]
            }
        })

        # Notify creation of subnet2, and expect no etcd write as this subnet
        # is not DHCP-enabled.
        context.current = subnet2
        self.driver.create_subnet_postcommit(context)
        self.assertEtcdWrites({})

        # Allow the etcd transport's resync thread to run again.  Expect no
        # change in etcd subnet data.
        self.give_way()
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({})
        self.assertEtcdDeletes(set())

        # Update subnet1 so as not to be DHCP-enabled.
        subnet1['enable_dhcp'] = False
        context.current = subnet1
        self.driver.update_subnet_postcommit(context)
        self.assertEtcdDeletes(set([
            '/calico/dhcp/v2/no-region/subnet/subnet-id-10.65.0--24'
        ]))

        # Update subnet2 to be DHCP-enabled.
        subnet2['enable_dhcp'] = True
        context.current = subnet2
        self.driver.update_subnet_postcommit(context)
        self.assertEtcdWrites({
            '/calico/dhcp/v2/no-region/subnet/subnet-id-10.28.0--24': {
                'network_id': 'net-id-2',
                'cidr': '10.28.0.0/24',
                'gateway_ip': '10.28.0.1',
                'host_routes': [],
                'dns_servers': ['172.18.10.55']
            }
        })

        # Do a resync where we simulate the etcd data having been lost.
        with lib.FixedUUID('uuid-subnet-hooks-2'):
            self.give_way()
            self.etcd_data = {}
            self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)

        expected_writes[
            '/calico/resources/v3/projectcalico.org/clusterinformations/' +
            'default']['spec']['clusterGUID'] = 'uuid-subnet-hooks-2'
        expected_writes.update({
            '/calico/dhcp/v2/no-region/subnet/subnet-id-10.28.0--24': {
                'network_id': 'net-id-2',
                'cidr': '10.28.0.0/24',
                'gateway_ip': '10.28.0.1',
                'host_routes': [],
                'dns_servers': ['172.18.10.55']},
        })
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())

        # Do a resync where we simulate having missed a dynamic update that
        # changed which subnets where DHCP-enabled.
        subnet1['enable_dhcp'] = True
        subnet2['enable_dhcp'] = False
        self.give_way()
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({
            '/calico/dhcp/v2/no-region/subnet/subnet-id-10.65.0--24': {
                'network_id': 'net-id-1',
                'cidr': '10.65.0.0/24',
                'gateway_ip': '10.65.0.1',
                'host_routes': [{'destination': '11.11.0.0/16',
                                 'nexthop': '10.65.0.1'}]}
        })
        self.assertEtcdDeletes(set([
            '/calico/dhcp/v2/no-region/subnet/subnet-id-10.28.0--24'
        ]))

        # Do a resync where we simulate having missed a dynamic update that
        # changed a Calico-relevant property of a DHCP-enabled subnet.
        subnet1['gateway_ip'] = '10.65.0.2'
        self.give_way()
        self.simulated_time_advance(mech_calico.RESYNC_INTERVAL_SECS)
        self.assertEtcdWrites({
            '/calico/dhcp/v2/no-region/subnet/subnet-id-10.65.0--24': {
                'network_id': 'net-id-1',
                'cidr': '10.65.0.0/24',
                'gateway_ip': '10.65.0.2',
                'host_routes': [{'destination': '11.11.0.0/16',
                                 'nexthop': '10.65.0.1'}]}
        })
        self.assertEtcdDeletes(set())

        # Delete subnet2.  No etcd effect because it was already deleted from
        # etcd above.
        context.current = subnet2
        self.driver.delete_subnet_postcommit(context)
        self.assertEtcdDeletes(set())

        # Delete subnet1.
        context.current = subnet1
        self.driver.delete_subnet_postcommit(context)
        self.assertEtcdDeletes(set([
            '/calico/dhcp/v2/no-region/subnet/subnet-id-10.65.0--24'
        ]))

    def test_check_segment_for_agent(self):
        """Test the mechanism driver's check_segment_for_agent entry point."""
        # Simulate ML2 asking the driver if it can handle a port.
        self.assertTrue(self.driver.check_segment_for_agent(
            {mech_calico.api.NETWORK_TYPE: 'flat',
             mech_calico.api.ID: 'shiny'},
            mech_calico.constants.AGENT_TYPE_DHCP
        ))

        # Simulate ML2 asking the driver if it can handle a port that
        # it can't handle.
        self.assertFalse(self.driver.check_segment_for_agent(
            {mech_calico.api.NETWORK_TYPE: 'vlan',
             mech_calico.api.ID: 'not-shiny'},
            mech_calico.constants.AGENT_TYPE_DHCP
        ))

    def test_neutron_rule_to_etcd_rule_icmp(self):
        # No type/code specified
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "ethertype": "IPv4",
            "protocol": "icmp",
        }), {'action': 'Allow', 'ipVersion': 4, 'protocol': 'ICMP'})
        # Type/code wildcarded, same as above.
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "ethertype": "IPv4",
            "protocol": "icmp",
            "port_range_min": -1,
            "port_range_max": -1,
        }), {'action': 'Allow', 'ipVersion': 4, 'protocol': 'ICMP'})
        # Type and code.
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "ethertype": "IPv4",
            "protocol": "icmp",
            "port_range_min": 123,
            "port_range_max": 100,
        }), {'icmp': {'code': 100, 'type': 123},
             'protocol': 'ICMP',
             'ipVersion': 4,
             'action': 'Allow'})
        # Numeric type.
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "ethertype": "IPv4",
            "protocol": 123,
            "direction": "egress",
            "remote_group_id": "foobar",
        }), {
            'ipVersion': 4,
            'protocol': 123,
            'destination': {'selector':
                            'has(sg.projectcalico.org/openstack-foobar)'},
            'action': 'Allow',
        })
        # Type and code, IPv6.
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "ethertype": "IPv6",
            "protocol": "icmp",
            "port_range_min": 123,
            "port_range_max": 100,
        }), {
            'ipVersion': 6,
            'protocol': 'ICMPv6',
            'icmp': {'type': 123, 'code': 100},
            'action': 'Allow',
        })

    def test_neutron_rule_to_etcd_rule_protocol_name(self):
        for neutron_protocol_spec, calico_protocol_spec in \
                lib.m_compat.IP_PROTOCOL_MAP.items():
            self.assertNeutronToEtcd(_neutron_rule_from_dict({
                "protocol": neutron_protocol_spec,
            }), {
                'action': 'Allow',
                'ipVersion': 4,
                'protocol': calico_protocol_spec,
            })

    def test_neutron_rule_to_etcd_rule_protocol_any(self):
        for protocol_spec in ['any', 0]:
            self.assertNeutronToEtcd(_neutron_rule_from_dict({
                "protocol": protocol_spec,
            }), {
                'action': 'Allow',
                'ipVersion': 4,
            })

    def test_sg_rule_ingress_no_remote_ip_prefix(self):
        # SG ingress rule with ports but no remote IP prefix
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "protocol": "tcp",
            "port_range_min": 25,
            "port_range_max": 34,
        }), {
            'action': 'Allow',
            'destination': {'ports': ['25:34']},
            'ipVersion': 4,
            'protocol': 'TCP',
        })

    def test_sg_rule_egress_no_remote_ip_prefix(self):
        # SG egress rule with ports but no remote IP prefix
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "direction": "egress",
            "protocol": "tcp",
            "port_range_min": 25,
            "port_range_max": 34,
        }), {
            'action': 'Allow',
            'destination': {'ports': ['25:34']},
            'ipVersion': 4,
            'protocol': 'TCP',
        })

    def test_sg_rule_ingress_with_remote_ip_prefix(self):
        # SG ingress rule with ports and remote IP prefix
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "protocol": "tcp",
            "remote_ip_prefix": "1.2.3.0/24",
            "port_range_min": 25,
            "port_range_max": 34,
        }), {
            'action': 'Allow',
            'destination': {'ports': ['25:34']},
            'ipVersion': 4,
            'protocol': 'TCP',
            'source': {'nets': ['1.2.3.0/24']},
        })

    def test_sg_rule_egress_with_remote_ip_prefix(self):
        # SG egress rule with ports and remote IP prefix
        self.assertNeutronToEtcd(_neutron_rule_from_dict({
            "direction": "egress",
            "protocol": "tcp",
            "remote_ip_prefix": "1.2.3.0/24",
            "port_range_min": 25,
            "port_range_max": 34,
        }), {
            'action': 'Allow',
            'destination': {'nets': ['1.2.3.0/24'], 'ports': ['25:34']},
            'ipVersion': 4,
            'protocol': 'TCP',
        })

    def test_not_master_does_not_resync(self):
        """Test that a driver that is not master does not resync."""
        # Initialize the state early to put the elector in place, then override
        # it to claim that the driver is not master.
        self.driver._post_fork_init()

        with mock.patch.object(self.driver, "elector") as m_elector:
            m_elector.master.return_value = False

            # Allow the etcd transport's resync thread to run. Nothing will
            # happen.
            self.give_way()
            self.simulated_time_advance(31)
            self.assertEtcdWrites({})

    def assertNeutronToEtcd(self, neutron_rule, exp_etcd_rule):
        etcd_rule = policy._neutron_rule_to_etcd_rule(neutron_rule)
        self.assertEqual(exp_etcd_rule, etcd_rule)

    def test_profile_prefixing(self):
        """Startup with existing profile data from another orchestrator."""

        # Check that we don't delete the other orchestrator's profile data.
        self.etcd_data = {
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            'mesos/profile-1': json.dumps({
                'apiVersion': 'projectcalico.org/v3',
                'kind': 'NetworkPolicy',
                'metadata': {'name': 'mesos-profile-1'},
                'spec': {
                    'egress': [
                        {'action': 'Allow',
                         'ipVersion': 4},
                        {'action': 'Allow',
                         'ipVersion': 6}],
                    'ingress': [
                        {'action': 'Allow',
                         'ipVersion': 4,
                         'source': {
                             'selector':
                             'has(sg.projectcalico.org/openstack-SGID-default)'
                         }},
                        {'action': 'Allow',
                         'ipVersion': 6,
                         'source': {
                             'selector':
                             'has(sg.projectcalico.org/openstack-SGID-default)'
                         }}],
                    'selector':
                    'has(sg.projectcalico.org/openstack-SGID-default)'}}
            )}
        with lib.FixedUUID('uuid-profile-prefixing'):
            self.give_way()
            self.simulated_time_advance(31)

        expected_writes = copy.deepcopy(self.initial_etcd3_writes)
        expected_writes[
            '/calico/resources/v3/projectcalico.org/clusterinformations/' +
            'default']['spec']['clusterGUID'] = 'uuid-profile-prefixing'
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set())

    def test_policy_coexistence(self):
        """Coexistence with other data in the 'openstack' namespace.

        Check that we _do_ clean up old policy data that has our prefix, but
        _don't_ touch policies without our prefix.
        """

        # Start up with two existing policies in the 'openstack'
        # namespace.
        self.etcd_data = {
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            'openstack/customer-policy-1': json.dumps({
                'apiVersion': 'projectcalico.org/v3',
                'kind': 'NetworkPolicy',
                'metadata': {
                    'name': 'customer-policy-2',
                    'namespace': 'openstack',
                },
                'spec': {
                    'selector':
                    'has(sg.projectcalico.org/openstack-SGID-default)'}}
            ),
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            'openstack/ossg.default.SOME_OLD_SG': json.dumps({
                'apiVersion': 'projectcalico.org/v3',
                'kind': 'NetworkPolicy',
                'metadata': {
                    'name': 'ossg.default.SOME_OLD_SG',
                    'namespace': 'openstack',
                },
                'spec': {
                    'selector':
                    'has(sg.projectcalico.org/openstack-SOME_OLD_SG)'}}
            ),
        }
        with lib.FixedUUID('uuid-profile-prefixing'):
            self.give_way()
            self.simulated_time_advance(31)

        expected_writes = copy.deepcopy(self.initial_etcd3_writes)
        expected_writes[
            '/calico/resources/v3/projectcalico.org/clusterinformations/' +
            'default']['spec']['clusterGUID'] = 'uuid-profile-prefixing'
        self.assertEtcdWrites(expected_writes)

        # We should clean up the old 'ossg.default.' policy, but not the
        # customer one.
        self.assertEtcdDeletes(set([
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            'openstack/ossg.default.SOME_OLD_SG'
        ]))

    def test_old_openstack_data(self):
        """Startup with existing but old OpenStack profile data."""

        # Check that we clean up policy data that we created, but not policy
        # data that the user created.
        our_policy_string = json.dumps({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'NetworkPolicy',
            'metadata': {
                'namespace': 'openstack',
                'name': 'ossg.default.OLD'
            },
            'spec': {
                'egress': [
                    {'action': 'Allow',
                     'ipVersion': 4},
                    {'action': 'Allow',
                     'ipVersion': 6}],
                'ingress': [
                    {'action': 'Allow',
                     'ipVersion': 4,
                     'source': {
                         'selector':
                         'has(sg.projectcalico.org/openstack-OLD)'}},
                    {'action': 'Allow',
                     'ipVersion': 6,
                     'source': {
                         'selector':
                         'has(sg.projectcalico.org/openstack-OLD)'}}],
                'selector': 'has(sg.projectcalico.org/openstack-OLD)'}}
        )
        user_policy_string = our_policy_string.replace("ossg", "user")
        self.etcd_data = {
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            'openstack/ossg.default.OLD': our_policy_string,
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            'openstack/user.default.OLD': user_policy_string,
        }
        with lib.FixedUUID('uuid-old-data'):
            self.give_way()
            self.simulated_time_advance(31)

        expected_writes = copy.deepcopy(self.initial_etcd3_writes)
        expected_writes[
            '/calico/resources/v3/projectcalico.org/clusterinformations/' +
            'default']['spec']['clusterGUID'] = 'uuid-old-data'
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set([
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            'openstack/ossg.default.OLD',
        ]))


class TestPluginEtcdRegion(TestPluginEtcdBase):

    def setUp_region(self):
        self.region = "europe"
        self.region_string = "region-europe"
        self.namespace = "openstack-region-europe"

    def test_legacy_openstack_data(self):
        """Startup with existing data in legacy "openstack" namespace."""

        # Check that we clean up policy data that we created, but not policy
        # data that the user created.
        our_policy_string = json.dumps({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'NetworkPolicy',
            'metadata': {
                'namespace': 'openstack',
                'name': 'ossg.default.OLD'
            },
            'spec': {
                'egress': [
                    {'action': 'Allow',
                     'ipVersion': 4},
                    {'action': 'Allow',
                     'ipVersion': 6}],
                'ingress': [
                    {'action': 'Allow',
                     'ipVersion': 4,
                     'source': {
                         'selector':
                         'has(sg.projectcalico.org/openstack-OLD)'}},
                    {'action': 'Allow',
                     'ipVersion': 6,
                     'source': {
                         'selector':
                         'has(sg.projectcalico.org/openstack-OLD)'}}],
                'selector': 'has(sg.projectcalico.org/openstack-OLD)'}}
        )
        user_policy_string = our_policy_string.replace("ossg", "user")
        self.etcd_data = {
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            'openstack/ossg.default.OLD': our_policy_string,
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            'openstack/user.default.OLD': user_policy_string,
        }
        with lib.FixedUUID('uuid-old-data'):
            self.give_way()
            self.simulated_time_advance(31)

        expected_writes = copy.deepcopy(self.initial_etcd3_writes)
        expected_writes[
            '/calico/resources/v3/projectcalico.org/clusterinformations/' +
            'default']['spec']['clusterGUID'] = 'uuid-old-data'
        self.assertEtcdWrites(expected_writes)
        self.assertEtcdDeletes(set([
            '/calico/resources/v3/projectcalico.org/networkpolicies/' +
            'openstack/ossg.default.OLD'
        ]))


class TestDriverStatusReporting(lib.Lib, unittest.TestCase):
    """Tests of the driver's status reporting function."""
    def setUp(self):
        super(TestDriverStatusReporting, self).setUp()

        # Mock out config.
        lib.m_compat.cfg.CONF.calico.etcd_host = "localhost"
        lib.m_compat.cfg.CONF.calico.etcd_port = 4001

    def test_felix_agent_state(self):
        self.assertEqual(
            {
                "agent_type": "Calico per-host agent (felix)",
                "binary": "calico-felix",
                "host": "host",
                "start_flag": True,
                'topic': mech_calico.constants.L2_AGENT_TOPIC,
            },
            mech_calico.felix_agent_state("host", True)
        )
        self.assertEqual(
            {
                "agent_type": "Calico per-host agent (felix)",
                "binary": "calico-felix",
                "host": "host2",
                'topic': mech_calico.constants.L2_AGENT_TOPIC,
            },
            mech_calico.felix_agent_state("host2", False)
        )

    def test_status_thread_epoch(self):
        self.driver._epoch = 2
        self.driver._status_updating_thread(1)

    @mock.patch("networking_calico.plugins.ml2.drivers.calico.mech_calico."
                "StatusWatcher",
                autospec=True)
    def test_status_thread_mainline(self, m_StatusWatcher):
        count = [0]

        with mock.patch.object(self.driver, "elector") as m_elector:
            m_elector.master.return_value = True

            def maybe_end_loop(*args, **kwargs):
                if count[0] == 2:
                    # Thread dies, should be restarted.
                    self.driver._etcd_watcher_thread = False
                if count[0] == 4:
                    # After a few loops, stop being the master...
                    m_elector.master.return_value = False
                if count[0] > 6:
                    # Then terminate the loop after a few more...
                    self.driver._epoch += 1
                count[0] += 1

            with mock.patch("eventlet.spawn") as m_spawn:
                with mock.patch("eventlet.sleep") as m_sleep:
                    m_sleep.side_effect = maybe_end_loop
                    self.driver._status_updating_thread(0)

        m_watcher = m_StatusWatcher.return_value
        self.assertEqual(
            [
                mock.call(m_watcher.start),
                mock.call(m_watcher.start),
            ],
            [c for c in m_spawn.mock_calls if c[0] == ""]
        )
        self.assertEqual(2, len(m_watcher.stop.mock_calls))
        self.assertIsNone(self.driver._etcd_watcher)

    def test_on_felix_alive(self):
        self.driver._get_db()
        self.driver._agent_update_context = mock.Mock()
        with mock.patch.object(self.driver, "state_report_rpc") as m_rpc:
            self.driver.on_felix_alive("hostfoo", True)
        self.assertEqual(
            [
                mock.call(
                    self.driver._agent_update_context,
                    {
                        "agent_type": "Calico per-host agent (felix)",
                        "binary": "calico-felix",
                        "host": "hostfoo",
                        "start_flag": True,
                        'topic': mech_calico.constants.L2_AGENT_TOPIC,
                    },
                    use_call=False
                )
            ],
            m_rpc.report_state.mock_calls
        )

    def test_on_port_status_changed(self):
        self.driver._last_status_queue_log_time = monotonic_time() - 100
        with mock.patch.object(self.driver, "_port_status_queue") as m_queue:
            m_queue.qsize.return_value = 100
            self.driver.on_port_status_changed("host", "port_id",
                                               {"status": "up"},
                                               priority="high")
            self.assertEqual(
                "up",
                self.driver._port_status_cache[("host", "port_id")]
            )
            self.assertEqual([mock.call(((0, mock.ANY),
                                         ("host",  "port_id")))],
                             m_queue.put.mock_calls)
            m_queue.put.reset_mock()
            # Send a duplicate low-priority change.
            self.driver.on_port_status_changed("host", "port_id",
                                               {"status": "up"},
                                               priority="low")
            # Should have no effect on the cache.
            self.assertEqual(
                "up",
                self.driver._port_status_cache[("host", "port_id")]
            )
            # And the queue update should be skipped.
            self.assertEqual([], m_queue.put.mock_calls)
            m_queue.put.reset_mock()

            # Send a duplicate high-priority change.
            self.driver.on_port_status_changed("host", "port_id",
                                               {"status": "up"},
                                               priority="high")
            # Should have no effect on the cache.
            self.assertEqual(
                "up",
                self.driver._port_status_cache[("host", "port_id")]
            )
            # But the queue update should happen.
            self.assertEqual([mock.call(((0, mock.ANY),
                                         ("host",  "port_id")))],
                             m_queue.put.mock_calls)
            m_queue.put.reset_mock()

            # Deletion takes a different code path.
            self.driver.on_port_status_changed("host", "port_id", None,
                                               priority="low")
            self.assertEqual({}, self.driver._port_status_cache)
            # Unknown value should be treated as deletion.
            self.driver.on_port_status_changed("host", "port_id",
                                               {"status": "unknown"},
                                               priority="low")
            self.assertEqual({}, self.driver._port_status_cache)
            # One queue put for each deletion.
            self.assertEqual(
                [
                    mock.call(((1, mock.ANY), ("host", "port_id"))),
                    mock.call(((1, mock.ANY), ("host", "port_id"))),
                ],
                m_queue.put.mock_calls
            )

    def test_loop_writing_port_statuses(self):
        with mock.patch.object(self.driver, "_port_status_queue") as m_queue:
            with mock.patch.object(self.driver,
                                   "_try_to_update_port_status") as m_try_upd:
                m_queue.get.side_effect = iter([((1, mock.ANY),
                                                 ("host", "port"))])
                self.assertRaises(StopIteration,
                                  self.driver._loop_writing_port_statuses,
                                  self.driver._epoch)
        self.assertEqual(
            [
                mock.call(mock.ANY, ("host", "port")),
            ],
            m_try_upd.mock_calls
        )

    def test_try_to_update_port_status(self):
        # New OpenStack releases have a host parameter.
        self.driver._get_db()

        # Driver uses reflection to check the function sig so we have to put
        # a real function here.
        mock_calls = []

        def m_update_port_status(context, port_id, status):
            """Older version of OpenStack; no host parameter"""
            mock_calls.append(mock.call(context, port_id, status))

        self.db.update_port_status = m_update_port_status
        context = mock.Mock()
        with mock.patch("eventlet.spawn_after", autospec=True) as m_spawn:
            self.driver._try_to_update_port_status(context, ("host", "p1"))
        self.assertEqual([mock.call(context, "p1",
                                    mech_calico.constants.PORT_STATUS_ERROR)],
                         mock_calls)
        self.assertEqual([], m_spawn.mock_calls)  # No retry on success

    def test_try_to_update_port_status_fail(self):
        # New OpenStack releases have a host parameter.
        self.driver._get_db()

        # Driver uses reflection to check the function sig so we have to put
        # a real function here.
        mock_calls = []

        def m_update_port_status(context, port_id, status, host=None):
            """Newer version of OpenStack; host parameter"""
            mock_calls.append(mock.call(context, port_id, status, host=host))
            raise lib.DBError()

        self.db.update_port_status = m_update_port_status
        self.driver._port_status_cache[("host", "p1")] = "up"
        context = mock.Mock()
        with mock.patch("eventlet.spawn_after", autospec=True) as m_spawn:
            self.driver._try_to_update_port_status(context, ("host", "p1"))
        self.assertEqual([mock.call(context, "p1",
                                    mech_calico.constants.PORT_STATUS_ACTIVE,
                                    host="host")],
                         mock_calls)
        self.assertEqual(
            [
                mock.call(5, self.driver._retry_port_status_update,
                          ("host", "p1"))
            ],
            m_spawn.mock_calls)

    def _port_status_update(self):
        with mock.patch.object(self.driver, "_port_status_queue") as m_queue:
            self.driver._retry_port_status_update(("host", "port"))
        self.assertEqual([mock.call(("host", "port"))], m_queue.put.mock_calls)


class TestStatusWatcherBase(_TestEtcdBase):

    def setUp_region(self):
        self.region = None
        self.region_string = "no-region"

    def setUp(self):
        self.setUp_region()
        _log.info("Region %r string %r", self.region, self.region_string)

        # Mock out config.
        lib.m_compat.cfg.CONF.calico.etcd_host = "localhost"
        lib.m_compat.cfg.CONF.calico.etcd_port = 4001
        lib.m_compat.cfg.CONF.calico.etcd_key_file = None
        lib.m_compat.cfg.CONF.calico.etcd_cert_file = None
        lib.m_compat.cfg.CONF.calico.etcd_ca_cert_file = None
        lib.m_compat.cfg.CONF.calico.openstack_region = self.region
        calico_config._reset_globals()
        datamodel_v2._reset_globals()

        super(TestStatusWatcherBase, self).setUp()
        self.driver = mock.Mock(spec=mech_calico.CalicoMechanismDriver)
        self.watcher = status.StatusWatcher(self.driver)

    def _add_test_endpoint(self):
        # Add a workload to be deleted
        m_port_status_node = mock.Mock()
        m_port_status_node.key = (
            ("/calico/felix/v2/%s/host/hostname/workload/" +
             "openstack/wlid/endpoint/ep1") % self.region_string
        )
        m_port_status_node.value = '{"status": "up"}'
        self.watcher._on_ep_set(m_port_status_node, "hostname", "wlid", "ep1")
        ep_id = datamodel_v1.WloadEndpointId("hostname", "openstack",
                                             "wlid", "ep1")
        self.assertEqual({"hostname": set([ep_id])},
                         self.watcher._endpoints_by_host)
        return m_port_status_node


class TestStatusWatcher(TestStatusWatcherBase):

    def test_tls(self):
        lib.m_compat.cfg.CONF.calico.etcd_cert_file = "cert-file"
        lib.m_compat.cfg.CONF.calico.etcd_ca_cert_file = "ca-cert-file"
        lib.m_compat.cfg.CONF.calico.etcd_key_file = "key-file"
        self.watcher = status.StatusWatcher(self.driver)

    @mock.patch('eventlet.spawn')
    def test_snapshot(self, m_spawn):
        # Populate initial status tree data, for initial snapshot testing.

        felix_status_key = '/calico/felix/v2/no-region/host/hostname/status'
        felix_last_reported_status_key = \
            '/calico/felix/v2/no-region/host/hostname/last_reported_status'
        ep_on_that_host_key = (
            '/calico/felix/v2/no-region/host/hostname/workload/' +
            'openstack/wlid/endpoint/ep1')
        ep_on_unknown_host_key = (
            '/calico/felix/v2/no-region/host/unknown/workload/' +
            'openstack/wlid/endpoint/ep2')

        self.etcd_data = {
            # An agent status key to ignore.
            felix_last_reported_status_key: json.dumps({
                "uptime": 10,
                "first_update": True}),
            # An agent status key to take notice of.
            felix_status_key: json.dumps({
                "uptime": 10,
                "first_update": True}),
            # A port status key to take notice of.
            ep_on_that_host_key: '{"status": "up"}',
            # A port status key to ignore.
            ep_on_unknown_host_key: '{"status": "up"}',
        }

        watch_events = []

        def _iterator():
            for e in watch_events:
                yield e
            _log.info("Stop watcher now")
            self.watcher.stop()
            yield None

        def _cancel():
            pass

        self.clientv3.watch_prefix.return_value = _iterator(), _cancel

        # Start the watcher.  It will do initial snapshot processing, then stop
        # when it tries to watch for further changes.
        self.watcher.start()

        self.driver.on_felix_alive.assert_called_once_with("hostname",
                                                           new=True)
        self.driver.on_port_status_changed.assert_has_calls([
            mock.call("unknown", "ep2", {"status": "up"}, priority="low"),
            mock.call("hostname", "ep1", {"status": "up"}, priority="low"),
        ], any_order=True)

        # Start the watcher again, with the same etcd data.  We should see the
        # same status callbacks.
        self.driver.on_felix_alive.reset_mock()
        self.driver.on_port_status_changed.reset_mock()
        self.clientv3.watch_prefix.return_value = _iterator(), _cancel
        self.watcher.start()
        self.driver.on_felix_alive.assert_not_called()
        self.driver.on_port_status_changed.assert_has_calls([
            mock.call("unknown", "ep2", {"status": "up"}, priority="low"),
            mock.call("hostname", "ep1", {"status": "up"}, priority="low"),
        ], any_order=True)

        # Resync after deleting the unknown host endpoint.  We should see that
        # endpoint reported with status None.
        del self.etcd_data[ep_on_unknown_host_key]
        self.driver.on_felix_alive.reset_mock()
        self.driver.on_port_status_changed.reset_mock()
        self.clientv3.watch_prefix.return_value = _iterator(), _cancel
        self.watcher.start()
        self.driver.on_felix_alive.assert_not_called()
        self.driver.on_port_status_changed.assert_has_calls([
            mock.call("unknown", "ep2", None, priority="low"),
            mock.call("hostname", "ep1", {"status": "up"}, priority="low"),
        ], any_order=True)

        # Resync after deleting the Felix status.  This does not affect the
        # status of ep1.
        del self.etcd_data[felix_status_key]
        self.driver.on_felix_alive.reset_mock()
        self.driver.on_port_status_changed.reset_mock()
        self.clientv3.watch_prefix.return_value = _iterator(), _cancel
        self.watcher.start()
        self.driver.on_felix_alive.assert_not_called()
        self.driver.on_port_status_changed.assert_has_calls([
            mock.call("hostname", "ep1", {"status": "up"}, priority="low"),
        ], any_order=True)

        # Resync with some follow-on events; checks that the priority goes
        # back to high after the snapshot.
        watch_events = [{
            "kv": {
                "key": ("/calico/felix/v2/no-region/host/hostname/workload/" +
                        "openstack/wlid/endpoint/ep1").encode(),
                "value": '{"status": "up"}'.encode(),
            },
            "type": "SET",
        }]
        self.driver.on_felix_alive.reset_mock()
        self.driver.on_port_status_changed.reset_mock()
        self.clientv3.watch_prefix.return_value = _iterator(), _cancel
        self.watcher.start()
        self.driver.on_felix_alive.assert_not_called()
        self.driver.on_port_status_changed.assert_has_calls([
            mock.call("hostname", "ep1", {"status": "up"}, priority="high"),
        ], any_order=True)

    def test_endpoint_status_add_delete(self):
        m_port_status_node = self._add_test_endpoint()
        m_port_status_node.action = "delete"
        self.watcher._on_ep_delete(m_port_status_node,
                                   "hostname", "wlid", "ep1")

        self.assertEqual(
            [
                mock.call("hostname", "ep1", {"status": "up"},
                          priority="high"),
                mock.call("hostname", "ep1", None, priority="high"),
            ],
            self.driver.on_port_status_changed.mock_calls)
        self.assertEqual({}, self.watcher._endpoints_by_host)

    def test_endpoint_status_add_bad_json(self):
        m_port_status_node = mock.Mock()
        m_port_status_node.key = "/calico/felix/v2/no-region/host/hostname/workload/" \
                                 "openstack/wlid/endpoint/ep1"
        m_port_status_node.value = '{"status": "up"'
        self.watcher._on_ep_set(m_port_status_node, "hostname", "wlid", "ep1")

        self.assertEqual(
            [
                mock.call("hostname", "ep1", None, priority="high"),
            ],
            self.driver.on_port_status_changed.mock_calls)
        self.assertEqual({}, self.watcher._endpoints_by_host)

    def test_endpoint_status_add_bad_id(self):
        m_port_status_node = mock.Mock()
        m_port_status_node.key = "/calico/felix/v2/no-region/host/hostname/workload/" \
                                 "openstack/wlid/endpoint"
        self.watcher._on_ep_set(m_port_status_node, "hostname", "wlid", "ep1")
        self.assertEqual(
            [],
            self.driver.on_port_status_changed.mock_calls)
        self.assertEqual({}, self.watcher._endpoints_by_host)

    def test_status_bad_json(self):
        for value in ["{", 10, "foo"]:
            m_response = mock.Mock()
            m_response.key = "/calico/felix/v2/no-region/host/hostname/status"
            m_response.value = value
            self.watcher._on_status_set(m_response, "foo")
        self.assertFalse(self.driver.on_felix_alive.called)

    def test_felix_status_expiry(self):
        # Put an endpoint in the cache to find later...
        m_response = mock.Mock()
        m_response.key = "/calico/felix/v2/no-region/host/hostname/workload/" \
                         "openstack/wlid/endpoint/epid"
        m_response.value = '{"status": "up"}'
        self.watcher._on_ep_set(m_response, "hostname", "wlid", "epid")

        # Then note that felix is down.
        m_response = mock.Mock()
        m_response.key = "/calico/felix/v2/no-region/host/hostname/status"
        self.watcher._on_status_del(m_response, "hostname")

        # Check that nothing happens to the port.  (Previously, we used to mark
        # the port as in ERROR but that behaviour was removed due to its
        # impact at high scale.)
        self.assertEqual(
            [
                mock.call("hostname", "epid", {"status": "up"},
                          priority="high"),
            ],
            self.driver.on_port_status_changed.mock_calls)


class TestMultiRegionStatusWatcher(TestStatusWatcherBase):

    def setUp_region(self):
        self.region = "europe"
        self.region_string = "region-europe"

    def test_endpoint_status_add_delete(self):
        m_port_status_node = self._add_test_endpoint()
        m_port_status_node.action = "delete"
        self.watcher._on_ep_delete(m_port_status_node,
                                   "hostname", "wlid", "ep1")

        self.assertEqual(
            [
                mock.call("hostname", "ep1", {"status": "up"},
                          priority="high"),
                mock.call("hostname", "ep1", None, priority="high"),
            ],
            self.driver.on_port_status_changed.mock_calls)
        self.assertEqual({}, self.watcher._endpoints_by_host)

    def test_handle_port_this_region(self):
        # Simulate status update for a workload in this region.
        m_port_status_node = mock.Mock()
        m_port_status_node.key = (
            "/calico/felix/v2/" + self.region_string +
            "/host/hostname/workload/openstack/wlid/endpoint/ep1"
        )
        m_port_status_node.value = '{"status": "up"}'
        m_port_status_node.action = "set"
        self.watcher.dispatcher.handle_event(m_port_status_node)
        self.assertEqual(
            [
                mock.call("hostname", "ep1", {"status": "up"},
                          priority="high"),
            ],
            self.driver.on_port_status_changed.mock_calls)

    def test_ignore_port_other_region(self):
        # Simulate status update for a workload in another region.
        m_port_status_node = mock.Mock()
        m_port_status_node.key = (
            "/calico/felix/v2/region-other/host/hostname/workload/" +
            "openstack/wlid/endpoint/ep1"
        )
        m_port_status_node.value = '{"status": "up"}'
        m_port_status_node.action = "set"
        self.watcher.dispatcher.handle_event(m_port_status_node)
        self.assertEqual(
            [],
            self.driver.on_port_status_changed.mock_calls)

    def test_handle_felix_this_region(self):
        self.driver.on_felix_alive.reset_mock()
        m_response = mock.Mock()
        m_response.action = "set"
        m_response.key = ("/calico/felix/v2/" +
                          self.region_string +
                          "/host/hostname/status")
        m_response.value = json.dumps({
            "uptime": 10,
            "first_update": True,
        })
        self.watcher.dispatcher.handle_event(m_response)
        self.assertTrue(self.driver.on_felix_alive.called)

    def test_ignore_felix_other_region(self):
        self.driver.on_felix_alive.reset_mock()
        m_response = mock.Mock()
        m_response.action = "set"
        m_response.key = "/calico/felix/v2/region-other/host/hostname/status"
        m_response.value = json.dumps({
            "uptime": 10,
            "first_update": True,
        })
        self.watcher.dispatcher.handle_event(m_response)
        self.assertFalse(self.driver.on_felix_alive.called)


def _neutron_rule_from_dict(overrides):
    rule = {
        "ethertype": "IPv4",
        "protocol": None,
        "remote_ip_prefix": None,
        "remote_group_id": None,
        "direction": "ingress",
        "port_range_min": None,
        "port_range_max": None,
    }
    rule.update(overrides)
    return rule
