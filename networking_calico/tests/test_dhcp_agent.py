# Copyright 2016 Metaswitch Networks
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

from collections import namedtuple
import etcd
import eventlet
import json
import logging
import mock
import socket

LOG = logging.getLogger(__name__)

from networking_calico.agent.dhcp_agent import CalicoDhcpAgent
from networking_calico.agent.dhcp_agent import FakePlugin
from networking_calico.agent.dhcp_agent import get_etcd_connection_settings
from networking_calico.agent.linux.dhcp import DnsmasqRouted
from networking_calico.common import config as calico_config
from networking_calico import datamodel_v1
from networking_calico.etcdutils import EtcdWatcher
from neutron.agent.dhcp_agent import register_options
from neutron.agent.linux import dhcp
from neutron.common import constants
from neutron.tests import base
from oslo_config import cfg


EtcdResponse = namedtuple('EtcdResponse', ['value'])


class TestFakePlugin(base.BaseTestCase):
    def setUp(self):
        super(TestFakePlugin, self).setUp()
        self.plugin = FakePlugin()

    def test_create(self):
        port = self.plugin.create_dhcp_port({
            'port': {'network_id': 'net-id-0'}
        })
        self.assertEqual({
            'network_id': 'net-id-0',
            'device_owner': 'network:dhcp',
            'id': 'net-id-0',
            'mac_address': '02:00:00:00:00:00'},
            port)

    def test_release(self):
        self.plugin.release_dhcp_port('calico', 'dhcp')


class TestDhcpAgent(base.BaseTestCase):
    def setUp(self):
        super(TestDhcpAgent, self).setUp()
        register_options(cfg.CONF)
        calico_config.register_options(cfg.CONF)

    @mock.patch('etcd.Client')
    def test_mainline(self, etcd_client_cls):
        # Create the DHCP agent.
        agent = CalicoDhcpAgent()
        etcd_client = etcd_client_cls.return_value

        # Check that running it invokes the etcd watcher loop.
        with mock.patch.object(agent, 'etcd') as etcdobj:
            agent.run()
            etcdobj.loop.assert_called_with()

        # Notify initial snapshot (empty).
        with mock.patch.object(agent, 'call_driver') as call_driver:
            etcd_snapshot_response = mock.Mock()
            etcd_snapshot_response.leaves = []
            agent.etcd._on_snapshot_loaded(etcd_snapshot_response)
            call_driver.assert_not_called()

        # Prepare subnet reads for the endpoints that we will notify.
        self.first_workload_read = True

        def etcd_client_read(key, **kwargs):
            LOG.info('etcd_client_read %s %s', key, kwargs)
            if 'v4subnet-1' in key:
                self.assertEqual('/calico/dhcp/v1/subnet/v4subnet-1',
                                 key)
                return EtcdResponse(value=json.dumps({
                    'cidr': '10.28.0.0/24',
                    'gateway_ip': '10.28.0.1',
                    'host_routes': []
                }))
            if 'v6subnet-1' in key:
                return EtcdResponse(value=json.dumps({
                    'cidr': '2001:db8:1::/80',
                    'gateway_ip': '2001:db8:1::1'
                }))
            if 'v4subnet-2' in key:
                return EtcdResponse(value=json.dumps({
                    'cidr': '10.29.0.0/24',
                    'gateway_ip': '10.29.0.1',
                    'host_routes': [{'destination': '11.11.0.0/16',
                                     'nexthop': '10.65.0.1'}]
                }))
            if key == '/calico/v1/host/nj-ubuntu/workload':
                if self.first_workload_read:
                    # This is the recursive read that the CalicoEtcdWatcher
                    # loop makes after we've triggered it to resync.
                    etcd_snapshot_node = mock.Mock()
                    etcd_snapshot_node.action = 'exist'
                    etcd_snapshot_node.key = (
                        "/calico/v1/host/" +
                        socket.gethostname() +
                        "/workload/openstack" +
                        "/workload_id/endpoint/endpoint-4"
                    )
                    etcd_snapshot_node.value = json.dumps({
                        'state': 'active',
                        'name': 'tap1234',
                        'mac': 'fe:16:65:12:33:44',
                        'profile_ids': ['profile-1'],
                        'ipv4_nets': ['10.28.0.2/32'],
                        'ipv4_subnet_ids': ['v4subnet-1'],
                        'ipv4_gateway': '10.28.0.1',
                        'ipv6_nets': [],
                        'ipv6_subnet_ids': []
                    })
                    etcd_snapshot_response = mock.Mock()
                    etcd_snapshot_response.etcd_index = 99
                    etcd_snapshot_response.leaves = [etcd_snapshot_node]
                    self.first_workload_read = False
                    return etcd_snapshot_response

            eventlet.sleep(10)
            return None

        etcd_client.read.side_effect = etcd_client_read

        with mock.patch.object(agent, 'call_driver') as call_driver:
            # Notify an endpoint.
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({
                'state': 'active',
                'name': 'tap1234',
                'mac': 'fe:16:65:12:33:44',
                'profile_ids': ['profile-1'],
                'ipv4_nets': ['10.28.0.2/32'],
                'ipv4_subnet_ids': ['v4subnet-1'],
                'ipv4_gateway': '10.28.0.1',
                'ipv6_nets': ['2001:db8:1::2/128'],
                'ipv6_subnet_ids': ['v6subnet-1'],
                'ipv6_gateway': '2001:db8:1::1'
            })),
                'hostname-ignored',
                'openstack',
                'workload-id-ignored',
                'endpoint-1'
            )

            # Check expected subnets were read from etcd.
            etcd_client.read.assert_has_calls([
                mock.call(datamodel_v1.key_for_subnet('v4subnet-1'),
                          consistent=True),
                mock.call(datamodel_v1.key_for_subnet('v6subnet-1'),
                          consistent=True)
            ],
                any_order=True)
            etcd_client.read.reset_mock()

            # Check DHCP driver was asked to restart.
            call_driver.assert_called_with('restart', mock.ANY)

            # Notify another endpoint (using the same subnets).
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({
                'state': 'active',
                'name': 'tap5678',
                'mac': 'fe:16:65:12:33:55',
                'profile_ids': ['profile-1'],
                'ipv4_nets': ['10.28.0.3/32'],
                'ipv4_subnet_ids': ['v4subnet-1'],
                'ipv4_gateway': '10.28.0.1',
                'ipv6_nets': ['2001:db8:1::3/128'],
                'ipv6_subnet_ids': ['v6subnet-1'],
                'ipv6_gateway': '2001:db8:1::1',
                'fqdn': 'calico-vm17.datcon.co.uk'
            })),
                'hostname-ignored',
                'openstack',
                'workload-id-ignored',
                'endpoint-2'
            )

            # Check no further etcd reads.
            etcd_client.read.assert_not_called()

            # Check DHCP driver was asked to restart.
            call_driver.assert_called_with('restart', mock.ANY)

            # Notify deletion of the first endpoint.
            agent.etcd.on_endpoint_delete(None,
                                          'hostname-ignored',
                                          'openstack',
                                          'workload-id-ignored',
                                          'endpoint-1')

            # Check no further etcd reads.
            etcd_client.read.assert_not_called()

            # Check DHCP driver was asked to reload allocations.
            call_driver.assert_called_with('restart', mock.ANY)

            # Notify another endpoint using a new subnet.
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({
                'state': 'active',
                'name': 'tapABCD',
                'mac': 'fe:16:65:12:33:66',
                'profile_ids': ['profile-1'],
                'ipv4_nets': ['10.29.0.3/32'],
                'ipv4_subnet_ids': ['v4subnet-2'],
                'ipv4_gateway': '10.29.0.1',
                'ipv6_nets': [],
                'ipv6_subnet_ids': []
            })),
                'hostname-ignored',
                'openstack',
                'workload-id-ignored',
                'endpoint-3'
            )

            # Check expected new subnet was read from etcd.
            etcd_client.read.assert_has_calls([
                mock.call(datamodel_v1.key_for_subnet('v4subnet-2'),
                          consistent=True)
            ])
            etcd_client.read.reset_mock()

            # Check DHCP driver was asked to restart.
            call_driver.assert_called_with('restart', mock.ANY)

            # Set the endpoint watcher loop running.
            eventlet.spawn(agent.etcd.loop)

            # Report that the subnet watcher noticed a change.
            agent.etcd.on_subnet_set(None, 'some-subnet-X')
            eventlet.sleep(0.2)

            # Check DHCP driver was asked to restart.
            call_driver.assert_called_with('restart', mock.ANY)

            # Report that the subnet watcher loaded a new snapshot.
            agent.etcd.subnet_watcher._on_snapshot_loaded('ignored')
            eventlet.sleep(0.2)

            # Check DHCP driver was asked to restart.
            call_driver.assert_called_with('restart', mock.ANY)

    @mock.patch('etcd.Client')
    def test_initial_snapshot(self, etcd_client_cls):
        # Create the DHCP agent.
        agent = CalicoDhcpAgent()
        etcd_client = etcd_client_cls.return_value

        # Check that running it invokes the etcd watcher loop.
        with mock.patch.object(agent, 'etcd') as etcdobj:
            agent.run()
            etcdobj.loop.assert_called_with()

        # Arrange for subnet read to fail.
        etcd_client.read.side_effect = etcd.EtcdKeyNotFound

        with mock.patch.object(agent, 'call_driver') as call_driver:
            # Notify a non-empty initial snapshot.
            etcd_snapshot_node = mock.Mock()
            etcd_snapshot_node.action = 'exist'
            etcd_snapshot_node.key = ("/calico/v1/host/" +
                                      socket.gethostname() +
                                      "/workload/openstack" +
                                      "/workload_id/endpoint/endpoint-4")
            etcd_snapshot_node.value = json.dumps({
                'state': 'active',
                'name': 'tap1234',
                'mac': 'fe:16:65:12:33:44',
                'profile_ids': ['profile-1'],
                'ipv4_nets': ['10.28.0.2/32'],
                'ipv4_subnet_ids': ['v4subnet-4'],
                'ipv4_gateway': '10.28.0.1',
                'ipv6_nets': [],
                'ipv6_subnet_ids': []
            })
            etcd_snapshot_response = mock.Mock()
            etcd_snapshot_response.leaves = [etcd_snapshot_node]
            agent.etcd._on_snapshot_loaded(etcd_snapshot_response)

            # Check expected subnet was read from etcd.
            etcd_client.read.assert_has_calls([
                mock.call(datamodel_v1.key_for_subnet('v4subnet-4'),
                          consistent=True)
            ])
            etcd_client.read.reset_mock()

            # Check DHCP driver was not troubled - because the subnet data was
            # missing and so the port could not be processed further.
            call_driver.assert_not_called()

    @mock.patch('etcd.Client')
    def test_dir_delete(self, etcd_client_cls):
        LOG.debug('test_dir_delete')

        # Create the DHCP agent.
        agent = CalicoDhcpAgent()
        etcd_client = etcd_client_cls.return_value

        def etcd_client_read(key, **kwargs):
            LOG.info('etcd_client_read %s %s', key, kwargs)
            if 'v4subnet-1' in key:
                return EtcdResponse(value=json.dumps({
                    'cidr': '10.28.0.0/24',
                    'gateway_ip': '10.28.0.1'
                }))
            if 'v6subnet-1' in key:
                return EtcdResponse(value=json.dumps({
                    'cidr': '2001:db8:1::/80',
                    'gateway_ip': '2001:db8:1::1'
                }))

            eventlet.sleep(10)
            return None

        LOG.debug('etcd_client=%r', etcd_client)
        etcd_client.read.side_effect = etcd_client_read

        # Notify initial snapshot (empty).
        etcd_snapshot_response = mock.Mock()
        etcd_snapshot_response.leaves = []
        LOG.debug('Call _on_snapshot_loaded')
        agent.etcd._on_snapshot_loaded(etcd_snapshot_response)

        with mock.patch.object(agent, 'call_driver') as call_driver:
            # Notify an endpoint.
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({
                'state': 'active',
                'name': 'tap1234',
                'mac': 'fe:16:65:12:33:44',
                'profile_ids': ['profile-1'],
                'ipv4_nets': ['10.28.0.2/32'],
                'ipv4_subnet_ids': ['v4subnet-1'],
                'ipv4_gateway': '10.28.0.1',
                'ipv6_nets': ['2001:db8:1::2/128'],
                'ipv6_subnet_ids': ['v6subnet-1'],
                'ipv6_gateway': '2001:db8:1::1'
            })),
                'hostname-ignored',
                'openstack',
                'workload-id-ignored',
                'endpoint-1'
            )

            # Check expected subnets were read from etcd.
            etcd_client.read.assert_has_calls([
                mock.call(datamodel_v1.key_for_subnet('v4subnet-1'),
                          consistent=True),
                mock.call(datamodel_v1.key_for_subnet('v6subnet-1'),
                          consistent=True)
            ],
                any_order=True)
            etcd_client.read.reset_mock()

            # Check DHCP driver was asked to restart.
            call_driver.assert_called_with('restart', mock.ANY)

            # Notify deletion of one of that endpoint's parent directories.
            agent.etcd.on_dir_delete(None,
                                     hostname='hostname-ignored',
                                     orchestrator='openstack',
                                     workload_id='workload-id-ignored')
            self.assertTrue(agent.etcd.resync_after_current_poll)

    @mock.patch.object(EtcdWatcher, 'loop')
    def test_kill_agent(self, loop_fn):

        # To test handling of SubnetWatcher's loop exiting, make
        # EtcdWatcher.loop throw an exception.
        loop_fn.side_effect = Exception('from test_kill_agent')

        # Create the DHCP agent and allow it to start the SubnetWatcher loop.
        agent = CalicoDhcpAgent()
        eventlet.sleep(0.2)

        # Check that exception handling caused the endpoint watcher loop to be
        # marked as stopped.
        self.assertTrue(agent.etcd._stopped)

    def test_invalid_endpoint_data(self):
        # Create the DHCP agent.
        agent = CalicoDhcpAgent()

        with mock.patch.object(agent, 'call_driver') as call_driver:
            # Notify an endpoint missing some required fields.
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({
                'state': 'active',
                'mac': 'fe:16:65:12:33:44',
                'ipv6_subnet_ids': ['v6subnet-1'],
                'ipv6_gateway': '2001:db8:1::1'
            })),
                'hostname-ignored',
                'openstack',
                'workload-id-ignored',
                'endpoint-1'
            )

            # Check DHCP driver was not asked to do anything.
            call_driver.assert_not_called()

            # Notify an endpoint with non-dict data.
            agent.etcd.on_endpoint_set(EtcdResponse(value="not even a dict!"),
                                       'hostname-ignored',
                                       'openstack',
                                       'workload-id-ignored',
                                       'endpoint-1')

            # Check DHCP driver was not asked to do anything.
            call_driver.assert_not_called()

            # One more variant.
            agent.etcd.on_endpoint_set(EtcdResponse(value="\"nor this!\""),
                                       'hostname-ignored',
                                       'openstack',
                                       'workload-id-ignored',
                                       'endpoint-1')

            # Check DHCP driver was not asked to do anything.
            call_driver.assert_not_called()

    @mock.patch('etcd.Client')
    def test_invalid_subnet_data(self, etcd_client_cls):
        # Create the DHCP agent.
        agent = CalicoDhcpAgent()
        etcd_client = etcd_client_cls.return_value

        # Arrange to deliver invalid subnet data.
        def etcd_client_read(key, **kwargs):
            LOG.info('etcd_client_read %s %s', key, kwargs)
            if 'v4subnet-1' in key:
                return EtcdResponse(value=json.dumps({
                    'gateway_ip': '10.28.0.1'
                }))
            if 'v6subnet-1' in key:
                return EtcdResponse(value=json.dumps({
                    'gateway_ip': '2001:db8:1::1'
                }))

            eventlet.sleep(10)
            return None

        etcd_client.read.side_effect = etcd_client_read

        # Notify an endpoint.
        agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({
            'state': 'active',
            'name': 'tap1234',
            'mac': 'fe:16:65:12:33:44',
            'profile_ids': ['profile-1'],
            'ipv4_nets': ['10.28.0.2/32'],
            'ipv4_subnet_ids': ['v4subnet-1'],
            'ipv4_gateway': '10.28.0.1',
            'ipv6_nets': ['2001:db8:1::2/128'],
            'ipv6_subnet_ids': ['v6subnet-1'],
            'ipv6_gateway': '2001:db8:1::1'
        })),
            'hostname-ignored',
            'openstack',
            'workload-id-ignored',
            'endpoint-1'
        )

        # Check that either the v4 or the v6 subnet was read from etcd.  Since
        # it's invalid, the processing of the new endpoint stops at that point,
        # and the other subnet is not read at all.
        read_calls = etcd_client.read.mock_calls
        self.assertEqual(1, len(read_calls))
        self.assertTrue(read_calls[0] in [
            mock.call(datamodel_v1.key_for_subnet('v4subnet-1'),
                      consistent=True),
            mock.call(datamodel_v1.key_for_subnet('v6subnet-1'),
                      consistent=True),
        ])
        etcd_client.read.reset_mock()

    @mock.patch('etcd.Client')
    def test_etcd_watchers_init_with_conf_values(self, *_):
        agent = CalicoDhcpAgent()

        provided_kwargs = get_etcd_connection_settings()

        def check_provided_args(watcher_obj, expected_key_to_poll):
            for attr_name in ('etcd_scheme', 'etcd_key',
                              'etcd_cert', 'etcd_ca'):
                self.assertEqual(
                    getattr(watcher_obj, attr_name),
                    provided_kwargs[attr_name]
                )

            # provided hosts are stored in form of list [(host, port)...]
            # on etcd watcher
            etcd_host, etcd_port = provided_kwargs['etcd_addrs'].split(':')
            self.assertEqual(watcher_obj.etcd_hosts,
                             [(etcd_host, int(etcd_port))])

            self.assertEqual(watcher_obj.key_to_poll, expected_key_to_poll)

        expected_key = \
            datamodel_v1.dir_for_host(socket.gethostname()) + '/workload'
        check_provided_args(agent.etcd, expected_key)

        expected_key = datamodel_v1.SUBNET_DIR
        check_provided_args(agent.etcd.subnet_watcher, expected_key)


commonutils = 'neutron.agent.linux.dhcp.commonutils'
try:
    from neutron.agent.linux.dhcp import commonutils as xxx  # noqa
except Exception:
    # In Mitaka the import name changed to 'common_utils'.
    commonutils = 'neutron.agent.linux.dhcp.common_utils'


class TestDnsmasqRouted(base.BaseTestCase):
    def setUp(self):
        super(TestDnsmasqRouted, self).setUp()
        register_options(cfg.CONF)
        cfg.CONF.set_override('dhcp_confs', '/run')
        cfg.CONF.set_override(
            'interface_driver',
            'networking_calico.agent.linux.interface.RoutedInterfaceDriver'
        )

    @mock.patch('neutron.agent.linux.dhcp.DeviceManager')
    @mock.patch(commonutils)
    def test_build_cmdline(self, commonutils, device_mgr_cls):
        v4subnet = mock.Mock()
        v4subnet.id = 'subnet-1'
        v4subnet.enable_dhcp = True
        v4subnet.ip_version = 4
        v4subnet.cidr = '10.28.0.0/24'
        v6subnet = mock.Mock()
        v6subnet.id = 'subnet-1'
        v6subnet.enable_dhcp = True
        v6subnet.ip_version = 6
        v6subnet.cidr = '2001:db8:1::/80'
        v6subnet.ipv6_ra_mode = constants.DHCPV6_STATEFUL
        v6subnet.ipv6_address_mode = constants.DHCPV6_STATEFUL
        network = mock.Mock()
        network.id = 'calico'
        network.subnets = [v4subnet, v6subnet]
        network.mtu = 0
        network.ports = [
            dhcp.DictModel({'device_id': 'tap1'}),
            dhcp.DictModel({'device_id': 'tap2'}),
            dhcp.DictModel({'device_id': 'tap3'}),
        ]
        device_mgr_cls.return_value.driver.bridged = False
        dhcp_driver = DnsmasqRouted(cfg.CONF, network, None)
        with mock.patch.object(dhcp_driver, '_get_value_from_conf_file') as gv:
            gv.return_value = 'ns-dhcp'
            cmdline = dhcp_driver._build_cmdline_callback('/run/pid_file')
        self.assertEqual([
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--except-interface=lo',
            '--pid-file=/run/pid_file',
            '--dhcp-hostsfile=/run/calico/host',
            '--addn-hosts=/run/calico/addn_hosts',
            '--dhcp-optsfile=/run/calico/opts',
            '--dhcp-leasefile=/run/calico/leases',
            '--dhcp-match=set:ipxe,175',
            '--bind-dynamic',
            '--interface=ns-dhcp',
            '--dhcp-range=set:tag0,10.28.0.0,static,86400s',
            '--dhcp-lease-max=16777216',
            '--conf-file=',
            '--domain=openstacklocal',
            '--dhcp-range=set:tag1,2001:db8:1::,static,off-link,80,86400s',
            '--enable-ra',
            '--interface=tap1',
            '--interface=tap2',
            '--interface=tap3',
            '--bridge-interface=ns-dhcp,tap1,tap2,tap3'],
            cmdline)
