# Copyright 2016 Metaswitch Networks
# Copyright 2018 Tigera, Inc. All rights reserved.
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
import eventlet
import json
import logging
import mock
import socket

from neutron.agent.dhcp_agent import register_options
from neutron.agent.linux import dhcp
from neutron.tests import base

from networking_calico.agent.dhcp_agent import CalicoDhcpAgent
from networking_calico.agent.dhcp_agent import FakePlugin
from networking_calico.agent.linux.dhcp import DnsmasqRouted
from networking_calico.common import config as calico_config
from networking_calico.compat import cfg
from networking_calico.compat import DHCPV6_STATEFUL
from networking_calico import datamodel_v1
from networking_calico import datamodel_v2
from networking_calico.etcdutils import EtcdWatcher

LOG = logging.getLogger(__name__)

EtcdResponse = namedtuple('EtcdResponse', ['value'])


def make_endpoint_name(endpoint_id):
    parts = [
        socket.gethostname(),
        'openstack',
        'workload-ignored',
        endpoint_id
    ]
    return '-'.join([p.replace('-', '--') for p in parts])


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
        self.mock_makedirs_p = mock.patch("os.makedirs")
        self.mock_makedirs = self.mock_makedirs_p.start()
        self.hostname = socket.gethostname()
        cfg.CONF.host = self.hostname

    def test_mainline(self):
        # Create the DHCP agent.
        agent = CalicoDhcpAgent()

        # Check that running it invokes the etcd watcher loop.
        with mock.patch.object(agent, 'etcd') as etcdobj:
            agent.run()
            etcdobj.start.assert_called_with()

        # Notify initial snapshot (empty).
        with mock.patch.object(agent, 'call_driver') as call_driver:
            snapshot_data = agent.etcd._pre_snapshot_hook()
            agent.etcd._post_snapshot_hook(snapshot_data)
            call_driver.assert_not_called()

        with mock.patch.object(agent, 'call_driver') as call_driver:
            # Notify subnets.
            agent.etcd.subnet_watcher.on_subnet_set(
                EtcdResponse(value=json.dumps({
                    'cidr': '10.28.0.0/24',
                    'gateway_ip': '10.28.0.1',
                    'host_routes': []
                })),
                'v4subnet-1'
            )
            agent.etcd.subnet_watcher.on_subnet_set(
                EtcdResponse(value=json.dumps({
                    'cidr': '2001:db8:1::/80',
                    'gateway_ip': '2001:db8:1::1'
                })),
                'v6subnet-1'
            )
            agent.etcd.subnet_watcher.on_subnet_set(
                EtcdResponse(value=json.dumps({
                    'cidr': '10.29.0.0/24',
                    'gateway_ip': '10.29.0.1',
                    'host_routes': [{'destination': '11.11.0.0/16',
                                     'nexthop': '10.65.0.1'}]
                })),
                'v4subnet-2'
            )

            # Notify an endpoint.
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({'spec': {
                'interfaceName': 'tap1234',
                'mac': 'fe:16:65:12:33:44',
                'profiles': ['profile-1'],
                'ipNetworks': ['10.28.0.2/32', '2001:db8:1::2/128'],
                'ipv4Gateway': '10.28.0.1',
                'ipv6Gateway': '2001:db8:1::1'
            }})),
                make_endpoint_name('endpoint-1')
            )

            # Check DHCP driver was asked to restart.
            call_driver.assert_called_with('restart', mock.ANY)

            # Notify another endpoint (using the same subnets).
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({'spec': {
                'interfaceName': 'tap5678',
                'mac': 'fe:16:65:12:33:55',
                'profiles': ['profile-1'],
                'ipNetworks': ['10.28.0.3/32', '2001:db8:1::3/128'],
                'ipv4Gateway': '10.28.0.1',
                'ipv6Gateway': '2001:db8:1::1',
                'fqdn': 'calico-vm17.datcon.co.uk'
            }})),
                make_endpoint_name('endpoint-2')
            )

            # Check DHCP driver was asked to restart.
            call_driver.assert_called_with('restart', mock.ANY)

            # Notify deletion of the first endpoint.
            agent.etcd.on_endpoint_delete(None,
                                          make_endpoint_name('endpoint-1'))

            # Check DHCP driver was asked to reload allocations.
            call_driver.assert_called_with('restart', mock.ANY)

            # Notify another endpoint using a new subnet.
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({'spec': {
                'interfaceName': 'tapABCD',
                'mac': 'fe:16:65:12:33:66',
                'profiles': ['profile-1'],
                'ipNetworks': ['10.29.0.3/32'],
                'ipv4Gateway': '10.29.0.1',
            }})),
                make_endpoint_name('endpoint-3')
            )

            # Check DHCP driver was asked to restart.
            call_driver.assert_called_with('restart', mock.ANY)

    def test_initial_snapshot(self):
        # Create the DHCP agent.
        agent = CalicoDhcpAgent()

        # Check that running it invokes the etcd watcher loop.
        with mock.patch.object(agent, 'etcd') as etcdobj:
            agent.run()
            etcdobj.start.assert_called_with()

        with mock.patch.object(agent, 'call_driver') as call_driver:
            # Notify a non-empty initial snapshot.
            snapshot_data = agent.etcd._pre_snapshot_hook()
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({'spec': {
                'interfaceName': 'tap1234',
                'mac': 'fe:16:65:12:33:44',
                'profiles': ['profile-1'],
                'ipNetworks': ['10.28.0.2/32'],
                'ipv4Gateway': '10.28.0.1',
            }})),
                make_endpoint_name('endpoint-4')
            )
            agent.etcd._post_snapshot_hook(snapshot_data)

            # Check DHCP driver was not troubled - because the subnet data was
            # missing and so the port could not be processed further.
            call_driver.assert_not_called()

    @mock.patch.object(EtcdWatcher, 'start')
    def test_kill_agent(self, loop_fn):

        # To test handling of SubnetWatcher's loop exiting, make
        # EtcdWatcher.start throw an exception.
        loop_fn.side_effect = Exception('from test_kill_agent')

        # Create the DHCP agent and allow it to start the SubnetWatcher loop.
        agent = CalicoDhcpAgent()
        agent.etcd._stopped = False
        eventlet.spawn(agent.etcd.subnet_watcher.start)
        eventlet.sleep(0.2)

        # Check that exception handling caused the endpoint watcher to be
        # marked as stopped.
        self.assertTrue(agent.etcd._stopped)

    def test_invalid_endpoint_data(self):
        # Create the DHCP agent.
        agent = CalicoDhcpAgent()

        with mock.patch.object(agent, 'call_driver') as call_driver:
            # Notify an endpoint missing some required fields.
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({
                'mac': 'fe:16:65:12:33:44',
                'ipNetworks': ['2001:db8:1::1']
            })),
                make_endpoint_name('endpoint-1')
            )

            # Check DHCP driver was not asked to do anything.
            call_driver.assert_not_called()

            # Notify an endpoint with non-dict data.
            agent.etcd.on_endpoint_set(
                EtcdResponse(value="not even a dict!"),
                make_endpoint_name('endpoint-1')
            )

            # Check DHCP driver was not asked to do anything.
            call_driver.assert_not_called()

            # One more variant.
            agent.etcd.on_endpoint_set(
                EtcdResponse(value="\"nor this!\""),
                make_endpoint_name('endpoint-1')
            )

            # Check DHCP driver was not asked to do anything.
            call_driver.assert_not_called()

    def test_endpoint_no_ipnetworks(self):
        # Create the DHCP agent.
        agent = CalicoDhcpAgent()

        with mock.patch.object(agent, 'call_driver') as call_driver:
            with mock.patch.object(agent.etcd, 'on_endpoint_delete') as ep_del:
                # Notify an endpoint that is valid but has no ipNetworks.
                agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({
                    'spec': {
                        'interfaceName': 'tapfe166512-33',
                        'mac': 'fe:16:65:12:33:44',
                        'ipNetworks': []
                    }})),
                    make_endpoint_name('endpoint-1')
                )

                # Check handled as a deletion.
                ep_del.assert_called()

            # Check DHCP driver was not asked to do anything.
            call_driver.assert_not_called()

    def test_no_subnet_data(self):
        # Create the DHCP agent.
        agent = CalicoDhcpAgent()

        with mock.patch.object(agent, 'call_driver') as call_driver:
            # Notify an endpoint.
            agent.etcd.on_endpoint_set(EtcdResponse(value=json.dumps({'spec': {
                'interfaceName': 'tap1234',
                'mac': 'fe:16:65:12:33:44',
                'profiles': ['profile-1'],
                'ipNetworks': ['10.28.0.2/32', '2001:db8:1::2/128'],
                'ipv4Gateway': '10.28.0.1',
                'ipv6Gateway': '2001:db8:1::1'
            }})),
                make_endpoint_name('endpoint-1')
            )
            call_driver.assert_not_called()

    def test_invalid_subnet_data(self):
        # Create the DHCP agent.
        agent = CalicoDhcpAgent()

        agent.etcd.subnet_watcher.on_subnet_set(EtcdResponse(value=json.dumps({
            'gateway_ip': '10.28.0.1'
        })),
            'v4subnet-1'
        )

        agent.etcd.subnet_watcher.on_subnet_set(EtcdResponse(value=json.dumps({
            'gateway_ip': '2001:db8:1::1'
        })),
            'v6subnet-1'
        )

        self.assertFalse(agent.etcd.subnet_watcher.subnets_by_id)

    def test_etcd_watchers_init_with_conf_values(self):
        agent = CalicoDhcpAgent()
        self.assertEqual(agent.etcd.prefix,
                         "/calico/resources/v3/projectcalico.org/" +
                         "workloadendpoints/openstack/" +
                         self.hostname.replace('-', '--') +
                         "-openstack-")
        self.assertEqual(agent.etcd.v1_subnet_watcher.prefix,
                         datamodel_v1.SUBNET_DIR)
        self.assertEqual(agent.etcd.subnet_watcher.prefix,
                         datamodel_v2.subnet_dir())

    def test_host_config(self):
        cfg.CONF.host = "my-special-hostname"
        agent = CalicoDhcpAgent()
        self.assertEqual(agent.etcd.prefix,
                         "/calico/resources/v3/projectcalico.org/" +
                         "workloadendpoints/openstack/" +
                         "my--special--hostname" +
                         "-openstack-")
        self.assertEqual(agent.etcd.v1_subnet_watcher.prefix,
                         datamodel_v1.SUBNET_DIR)
        self.assertEqual(agent.etcd.subnet_watcher.prefix,
                         datamodel_v2.subnet_dir())

    def test_region_config(self):
        cfg.CONF.set_override('openstack_region',
                              'asia-central',
                              group='calico')
        calico_config._reset_globals()
        agent = CalicoDhcpAgent()
        self.assertEqual(agent.etcd.prefix,
                         "/calico/resources/v3/projectcalico.org/" +
                         "workloadendpoints/openstack-region-asia-central/" +
                         self.hostname.replace('-', '--') +
                         "-openstack-")
        self.assertEqual(agent.etcd.v1_subnet_watcher.prefix,
                         datamodel_v1.SUBNET_DIR)
        self.assertEqual(agent.etcd.subnet_watcher.prefix,
                         datamodel_v2.subnet_dir("region-asia-central"))
        calico_config._reset_globals()


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
        self.mock_makedirs_p = mock.patch("os.makedirs")
        self.mock_makedirs = self.mock_makedirs_p.start()

    @mock.patch('neutron.agent.linux.dhcp.DeviceManager')
    @mock.patch(commonutils)
    def test_build_cmdline(self, commonutils, device_mgr_cls):
        v4subnet = mock.Mock()
        v4subnet.id = 'v4subnet-1'
        v4subnet.enable_dhcp = True
        v4subnet.ip_version = 4
        v4subnet.cidr = '10.28.0.0/24'
        v6subnet = mock.Mock()
        v6subnet.id = 'v6subnet-1'
        v6subnet.enable_dhcp = True
        v6subnet.ip_version = 6
        v6subnet.cidr = '2001:db8:1::/80'
        v6subnet.ipv6_ra_mode = DHCPV6_STATEFUL
        v6subnet.ipv6_address_mode = DHCPV6_STATEFUL
        network = mock.Mock()
        network.id = 'calico'
        network.subnets = [v4subnet, v6subnet]
        network.mtu = 0
        network.ports = [
            dhcp.DictModel({'device_id': 'tap1'}),
            dhcp.DictModel({'device_id': 'tap2'}),
            dhcp.DictModel({'device_id': 'tap3'}),
        ]
        network.non_local_subnets = []
        network.get.side_effect = lambda key, dflt=None: dflt
        device_mgr_cls.return_value.driver.bridged = False
        dhcp_driver = DnsmasqRouted(cfg.CONF,
                                    network,
                                    None,
                                    plugin=FakePlugin())
        with mock.patch.object(dhcp_driver, '_get_value_from_conf_file') as gv:
            gv.return_value = 'ns-dhcp'
            cmdline = dhcp_driver._build_cmdline_callback('/run/pid_file')

        # Filter out dnsmasq args that we don't care about.
        filtered_args = []
        for arg in cmdline:
            if '--domain=' in arg:
                continue
            if arg in [
                    '--no-hosts',
                    '--no-resolv',
                    '--pid-file=/run/pid_file',
                    '--dhcp-hostsfile=/run/calico/host',
                    '--addn-hosts=/run/calico/addn_hosts',
                    '--dhcp-optsfile=/run/calico/opts',
                    '--dhcp-leasefile=/run/calico/leases',
                    '--dhcp-match=set:ipxe,175',
                    '--dhcp-lease-max=16777216',
                    '--conf-file=',
            ]:
                continue
            filtered_args.append(arg)

        # Check the remaining filtered args against what we expect.
        self.assertEqual([
            'dnsmasq',
            '--except-interface=lo',
            '--bind-dynamic',
            '--interface=ns-dhcp',
            '--dhcp-range=set:subnet-v4subnet-1,10.28.0.0' +
            ',static,255.255.255.0,86400s',
            '--dhcp-range=set:subnet-v6subnet-1,2001:db8:1::' +
            ',static,off-link,80,86400s',
            '--enable-ra',
            '--interface=tap1',
            '--interface=tap2',
            '--interface=tap3',
            '--bridge-interface=ns-dhcp,tap1,tap2,tap3'],
            filtered_args)
