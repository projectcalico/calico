# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import json
import unittest
from mock import patch, Mock, call
from netaddr import IPAddress, IPNetwork
from subprocess import CalledProcessError
from pycalico.datastore_datatypes import IPPool
import pycalico.netns
import calico_rkt

CONTAINER_ID = 'ff3afbd1-17ad-499d-b514-72438c009e81'
NETNS_ROOT = '/var/lib/rkt/pods/run'
ORCHESTRATOR_ID = "rkt"

ENV = {
    'CNI_IFNAME': 'eth0',
    'CNI_ARGS': '',
    'CNI_COMMAND': 'ADD',
    'CNI_PATH': '.../.../...',
    'CNI_NETNS': 'netns',
    'CNI_CONTAINERID': CONTAINER_ID,
}
CONF = {
    "name": "test",
            "type": "calico",
            "ipam": {
                "type": "host-local",
                "subnet": "10.22.0.0/16",
                "routes": [{"dst": "0.0.0.0/0"}],
                "range-start": "",
                "range-end": "",
            },
}
ARGS = {
    'command': ENV['CNI_COMMAND'],
    'container_id': ENV['CNI_CONTAINERID'],
    'interface': ENV['CNI_IFNAME'],
    'netns': ENV['CNI_NETNS'],
    'name': CONF['name'],
    'subnet': CONF['ipam']['subnet'],
}


class RktPluginTest(unittest.TestCase):

    @patch('calico_rkt.create',
           autospec=True)
    def test_main_ADD(self, m_create):
        ARGS['command'] = 'ADD'
        calico_rkt.calico_rkt(ARGS)

        m_create.assert_called_once_with(ARGS)

    @patch('calico_rkt.delete',
           autospec=True)
    def test_main_DEL(self, m_delete):
        ARGS['command'] = 'DEL'
        calico_rkt.calico_rkt(ARGS)

        m_delete.assert_called_once_with(ARGS)

    @patch('calico_rkt.datastore_client',
           autospec=True)
    @patch('calico_rkt._create_calico_endpoint',
           autospec=True)
    @patch('calico_rkt._set_profile_on_endpoint',
           autospec=True)
    def test_create(self, m_set_profile, m_create_ep, m_client):

        ip_ = '1.2.3.4/24'
        path_ = '%s/%s/%s' % (NETNS_ROOT, ARGS['container_id'], ARGS['netns'])

        mock_ep = Mock()
        m_create_ep.return_value = mock_ep, ip_

        calico_rkt.create(ARGS)

        m_create_ep.assert_called_once_with(container_id=ARGS['container_id'],
                                            netns_path=path_,
                                            interface=ARGS['interface'],
                                            subnet=ARGS['subnet'])
        m_set_profile.assert_called_once_with(endpoint=mock_ep,
                                              profile_name="test")


    @patch('calico_rkt.HOSTNAME',
           autospec=True)
    @patch('calico_rkt.datastore_client',
           autospec=True)
    @patch('calico_rkt._container_add', return_value=('ep', 'ip'),
           autospec=True)
    def test_create_calico_endpoint(self, m_con_add, m_client, m_host):
        m_client.get_endpoint.return_value = None
        m_client.get_endpoint.side_effect = KeyError()

        id_, path_ = 'testcontainer', 'path/to/ns'

        calico_rkt._create_calico_endpoint(container_id=id_,
                                           netns_path=path_,
                                           interface=ARGS['interface'],
                                           subnet=ARGS['subnet'])

        m_client.get_endpoint.assert_called_once_with(hostname=m_host,
                                                      orchestrator_id=ORCHESTRATOR_ID,
                                                      workload_id=id_)
        m_con_add.assert_called_once_with(hostname=m_host,
                                          orchestrator_id=ORCHESTRATOR_ID,
                                          container_id=id_,
                                          netns_path=path_,
                                          interface=ARGS['interface'],
                                          subnet=ARGS['subnet'])

    @patch("sys.exit",
           autospec=True)
    @patch('calico_rkt.HOSTNAME',
           autospec=True)
    @patch('calico_rkt.datastore_client',
           autospec=True)
    @patch('calico_rkt._container_add', return_value=('ep', 'ip'),
           autospec=True)
    def test_create_calico_endpoint_fail(self, m_con_add, m_client, m_host, m_sys_exit):
        m_client.get_endpoint.return_value = "Endpoint Exists"

        id_, path_ = 'testcontainer', 'path/to/ns'

        calico_rkt._create_calico_endpoint(container_id=id_,
                                           netns_path=path_,
                                           interface=ARGS['interface'],
                                           subnet=ARGS['subnet'])

        m_client.get_endpoint.assert_called_once_with(hostname=m_host,
                                                      orchestrator_id=ORCHESTRATOR_ID,
                                                      workload_id=id_)
        m_sys_exit.assert_called_once_with(1)

    @patch('calico_rkt.HOSTNAME',
           autospec=True)
    @patch('calico_rkt.datastore_client',
           autospec=True)
    @patch('calico_rkt._assign_to_pool', return_value=(IPPool('1.2.0.0/16'), IPAddress('1.2.3.4')),
           autospec=True)
    def test_container_add(self, m_assign_pool, m_client, m_host):
        m_ep = Mock()
        m_client.create_endpoint.return_value = m_ep
        m_ep.provision_veth.return_value = 'macaddress'

        id_, path_ = 'testcontainer', 'path/to/ns'

        calico_rkt._container_add(hostname=m_host,
                                  orchestrator_id=ORCHESTRATOR_ID,
                                  container_id=id_,
                                  netns_path=path_,
                                  interface=ARGS['interface'],
                                  subnet=ARGS['subnet'])

        m_assign_pool.assert_called_once_with(ARGS['subnet'])
        m_client.create_endpoint.assert_called_once_with(
            m_host, ORCHESTRATOR_ID, id_, [IPAddress('1.2.3.4')])
        m_ep.provision_veth.assert_called_once()
        m_client.set_endpoint.assert_called_once_with(m_ep)

    @patch('calico_rkt.HOSTNAME',
           autospec=True)
    @patch('calico_rkt.datastore_client',
           autospec=True)
    @patch('pycalico.netns',
           autospec=True)
    def test_container_remove(self, m_netns, m_client, m_host):
        m_ep = Mock()
        m_ep.ipv4_nets = set()
        m_ep.ipv4_nets.add(IPNetwork('1.2.3.4/32'))
        m_ep.ipv6_nets = set()
        m_ep.name = 'endpoint_test'

        m_client.get_endpoint.return_value = m_ep
        id_ = '123'

        calico_rkt._container_remove(hostname=m_host,
                                     orchestrator_id=ORCHESTRATOR_ID,
                                     container_id=id_)
        m_client.get_endpoint.assert_called_once_with(hostname=m_host,
                                                      orchestrator_id=ORCHESTRATOR_ID,
                                                      workload_id=id_)
        m_client.remove_workload.assert_called_once_with(hostname=m_host,
                                                         orchestrator_id=ORCHESTRATOR_ID,
                                                         workload_id=id_)
        m_client.unassign_address.assert_called_once_with(
            None, IPAddress('1.2.3.4'))

    @patch('calico_rkt.datastore_client',
           autospec=True)
    def test_set_profile_on_endpoint(self, m_client):
        m_client.profile_exists.return_value = False

        m_ep = Mock()
        m_ep.endpoint_id = '1234'

        p_name, ip_ = 'profile', '1.2.3.4'

        calico_rkt._set_profile_on_endpoint(endpoint=m_ep,
                                            profile_name=p_name)

        m_client.profile_exists.assert_called_once_with(p_name)
        m_client.create_profile.assert_called_once_with(p_name)
        m_client.set_profiles_on_endpoint.assert_called_once_with(profile_names=[p_name],
                                                                  endpoint_id='1234')

    @patch('calico_rkt.datastore_client',
           autospec=True)
    def test_create_assign_rules(self, m_client):
        m_profile = Mock()
        m_client.get_profile.return_value = m_profile

        p_name = 'profile'

        calico_rkt._assign_default_rules(profile_name=p_name)

        m_client.get_profile.assert_called_once_with(p_name)
        m_client.profile_update_rules.assert_called_once_with(m_profile)

    @patch('calico_rkt.datastore_client',
           autospec=True)
    @patch('pycalico.ipam.SequentialAssignment.allocate',
           autospec=True)
    def test_assign_to_pool(self, m_seq, m_client):
        m_seq.return_value = '10.22.0.1'
        calico_rkt._assign_to_pool(subnet=ARGS['subnet'])
        m_client.add_ip_pool.assert_called_once_with(4, IPPool("10.22.0.0/16"))
