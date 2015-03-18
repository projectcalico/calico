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
openstack.test.lib
~~~~~~~~~~~

Common code for Neutron driver UT.
"""
import mock
import sys

sys.modules['neutron'] = m_neutron = mock.Mock()
sys.modules['neutron.common'] = m_neutron.common
sys.modules['neutron.openstack'] = m_neutron.openstack
sys.modules['neutron.openstack.common'] = m_neutron.openstack.common
sys.modules['neutron.plugins'] = m_neutron.plugins
sys.modules['neutron.plugins.ml2'] = m_neutron.plugins.ml2
sys.modules['neutron.plugins.ml2.drivers'] = m_neutron.plugins.ml2.drivers
sys.modules['etcd'] = m_etcd = mock.Mock()


# Define a stub class, that we will use as the base class for
# CalicoMechanismDriver.
class DriverBase(object):
    def __init__(self, agent_type, vif_type, vif_details):
        pass

# Replace Neutron's SimpleAgentMechanismDriverBase - which is the base class
# that CalicoMechanismDriver inherits from - with this stub class.
m_neutron.plugins.ml2.drivers.mech_agent.SimpleAgentMechanismDriverBase = \
    DriverBase

import calico.openstack.mech_calico as mech_calico


class Lib(object):

    # Ports to return when the driver asks the OpenStack database for all
    # current ports.
    osdb_ports = []

    def setUp(self):
        # If an arg mismatch occurs, we want to see the complete diff of it.
        self.maxDiff = 1000

        # Create an instance of CalicoMechanismDriver.
        self.driver = mech_calico.CalicoMechanismDriver()

        # Hook the (mock) Neutron database.
        self.db = mech_calico.manager.NeutronManager.get_plugin()
        self.db_context = mech_calico.ctx.get_admin_context()

        # Arrange what the DB's get_ports will return.
        self.db.get_ports.side_effect = lambda *args: self.osdb_ports

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

        # Prep a null response to the following
        # _get_port_security_group_bindings call.
        self.db._get_port_security_group_bindings.return_value = []
