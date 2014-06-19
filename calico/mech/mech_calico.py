# Copyright (c) 2014 Metaswitch Networks
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

from neutron.common import constants
from neutron.extensions import portbindings
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import mech_agent
from calico import common as calico_common

LOG = log.getLogger(__name__)


class CalicoMechanismDriver(mech_agent.SimpleAgentMechanismDriverBase):
    """Attach to networks using Calico L2 agent.

    The CalicoMechanismDriver integrates the ml2 plugin with the
    Calico L2 agent. Port binding with this driver requires the
    Calico agent to be running on the port's host.
    """

    def __init__(self):
        super(CalicoMechanismDriver, self).__init__(
            calico_common.AGENT_TYPE_CALICO,
            portbindings.VIF_TYPE_ROUTED,
            {portbindings.CAP_PORT_FILTER: True})

    def check_segment_for_agent(self, segment, agent):
        mappings = agent['configurations'].get('interface_mappings', {})
        tunnel_types = agent['configurations'].get('tunnel_types', [])
        LOG.debug(_("Checking segment: %(segment)s "
                    "for mappings: %(mappings)s "
                    "with tunnel_types: %(tunnel_types)s"),
                  {'segment': segment, 'mappings': mappings,
                   'tunnel_types': tunnel_types})
        network_type = segment[api.NETWORK_TYPE]
        if network_type == 'local':
            return True
        elif network_type in tunnel_types:
            return True
        elif network_type in ['flat', 'vlan']:
            return segment[api.PHYSICAL_NETWORK] in mappings
        else:
            return False
