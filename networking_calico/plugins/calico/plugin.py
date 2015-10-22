# Copyright (c) 2015 Cisco Systems.  All Rights Reserved.
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

from neutron.db import l3_db
from neutron.plugins.ml2.plugin import Ml2Plugin

try:
    # Icehouse, Juno
    from neutron.openstack.common import log
except ImportError:
    # Kilo
    from oslo_log import log

try:
    # Icehouse, Juno
    from oslo.config import cfg
except ImportError:
    # Kilo
    from oslo_config import cfg

LOG = log.getLogger(__name__)


class CalicoPlugin(Ml2Plugin, l3_db.L3_NAT_db_mixin):
    def __init__(self):
        # Add the ability to handle floating IPs.
        self._supported_extension_aliases.extend(["router"])

        # Set ML2 options so the user doesn't have to.
        LOG.info("Forcing ML2 mechanism_drivers to 'calico'")
        cfg.CONF.set_override('mechanism_drivers', ['calico'], group='ml2')
        LOG.info("Forcing ML2 type_drivers to 'local, flat'")
        cfg.CONF.set_override('type_drivers', ['local', 'flat'], group='ml2')
        LOG.info("Forcing ML2 tenant_network_types to 'local'")
        cfg.CONF.set_override('tenant_network_types', ['local'], group='ml2')

        super(CalicoPlugin, self).__init__()

    # Intercept floating IP associates/disassociates so we can trigger an
    # appropriate endpoint update.
    def _update_floatingip(self, context, id, floatingip):
        old_floatingip, new_floatingip = super(
            CalicoPlugin, self)._update_floatingip(context, id, floatingip)

        if new_floatingip['port_id']:
            context.fip_update_port_id = new_floatingip['port_id']
            self.mechanism_manager._call_on_drivers('update_floatingip',
                                                    context)
        if old_floatingip['port_id']:
            context.fip_update_port_id = old_floatingip['port_id']
            self.mechanism_manager._call_on_drivers('update_floatingip',
                                                    context)

        return old_floatingip, new_floatingip
