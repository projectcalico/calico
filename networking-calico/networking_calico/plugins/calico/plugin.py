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

# Import Ml2Plugin before l3_db to fix https://github.com/projectcalico/calico/issues/8494
from neutron.plugins.ml2.plugin import Ml2Plugin
from neutron.db import l3_db
from neutron.db.models import l3

from networking_calico.compat import cfg
from networking_calico.compat import constants
from networking_calico.compat import log


LOG = log.getLogger(__name__)


class CalicoPlugin(Ml2Plugin, l3_db.L3_NAT_db_mixin):

    # These attributes specify whether the plugin supports or not
    # bulk/pagination/sorting operations. Name mangling is used in
    # order to ensure it is qualified by class
    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        # Add the ability to handle floating IPs.
        self._supported_extension_aliases.extend(["router"])

        # Suppress the Neutron server's DHCP agent scheduling.  This is useful
        # because it suppresses many WARNING logs that would otherwise appear,
        # but that are actually spurious in a Calico/OpenStack deployment.
        self._supported_extension_aliases.remove("dhcp_agent_scheduler")

        # Set ML2 options so the user doesn't have to.
        LOG.info("Forcing ML2 mechanism_drivers to 'calico'")
        cfg.CONF.set_override('mechanism_drivers', ['calico'], group='ml2')
        LOG.info("Forcing ML2 type_drivers to 'local, flat'")
        cfg.CONF.set_override('type_drivers', ['local', 'flat'], group='ml2')
        LOG.info("Forcing ML2 tenant_network_types to 'local'")
        cfg.CONF.set_override('tenant_network_types', ['local'], group='ml2')

        # This is a bit of a hack to get the models_v2.Port attributes setup in such
        # a way as to avoid tracebacks in the neutron-server log.
        #
        # The tracebacks are not purely cosmetic as they cause all tests run after TestFloatingIPs
        # to fail, presumably as a result of the neutron-server being left in a bad state. The bad
        # state is likely because the error occurs during a cleanup action ("_clean_garbage") which
        # leaves important resources orphaned with no known way to recover.
        #
        # The side-effects within the Router setup that we care about likely have to do with the
        # "orm.relationship" calls but rather than port those directly here and risk any changes that might
        # occur in the future that could render this assumption false we can just rely
        # on the maintainers of this class to keep things up-to-date on our behalf.
        #
        # An example of the traceback looks like this:
        # Traceback (most recent call last):
        #   File "/usr/lib/python3/dist-packages/oslo_service/loopingcall.py", line 150, in _run_loop
        #     result = func(*self.args, **self.kw)
        #   File "/usr/lib/python3/dist-packages/neutron/db/l3_db.py", line 163, in _clean_garbage
        #     candidates = self._get_dead_floating_port_candidates(context)
        #   File "/usr/lib/python3/dist-packages/neutron/db/l3_db.py", line 198, in _get_dead_floating_port_candidates
        #     return {p['id'] for p in self._core_plugin.get_ports(context, filters)}
        #   File "/usr/lib/python3/dist-packages/neutron_lib/db/api.py", line 218, in wrapped
        #     return method(*args, **kwargs)
        #   File "/usr/lib/python3/dist-packages/neutron_lib/db/api.py", line 139, in wrapped
        #     setattr(e, '_RETRY_EXCEEDED', True)
        #   File "/usr/lib/python3/dist-packages/oslo_utils/excutils.py", line 227, in __exit__
        #     self.force_reraise()
        #   File "/usr/lib/python3/dist-packages/oslo_utils/excutils.py", line 200, in force_reraise
        #     raise self.value
        #   File "/usr/lib/python3/dist-packages/neutron_lib/db/api.py", line 135, in wrapped
        #     return f(*args, **kwargs)
        #   File "/usr/lib/python3/dist-packages/oslo_db/api.py", line 154, in wrapper
        #     ectxt.value = e.inner_exc
        #   File "/usr/lib/python3/dist-packages/oslo_utils/excutils.py", line 227, in __exit__
        #     self.force_reraise()
        #   File "/usr/lib/python3/dist-packages/oslo_utils/excutils.py", line 200, in force_reraise
        #     raise self.value
        #   File "/usr/lib/python3/dist-packages/oslo_db/api.py", line 142, in wrapper
        #     return f(*args, **kwargs)
        #   File "/usr/lib/python3/dist-packages/neutron_lib/db/api.py", line 183, in wrapped
        #     LOG.debug("Retry wrapper got retriable exception: %s", e)
        #   File "/usr/lib/python3/dist-packages/oslo_utils/excutils.py", line 227, in __exit__
        #     self.force_reraise()
        #   File "/usr/lib/python3/dist-packages/oslo_utils/excutils.py", line 200, in force_reraise
        #     raise self.value
        #   File "/usr/lib/python3/dist-packages/neutron_lib/db/api.py", line 179, in wrapped
        #     return f(*dup_args, **dup_kwargs)
        #   File "/usr/lib/python3/dist-packages/neutron/db/db_base_plugin_v2.py", line 1601, in get_ports
        #     lazy_fields = [models_v2.Port.port_forwardings,
        # AttributeError: type object 'Port' has no attribute 'port_forwardings'
        _ = l3.Router()

        super(CalicoPlugin, self).__init__()

    # Intercept floating IP associates/disassociates so we can trigger an
    # appropriate endpoint update.
    def _update_floatingip(self, context, id, floatingip):
        LOG.info("CalicoPlugin _update_floatingip: %s", floatingip)
        old_floatingip, new_floatingip = super(
            CalicoPlugin, self)._update_floatingip(context, id, floatingip)

        LOG.info("CalicoPlugin new_floatingip=%s", new_floatingip)
        if new_floatingip['port_id']:
            context.fip_update_port_id = new_floatingip['port_id']
            self.mechanism_manager._call_on_drivers('update_floatingip',
                                                    context)

        LOG.info("CalicoPlugin old_floatingip=%s", old_floatingip)
        if old_floatingip['port_id']:
            context.fip_update_port_id = old_floatingip['port_id']
            self.mechanism_manager._call_on_drivers('update_floatingip',
                                                    context)

        return old_floatingip, new_floatingip

    def create_floatingip(self, context, floatingip,
                          initial_status=constants.FLOATINGIP_STATUS_ACTIVE):
        LOG.info("CalicoPlugin create_floatingip: %s", floatingip)
        new_floatingip = super(CalicoPlugin, self).create_floatingip(
            context,
            floatingip,
            initial_status=initial_status
        )
        LOG.info("CalicoPlugin new_floatingip=%s", new_floatingip)
        if new_floatingip['port_id']:
            context.fip_update_port_id = new_floatingip['port_id']
            self.mechanism_manager._call_on_drivers('update_floatingip',
                                                    context)
        return new_floatingip
