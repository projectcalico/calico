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

# Import Ml2Plugin before l3_db to fix
# https://github.com/projectcalico/calico/issues/8494
from neutron.plugins.ml2.plugin import Ml2Plugin
from neutron.db import l3_db  # noqa: I100
from neutron.db.models import l3

from neutron_lib import constants

from oslo_config import cfg

from oslo_log import log

from networking_calico.plugins.calico.context import SGRUpdateContext


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
        cfg.CONF.set_override("mechanism_drivers", ["calico"], group="ml2")
        LOG.info("Forcing ML2 type_drivers to 'local, flat'")
        cfg.CONF.set_override("type_drivers", ["local", "flat"], group="ml2")
        LOG.info("Forcing ML2 tenant_network_types to 'local'")
        cfg.CONF.set_override("tenant_network_types", ["local"], group="ml2")

        # Here we add, rather than forcing the entire value, because DevStack
        # testing configures 'port-security' here.
        LOG.info("Add 'qos' to ML2 extension_drivers, if not already present")
        if "qos" not in cfg.CONF.ml2.extension_drivers:
            cfg.CONF.set_override(
                "extension_drivers",
                cfg.CONF.ml2.extension_drivers + ["qos"],
                group="ml2",
            )

        # This is a bit of a hack to get the models_v2.Port attributes setup in such
        # a way as to avoid tracebacks in the neutron-server log.
        #
        # The tracebacks are not purely cosmetic as they cause all tests run after
        # TestFloatingIPs to fail, presumably as a result of the neutron-server being
        # left in a bad state. The bad state is likely because the error occurs during a
        # cleanup action ("_clean_garbage") which leaves important resources orphaned
        # with no known way to recover.
        #
        # The side-effects within the Router setup that we care about likely have to do
        # with the "orm.relationship" calls but rather than port those directly here and
        # risk any changes that might occur in the future that could render this
        # assumption false we can just rely on the maintainers of this class to keep
        # things up-to-date on our behalf.
        #
        # An example of the traceback looks like this:
        # Traceback (most recent call last):
        #   .../oslo_service/loopingcall.py", line 150, in _run_loop
        #     result = func(*self.args, **self.kw)
        #   .../neutron/db/l3_db.py", line 163, in _clean_garbage
        #     candidates = self._get_dead_floating_port_candidates(context)
        #   .../neutron/db/l3_db.py", line 198, in _get_dead_floating_port_candidates
        #     return {p['id'] for p in self._core_plugin.get_ports(context, filters)}
        #   .../neutron_lib/db/api.py", line 218, in wrapped
        #     return method(*args, **kwargs)
        #   .../neutron_lib/db/api.py", line 139, in wrapped
        #     setattr(e, '_RETRY_EXCEEDED', True)
        #   .../oslo_utils/excutils.py", line 227, in __exit__
        #     self.force_reraise()
        #   .../oslo_utils/excutils.py", line 200, in force_reraise
        #     raise self.value
        #   .../neutron_lib/db/api.py", line 135, in wrapped
        #     return f(*args, **kwargs)
        #   .../oslo_db/api.py", line 154, in wrapper
        #     ectxt.value = e.inner_exc
        #   .../oslo_utils/excutils.py", line 227, in __exit__
        #     self.force_reraise()
        #   .../oslo_utils/excutils.py", line 200, in force_reraise
        #     raise self.value
        #   .../oslo_db/api.py", line 142, in wrapper
        #     return f(*args, **kwargs)
        #   .../neutron_lib/db/api.py", line 183, in wrapped
        #     LOG.debug("Retry wrapper got retriable exception: %s", e)
        #   .../oslo_utils/excutils.py", line 227, in __exit__
        #     self.force_reraise()
        #   .../oslo_utils/excutils.py", line 200, in force_reraise
        #     raise self.value
        #   .../neutron_lib/db/api.py", line 179, in wrapped
        #     return f(*dup_args, **dup_kwargs)
        #   .../neutron/db/db_base_plugin_v2.py", line 1601, in get_ports
        #     lazy_fields = [models_v2.Port.port_forwardings,
        # AttributeError: type object 'Port' has no attribute 'port_forwardings'
        _ = l3.Router()

        super(CalicoPlugin, self).__init__()

    # Intercept floating IP associates/disassociates so we can trigger an
    # appropriate endpoint update.
    def _update_floatingip(self, context, id, floatingip):
        LOG.info("CalicoPlugin _update_floatingip: %s", floatingip)
        old_floatingip, new_floatingip = super(CalicoPlugin, self)._update_floatingip(
            context, id, floatingip
        )

        LOG.info("CalicoPlugin new_floatingip=%s", new_floatingip)
        if new_floatingip["port_id"]:
            context.fip_update_port_id = new_floatingip["port_id"]
            self.mechanism_manager._call_on_drivers("update_floatingip", context)

        LOG.info("CalicoPlugin old_floatingip=%s", old_floatingip)
        if old_floatingip["port_id"]:
            context.fip_update_port_id = old_floatingip["port_id"]
            self.mechanism_manager._call_on_drivers("update_floatingip", context)

        return old_floatingip, new_floatingip

    def create_floatingip(
        self, context, floatingip, initial_status=constants.FLOATINGIP_STATUS_ACTIVE
    ):
        LOG.info("CalicoPlugin create_floatingip: %s", floatingip)
        new_floatingip = super(CalicoPlugin, self).create_floatingip(
            context, floatingip, initial_status=initial_status
        )
        LOG.info("CalicoPlugin new_floatingip=%s", new_floatingip)
        if new_floatingip["port_id"]:
            context.fip_update_port_id = new_floatingip["port_id"]
            self.mechanism_manager._call_on_drivers("update_floatingip", context)
        return new_floatingip

    def create_security_group_rule(self, context, security_group_rule):
        rule = super().create_security_group_rule(context, security_group_rule)
        sgids = [rule["security_group_id"]]
        self._notify_sg_rule_updated(context, sgids)
        return rule

    def create_security_group_rule_bulk(self, context, security_group_rules):
        rules = super().create_security_group_rule_bulk_native(
            context, security_group_rules
        )
        sgids = set([r["security_group_id"] for r in rules])
        self._notify_sg_rule_updated(context, list(sgids))
        return rules

    def delete_security_group_rule(self, context, sgrid):
        rule = self.get_security_group_rule(context, sgrid)
        super().delete_security_group_rule(context, sgrid)
        self._notify_sg_rule_updated(context, [rule["security_group_id"]])

    def _notify_sg_rule_updated(self, context, sgids):
        self.mechanism_manager._call_on_drivers(
            "security_groups_rule_updated", SGRUpdateContext(context, sgids)
        )
