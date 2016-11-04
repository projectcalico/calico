# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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

import logging
from calico.felix.actor import Actor, actor_message
from calico.felix.futils import IPV4, IPV6
from calico.felix.ipsets import Ipset, FELIX_PFX

_log = logging.getLogger(__name__)


ALL_POOLS_SET_NAME = FELIX_PFX + "all-ipam-pools"
MASQ_POOLS_SET_NAME = FELIX_PFX + "masq-ipam-pools"

MASQ_RULE_FRAGMENT = ("POSTROUTING "
                      "--match set --match-set %s src "
                      "--match set ! --match-set %s dst "
                      "--jump MASQUERADE" % (MASQ_POOLS_SET_NAME,
                                             ALL_POOLS_SET_NAME))

class MasqueradeManager(Actor):
    def __init__(self, ip_type, iptables_mgr):
        super(MasqueradeManager, self).__init__(qualifier=str(ip_type))
        assert ip_type in (IPV4, IPV6)
        assert iptables_mgr.table == "nat"
        self.ip_type = ip_type
        self.pools_by_id = {}
        self._iptables_mgr = iptables_mgr
        ip_family = "inet" if ip_type == IPV4 else "inet6"
        self._all_pools_ipset = Ipset(ALL_POOLS_SET_NAME,
                                      ALL_POOLS_SET_NAME + "-tmp",
                                      ip_family,
                                      "hash:net")
        self._masq_pools_ipset = Ipset(MASQ_POOLS_SET_NAME,
                                       MASQ_POOLS_SET_NAME + "-tmp",
                                       ip_family,
                                       "hash:net")
        self._dirty = False

    @actor_message()
    def apply_snapshot(self, pools_by_id):
        _log.info("Applying IPAM pool snapshot with %s pools",
                  len(pools_by_id))
        self.pools_by_id.clear()
        self.pools_by_id.update(pools_by_id)
        self._dirty = True

    @actor_message()
    def on_ipam_pool_updated(self, pool_id, pool):
        if self.pools_by_id.get(pool_id) != pool:
            if pool is None:
                _log.info("IPAM pool deleted: %s", pool_id)
                del self.pools_by_id[pool_id]
            else:
                if ":" in pool["cidr"]:
                    _log.debug("Ignoring IPv6 pool: %s", pool_id)
                    return
                _log.info("IPAM pool %s updated: %s", pool_id, pool)
                self.pools_by_id[pool_id] = pool
            self._dirty = True

    def _finish_msg_batch(self, batch, results):
        _log.debug("Finishing batch of IPAM pool changes")
        if self._dirty:
            _log.info("Marked as dirty, looking for masq-enabled pools")
            masq_enabled_cidrs = set()
            all_cidrs = set()
            for pool in self.pools_by_id.itervalues():
                all_cidrs.add(pool["cidr"])
                if pool.get("masquerade", False):
                    masq_enabled_cidrs.add(pool["cidr"])
            if masq_enabled_cidrs:
                _log.info("There are masquerade-enabled pools present. "
                          "Updating.")
                self._all_pools_ipset.replace_members(all_cidrs)
                self._masq_pools_ipset.replace_members(masq_enabled_cidrs)
                # Enable masquerading for traffic coming from pools that
                # have it enabled only when the traffic is heading to an IP
                # that isn't in any Calico-owned pool.  (We assume that NAT
                # is not required for Calico-owned IPs.)
                self._iptables_mgr.ensure_rule_inserted(MASQ_RULE_FRAGMENT,
                                                        async=True)
            else:
                _log.info("No masquerade-enabled pools present. "
                          "Removing rules and ipsets.")
                # Ensure that the rule doesn't exist before we try to remove
                # our ipsets. Have to make a blocking call so that we don't
                # try to remove the ipsets before we've cleaned up the rule
                # that references them.
                self._iptables_mgr.ensure_rule_removed(MASQ_RULE_FRAGMENT,
                                                       async=False)
                # Safe to call even if the ipsets don't exist:
                self._all_pools_ipset.delete()
                self._masq_pools_ipset.delete()
            self._dirty = False
            _log.info("Finished refreshing ipsets")
