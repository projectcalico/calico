# -*- coding: utf-8 -*-
# Copyright (c) 2015 Metaswitch Networks
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
"""
felix.splitter
~~~~~~~~~~~~~

Simple object that just splits notifications out for IPv4 and IPv6.
"""
import functools
import logging
import gevent
from calico.felix.actor import Actor, actor_message

_log = logging.getLogger(__name__)


class UpdateSplitter(Actor):
    """
    Actor that takes the role of message broker, farming updates out to IPv4
    and IPv6-specific actors.

    Users of the API should follow this contract:

    (1) send an apply_snapshot message containing a complete and consistent
        snapshot of the data model.
    (2) send in-order updates via the on_xyz_update messages.
    (3) at any point, repeat from (1)
    """
    def __init__(self, config, ipsets_mgrs, rules_managers, endpoint_managers,
                 iptables_updaters, ipv4_masq_manager):
        super(UpdateSplitter, self).__init__()
        self.config = config
        self.ipsets_mgrs = ipsets_mgrs
        self.iptables_updaters = iptables_updaters
        self.rules_mgrs = rules_managers
        self.endpoint_mgrs = endpoint_managers
        self.ipv4_masq_manager = ipv4_masq_manager
        self._cleanup_scheduled = False

    # @actor_message()
    # def apply_snapshot(self, rules_by_prof_id, tags_by_prof_id,
    #                    endpoints_by_id, ipv4_pools_by_id):
    #     """
    #     Replaces the whole cache state with the input.  Applies deltas vs the
    #     current active state.
    #
    #     :param rules_by_prof_id: A dict mapping security profile ID to a list
    #         of profile rules, each of which is a dict.
    #     :param tags_by_prof_id: A dict mapping security profile ID to a list of
    #         profile tags.
    #     :param endpoints_by_id: A dict mapping EndpointId objects to endpoint
    #         data dicts.
    #     :param ipv4_pools_by_id: A dict mapping IPAM pool ID to dicts
    #         representing the pool.
    #     """
    #     # Step 1: fire in data update events to the profile and tag managers
    #     # so they can build their indexes before we activate anything.
    #     _log.info("Applying snapshot. Queueing rules.")
    #     for rules_mgr in self.rules_mgrs:
    #         rules_mgr.apply_snapshot(rules_by_prof_id, async=True)
    #     _log.info("Applying snapshot. Queueing tags/endpoints to ipset mgr.")
    #     for ipset_mgr in self.ipsets_mgrs:
    #         ipset_mgr.apply_snapshot(tags_by_prof_id, endpoints_by_id,
    #                                  async=True)
    #
    #     # Step 2: fire in update events into the endpoint manager, which will
    #     # recursively trigger activation of profiles and tags.
    #     _log.info("Applying snapshot. Queueing endpoints->endpoint mgr.")
    #     for ep_mgr in self.endpoint_mgrs:
    #         ep_mgr.apply_snapshot(endpoints_by_id, async=True)
    #
    #     # Step 3: send update to NAT manager.
    #     _log.info("Applying snapshot.  Queueing IPv4 pools -> masq mgr.")
    #     self.ipv4_masq_manager.apply_snapshot(ipv4_pools_by_id, async=True)
    #
    #     _log.info("Applying snapshot. DONE. %s rules, %s tags, "
    #               "%s endpoints, %s pools", len(rules_by_prof_id),
    #               len(tags_by_prof_id), len(endpoints_by_id),
    #               len(ipv4_pools_by_id))
    #
    #     # Since we don't wait for all the above processing to finish, set a
    #     # timer to clean up orphaned ipsets and tables later.  If the snapshot
    #     # takes longer than this timer to apply then we might do the cleanup
    #     # before the snapshot is finished.  That would cause dropped packets
    #     # until applying the snapshot finishes.
    #     if not self._cleanup_scheduled:
    #         _log.info("No cleanup scheduled, scheduling one.")
    #         gevent.spawn_later(self.config.STARTUP_CLEANUP_DELAY,
    #                            functools.partial(self.trigger_cleanup,
    #                                              async=True))
    #         self._cleanup_scheduled = True

    @actor_message()
    def trigger_cleanup(self):
        """
        Called from a separate greenlet, asks the managers to clean up
        unused ipsets and iptables.
        """
        self._cleanup_scheduled = False
        _log.info("Triggering a cleanup of orphaned ipsets/chains")
        # Need to clean up iptables first because they reference ipsets
        # and force them to stay alive.
        for ipt_updater in self.iptables_updaters:
            ipt_updater.cleanup(async=False)
        # It's still worth a try to clean up any ipsets that we can.
        for ipset_mgr in self.ipsets_mgrs:
            ipset_mgr.cleanup(async=False)

    @actor_message()
    def on_rules_update(self, profile_id, rules):
        """
        Process an update to the rules of the given profile.
        :param str profile_id: Profile ID in question
        :param dict[str,list[dict]] rules: New set of inbound/outbound rules
            or None if the rules have been deleted.
        """
        _log.info("Profile update: %s", profile_id)
        for rules_mgr in self.rules_mgrs:
            rules_mgr.on_rules_update(profile_id, rules, async=True)

    @actor_message()
    def on_tags_update(self, profile_id, tags):
        """
        Called when the given tag list has changed or been deleted.
        :param str profile_id: Profile ID in question
        :param list[str] tags: List of tags for the given profile or None if
            deleted.
        """
        _log.info("Tags for profile %s updated", profile_id)
        for ipset_mgr in self.ipsets_mgrs:
            ipset_mgr.on_tags_update(profile_id, tags, async=True)

    @actor_message()
    def on_interface_update(self, name, iface_up):
        """
        Called when an interface state has changed.

        :param str name: Interface name
        """
        _log.info("Interface %s state changed", name)
        for endpoint_mgr in self.endpoint_mgrs:
            endpoint_mgr.on_interface_update(name, iface_up, async=True)

    @actor_message()
    def on_endpoint_update(self, endpoint_id, endpoint):
        """
        Process an update to the given endpoint.  endpoint may be None if
        the endpoint was deleted.

        :param EndpointId endpoint_id: EndpointId object in question
        :param dict endpoint: Endpoint data dict
        """
        _log.info("Endpoint update for %s.", endpoint_id)
        for ipset_mgr in self.ipsets_mgrs:
            ipset_mgr.on_endpoint_update(endpoint_id, endpoint, async=True)
        for endpoint_mgr in self.endpoint_mgrs:
            endpoint_mgr.on_endpoint_update(endpoint_id, endpoint, async=True)

    @actor_message()
    def on_ipam_pool_update(self, pool_id, pool):
        _log.info("IPAM pool %s updated", pool_id)
        self.ipv4_masq_manager.on_ipam_pool_updated(pool_id, pool, async=True)
