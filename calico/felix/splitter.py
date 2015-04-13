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
import logging
import gevent

_log = logging.getLogger(__name__)


class UpdateSplitter(object):
    def __init__(self, config, ipsets_mgrs, rules_managers, endpoint_managers,
                 iptables_updaters):

        self.config = config
        self.ipsets_mgrs = ipsets_mgrs
        self.iptables_updaters = iptables_updaters
        self.rules_mgrs = rules_managers
        self.endpoint_mgrs = endpoint_managers

    def apply_snapshot(self, rules_by_prof_id, tags_by_prof_id,
                       endpoints_by_id):
        """
        Replaces the whole cache state with the input.  Applies deltas vs the
        current active state.
        """
        # Step 1: fire in data update events to the profile and tag managers
        # so they can build their indexes before we activate anything.
        _log.info("Applying snapshot. STAGE 1a: rules.")
        for rules_mgr in self.rules_mgrs:
            rules_mgr.apply_snapshot(rules_by_prof_id, async=True)
        _log.info("Applying snapshot. STAGE 1b: tags.")
        for ipset_mgr in self.ipsets_mgrs:
            ipset_mgr.apply_snapshot(tags_by_prof_id, endpoints_by_id,
                                     async=True)

        # Step 2: fire in update events into the endpoint manager, which will
        # recursively trigger activation of profiles and tags.
        _log.info("Applying snapshot. STAGE 2: endpoints->endpoint mgr.")
        for ep_mgr in self.endpoint_mgrs:
            ep_mgr.apply_snapshot(endpoints_by_id, async=True)

        _log.info("Applying snapshot. DONE. %s rules, %s tags, "
                  "%s endpoints", len(rules_by_prof_id), len(tags_by_prof_id),
                  len(endpoints_by_id))

        # Since we don't wait for all the above processing to finish, set a
        # timer to clean up orphaned ipsets and tables later.  If the snapshot
        # takes longer than this timer to apply then we might do the cleanup
        # before the snapshot is finished.  That would cause dropped packets
        # until applying the snapshot finishes.
        gevent.spawn_later(self.config.STARTUP_CLEANUP_DELAY,
                           self.trigger_cleanup)

    def trigger_cleanup(self):
        """
        Called from a separate greenlet, asks the managers to clean up
        unused ipsets and iptables.
        """
        _log.info("Triggering a cleanup of orphaned ipsets/chains")
        try:
            # Need to clean up iptables first because they reference ipsets
            # and force them to stay alive.
            for ipt_updater in self.iptables_updaters:
                ipt_updater.cleanup(async=False)
        except Exception:
            _log.exception("iptables cleanup failed, will retry on resync.")
        try:
            # It's still worth a try to clean up any ipsets that we can.
            for ipset_mgr in self.ipsets_mgrs:
                ipset_mgr.cleanup(async=False)
        except Exception:
            _log.exception("ipsets cleanup failed, will retry on resync.")

    def on_rules_update(self, profile_id, rules):
        """
        Process an update to the rules of the given profile.
        :param dict[str,list[dict]] rules: New set of inbound/outbound rules
            or None if the rules have been deleted.
        """
        _log.info("Profile update: %s", profile_id)
        for rules_mgr in self.rules_mgrs:
            rules_mgr.on_rules_update(profile_id, rules, async=True)

    def on_tags_update(self, profile_id, tags):
        """
        Called when the given tag list has changed or been deleted.
        :param list[str] tags: List of tags for the given profile or None if
            deleted.
        """
        _log.info("Tags for profile %s updated", profile_id)
        for ipset_mgr in self.ipsets_mgrs:
            ipset_mgr.on_tags_update(profile_id, tags, async=True)

    def on_interface_update(self, name):
        _log.info("Interface %s up", name)
        for endpoint_mgr in self.endpoint_mgrs:
            endpoint_mgr.on_interface_update(name, async=True)

    def on_endpoint_update(self, endpoint_id, endpoint):
        """
        Process an update to the given endpoint.  endpoint may be None if
        the endpoint was deleted.
        """
        _log.info("Endpoint update for %s.", endpoint_id)
        for ipset_mgr in self.ipsets_mgrs:
            ipset_mgr.on_endpoint_update(endpoint_id, endpoint, async=True)
        for endpoint_mgr in self.endpoint_mgrs:
            endpoint_mgr.on_endpoint_update(endpoint_id, endpoint, async=True)
