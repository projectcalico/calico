# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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

Function for fanning our updates to the IPv4 and IPv6 versions of
the manager classes.
"""
import logging
import os

import functools
import gevent

from calico.felix.actor import Actor, actor_message

_log = logging.getLogger(__name__)


class UpdateSplitter(object):
    """
    Fans out notifications for IPv4 and IPv6 to the relevant actors.

    Historical note: this used to be a fully-fledged Actor but that
    significantly increases the number of messages we send per update.

    Thread safety: this object is accessed from multiple threads,
    which is safe because it doesn't have any mutable state.
    """
    def __init__(self, managers):
        super(UpdateSplitter, self).__init__()
        self.managers = managers

        self.in_sync_mgrs = self._managers_with("on_datamodel_in_sync")
        self.rules_upd_mgrs = self._managers_with("on_rules_update")
        self.tags_upd_mgrs = self._managers_with("on_tags_update")
        self.iface_upd_mgrs = self._managers_with("on_interface_update")
        self.ep_upd_mgrs = self._managers_with("on_endpoint_update")
        self.host_ep_upd_mgrs = self._managers_with("on_host_ep_update")
        self.ipam_upd_mgrs = self._managers_with("on_ipam_pool_updated")
        self.selector_mgrs = self._managers_with("on_policy_selector_update")
        self.tier_data_mgrs = self._managers_with("on_tier_data_update")
        self.prof_labels_mgrs = self._managers_with("on_prof_labels_set")
        self.ipset_added_upd_mgrs = self._managers_with("on_ipset_update")
        self.ipset_removed_upd_mgrs = self._managers_with("on_ipset_removed")
        self.ipset_upd_mgrs = self._managers_with("on_ipset_delta_update")

    def _managers_with(self, method_name):
        return [m for m in self.managers if hasattr(m, method_name)]

    def on_datamodel_in_sync(self):
        """
        Called when the data-model is known to be in-sync.
        """
        for mgr in self.in_sync_mgrs:
            mgr.on_datamodel_in_sync(async=True)

    def on_rules_update(self, profile_id, rules):
        """
        Process an update to the rules of the given profile.
        :param str|TieredPolicyId profile_id: Profile ID in question
        :param dict[str,list[dict]] rules: New set of inbound/outbound rules
            or None if the rules have been deleted.
        """
        _log.info("Profile update: %s", profile_id)
        _log.debug("Profile update %s = %s", profile_id, rules)
        for mgr in self.rules_upd_mgrs:
            mgr.on_rules_update(profile_id, rules, async=True)

    def on_tags_update(self, profile_id, tags):
        """
        Called when the given tag list has changed or been deleted.
        :param str profile_id: Profile ID in question
        :param list[str] tags: List of tags for the given profile or None if
            deleted.
        """
        _log.info("Tags for profile %s updated", profile_id)
        for mgr in self.tags_upd_mgrs:
            mgr.on_tags_update(profile_id, tags, async=True)

    def on_prof_labels_set(self, profile_id, labels):
        """
        Called when the labels for a policy profile are updated.
        :param str profile_id: ID of the profile.
        :param labels: dict or, None to signify deletion.
        """
        _log.info("Profile %s labels updated", profile_id)
        for mgr in self.prof_labels_mgrs:
            mgr.on_prof_labels_set(profile_id, labels, async=True)

    def on_tier_data_update(self, tier, data_or_none):
        """
        Called when the metadata for a policy tier is updated.
        :param str tier: name of the tier.
        :param dict|NoneType data_or_none: dict containing its data or None.
        """
        _log.info("Data for tier %s updated", tier)
        for mgr in self.tier_data_mgrs:
            mgr.on_tier_data_update(tier, data_or_none, async=True)

    def on_policy_selector_update(self, policy_id, selector_or_none,
                                  order_or_none):
        """
        Called when the selector for a tiered-policy is updated.
        :param policy_id:
        :param selector_or_none:
        """
        _log.info("Selector for profile %s updated", policy_id)
        for mgr in self.selector_mgrs:
            mgr.on_policy_selector_update(policy_id, selector_or_none,
                                          order_or_none, async=True)

    def on_interface_update(self, name, iface_up):
        """
        Called when an interface state has changed.

        :param str name: Interface name
        :param bool iface_up: True if the interface is up, False if notF.
        """
        _log.info("Interface %s state changed", name)
        for mgr in self.iface_upd_mgrs:
            mgr.on_interface_update(name, iface_up, async=True)

    def on_endpoint_update(self, endpoint_id, endpoint):
        """
        Process an update to the given endpoint.  endpoint may be None if
        the endpoint was deleted.

        :param WloadEndpointId endpoint_id: WloadEndpointId object in question
        :param dict endpoint: Endpoint data dict
        """
        _log.debug("Endpoint update for %s.", endpoint_id)
        _log.debug("Endpoint update %s = %s", endpoint_id, endpoint)
        for mgr in self.ep_upd_mgrs:
            mgr.on_endpoint_update(endpoint_id, endpoint, async=True)

    def on_host_ep_update(self, combined_id, iface_data):
        """
        Fan out an update to a host endpoint.

        :param HostEndpointId combined_id: Id of the interface.
        :param dict|NoneType iface_data: JSON data or None for a deletion.
        """
        _log.info("Host interface %s updated", combined_id)
        _log.debug("Host endpoint update %s = %s", combined_id, iface_data)
        for mgr in self.host_ep_upd_mgrs:
            mgr.on_host_ep_update(combined_id, iface_data, async=True)

    def on_ipam_pool_updated(self, pool_id, pool):
        """
        Fan out an update to the given IPAM pool.

        :param pool_id: Opaque ID of the pool
        :param pool: Either a dict representing the pool or None for a
               deletion.
        """
        _log.info("IPAM pool %s updated", pool_id)
        for mgr in self.ipam_upd_mgrs:
            mgr.on_ipam_pool_updated(pool_id, pool, async=True)

    def on_ipset_update(self, ipset_id, members):
        _log.info("IP set update %s", ipset_id)
        _log.debug("IP set update %s = %s", ipset_id, members)
        for mgr in self.ipset_added_upd_mgrs:
            mgr.on_ipset_update(ipset_id, members, async=True)

    def on_ipset_removed(self, ipset_id):
        _log.info("IP set removed %s", ipset_id)
        for mgr in self.ipset_removed_upd_mgrs:
            mgr.on_ipset_removed(ipset_id, async=True)

    def on_ipset_delta_update(self, ipset_id, added_ips, removed_ips):
        _log.debug("IP set updates for %s: added: %s, removed: %s",
                   ipset_id, added_ips, removed_ips)
        for mgr in self.ipset_upd_mgrs:
            mgr.on_ipset_delta_update(ipset_id, added_ips, removed_ips,
                                      async=True)


class CleanupManager(Actor):
    """
    Manages the post-graceful restart cleanup scheduling.

    This is a pretty trivial Actor in that its only state is a
    single one-way flag but making it an Actor lets us re-use
    the UpdateSplitter logic to fan out the on_datamodel_in_sync()
    call.
    """
    def __init__(self, config, iptables_updaters, ipsets_mgrs):
        super(CleanupManager, self).__init__()
        self.config = config
        self.iptables_updaters = iptables_updaters
        self.ipsets_mgrs = ipsets_mgrs
        self._cleanup_done = False

    @actor_message()
    def on_datamodel_in_sync(self):
        if not self._cleanup_done:
            # Datamodel in sync for the first time.  Give the managers some
            # time to finish processing, then trigger cleanup.
            self._cleanup_done = True
            _log.info("No cleanup scheduled, scheduling one.")
            gevent.spawn_later(self.config.STARTUP_CLEANUP_DELAY,
                               functools.partial(self._do_cleanup,
                                                 async=True))
        self._cleanup_done = True

    @actor_message()
    def _do_cleanup(self):
        try:
            _log.info("Triggering a cleanup of orphaned ipsets/chains")
            # Need to clean up iptables first because they reference ipsets
            # and force them to stay alive.  Note: we use async=False to
            # ensure that the cleanup is complete before we start the
            # ipsets cleanup.
            for ipt_updater in self.iptables_updaters:
                ipt_updater.cleanup(async=False)
            _log.info("iptables cleanup complete, moving on to ipsets")
            for ipset_mgr in self.ipsets_mgrs:
                ipset_mgr.cleanup(async=False)

            # We've cleaned up any unused ipsets and iptables.   Let any
            # plugins know in case they want to take any action.
            for plugin_name, plugin in self.config.plugins.iteritems():
                _log.info("Invoking cleanup_complete for plugin %s",
                          plugin_name)
                plugin.cleanup_complete(self.config)
        except:
            _log.exception("Failed to cleanup iptables or ipsets state, "
                           "exiting")
            os._exit(1)
            raise  # Keep linter happy.
