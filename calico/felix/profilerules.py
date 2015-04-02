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
felix.profilerules
~~~~~~~~~~~~

ProfileRules actor, handles local profile chains.
"""

import logging
from calico.felix.actor import actor_event
from calico.felix.frules import (profile_to_chain_name,
                                 rules_to_chain_rewrite_lines)
from calico.felix.refcount import ReferenceManager, RefCountedActor, RefHelper

_log = logging.getLogger(__name__)


class RulesManager(ReferenceManager):
    """
    Actor that manages the life cycle of ProfileRules objects.
    Users must ensure that they correctly pair calls to
    get_and_incref() and decref().

    This class ensures that rules chains are properly quiesced
    before their Actors are deleted.
    """
    def __init__(self, ip_version, iptables_updater, ipset_manager):
        super(RulesManager, self).__init__(qualifier="v%d" % ip_version)
        self.ip_version = ip_version
        self.iptables_updater = iptables_updater
        self.ipset_manager = ipset_manager
        self.rules_by_profile_id = {}

    def _create(self, profile_id):
        return ProfileRules(profile_id,
                            self.ip_version,
                            self.iptables_updater,
                            self.ipset_manager)

    def _on_object_started(self, profile_id, active_profile):
        profile_or_none = self.rules_by_profile_id.get(profile_id)
        _log.debug("Applying initial update to rules %s: %s", profile_id,
                   profile_or_none)
        active_profile.on_profile_update(profile_or_none, async=True)

    @actor_event
    def apply_snapshot(self, rules_by_profile_id):
        missing_ids = set(self.rules_by_profile_id.keys())
        for profile_id, profile in rules_by_profile_id.iteritems():
            self.on_rules_update(profile_id, profile)  # Skips queue
            missing_ids.discard(profile_id)
            self._maybe_yield()
        for dead_profile_id in missing_ids:
            self.on_rules_update(dead_profile_id, None)

    @actor_event
    def on_rules_update(self, profile_id, profile):
        _log.debug("Processing update to %s", profile_id)
        if profile_id is not None:
            self.rules_by_profile_id[profile_id] = profile
        else:
            self.rules_by_profile_id.pop(profile_id, None)
        if self._is_starting_or_live(profile_id):
            ap = self.objects_by_id[profile_id]
            ap.on_profile_update(profile, async=True)


class ProfileRules(RefCountedActor):
    """
    Actor that owns the per-profile rules chains.
    """
    def __init__(self, profile_id, ip_version, iptables_updater, ipset_mgr):
        super(ProfileRules, self).__init__(qualifier=profile_id)
        assert profile_id is not None

        self.id = profile_id
        self.ip_version = ip_version
        self.ipset_mgr = ipset_mgr
        self._iptables_updater = iptables_updater
        self.notified_ready = False

        self.ipset_refs = RefHelper(self, ipset_mgr, self._maybe_update)

        self._profile = None
        """
        :type dict|None: filled in by first update.  Reset to None on delete.
        """
        self.dead = False

    @actor_event
    def on_profile_update(self, profile):
        """
        Update the programmed iptables configuration with the new
        profile.
        """
        _log.debug("Profile update to %s: %s", self.id, profile)
        assert profile is None or profile["id"] == self.id
        assert not self.dead, "Shouldn't receive updates after we're dead."

        old_tags = extract_tags_from_profile(self._profile)
        new_tags = extract_tags_from_profile(profile)

        removed_tags = old_tags - new_tags
        added_tags = new_tags - old_tags
        for tag in removed_tags:
            _log.debug("Queueing ipset for tag %s for decref", tag)
            self.ipset_refs.discard_ref(tag)
        for tag in added_tags:
            _log.debug("Requesting ipset for tag %s", tag)
            self.ipset_refs.acquire_ref(tag)

        self._profile = profile
        self._maybe_update()

    def _maybe_update(self):
        if self.dead:
            _log.debug("Not updating: profile is dead.")
        elif not self.ipset_refs.ready:
            _log.debug("Can't program rules %s yet, waiting on ipsets",
                       self.id)
        else:
            _log.debug("Ready to program rules for %s", self.id)
            self._update_chains()

    @actor_event
    def on_unreferenced(self):
        """
        Called to tell us that this profile is no longer needed.  Removes
        our iptables configuration.
        """
        self.dead = True
        chains = []
        for direction in ["inbound", "outbound"]:
            chain_name = profile_to_chain_name(direction, self.id)
            chains.append(chain_name)
        self._iptables_updater.delete_chains("filter", chains, async=False)
        self.ipset_refs.discard_all()
        self.ipset_refs = None # Break ref cycle.
        self._profile = None
        self._notify_cleanup_complete()

    def _update_chains(self):
        """
        Updates the chains in the dataplane.
        """
        updates = {}
        for direction in ("inbound", "outbound"):
            _log.debug("Updating %s chain for profile %s", direction,
                       self.id)
            new_profile = self._profile or {}
            _log.debug("Profile %s: %s", self.id, self._profile)
            rules_key = "%s_rules" % direction
            new_rules = new_profile.get(rules_key, [])
            chain_name = profile_to_chain_name(direction, self.id)
            tag_to_ip_set_name = {}
            for tag, ipset in self.ipset_refs.iteritems():
                tag_to_ip_set_name[tag] = ipset.name
            updates[chain_name] = rules_to_chain_rewrite_lines(
                chain_name,
                new_rules,
                self.ip_version,
                tag_to_ip_set_name,
                on_allow="RETURN")
        _log.debug("Queueing programming for rules %s: %s", self.id,
                   updates)
        self._iptables_updater.rewrite_chains("filter", updates, {},
                                              async=False)
        # TODO Isolate exceptions from programming the chains to this profile.
        # PLW: Radical thought - could we just say that the profile should be
        # OK, and therefore we don't care? In other words, do we need to handle
        # the error cleverly in the short term, or could we just say that since
        # we built the rules they really should always work.
        if not self.notified_ready:
            self._notify_ready()
            self.notified_ready = True


def extract_tags_from_profile(profile):
    if profile is None:
        return set()
    tags = set()
    for in_or_out in ["inbound_rules", "outbound_rules"]:
        for rule in profile.get(in_or_out, []):
            tags.update(extract_tags_from_rule(rule))
    return tags


def extract_tags_from_rule(rule):
    return set(rule[key] for key in ["src_tag", "dst_tag"]
               if key in rule and rule[key] is not None)
