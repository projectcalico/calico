# -*- coding: utf-8 -*-
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
"""
felix.profilerules
~~~~~~~~~~~~

ProfileRules actor, handles local profile chains.
"""
import logging

from calico.felix.actor import actor_message
from calico.felix.futils import FailedSystemCall
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
    def __init__(self, config, ip_version, iptables_updater, ipset_manager):
        super(RulesManager, self).__init__(qualifier="v%d" % ip_version)
        self.iptables_generator = config.plugins["iptables_generator"]
        self.ip_version = ip_version
        self.iptables_updater = iptables_updater
        self.ipset_manager = ipset_manager
        self.rules_by_profile_id = {}
        self._datamodel_in_sync = False

    def _create(self, profile_id):
        return ProfileRules(self.iptables_generator,
                            profile_id,
                            self.ip_version,
                            self.iptables_updater,
                            self.ipset_manager)

    def _on_object_started(self, profile_id, active_profile):
        profile_or_none = self.rules_by_profile_id.get(profile_id)
        _log.debug("Applying initial update to rules %s: %s", profile_id,
                   profile_or_none)
        active_profile.on_profile_update(profile_or_none, async=True)

    def _maybe_start(self, obj_id, in_sync=False):
        """
        Override: gates starting the ProfileRules on being in sync.

        :param obj_id: The ID of the object (profile) that we'd like to start.
        :param in_sync: True if we know that this profile is in-sync even if
               we might not have received the global in-sync message.
        """
        in_sync |= self._datamodel_in_sync
        if in_sync or obj_id in self.rules_by_profile_id:
            # Either we're globally in-sync or we've explicitly heard about
            # this profile so we know it is in sync.  Defer to the superclass.
            _log.debug("Profile %s is in-sync, deferring to superclass.",
                       obj_id)
            return super(RulesManager, self)._maybe_start(obj_id)
        else:
            _log.info("Delaying startup of profile %s because datamodel is"
                      "not in sync.", obj_id)

    @actor_message()
    def on_datamodel_in_sync(self):
        if not self._datamodel_in_sync:
            _log.info("%s: datamodel now in sync, unblocking profile startup",
                      self)
            self._datamodel_in_sync = True
            self._maybe_start_all()

    @actor_message()
    def on_rules_update(self, profile_id, profile, force_reprogram=False):
        if profile is not None:
            _log.info("Rules for profile %s updated.", profile_id)
            self.rules_by_profile_id[profile_id] = profile
        else:
            _log.debug("Rules for profile %s deleted.", profile_id)
            self.rules_by_profile_id.pop(profile_id, None)
        if self._is_starting_or_live(profile_id):
            _log.info("Profile %s is active, kicking the ProfileRules.",
                      profile_id)
            ap = self.objects_by_id[profile_id]
            ap.on_profile_update(profile, force_reprogram=force_reprogram,
                                 async=True)
        elif profile_id in self.objects_by_id:
            _log.debug("Checking if the update allows us to start profile %s",
                       profile_id)
            # Pass in_sync=True because we now explicitly know this profile is
            # in sync, even if this is a deletion.
            self._maybe_start(profile_id, in_sync=True)


class ProfileRules(RefCountedActor):
    """
    Actor that owns the per-profile rules chains.
    """
    def __init__(self, iptables_generator, profile_id, ip_version,
                 iptables_updater, ipset_mgr):
        super(ProfileRules, self).__init__(qualifier=profile_id)
        assert profile_id is not None

        self.iptables_generator = iptables_generator
        self.id = profile_id
        self.ip_version = ip_version
        self._ipset_mgr = ipset_mgr
        self._iptables_updater = iptables_updater
        self._ipset_refs = RefHelper(self, ipset_mgr, self._on_ipsets_acquired)

        # Latest profile update - a profile dictionary.
        self._pending_profile = None
        # Currently-programmed profile dictionary.
        self._profile = None
        # The IDs of the tags and selector ipsets it requires.
        self._required_ipsets = set()

        # State flags.
        self._notified_ready = False
        self._cleaned_up = False
        self._dead = False
        self._dirty = True

    @actor_message()
    def on_profile_update(self, profile, force_reprogram=False):
        """
        Update the programmed iptables configuration with the new
        profile.

        :param dict[str]|NoneType profile: Dictionary of all profile data or
            None if profile is to be deleted.
        """
        _log.debug("%s: Profile update: %s", self, profile)
        assert not self._dead, "Shouldn't receive updates after we're dead."
        self._pending_profile = profile
        self._dirty |= force_reprogram

    @actor_message()
    def on_unreferenced(self):
        """
        Called to tell us that this profile is no longer needed.
        """
        # Flag that we're dead and then let finish_msg_batch() do the cleanup.
        self._dead = True

    def _on_ipsets_acquired(self):
        """
        Callback from the RefHelper once it's acquired all the ipsets we
        need.

        This is called from an actor_message on our greenlet.
        """
        # Nothing to do here, if this is being called then we're already in
        # a message batch so _finish_msg_batch() will get called next.
        _log.info("All required ipsets acquired.")

    def _finish_msg_batch(self, batch, results):
        # Due to dependency management in IptablesUpdater, we don't need to
        # worry about programming the dataplane before notifying so do it on
        # this common code path.
        if not self._notified_ready:
            self._notify_ready()
            self._notified_ready = True

        if self._dead:
            # Only want to clean up once.  Note: we can get here a second time
            # if we had a pending ipset incref in-flight when we were asked
            # to clean up.
            if not self._cleaned_up:
                try:
                    _log.info("%s unreferenced, removing our chains", self)
                    self._delete_chains()
                    self._ipset_refs.discard_all()
                    self._ipset_refs = None  # Break ref cycle.
                    self._profile = None
                    self._pending_profile = None
                finally:
                    self._cleaned_up = True
                    self._notify_cleanup_complete()
        else:
            if self._pending_profile != self._profile:
                _log.debug("Profile data changed, updating ipset references.")
                # Make sure that all the new tags and selectors are active.
                # We can't discard unneeded ones until we've updated iptables.
                new_tags_and_sels = extract_tags_and_selectors_from_profile(
                    self._pending_profile
                )
                for tag_or_sel in new_tags_and_sels:
                    _log.debug("Requesting ipset for tag %s", tag_or_sel)
                    # Note: acquire_ref() is a no-op if already acquired.
                    self._ipset_refs.acquire_ref(tag_or_sel)

                self._dirty = True
                self._profile = self._pending_profile
                self._required_ipsets = new_tags_and_sels

            if (self._dirty and
                    self._ipset_refs.ready and
                    self._pending_profile is not None):
                _log.info("Ready to program rules for %s", self.id)
                try:
                    self._update_chains()
                except FailedSystemCall as e:
                    _log.error("Failed to program profile chain %s; error: %r",
                               self, e)
                else:
                    # Now we've updated iptables, we can tell the RefHelper
                    # to discard the tags we no longer need.
                    self._ipset_refs.replace_all(self._required_ipsets)
                    self._dirty = False
            elif not self._dirty:
                _log.debug("No changes to program.")
            elif self._pending_profile is None:
                _log.info("Profile is None, removing our chains")
                try:
                    self._delete_chains()
                except FailedSystemCall:
                    _log.exception("Failed to delete chains for profile %s",
                                   self.id)
                else:
                    self._ipset_refs.discard_all()
                    self._dirty = False
            else:
                assert not self._ipset_refs.ready
                _log.info("Can't program rules %s yet, waiting on ipsets",
                          self.id)

    def _delete_chains(self):
        """
        Removes our chains from the dataplane, blocks until complete.
        """
        # Need to block here: have to wait for chains to be deleted
        # before we can decref our ipsets.
        self._iptables_updater.delete_chains(
            self.iptables_generator.profile_chain_names(self.id),
            async=False)

    def _update_chains(self):
        """
        Updates the chains in the dataplane.

        Blocks until the update is complete.

        On entry, self._pending_profile must not be None.

        :raises FailedSystemCall: if the update fails.
        """
        _log.info("%s Programming iptables with our chains.", self)
        assert self._pending_profile is not None, \
            "_update_chains called with no _pending_profile"
        tag_or_sel_to_ip_set_name = {}
        for tag_or_sel, ipset in self._ipset_refs.iteritems():
            tag_or_sel_to_ip_set_name[tag_or_sel] = ipset.ipset_name

        _log.info("Updating chains for profile %s", self.id)
        _log.debug("Profile %s: %s", self.id, self._profile)

        updates, deps = self.iptables_generator.profile_updates(
            self.id,
            self._pending_profile,
            self.ip_version,
            tag_to_ipset=tag_or_sel_to_ip_set_name,
            selector_to_ipset=tag_or_sel_to_ip_set_name,
            comment_tag=self.id)

        _log.debug("Queueing programming for rules %s: %s", self.id,
                   updates)

        self._iptables_updater.rewrite_chains(updates, deps, async=False)


def extract_tags_and_selectors_from_profile(profile):
    if profile is None:
        return set()
    tags_and_sels = set()
    for in_or_out in ["inbound_rules", "outbound_rules"]:
        for rule in profile.get(in_or_out, []):
            for neg_pfx in ["", "!"]:
                for suffix in ["src_ip_set_ids", "dst_ip_set_ids"]:
                    key = neg_pfx + suffix
                    tags_and_sels.update(rule.get(key) or [])
    return tags_and_sels


class UnsupportedICMPType(Exception):
    pass
