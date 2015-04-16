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
felix.ipsets
~~~~~~~~~~~~

IP sets management functions.
"""
from collections import defaultdict

import logging
import os
import tempfile

from calico.felix import futils
from calico.felix.futils import IPV4, IPV6, FailedSystemCall
from calico.felix.actor import actor_message
from calico.felix.refcount import ReferenceManager, RefCountedActor
import re

_log = logging.getLogger(__name__)

FELIX_PFX = "felix-"
IPSET_PREFIX = { IPV4: FELIX_PFX+"v4-", IPV6: FELIX_PFX+"v6-" }
IPSET_TMP_PREFIX = { IPV4: FELIX_PFX+"tmp-v4-", IPV6: FELIX_PFX+"tmp-v6-" }


def tag_to_ipset_name(ip_type, tag, tmp=False):
    """
    Turn a tag ID in all its glory into an ipset name.
    """
    if not tmp:
        name = IPSET_PREFIX[ip_type] + tag
    else:
        name = IPSET_TMP_PREFIX[ip_type] + tag
    return name


class IpsetManager(ReferenceManager):
    def __init__(self, ip_type):
        """
        Manages all the ipsets for tags for either IPv4 or IPv6.

        :param ip_type: IP type (IPV4 or IPV6)
        """
        super(IpsetManager, self).__init__(qualifier=ip_type)

        self.ip_type = ip_type

        # State.
        self.tags_by_prof_id = {}
        self.endpoints_by_ep_id = {}

        # Indexes.
        self.endpoint_ids_by_tag = defaultdict(set)
        self.endpoint_ids_by_profile_id = defaultdict(set)

    def _create(self, tag_id):
        # Create the ActiveIpset, and put a message on the queue that will
        # trigger it to update the ipset as soon as it starts. Note that we do
        # this now so that it is sure to be processed with the first batch even
        # if other messages are arriving.
        active_ipset = ActiveIpset(futils.uniquely_shorten(tag_id, 16),
                                   self.ip_type)

        members = set()
        for ep_id in self.endpoint_ids_by_tag.get(tag_id, set()):
            ep = self.endpoints_by_ep_id.get(ep_id, {})
            nets = self.nets_key
            members.update(map(futils.net_to_ip, ep.get(nets, [])))

        active_ipset.replace_members(members, async=True)
        return active_ipset

    def _on_object_started(self, tag_id, ipset):
        _log.debug("ActiveIpset actor for %s started", tag_id)

    @property
    def nets_key(self):
        nets = "ipv4_nets" if self.ip_type == IPV4 else "ipv6_nets"
        return nets

    @actor_message()
    def apply_snapshot(self, tags_by_prof_id, endpoints_by_id):
        missing_profile_ids = set(self.tags_by_prof_id.keys())
        for profile_id, tags in tags_by_prof_id.iteritems():
            self.on_tags_update(profile_id, tags)
            missing_profile_ids.discard(profile_id)
            self._maybe_yield()
        for profile_id in missing_profile_ids:
            self.on_tags_update(profile_id, None)
            self._maybe_yield()
        del missing_profile_ids
        missing_endpoints = set(self.endpoints_by_ep_id.keys())
        for endpoint_id, endpoint in endpoints_by_id.iteritems():
            self.on_endpoint_update(endpoint_id, endpoint)
            missing_endpoints.discard(endpoint_id)
            self._maybe_yield()
        for ep_id in missing_endpoints:
            self.on_endpoint_update(ep_id, None)
            self._maybe_yield()

    @actor_message()
    def cleanup(self):
        """
        Clean up left-over ipsets that existed at start-of-day.
        """
        all_ipsets = list_ipset_names()
        # only clean up our own rubbish.
        pfx = IPSET_PREFIX[self.ip_type]
        tmppfx = IPSET_TMP_PREFIX[self.ip_type]
        felix_ipsets = set([n for n in all_ipsets if n.startswith(pfx) or
                                                     n.startswith(tmppfx)])
        whitelist = set()
        for ipset in self.objects_by_id.values():
            # Ask the ipset for all the names it may use and whitelist.
            whitelist.update(ipset.owned_ipset_names())
        _log.debug("Whitelisted ipsets: %s", whitelist)
        ipsets_to_delete = felix_ipsets - whitelist
        _log.debug("Deleting ipsets: %s", ipsets_to_delete)
        # Delete the ipsets before we return.  We can't queue these up since
        # that could conflict if someone increffed one of the ones we're about
        # to delete.
        for ipset_name in ipsets_to_delete:
            try:
                futils.check_call(["ipset", "destroy", ipset_name])
            except FailedSystemCall:
                _log.exception("Failed to clean up dead ipset %s, will "
                               "retry on next cleanup.", ipset_name)

    @actor_message()
    def on_tags_update(self, profile_id, tags):
        """
        Called when the given tag list has changed or been deleted.
        :param list[str]|NoneType tags: List of tags for the given profile or
            None if deleted.
        """
        _log.info("Tags for profile %s updated", profile_id)
        old_tags = self.tags_by_prof_id.get(profile_id, [])
        new_tags = tags or []
        self._process_tag_updates(profile_id, set(old_tags), set(new_tags))

        if tags is None:
            _log.info("Tags for profile %s deleted", profile_id)
            self.tags_by_prof_id.pop(profile_id, None)
        else:
            self.tags_by_prof_id[profile_id] = tags

    def _process_tag_updates(self, profile_id, old_tags, new_tags):
        """
        Updates the active ipsets associated with the change in tags
        of the given profile ID.
        """
        endpoint_ids = self.endpoint_ids_by_profile_id.get(profile_id, set())
        _log.debug("Endpoint IDs with this profile: %s", endpoint_ids)
        added_tags = new_tags - old_tags
        _log.debug("Profile %s added tags: %s", profile_id, added_tags)
        removed_tags = old_tags - new_tags
        _log.debug("Profile %s removed tags: %s", profile_id, removed_tags)
        for added, upd_tags in [(True, added_tags), (False, removed_tags)]:
            for tag in upd_tags:
                if added:
                    self.endpoint_ids_by_tag[tag] |= endpoint_ids
                else:
                    self.endpoint_ids_by_tag[tag] -= endpoint_ids
                if self._is_starting_or_live(tag):
                    # Tag is in-use, update its members.
                    ipset = self.objects_by_id[tag]
                    for endpoint_id in endpoint_ids:
                        endpoint = self.endpoints_by_ep_id[endpoint_id]
                        for ip in map(futils.net_to_ip,
                                      endpoint.get(self.nets_key, [])):
                            if added:
                                ipset.add_member(ip, async=True)
                            else:
                                ipset.remove_member(ip, async=True)

    @actor_message()
    def on_endpoint_update(self, endpoint_id, endpoint):
        old_endpoint = self.endpoints_by_ep_id.get(endpoint_id, {})
        old_prof_id = old_endpoint.get("profile_id")
        if old_prof_id:
            old_tags = set(self.tags_by_prof_id.get(old_prof_id, []))
        else:
            old_tags = set()

        if endpoint is None:
            _log.info("Endpoint %s deleted", endpoint_id)
            if endpoint_id not in self.endpoints_by_ep_id:
                _log.warn("Delete for unknown endpoint %s", endpoint_id)
                return
            # Update profile index.
            eps_for_profile = self.endpoint_ids_by_profile_id[old_prof_id]
            eps_for_profile.discard(endpoint_id)
            if not eps_for_profile:
                # Profile no longer has any endpoints using it, clean up
                # the index.
                _log.debug("Profile %s now unused", old_prof_id)
                del self.endpoint_ids_by_profile_id[old_prof_id]
            for tag in old_tags:
                self.endpoint_ids_by_tag[tag].discard(endpoint_id)
                if not self.endpoint_ids_by_tag[tag]:
                    del self.endpoint_ids_by_tag[tag]
                if self._is_starting_or_live(tag):
                    for ip in map(futils.net_to_ip,
                                  old_endpoint[self.nets_key]):
                        ipset = self.objects_by_id[tag]
                        ipset.remove_member(ip, async=True)
            self.endpoints_by_ep_id.pop(endpoint_id, None)
        else:
            _log.info("Endpoint %s update received", endpoint_id)
            new_prof_id = endpoint["profile_id"]
            new_tags = set(self.tags_by_prof_id.get(new_prof_id, []))

            # Calculate impact on tags due to any change of profile or IP
            # address and queue updates to ipsets.
            old_ips = set(map(futils.net_to_ip,
                              old_endpoint.get(self.nets_key, [])))
            new_ips = set(map(futils.net_to_ip,
                              endpoint.get(self.nets_key, [])))
            for removed_ip in old_ips - new_ips:
                for tag in old_tags:
                    if self._is_starting_or_live(tag):
                        ipset = self.objects_by_id[tag]
                        ipset.remove_member(removed_ip, async=True)
            for tag in old_tags - new_tags:
                self.endpoint_ids_by_tag[tag].discard(endpoint_id)
                if self._is_starting_or_live(tag):
                    ipset = self.objects_by_id[tag]
                    for ip in old_ips:
                        ipset.remove_member(ip, async=True)
            for tag in new_tags:
                self.endpoint_ids_by_tag[tag].add(endpoint_id)
                if self._is_starting_or_live(tag):
                    ipset = self.objects_by_id[tag]
                    for ip in new_ips:
                        ipset.add_member(ip, async=True)

            self.endpoints_by_ep_id[endpoint_id] = endpoint
            if old_prof_id and old_prof_id != new_prof_id:
                ids = self.endpoint_ids_by_profile_id[old_prof_id]
                ids.discard(endpoint_id)
                if not ids:
                    del self.endpoint_ids_by_profile_id[old_prof_id]
            self.endpoint_ids_by_profile_id[new_prof_id].add(endpoint_id)

        _log.info("Endpoint update complete")


class ActiveIpset(RefCountedActor):

    def __init__(self, tag, ip_type):
        """
        Actor managing a single ipset.

        :param str tag: Name of tag that this ipset represents.
        :param ip_type: IPV4 or IPV6
        """
        super(ActiveIpset, self).__init__(qualifier=tag)

        self.tag = tag
        self.ip_type = ip_type
        self.name = tag_to_ipset_name(ip_type, tag)
        self.tmpname = tag_to_ipset_name(ip_type, tag, tmp=True)
        self.family = "inet" if ip_type == IPV4 else "inet6"

        # Members - which entries should be in the ipset.
        self.members = set()

        # Members which really are in the ipset.
        self.programmed_members = None

        # Do the sets exist?
        self.set_exists = ipset_exists(self.name)
        self.tmpset_exists = ipset_exists(self.tmpname)

        # Notified ready?
        self.notified_ready = False

    def owned_ipset_names(self):
        """
        This method is safe to call from another greenlet; it only accesses
        immutable state.

        :return: set of name of ipsets that this Actor owns and manages.  the
                 sets may or may not be present.
        """
        return set([self.name, self.tmpname])

    @actor_message()
    def replace_members(self, members):
        _log.info("Replacing members of ipset %s", self.name)
        assert isinstance(members, set), "Expected members to be a set"
        self.members = members

    @actor_message()
    def add_member(self, member):
        _log.info("Adding member %s to ipset %s", member, self.name)
        if member not in self.members:
            self.members.add(member)

    @actor_message()
    def remove_member(self, member):
        _log.info("Removing member %s from ipset %s", member, self.name)
        try:
            self.members.remove(member)
        except KeyError:
            _log.info("%s was not in ipset %s", member, self.name)

    @actor_message()
    def on_unreferenced(self):
        try:
            if self.set_exists:
                futils.check_call(["ipset", "destroy", self.name])
            if self.tmpset_exists:
                futils.check_call(["ipset", "destroy", self.tmpname])
        finally:
            self._notify_cleanup_complete()

    def _finish_msg_batch(self, batch, results):
        # No need to combine members of the batch (although we could). None of
        # the add_members / remove_members / replace_members calls actually
        # does any work, just updating state. The _finish_msg_batch call will
        # then program the real changes.
        if self.members != self.programmed_members:
            self._sync_to_ipset()

        if not self.notified_ready:
            # We have created the set, so we are now ready.
            self.notified_ready = True
            self._notify_ready()

    def _sync_to_ipset(self):
        _log.debug("Setting ipset %s to %s", self.name, self.members)
        fd, filename = tempfile.mkstemp(text=True)
        f = os.fdopen(fd, "w")

        if not self.set_exists:
            # ipset does not exist, so just create it and put the data in it.
            set_name = self.name
            create = True
            swap = False
        elif not self.tmpset_exists:
            # Set exists, but tmpset does not
            set_name = self.tmpname
            create = True
            swap = True
        else:
            # Both set and tmpset exist
            set_name = self.tmpname
            create = False
            swap = True

        if create:
            f.write("create %s hash:ip family %s\n" % (set_name, self.family))
        else:
            f.write("flush %s\n" % (set_name))

        for member in self.members:
            f.write("add %s %s\n" % (set_name, member))

        if swap:
            f.write("swap %s %s\n" % (self.name, self.tmpname))
            f.write("destroy %s\n" % (self.tmpname))

        f.close()

        # Load that data.
        futils.check_call(["ipset", "restore", "-file", filename])

        # By the time we get here, the set exists, and the tmpset does not if
        # we just destroyed it after a swap (it might still exist if it did and
        # the main set did not when we started, unlikely though that seems!).
        self.set_exists = True
        if swap:
            self.tmpset_exists = False

        # Tidy up the tmp file.
        os.remove(filename)

        # We have got the set into the correct state.
        self.programmed_members = self.members.copy()


def ipset_exists(name):
    """
    Check if a set of the correct name exists.
    """
    return futils.call_silent(["ipset", "list", name]) == 0


def list_ipset_names():
    """
    List all names of ipsets. Note that this is *not* the same as the ipset
    list command which lists contents too (hence the name change).
    """
    data = futils.check_call(["ipset", "list"]).stdout
    lines = data.split("\n")

    names = []

    for line in lines:
        words = line.split()
        if len(words) > 1 and words[0] == "Name:":
            names.append(words[1])

    return names
