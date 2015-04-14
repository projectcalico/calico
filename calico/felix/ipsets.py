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

from calico.felix import futils
from calico.felix.futils import IPV4, IPV6, FailedSystemCall
from calico.felix.actor import actor_message
from calico.felix.refcount import ReferenceManager, RefCountedActor

_log = logging.getLogger(__name__)

FELIX_PFX = "felix-"
IPSET_PREFIX = { IPV4: FELIX_PFX+"v4-", IPV6: FELIX_PFX+"v6-" }
IPSET_TMP_PREFIX = { IPV4: FELIX_PFX+"tmp-v4-", IPV6: FELIX_PFX+"tmp-v6-" }


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

        # Main index self.ip_owners_by_tag[tag][ip] == set([endpoint_id])
        self.ip_owners_by_tag = defaultdict(lambda: defaultdict(set))
        # And the actual ip memberships
        self.ips_in_tag = defaultdict(set)

        self.endpoint_ids_by_profile_id = defaultdict(set)

    def _create(self, tag_id):
        # Create the ActiveIpset, and put a message on the queue that will
        # trigger it to update the ipset as soon as it starts. Note that we do
        # this now so that it is sure to be processed with the first batch even
        # if other messages are arriving.
        active_ipset = ActiveIpset(futils.uniquely_shorten(tag_id, 16),
                                   self.ip_type)
        members = self.ips_in_tag.get(tag_id, set())
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
        _log.info("Applying tags snapshot. %s tags, %s endpoints",
                  len(tags_by_prof_id), len(endpoints_by_id))
        missing_profile_ids = set(self.tags_by_prof_id.keys())
        for profile_id, tags in tags_by_prof_id.iteritems():
            assert tags is not None
            self.on_tags_update(profile_id, tags)
            missing_profile_ids.discard(profile_id)
            self._maybe_yield()
        for profile_id in missing_profile_ids:
            self.on_tags_update(profile_id, None)
            self._maybe_yield()
        del missing_profile_ids
        missing_endpoints = set(self.endpoints_by_ep_id.keys())
        for endpoint_id, endpoint in endpoints_by_id.iteritems():
            assert endpoint is not None
            self.on_endpoint_update(endpoint_id, endpoint)
            missing_endpoints.discard(endpoint_id)
            self._maybe_yield()
        for ep_id in missing_endpoints:
            self.on_endpoint_update(ep_id, None)
            self._maybe_yield()
        _log.info("Tags snapshot applied: %s tags, %s endpoints",
                  len(tags_by_prof_id), len(endpoints_by_id))

    @actor_message()
    def cleanup(self):
        """
        Clean up left-over ipsets that existed at start-of-day.
        """
        _log.info("Cleaning up left-over ipsets.")
        all_ipsets = list_ipset_names()
        # only clean up our own rubbish.
        pfx = IPSET_PREFIX[self.ip_type]
        tmppfx = IPSET_TMP_PREFIX[self.ip_type]
        felix_ipsets = set([n for n in all_ipsets if n.startswith(pfx) or
                                                     n.startswith(tmppfx)])
        whitelist = set()
        for ipset in (self.objects_by_id.values() +
                      self.stopping_objects_by_id.values()):
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

    def _extract_ips(self, endpoint):
        if endpoint is None:
            return set()
        return set(map(futils.net_to_ip,
                       endpoint.get(self.nets_key, [])))

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
        for endpoint_id in endpoint_ids:
            endpoint = self.endpoints_by_ep_id.get(endpoint_id, {})
            for tag_id in removed_tags:
                for ip in self._extract_ips(endpoint):
                    removed = self._remove_mapping(tag_id, endpoint_id, ip)
                    if removed and self._is_starting_or_live(tag_id):
                        _log.debug("Removing IP %s from tag %s", ip, tag_id)
                        self.objects_by_id.remove_member(ip)
            for tag_id in added_tags:
                for ip in self._extract_ips(endpoint):
                    added = self._add_mapping(tag_id, endpoint_id, ip)
                    if added and self._is_starting_or_live(tag_id):
                        _log.debug("Adding IP %s to tag %s", ip, tag_id)
                        self.objects_by_id.add_member(ip)

    @actor_message()
    def on_endpoint_update(self, endpoint_id, endpoint):
        old_endpoint = self.endpoints_by_ep_id.get(endpoint_id, {})
        old_prof_id = old_endpoint.get("profile_id")
        if old_prof_id:
            old_tags = set(self.tags_by_prof_id.get(old_prof_id, []))
        else:
            old_tags = set()

        if endpoint is None:
            new_tags = set()
            new_prof_id = None
        else:
            new_prof_id = endpoint.get["profile_id"]
            new_tags = self.tags_by_prof_id.get(new_prof_id, set())

        if new_prof_id != old_prof_id:
            self._remove_profile_index(old_prof_id, endpoint_id)
            self._add_profile_index(new_prof_id, endpoint_id)

        added_tags = new_tags - old_tags
        unchanged_tags = new_tags & old_tags
        removed_tags = old_tags - new_tags

        old_ips = self._extract_ips(old_endpoint)
        new_ips = self._extract_ips(endpoint)

        removed_ips_by_tag = defaultdict(set)
        added_ips_by_tag = defaultdict(set)

        # Remove *old* IPs from removed tags.
        for tag in removed_tags:
            for ip in old_ips:
                ip_removed = self._remove_mapping(tag, endpoint_id, ip)
                if ip_removed:
                    removed_ips_by_tag[tag].add(ip)
        # Change IPs in unchanged tags.
        added_ips = new_ips - old_ips
        removed_ips = old_ips - new_ips
        for tag in unchanged_tags:
            for ip in removed_ips:
                ip_removed = self._remove_mapping(tag, endpoint_id, ip)
                if ip_removed:
                    removed_ips_by_tag[tag].add(ip)
            for ip in added_ips:
                ip_added = self._add_mapping(tag, endpoint_id, ip)
                if ip_added:
                    added_ips_by_tag[tag].add(ip)
        # Add *new* IPs to new tags.
        for tag in added_tags:
            for ip in new_ips:
                ip_added = self._add_mapping(tag, endpoint_id, ip)
                if ip_added:
                    added_ips_by_tag[tag].add(ip)

        # Pass updates to the active ipsets.
        for tag, ip in removed_ips_by_tag.iteritems():
            if self._is_starting_or_live(tag):
                self.objects_by_id[tag].remove_member(ip)
        for tag, ip in added_ips_by_tag.iteritems():
            if self._is_starting_or_live(tag):
                self.objects_by_id[tag].add_member(ip)

        _log.info("Endpoint update complete")

    def _remove_mapping(self, tag_id, endpoint_id, ip_address):
        """
        Removes the given tag->endpoint->IP mapping from the
        ip_owners_by_tag and ips_in_tag indexes.
        :return: True if the update resulted in removing that IP from the tag.
        """
        ep_ids = self.ip_owners_by_tag[tag_id][ip_address]
        ep_ids.discard(endpoint_id)
        ip_removed = False
        if not ep_ids and ip_address in self.ips_in_tag:
            self.ips_in_tag[tag_id].discard(ip_address)
            del self.ip_owners_by_tag[tag_id][ip_address]
            ip_removed = True
        return ip_removed

    def _add_mapping(self, tag_id, endpoint_id, ip_address):
        """
        Add the given tag->endpoint->IP mapping to the
        ip_owners_by_tag and ips_in_tag indexes.
        :return: True if the IP wasn't already in that tag.
        """
        ep_ids = self.ip_owners_by_tag[tag_id][ip_address]
        ip_added = not bool(ep_ids)
        ep_ids.add(endpoint_id)
        self.ips_in_tag[tag_id].add(ip_address)
        return ip_added

    def _remove_profile_index(self, prof_id, endpoint_id):
        if prof_id is None:
            return
        endpoints = self.endpoint_ids_by_profile_id[prof_id]
        endpoints.discard(endpoint_id)
        if not endpoints:
            _log.debug("No more endpoints use profile %s", prof_id)
            del self.endpoint_ids_by_profile_id[prof_id]

    def _add_profile_index(self, prof_id, endpoint_id):
        if prof_id is None:
            return
        self.endpoint_ids_by_profile_id[prof_id].add(endpoint_id)

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

        # Notified ready?
        self.notified_ready = False
        self.stopped = False

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
        # Mark the object as stopped so that we don't accidentally recreate
        # the ipset in _finish_msg_batch.
        self.stopped = True
        try:
            # Destroy the ipsets - ignoring any errors.
            _log.debug("Delete ipsets %s and %s if they exist",
                       self.name, self.tmpname)
            futils.call_silent(["ipset", "destroy", self.name])
            futils.call_silent(["ipset", "destroy", self.tmpname])
        finally:
            self._notify_cleanup_complete()

    def _finish_msg_batch(self, batch, results):
        # No need to combine members of the batch (although we could). None of
        # the add_members / remove_members / replace_members calls actually
        # does any work, just updating state. The _finish_msg_batch call will
        # then program the real changes.
        if not self.stopped and self.members != self.programmed_members:
            self._sync_to_ipset()

        if not self.notified_ready:
            # We have created the set, so we are now ready.
            self.notified_ready = True
            self._notify_ready()

    def _sync_to_ipset(self):
        _log.debug("Setting ipset %s to %s", self.name, self.members)

        # We use ipset restore, which processes a batch of ipset updates.
        # The only operation that we're sure is atomic is swapping two ipsets
        # so we build up the complete set of members in a temporary ipset,
        # swap it into place and then delete the old ipset.
        create_cmd = "create %s hash:ip family %s --exist"
        input_lines = [
            # Ensure both the main set and the temporary set exist.
            create_cmd % (self.name, self.family),
            create_cmd % (self.tmpname, self.family),

            # Flush the temporary set.  This is a no-op unless we had a
            # left-over temporary set before.
            "flush %s" % self.tmpname,
        ]
        # Add all the members to the temporary set,
        input_lines += ["add %s %s" % (self.tmpname, m) for m in self.members]
        # Then, atomically swap the temporary set into place.
        input_lines.append("swap %s %s" % (self.name, self.tmpname))
        # Finally, delete the temporary set (which was the old active set).
        input_lines.append("destroy %s" % self.tmpname)
        # COMMIT tells ipset restore to actually execute the changes.
        input_lines.append("COMMIT")

        input_str = "\n".join(input_lines) + "\n"
        futils.check_call(["ipset", "restore"], input_str=input_str)

        # We have got the set into the correct state.
        self.programmed_members = self.members.copy()

    def __str__(self):
        return self.__class__.__name__ + "<queue_len=%s,live=%s,msg=%s," \
                                         "name=%s,id=%s>" % (
            self._event_queue.qsize(),
            bool(self.greenlet),
            self._current_msg,
            self.name,
            self._id,
        )


def tag_to_ipset_name(ip_type, tag, tmp=False):
    """
    Turn a (possibly shortened) tag ID into an ipset name.
    """
    if not tmp:
        name = IPSET_PREFIX[ip_type] + tag
    else:
        name = IPSET_TMP_PREFIX[ip_type] + tag
    return name


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
