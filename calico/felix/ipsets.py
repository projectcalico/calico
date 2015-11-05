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
from itertools import chain
import logging

from calico.felix import futils
from calico.felix.futils import IPV4, IPV6, FailedSystemCall
from calico.felix.actor import actor_message, Actor
from calico.felix.refcount import ReferenceManager, RefCountedActor

_log = logging.getLogger(__name__)

FELIX_PFX = "felix-"
IPSET_PREFIX = {IPV4: FELIX_PFX+"v4-", IPV6: FELIX_PFX+"v6-"}
IPSET_TMP_PREFIX = {IPV4: FELIX_PFX+"tmp-v4-", IPV6: FELIX_PFX+"tmp-v6-"}
DEFAULT_IPSET_SIZE = 2**20


class IpsetManager(ReferenceManager):
    def __init__(self, ip_type, config):
        """
        Manages all the ipsets for tags for either IPv4 or IPv6.

        :param ip_type: IP type (IPV4 or IPV6)
        """
        super(IpsetManager, self).__init__(qualifier=ip_type)

        self.ip_type = ip_type
        self._config = config

        # State.
        # Tag IDs indexed by profile IDs
        self.tags_by_prof_id = {}
        # EndpointData "structs" indexed by EndpointId.
        self.endpoint_data_by_ep_id = {}

        # Main index.  Since an IP address can be assigned to multiple
        # endpoints, we need to track which endpoints reference an IP.  When
        # we find the set of endpoints with an IP is empty, we remove the
        # ip from the tag.
        # ip_owners_by_tag[tag][ip] = set([(profile_id, combined_id),
        #                                  (profile_id, combined_id2), ...]) |
        #                             (profile_id, combined_id)
        # Here "combined_id" is an EndpointId object.
        self.ip_owners_by_tag = defaultdict(lambda: defaultdict(lambda: None))

        # Set of EndpointId objects referenced by profile IDs.
        self.endpoint_ids_by_profile_id = defaultdict(set)

        # Set of tag IDs that may be out of sync. Accumulated by the
        # index-update functions. We apply the updates in _finish_msg_batch().
        # May include non-live tag IDs.
        self._dirty_tags = set()
        self._datamodel_in_sync = False

    def _create(self, tag_id):
        active_ipset = TagIpset(futils.uniquely_shorten(tag_id, 16),
                                self.ip_type,
                                max_elem=self._config.MAX_IPSET_SIZE)
        return active_ipset

    def _maybe_start(self, obj_id):
        if self._datamodel_in_sync:
            _log.debug("Datamodel is in-sync, deferring to superclass.")
            return super(IpsetManager, self)._maybe_start(obj_id)
        else:
            _log.info("Delaying startup of tag %s because datamodel is"
                      "not in sync.", obj_id)

    def _on_object_started(self, tag_id, active_ipset):
        _log.debug("TagIpset actor for %s started", tag_id)
        # Fill the ipset in with its members, this will trigger its first
        # programming, after which it will call us back to tell us it is ready.
        # We can't use self._dirty_tags to defer this in case the set becomes
        # unreferenced before _finish_msg_batch() is called.
        self._update_active_ipset(tag_id)

    def _update_active_ipset(self, tag_id):
        """
        Replaces the members of the identified TagIpset with the
        current set.

        :param tag_id: The ID of the tag, must be an active tag.
        """
        assert self._is_starting_or_live(tag_id)
        assert self._datamodel_in_sync
        active_ipset = self.objects_by_id[tag_id]
        members = frozenset(self.ip_owners_by_tag.get(tag_id, {}).iterkeys())
        active_ipset.replace_members(members, async=True)

    def _update_dirty_active_ipsets(self):
        """
        Updates the members of any live ActiveIpsets that are marked dirty.

        Clears the set of dirty tags as a side-effect.
        """
        num_updates = 0
        for tag_id in self._dirty_tags:
            if self._is_starting_or_live(tag_id):
                self._update_active_ipset(tag_id)
                num_updates += 1
            self._maybe_yield()
        if num_updates > 0:
            _log.info("Sent updates to %s updated tags", num_updates)
        self._dirty_tags.clear()

    @property
    def nets_key(self):
        nets = "ipv4_nets" if self.ip_type == IPV4 else "ipv6_nets"
        return nets

    @actor_message()
    def on_datamodel_in_sync(self):
        if not self._datamodel_in_sync:
            _log.info("Datamodel now in sync, uncorking updates to TagIpsets")
            self._datamodel_in_sync = True
            self._maybe_start_all()

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
        felix_ipsets = set([n for n in all_ipsets if (n.startswith(pfx) or
                                                      n.startswith(tmppfx))])
        whitelist = set()
        live_ipsets = self.objects_by_id.itervalues()
        # stopping_objects_by_id is a dict of sets of TagIpset objects,
        # chain them together.
        stopping_ipsets = chain.from_iterable(
            self.stopping_objects_by_id.itervalues())
        for ipset in chain(live_ipsets, stopping_ipsets):
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
        Called when the tag list of the given profile has changed or been
        deleted.

        Updates the indices and notifies any live TagIpset objects of any
        any changes that affect them.

        :param str profile_id: Profile ID affected.
        :param list[str]|NoneType tags: List of tags for the given profile or
            None if deleted.
        """
        _log.info("Tags for profile %s updated", profile_id)

        # General approach is to default to the empty list if the new/old
        # tag list is missing; then add/delete falls out: all the tags will
        # end up in added_tags/removed_tags.
        old_tags = set(self.tags_by_prof_id.get(profile_id, []))
        new_tags = set(tags or [])
        # Find the endpoints that use these tags and work out what tags have
        # been added/removed.
        endpoint_ids = self.endpoint_ids_by_profile_id.get(profile_id, set())
        added_tags = new_tags - old_tags
        removed_tags = old_tags - new_tags
        _log.debug("Endpoint IDs with this profile: %s", endpoint_ids)
        _log.debug("Profile %s added tags: %s", profile_id, added_tags)
        _log.debug("Profile %s removed tags: %s", profile_id, removed_tags)

        for endpoint_id in endpoint_ids:
            endpoint = self.endpoint_data_by_ep_id.get(endpoint_id,
                                                       EMPTY_ENDPOINT_DATA)
            ip_addrs = endpoint.ip_addresses
            for tag_id in removed_tags:
                for ip in ip_addrs:
                    self._remove_mapping(tag_id, profile_id, endpoint_id, ip)
            for tag_id in added_tags:
                for ip in ip_addrs:
                    self._add_mapping(tag_id, profile_id, endpoint_id, ip)

        if tags is None:
            _log.info("Tags for profile %s deleted", profile_id)
            self.tags_by_prof_id.pop(profile_id, None)
        else:
            self.tags_by_prof_id[profile_id] = tags

    @actor_message()
    def on_endpoint_update(self, endpoint_id, endpoint):
        """
        Update tag memberships and indices with the new endpoint dict.

        :param EndpointId endpoint_id: ID of the endpoint.
        :param dict|NoneType endpoint: Either a dict containing endpoint
            information or None to indicate deletion.

        """
        endpoint_data = self._endpoint_data_from_dict(endpoint_id, endpoint)
        self._on_endpoint_data_update(endpoint_id, endpoint_data)

    def _endpoint_data_from_dict(self, endpoint_id, endpoint_dict):
        """
        Convert the endpoint dict, which may be large, into a struct-like
        object in order to save occupancy.

        As an optimization, if the endpoint doesn't contain any data relevant
        to this manager, returns EMPTY_ENDPOINT_DATA.

        :param dict|None endpoint_dict: The data model endpoint dict or None.
        :return: An EndpointData object containing the data. If the input
            was None, EMPTY_ENDPOINT_DATA is returned.
        """
        if endpoint_dict is not None:
            profile_ids = endpoint_dict.get("profile_ids", [])
            nets_list = endpoint_dict.get(self.nets_key, [])
            if profile_ids and nets_list:
                # Optimization: only return an object if this endpoint makes
                # some contribution to the IP addresses in the tags.
                ips = map(futils.net_to_ip, nets_list)
                return EndpointData(profile_ids, ips)
            else:
                _log.debug("Endpoint makes no contribution, "
                           "treating as missing: %s", endpoint_id)
        return EMPTY_ENDPOINT_DATA

    def _on_endpoint_data_update(self, endpoint_id, endpoint_data):
        """
        Update tag memberships and indices with the new EndpointData
        object.

        :param EndpointId endpoint_id: ID of the endpoint.
        :param EndpointData endpoint_data: An EndpointData object
            EMPTY_ENDPOINT_DATA to indicate deletion (or endpoint being
            optimized out).

        """
        # Endpoint updates are the most complex to handle because they may
        # change the profile IDs (and hence the set of tags) as well as the
        # ip addresses attached to the interface.  In addition, the endpoint
        # may or may not have existed before.
        #
        # General approach: force all the possibilities through the same
        # update loops by defaulting values.  For example, if there was no
        # previous endpoint then we default old_tags to the empty set.  Then,
        # when we calculate removed_tags, we'll get the empty set and the
        # removal loop will be skipped.
        old_endpoint = self.endpoint_data_by_ep_id.pop(endpoint_id,
                                                       EMPTY_ENDPOINT_DATA)
        old_prof_ids = old_endpoint.profile_ids
        old_tags = set()
        for profile_id in old_prof_ids:
            for tag in self.tags_by_prof_id.get(profile_id, []):
                old_tags.add((profile_id, tag))

        if endpoint_data != EMPTY_ENDPOINT_DATA:
            # EMPTY_ENDPOINT_DATA represents a deletion (or that the endpoint
            # has been optimized out earlier in the pipeline).  Only store
            # off real endpoints.
            _log.debug("Endpoint %s updated", endpoint_id)
            self.endpoint_data_by_ep_id[endpoint_id] = endpoint_data

        new_prof_ids = endpoint_data.profile_ids
        new_tags = set()
        for profile_id in new_prof_ids:
            for tag in self.tags_by_prof_id.get(profile_id, []):
                new_tags.add((profile_id, tag))

        if new_prof_ids != old_prof_ids:
            # Profile ID changed, or an add/delete.  the _xxx_profile_index
            # methods ignore profile_id == None so we'll do the right thing.
            _log.debug("Profile IDs changed from %s to %s",
                       old_prof_ids, new_prof_ids)
            self._remove_profile_index(old_prof_ids, endpoint_id)
            self._add_profile_index(new_prof_ids, endpoint_id)

        # Since we've defaulted new/old_tags to set() if needed, we can
        # use set operations to calculate the tag changes.
        added_tags = new_tags - old_tags
        unchanged_tags = new_tags & old_tags
        removed_tags = old_tags - new_tags

        # These default to set() if there are no IPs.
        old_ips = old_endpoint.ip_addresses
        new_ips = endpoint_data.ip_addresses

        # Add *new* IPs to new tags.  On a deletion, added_tags will be empty.
        # Do this first to avoid marking ipsets as dirty if an endpoint moves
        # from one profile to another but keeps the same tag.
        for profile_id, tag in added_tags:
            for ip in new_ips:
                self._add_mapping(tag, profile_id,  endpoint_id, ip)
        # Change IPs in unchanged tags.
        added_ips = new_ips - old_ips
        removed_ips = old_ips - new_ips
        for profile_id, tag in unchanged_tags:
            for ip in removed_ips:
                self._remove_mapping(tag, profile_id,  endpoint_id, ip)
            for ip in added_ips:
                self._add_mapping(tag, profile_id,  endpoint_id, ip)
        # Remove *all* *old* IPs from removed tags.  For a deletion, only this
        # loop will fire.
        for profile_id, tag in removed_tags:
            for ip in old_ips:
                self._remove_mapping(tag, profile_id, endpoint_id, ip)

    def _add_mapping(self, tag_id, profile_id, endpoint_id, ip_address):
        """
        Adds the given tag->IP->profile->endpoint mapping to the index.
        Marks the tag as dirty if the update resulted in the IP being
        newly added.

        :param str tag_id: Tag ID
        :param str profile_id: Profile ID
        :param EndpointId endpoint_id: ID of the endpoint
        :param str ip_address: IP address to add
        """
        ip_added = not bool(self.ip_owners_by_tag[tag_id][ip_address])
        owners = self.ip_owners_by_tag[tag_id][ip_address]
        new_mapping = (profile_id, endpoint_id)
        if not owners:
            self.ip_owners_by_tag[tag_id][ip_address] = new_mapping
        elif isinstance(owners, set):
            owners.add(new_mapping)
        else:
            self.ip_owners_by_tag[tag_id][ip_address] = set([
                owners,
                new_mapping
            ])

        if ip_added:
            self._dirty_tags.add(tag_id)

    def _remove_mapping(self, tag_id, profile_id, endpoint_id, ip_address):
        """
        Removes the tag->IP->profile->endpoint mapping from index.
        Marks the tag as dirty if the update resulted in the IP being
        removed.

        :param str tag_id: Tag ID
        :param str profile_id: Profile ID
        :param EndpointId endpoint_id: ID of the endpoint
        :param str ip_address: IP address to remove
        """
        owners = self.ip_owners_by_tag[tag_id][ip_address]
        removed_mapping = (profile_id, endpoint_id)
        if owners == removed_mapping:
            # This was the sole owner of the IP in the tag, remove it.
            _log.debug("%s was sole owner of IP %s, IP no longer in tag",
                       removed_mapping, ip_address)
            del self.ip_owners_by_tag[tag_id][ip_address]
            if not self.ip_owners_by_tag[tag_id]:
                _log.debug("Tag %s now empty, removing", tag_id)
                del self.ip_owners_by_tag[tag_id]
            self._dirty_tags.add(tag_id)
        elif isinstance(owners, set):
            assert len(owners) != 1, ("ip_owners_by_tag entry should never "
                                      "be a set with 1 entry")
            _log.debug("Tag %s still contains IP %s", tag_id, ip_address)
            owners.discard(removed_mapping)
            if len(owners) == 1:
                _log.debug("IP %s now only has one owner, replacing set with "
                           "single tuple", ip_address)
                self.ip_owners_by_tag[tag_id][ip_address] = owners.pop()

    def _add_profile_index(self, prof_ids, endpoint_id):
        """
        Notes in the index that an endpoint uses the given profiles.

        :param set[str] prof_ids: set of profile IDs that the endpoint is in.
        :param EndpointId endpoint_id: ID of the endpoint
        """
        for prof_id in prof_ids:
            self.endpoint_ids_by_profile_id[prof_id].add(endpoint_id)

    def _remove_profile_index(self, prof_ids, endpoint_id):
        """
        Notes in the index that an endpoint no longer uses any of the
        given profiles.

        :param set[str] prof_ids: set of profile IDs to remove the endpoint
            from.
        :param EndpointId endpoint_id: ID of the endpoint
        """
        for prof_id in prof_ids:
            endpoints = self.endpoint_ids_by_profile_id[prof_id]
            endpoints.discard(endpoint_id)
            if not endpoints:
                _log.debug("No more endpoints use profile %s", prof_id)
                del self.endpoint_ids_by_profile_id[prof_id]

    def _finish_msg_batch(self, batch, results):
        """
        Called after a batch of messages is finished, processes any
        pending TagIpset member updates.

        Doing that here allows us to lots of updates into one replace
        operation.  It also avoid wasted effort if tags are flapping.
        """
        super(IpsetManager, self)._finish_msg_batch(batch, results)
        self._update_dirty_active_ipsets()


class EndpointData(object):
    """
    Space-efficient read-only 'struct' to hold only the endpoint data
    that we need.
    """
    __slots__ = ["_profile_ids", "_ip_addresses"]

    def __init__(self, profile_ids, ip_addresses):
        """
        :param sequence profile_ids: The profile IDs for the endpoint.
        :param sequence ip_addresses: IP addresses for the endpoint.
        """
        # Note: profile IDs are ordered in the data model but the ipsets
        # code doesn't care about the ordering so it's safe to sort these here
        # for comparison purposes.
        self._profile_ids = tuple(sorted(profile_ids))
        self._ip_addresses = tuple(sorted(ip_addresses))

    @property
    def profile_ids(self):
        """:returns set[str]: profile IDs."""
        # Generate set on demand to keep occupancy down.  250B overhead for a
        # set vs 64 for a tuple.
        return set(self._profile_ids)

    @property
    def ip_addresses(self):
        """:returns set[str]: IP addresses."""
        # Generate set on demand to keep occupancy down.  250B overhead for a
        # set vs 64 for a tuple.
        return set(self._ip_addresses)

    def __repr__(self):
        return self.__class__.__name__ + "(%s,%s)" % (self._profile_ids,
                                                      self._ip_addresses)

    def __eq__(self, other):
        if other is self:
            return True
        if not isinstance(other, EndpointData):
            return False
        return (other._profile_ids == self._profile_ids and
                other._ip_addresses == self._ip_addresses)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self._profile_ids) + hash(self._ip_addresses)


EMPTY_ENDPOINT_DATA = EndpointData([], [])


class IpsetActor(Actor):
    """
    Actor managing a single ipset.

    Batches up updates to minimise the number of actual dataplane updates.
    """

    def __init__(self, ipset, qualifier=None):
        """
        :param Ipset ipset: Ipset object to wrap.
        :param str qualifier: Actor qualifier string for logging.
        """
        super(IpsetActor, self).__init__(qualifier=qualifier)

        self._ipset = ipset
        # Members - which entries should be in the ipset.  None means
        # "unknown", but this is updated immediately on actor startup.
        self.members = None
        # Members which really are in the ipset; again None means "unknown".
        self.programmed_members = None

        self._force_reprogram = True
        self.stopped = False

    @property
    def ipset_name(self):
        """
        The name of the primary ipset.  Safe to access from another greenlet;
        only accesses immutable state.
        """
        return self._ipset.set_name

    def owned_ipset_names(self):
        """
        This method is safe to call from another greenlet; it only accesses
        immutable state.

        :return: set of name of ipsets that this Actor owns and manages.  the
                 sets may or may not be present.
        """
        return set([self._ipset.set_name, self._ipset.temp_set_name])

    @actor_message()
    def replace_members(self, members, force_reprogram=False):
        """
        Replace the members of this ipset with the supplied set.

        :param set[str] members: IP address strings. Must be a copy
        (as this routine keeps a link to it).
        """
        _log.info("Replacing members of ipset %s", self.name)
        self.members = members
        self._force_reprogram |= force_reprogram

    def _finish_msg_batch(self, batch, results):
        _log.debug("IpsetActor._finish_msg_batch() called")
        if not self.stopped:
            self._sync_to_ipset()

    def _sync_to_ipset(self):
        if len(self.members) > self._ipset.max_elem:
            _log.error("ipset %s exceeds maximum size %s.  ipset will not"
                       "be updated until size drops below %s.",
                       self.ipset_name, self._ipset.max_elem,
                       self._ipset.max_elem)
            return
        # Defer to our helper to actually make the changes.
        if self._force_reprogram:
            _log.debug("Replacing content of ipset %s with %s", self,
                       self.members)
            self._ipset.replace_members(self.members)
        elif self.programmed_members != self.members:
            assert self.programmed_members is not None
            _log.debug("Updating ipset %s to %s", self, self.members)
            self._ipset.update_members(self.programmed_members, self.members)
        else:
            _log.debug("Ipset %s already in correct state", self)

        # Now in correct state, with programmed_members matching members, and
        # no need for a forced reprogram.
        self.programmed_members = self.members
        self._force_reprogram = False


class TagIpset(IpsetActor, RefCountedActor):
    """
    Specialised, RefCountedActor managing a single tag's ipset.
    """

    def __init__(self, tag, ip_type, max_elem=DEFAULT_IPSET_SIZE):
        """
        :param str tag: Name of tag that this ipset represents.  Note: not
            the name of the ipset itself.  The name of the ipset is derived
            from this value.
        :param ip_type: One of the constants, futils.IPV4 or futils.IPV6
        """
        self.tag = tag
        name = tag_to_ipset_name(ip_type, tag)
        tmpname = tag_to_ipset_name(ip_type, tag, tmp=True)
        family = "inet" if ip_type == IPV4 else "inet6"
        # Helper class, used to do atomic rewrites of ipsets.
        ipset = Ipset(name, tmpname, family, "hash:ip", max_elem=max_elem)
        super(TagIpset, self).__init__(ipset, qualifier=tag)

        # Notified ready?
        self.notified_ready = False

    @actor_message()
    def on_unreferenced(self):
        # Mark the object as stopped so that we don't accidentally recreate
        # the ipset in _finish_msg_batch.
        self.stopped = True
        try:
            self._ipset.delete()
        finally:
            self._notify_cleanup_complete()

    def _finish_msg_batch(self, batch, results):
        _log.debug("_finish_msg_batch on TagIpset")
        super(TagIpset, self)._finish_msg_batch(batch, results)
        if not self.notified_ready:
            # We have created the set, so we are now ready.
            _log.debug("TagIpset _finish_msg_batch notifying ready")
            self.notified_ready = True
            self._notify_ready()


class Ipset(object):
    """
    (Synchronous) wrapper around an ipset, supporting atomic rewrites.
    """
    def __init__(self, ipset_name, temp_ipset_name, ip_family,
                 ipset_type="hash:ip", max_elem=DEFAULT_IPSET_SIZE):
        """
        :param str ipset_name: name of the primary ipset.  Must be less than
            32 chars.
        :param str temp_ipset_name: name of a secondary, temporary ipset to
            use when doing an atomic rewrite.  Must be less than 32 chars.
        """
        assert len(ipset_name) < 32
        assert len(temp_ipset_name) < 32
        self.set_name = ipset_name
        self.temp_set_name = temp_ipset_name
        self.type = ipset_type
        assert ip_family in ("inet", "inet6")
        self.family = ip_family
        self.max_elem = max_elem

    def exists(self, temp_set=False):
        try:
            futils.check_call(
                ["ipset", "list",
                 self.temp_set_name if temp_set else self.set_name]
            )
        except FailedSystemCall as e:
            if e.retcode == 1 and "does not exist" in e.stderr:
                return False
            else:
                _log.exception("Failed to check if ipset exists")
                raise
        else:
            return True

    def ensure_exists(self):
        """
        Creates the ipset iff it does not exist.

        Leaves the set and its contents untouched if it already exists.
        """
        input_lines = [self._create_cmd(self.set_name)]
        self._exec_and_commit(input_lines)

    def update_members(self, old_members, new_members):
        """
        Update the ipset with changes to members. The set must exist.
        """
        assert len(new_members) <= self.max_elem
        try:
            input_lines = ["del %s %s" % (self.set_name, m)
                           for m in (old_members - new_members)]
            input_lines += ["add %s %s" % (self.set_name, m)
                            for m in (new_members - old_members)]
            _log.info("Making %d changes (new size %d) to ipset %s",
                      len(input_lines), len(new_members), self.set_name)
            self._exec_and_commit(input_lines)
        except FailedSystemCall as err:
            # An error; log it and try nuking the ipset to continue.
            _log.error("Failed to update ipset %s (%s) - retrying",
                       self.set_name, err.stderr)
            self.replace_members(new_members)

    def replace_members(self, members):
        """
        Atomically rewrites the ipset with the new members.

        Creates the set if it does not exist.
        """
        # We use ipset restore, which processes a batch of ipset updates.
        # The only operation that we're sure is atomic is swapping two ipsets
        # so we build up the complete set of members in a temporary ipset,
        # swap it into place and then delete the old ipset.
        _log.info("Rewriting ipset %s with %d members", self, len(members))
        assert len(members) <= self.max_elem
        # Try to destroy the temporary set so that we get to recreate it below,
        # possibly with new parameters.
        if futils.call_silent(["ipset", "destroy", self.temp_set_name]) != 0:
            if self.exists(temp_set=True):
                _log.error("Failed to delete temporary ipset %s.  Subsequent "
                           "commands may fail.",
                           self.temp_set_name)
        if not self.exists():
            # Ensure the main set exists so we can re-use the atomic swap
            # code below.
            _log.debug("Main set doesn't exist, creating it...")
            input_lines = [self._create_cmd(self.set_name)]
        else:
            # Avoid trying to create the main set in case we try to create it
            # with differing parameters (which fails even with the --exist
            # flag).
            _log.debug("Main set exists, skipping create.")
            input_lines = []
        input_lines += [
            # Ensure the temporary set exists.
            self._create_cmd(self.temp_set_name),
            # Flush the temporary set.  This is a no-op unless we failed to
            # delete the set above.
            "flush %s" % self.temp_set_name,
        ]
        # Add all the members to the temporary set,
        input_lines += ["add %s %s" % (self.temp_set_name, m)
                        for m in members]
        # Then, atomically swap the temporary set into place.
        input_lines.append("swap %s %s" % (self.set_name, self.temp_set_name))
        # Finally, delete the temporary set (which was the old active set).
        input_lines.append("destroy %s" % self.temp_set_name)
        # COMMIT tells ipset restore to actually execute the changes.
        self._exec_and_commit(input_lines)

    def _exec_and_commit(self, input_lines):
        """
        Executes the the given lines of "ipset restore" input and
        follows them with a COMMIT call.
        """
        input_lines.append("COMMIT")
        input_str = "\n".join(input_lines) + "\n"
        futils.check_call(["ipset", "restore"], input_str=input_str)

    def _create_cmd(self, name):
        """
        :returns an ipset restore line to create the given ipset iff it
            doesn't exist.
        """
        return ("create %s %s family %s maxelem %s --exist" %
                (name, self.type, self.family, self.max_elem))

    def delete(self):
        """
        Deletes the ipsets.  This is done on a best-effort basis.
        """
        _log.debug("Delete ipsets %s and %s if they exist",
                   self.set_name, self.temp_set_name)
        futils.call_silent(["ipset", "destroy", self.set_name])
        futils.call_silent(["ipset", "destroy", self.temp_set_name])


# For IP-in-IP support, a global ipset that contains the IP addresses of all
# the calico hosts.  Only populated when IP-in-IP is enabled and the data is
# in etcd.
HOSTS_IPSET_V4 = Ipset(FELIX_PFX + "calico-hosts-4",
                       FELIX_PFX + "calico-hosts-4-tmp",
                       "inet")


def tag_to_ipset_name(ip_type, tag, tmp=False):
    """
    Turn a (possibly shortened) tag ID into an ipset name.

    :param str ip_type: IP type (IPV4 or IPV6)
    :param str tag: Tag ID
    :param bool tmp: Is this the tmp ipset, or the permanent one?
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

    :returns: List of names of ipsets.
    """
    data = futils.check_call(["ipset", "list"]).stdout
    lines = data.split("\n")

    names = []

    for line in lines:
        words = line.split()
        if len(words) > 1 and words[0] == "Name:":
            names.append(words[1])

    return names
