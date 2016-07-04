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
felix.ipsets
~~~~~~~~~~~~

IP sets management functions.
"""

from collections import defaultdict
from itertools import chain
import logging

from calico.datamodel_v1 import HostEndpointId, WloadEndpointId
from calico.felix import futils
from calico.calcollections import SetDelta
from calico.felix.futils import IPV4, IPV6, FailedSystemCall
from calico.felix.actor import actor_message, Actor
from calico.felix.labels import LabelValueIndex, LabelInheritanceIndex
from calico.felix.refcount import ReferenceManager, RefCountedActor
from calico.felix.selectors import SelectorExpression

_log = logging.getLogger(__name__)

FELIX_PFX = "felix-"
IPSET_PREFIX = {IPV4: FELIX_PFX+"v4-", IPV6: FELIX_PFX+"v6-"}
IPSET_TMP_PREFIX = {IPV4: FELIX_PFX+"tmp-v4-", IPV6: FELIX_PFX+"tmp-v6-"}
DEFAULT_IPSET_SIZE = 2**20
DUMMY_PROFILE = "dummy"

# Number of chars we have left over in the ipset name after we take out the
# "felix-tmp-v4" prefix.
MAX_NAME_LENGTH = 16


class IpsetManager(ReferenceManager):
    # Using a larger batch delay here significantly reduces CPU usage when
    # we're under heavy churn.
    batch_delay = 0.05

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
        # EndpointData "structs" indexed by WloadEndpointId.
        self.endpoint_data_by_ep_id = {}

        # Main index.  Tracks which IPs are currently in each tag.
        self.tag_membership_index = TagMembershipIndex()
        # Take copies of the key functions; avoids messy long lines.
        self._add_mapping = self.tag_membership_index.add_mapping
        self._remove_mapping = self.tag_membership_index.remove_mapping

        # Set of WloadEndpointId objects referenced by profile IDs.
        self.endpoint_ids_by_profile_id = defaultdict(set)

        # LabelNode index, used to cross-reference endpoint labels against
        # selectors.
        self._label_index = LabelValueIndex()
        self._label_index.on_match_started = self._on_label_match_started
        self._label_index.on_match_stopped = self._on_label_match_stopped
        self._label_inherit_idx = LabelInheritanceIndex(self._label_index)
        # Sets used to defer updates of the label match cache until we're ready
        # to handle them.
        self._started_label_matches = set()
        self._stopped_label_matches = set()

        # One-way flag set when we know the datamodel is in sync.  We can't
        # rewrite any ipsets before we're in sync or we risk omitting some
        # values.
        self._datamodel_in_sync = False

    def _create(self, tag_id_or_sel):
        if isinstance(tag_id_or_sel, SelectorExpression):
            _log.debug("Creating ipset for expression %s", tag_id_or_sel)
            sel = tag_id_or_sel
            self._label_index.on_expression_update(sel, sel)
            ipset_name = futils.uniquely_shorten(sel.unique_id,
                                                 MAX_NAME_LENGTH)
            self._process_stopped_label_matches()
            self._process_started_label_matches()
        else:
            _log.debug("Creating ipset for tag %s", tag_id_or_sel)
            ipset_name = futils.uniquely_shorten(tag_id_or_sel,
                                                 MAX_NAME_LENGTH)
        active_ipset = RefCountedIpsetActor(
            ipset_name,
            self.ip_type,
            max_elem=self._config.MAX_IPSET_SIZE
        )
        return active_ipset

    def _maybe_start(self, obj_id):
        if self._datamodel_in_sync:
            _log.debug("Datamodel is in-sync, deferring to superclass.")
            return super(IpsetManager, self)._maybe_start(obj_id)
        else:
            _log.info("Delaying startup of ipset for %s because datamodel is "
                      "not in sync.", obj_id)

    def _on_object_started(self, tag_id, active_ipset):
        _log.debug("RefCountedIpsetActor actor for %s started", tag_id)
        # Fill the ipset in with its members, this will trigger its first
        # programming, after which it will call us back to tell us it is ready.
        # We can't use self._dirty_tags to defer this in case the set becomes
        # unreferenced before _finish_msg_batch() is called.
        assert self._is_starting_or_live(tag_id)
        assert self._datamodel_in_sync
        active_ipset = self.objects_by_id[tag_id]
        members = self.tag_membership_index.members(tag_id)
        active_ipset.replace_members(members, async=True)

    def _update_dirty_active_ipsets(self):
        """
        Updates the members of any live TagIpsets that are dirty.

        Clears the index of dirty TagIpsets as a side-effect.
        """
        tag_index = self.tag_membership_index
        ips_added, ips_removed = tag_index.get_and_reset_changes_by_tag()
        num_updates = 0
        for tag_id, removed_ips in ips_removed.iteritems():
            if self._is_starting_or_live(tag_id):
                assert self._datamodel_in_sync
                active_ipset = self.objects_by_id[tag_id]
                active_ipset.remove_members(removed_ips, async=True)
                num_updates += 1
            self._maybe_yield()
        for tag_id, added_ips in ips_added.iteritems():
            if self._is_starting_or_live(tag_id):
                assert self._datamodel_in_sync
                active_ipset = self.objects_by_id[tag_id]
                active_ipset.add_members(added_ips, async=True)
                num_updates += 1
            self._maybe_yield()
        if num_updates > 0:
            _log.info("Sent %s updates to updated tags", num_updates)

    @property
    def nets_key(self):
        nets = "ipv4_nets" if self.ip_type == IPV4 else "ipv6_nets"
        return nets

    @property
    def expected_ips_key(self):
        key = ("expected_ipv4_addrs" if self.ip_type == IPV4
               else "expected_ipv6_addrs")
        return key

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
        # stopping_objects_by_id is a dict of sets of RefCountedIpsetActor
        # objects, chain them together.
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

        Updates the indices and notifies any live RefCountedIpsetActor
        objects of any changes that affect them.

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
    def on_prof_labels_set(self, profile_id, labels):
        _log.debug("Profile labels updated for %s: %s", profile_id, labels)
        self._label_inherit_idx.on_parent_labels_update(profile_id, labels)
        # Flush the updates.
        self._process_stopped_label_matches()
        self._process_started_label_matches()

    @actor_message()
    def on_host_ep_update(self, combined_id, endpoint):
        """
        Update tag/selector memberships and indices with the new interface
        data dict.

        :param HostEndpointId combined_id: ID of the host endpoint.
        :param dict|NoneType endpoint: Either a dict containing interface
            information or None to indicate deletion.
        """
        # For our purposes, host endpoints are indexed as endpoints.
        assert isinstance(combined_id, HostEndpointId)
        self._on_endpoint_or_host_ep_update(combined_id, endpoint)

    @actor_message()
    def on_endpoint_update(self, endpoint_id, endpoint):
        """
        Update tag/selector memberships and indices with the new endpoint dict.

        :param WloadEndpointId endpoint_id: ID of the endpoint.
        :param dict|NoneType endpoint: Either a dict containing endpoint
            information or None to indicate deletion.
        """
        assert isinstance(endpoint_id, WloadEndpointId)
        self._on_endpoint_or_host_ep_update(endpoint_id, endpoint)

    def _on_endpoint_or_host_ep_update(self, combined_id, data):
        """
        Update tag/selector memberships and indices with the new
        host ep/endpoint dict.

        We care about the labels, profiles and IP addresses.  For host
        endpoints, we include the expected_ipvX_addrs in the IP addresses.

        :param HostEndpointId|WloadEndpointId combined_id: ID of the endpoint.
        :param dict|NoneType data: Either a dict containing endpoint
            information or None to indicate deletion.
        """
        endpoint_data = self._endpoint_data_from_dict(combined_id, data)
        if data and endpoint_data != EMPTY_ENDPOINT_DATA:
            # This endpoint makes a contribution to the IP addresses, we need
            # to index its labels.
            labels = data.get("labels", {})
            prof_ids = data.get("profile_ids", [])
        else:
            labels = None
            prof_ids = None
        # Remove the endpoint from the label index so that we clean up its
        # old IP addresses.
        self._label_inherit_idx.on_item_update(combined_id, None, None)
        self._process_stopped_label_matches()
        # Now update the main cache of endpoint data.
        self._on_endpoint_data_update(combined_id, endpoint_data)
        # And then, if not doing a deletion, add the endpoint back into the
        # label index.
        if labels is not None:
            self._label_inherit_idx.on_item_update(combined_id, labels,
                                                   prof_ids)
            self._process_started_label_matches()

    def _on_label_match_started(self, expr_id, item_id):
        """Callback from the label index to tell us that a match started."""
        _log.debug("SelectorExpression %s now matches %s", expr_id, item_id)
        self._started_label_matches.add((expr_id, item_id))

    def _on_label_match_stopped(self, expr_id, item_id):
        """Callback from the label index to tell us that a match stopped."""
        _log.debug("SelectorExpression %s no longer matches %s",
                   expr_id, item_id)
        self._stopped_label_matches.add((expr_id, item_id))

    def _process_started_label_matches(self):
        for selector, item_id in self._started_label_matches:
            ep_data = self.endpoint_data_by_ep_id[item_id]
            ip_addrs = ep_data.ip_addresses
            _log.debug("Adding %s to expression %s", ip_addrs, selector)
            for ip in ip_addrs:
                self._add_mapping(selector, DUMMY_PROFILE, item_id, ip)
        self._started_label_matches.clear()

    def _process_stopped_label_matches(self):
        for selector, item_id in self._stopped_label_matches:
            ep_data = self.endpoint_data_by_ep_id[item_id]
            for ip in ep_data.ip_addresses:
                self._remove_mapping(selector, DUMMY_PROFILE, item_id, ip)
        self._stopped_label_matches.clear()

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
            nets = endpoint_dict.get(self.nets_key, [])
            ips = map(futils.net_to_ip, nets)
            exp_ips = endpoint_dict.get(self.expected_ips_key, [])

            if ips or exp_ips:
                # Optimization: only return an object if this endpoint makes
                # some contribution to the IP addresses.
                return EndpointData(profile_ids, ips + exp_ips)
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
                self._add_mapping(tag, profile_id, endpoint_id, ip)
        # Change IPs in unchanged tags.
        added_ips = new_ips - old_ips
        removed_ips = old_ips - new_ips
        for profile_id, tag in unchanged_tags:
            for ip in removed_ips:
                self._remove_mapping(tag, profile_id, endpoint_id, ip)
            for ip in added_ips:
                self._add_mapping(tag, profile_id, endpoint_id, ip)
        # Remove *all* *old* IPs from removed tags.  For a deletion, only this
        # loop will fire.
        for profile_id, tag in removed_tags:
            for ip in old_ips:
                self._remove_mapping(tag, profile_id, endpoint_id, ip)

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
        pending RefCountedIpsetActor member updates.

        Doing that here allows us to lots of updates into one replace
        operation.  It also avoid wasted effort if tags are flapping.
        """
        super(IpsetManager, self)._finish_msg_batch(batch, results)
        self._update_dirty_active_ipsets()


class TagMembershipIndex(object):
    """Indexes tag memberships to allow efficient calculation of changes."""
    def __init__(self):
        # Main index.  Since an IP address can be assigned to multiple
        # endpoints, we need to track which endpoints reference an IP.  When
        # we find the set of endpoints with an IP is empty, we remove the
        # ip from the tag.
        # ip_owners_by_tag[tag][ip] = set([(profile_id, combined_id),
        #                                  (profile_id, combined_id2), ...]) |
        #                             (profile_id, combined_id)
        # Here "combined_id" is an WloadEndpointId object.
        self.ip_owners_by_tag = defaultdict(lambda: defaultdict(lambda: None))
        # IPs added and removed since the last reset.
        self.ips_added_by_tag = defaultdict(set)
        self.ips_removed_by_tag = defaultdict(set)

    def add_mapping(self, tag_id, profile_id, endpoint_id, ip_address):
        """
        Adds the given tag->IP->profile->endpoint mapping to the index.
        Marks the tag as dirty if the update resulted in the IP being
        newly added.

        :param str tag_id: Tag ID
        :param str profile_id: Profile ID
        :param EndpointId endpoint_id: ID of the endpoint
        :param str ip_address: IP address to add
        """
        if not self.ip_owners_by_tag[tag_id][ip_address]:
            self._on_ip_added(ip_address, tag_id)
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

    def remove_mapping(self, tag_id, profile_id, endpoint_id, ip_address):
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
            self._on_ip_removed(ip_address, tag_id)
        else:
            assert isinstance(owners, set), (
                "Expected owners of IP %s to be %s or a set but got %s" %
                (ip_address, removed_mapping, owners)
            )
            assert len(owners) > 1, ("ip_owners_by_tag entry should never "
                                     "be a set with <=1 entry")
            assert removed_mapping in owners, (
                "Owners set for IP %s should contain %s" %
                (ip_address, removed_mapping)
            )
            _log.debug("Tag %s still contains IP %s", tag_id, ip_address)
            owners.remove(removed_mapping)
            if len(owners) == 1:
                _log.debug("IP %s now only has one owner, replacing set with "
                           "single tuple", ip_address)
                self.ip_owners_by_tag[tag_id][ip_address] = owners.pop()

    def _on_ip_added(self, ip_address, tag_id):
        """
        Track the addition of an IP address to the given tag.

        Only affects the ips_(added|removed)_by_tag mappings.  An
        addition following a removal cleans up the removal.
        """
        _log.debug("IP %s added to tag %s", ip_address, tag_id)
        # Track the addition.
        self.ips_added_by_tag[tag_id].add(ip_address)
        # The addition invalidates any previous removal; clean that up.
        removed_ips_for_tag = self.ips_removed_by_tag[tag_id]
        removed_ips_for_tag.discard(ip_address)
        if not removed_ips_for_tag:
            del self.ips_removed_by_tag[tag_id]

    def _on_ip_removed(self, ip_address, tag_id):
        """
        Track the removal of an IP address to the given tag.

        Only affects the ips_(added|removed)_by_tag mappings.  A
        removal following an addition cleans up the addition.
        """
        _log.debug("IP %s removed from tag %s", ip_address, tag_id)
        # Track the removal.
        self.ips_removed_by_tag[tag_id].add(ip_address)
        # The addition invalidates any previous addition; clean that up.
        added_ips_for_tag = self.ips_added_by_tag[tag_id]
        added_ips_for_tag.discard(ip_address)
        if not added_ips_for_tag:
            del self.ips_added_by_tag[tag_id]

    def members(self, tag_id):
        members = self.ip_owners_by_tag.get(tag_id, {}).keys()
        return members

    def get_and_reset_changes_by_tag(self):
        """ Get the deltas accumulated since the last reset.
        :return: tuple of two dicts.  The first contains the added IPs by tag,
                 the second contains the removed IPs by tag.
        """
        added_and_removed = self.ips_added_by_tag, self.ips_removed_by_tag
        self.ips_added_by_tag = defaultdict(set)
        self.ips_removed_by_tag = defaultdict(set)
        return added_and_removed


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
        # Members - which entries should be in the ipset.
        self.members = None
        # SetDelta, used to track a sequence of changes.
        self.changes = None

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
    def replace_members(self, members):
        """
        Replace the members of this ipset with the supplied set.

        :param set[str]|list[str] members: The IP address strings.  This
               method takes a copy of the contents.
        """
        _log.info("Replacing members of ipset %s", self.name)
        self.members = set(members)
        self._force_reprogram = True  # Force a full rewrite of the set.
        self.changes = SetDelta(self.members)  # Any changes now obsolete.

    @actor_message()
    def add_members(self, new_members):
        _log.debug("Adding %s to tag ipset %s", new_members, self.name)
        assert self.members is not None, (
            "add_members() called before init by replace_members()"
        )
        for member in new_members:
            self.changes.add(member)

    @actor_message()
    def remove_members(self, removed_members):
        _log.debug("Removing %s from tag ipset %s", removed_members, self.name)
        assert self.members is not None, (
            "remove_members() called before init by replace_members()"
        )
        for member in removed_members:
            self.changes.remove(member)

    def _finish_msg_batch(self, batch, results):
        _log.debug("IpsetActor._finish_msg_batch() called")
        if not self.stopped:
            self._sync_to_ipset()

    def _sync_to_ipset(self):
        _log.debug("Syncing %s to kernel", self.name)
        if self.changes.resulting_size > self._ipset.max_elem:
            _log.error("ipset %s exceeds maximum size %s.  ipset will not "
                       "be updated until size drops below %s.",
                       self.ipset_name, self._ipset.max_elem,
                       self._ipset.max_elem)
            return

        if not self._force_reprogram:
            # Just an incremental update, try to apply it as a delta.
            if not self.changes.empty:
                _log.debug("Normal update, attempting to apply as a delta:"
                           "added=%s, removed=%s", self.changes.added_entries,
                           self.changes.removed_entries)
                try:
                    self._ipset.apply_changes(self.changes.added_entries,
                                              self.changes.removed_entries)
                except FailedSystemCall as e:
                    _log.error("Failed to update ipset %s, attempting to "
                               "do a full rewrite RC=%s, err=%s",
                               self.name, e.retcode, e.stderr)
                    self._force_reprogram = True

        # Either we're now in sync or we're about to try rewriting the ipset
        # as a whole.  Either way, apply the changes to the members set.
        self.changes.apply_and_reset()

        if self._force_reprogram:
            # Initial update or post-failure, completely replace the ipset's
            # contents with an atomic swap.
            _log.debug("Replacing content of ipset %s with %s", self,
                       self.members)
            self._ipset.replace_members(self.members)
            self._force_reprogram = False
        _log.debug("Finished syncing %s to kernel", self.name)


class RefCountedIpsetActor(IpsetActor, RefCountedActor):
    """
    Specialised, RefCountedActor managing a single ipset for a tag or
    selector.
    """

    def __init__(self, name_stem, ip_type, max_elem=DEFAULT_IPSET_SIZE):
        """
        :param str name_stem: ipset name suffix. The name of the ipset is
               derived from this value.
        :param ip_type: One of the constants, futils.IPV4 or futils.IPV6
        """
        self.name_stem = name_stem
        suffix = tag_to_ipset_name(ip_type, name_stem)
        tmpname = tag_to_ipset_name(ip_type, name_stem, tmp=True)
        family = "inet" if ip_type == IPV4 else "inet6"
        # Helper class, used to do atomic rewrites of ipsets.
        ipset = Ipset(suffix, tmpname, family, "hash:ip", max_elem=max_elem)
        super(RefCountedIpsetActor, self).__init__(ipset, qualifier=suffix)

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
        _log.debug("_finish_msg_batch on RefCountedIpsetActor")
        super(RefCountedIpsetActor, self)._finish_msg_batch(batch, results)
        if not self.notified_ready:
            # We have created the set, so we are now ready.
            _log.debug("RefCountedIpsetActor notifying ready")
            self.notified_ready = True
            self._notify_ready()

    def __str__(self):
        return self.__class__.__name__ + "<%s,%s>" % (self._id, self.name)


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

    def apply_changes(self, added_entries, removed_entries):
        """
        Update the ipset with changes to members. The set must exist.

        :raises FailedSystemCall if the update fails.
        """
        input_lines = ["del %s %s" % (self.set_name, m)
                       for m in removed_entries]
        input_lines += ["add %s %s" % (self.set_name, m)
                        for m in added_entries]
        _log.info("Making %d changes to ipset %s",
                  len(input_lines), self.set_name)
        self._exec_and_commit(input_lines)

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
        assert isinstance(members, (set, frozenset))
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
