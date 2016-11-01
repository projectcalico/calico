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

from calico.felix import futils
from calico.calcollections import SetDelta
from calico.felix.futils import IPV4, IPV6, FailedSystemCall
from calico.felix.actor import actor_message, Actor
from calico.felix.refcount import ReferenceManager, RefCountedActor

_log = logging.getLogger(__name__)

FELIX_PFX = "felix-"

# Historic prefixes that any previous version of felix has used, for cleanup
# purposes.
OLD_PREFIXES = {
    IPV4: {"felix-v4-", "felix-tmp-v4-"},
    IPV6: {"felix-v4-", "felix-tmp-v6-"},
}

IPSET_PREFIX = {IPV4: FELIX_PFX+"4-", IPV6: FELIX_PFX+"6-"}
IPSET_TMP_PREFIX = {IPV4: FELIX_PFX+"4t", IPV6: FELIX_PFX+"6t"}

ALL_FELIX_PREFIXES = {
    IPV4: {IPSET_PREFIX[IPV4], IPSET_TMP_PREFIX[IPV4]} | OLD_PREFIXES[IPV4],
    IPV6: {IPSET_PREFIX[IPV6], IPSET_TMP_PREFIX[IPV6]} | OLD_PREFIXES[IPV6],
}

DEFAULT_IPSET_SIZE = 2**20
DUMMY_PROFILE = "dummy"

# Number of chars we have left over in the ipset name after we take out the
# "felix-tmp-v4" prefix.
MAX_NAME_LENGTH = 31 - len(IPSET_TMP_PREFIX[IPV4])


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

        self._pre_calc_ipsets_by_id = defaultdict(set)
        self._pre_calc_added_ips_by_id = defaultdict(set)
        self._pre_calc_removed_ips_by_id = defaultdict(set)

        # One-way flag set when we know the datamodel is in sync.  We can't
        # rewrite any ipsets before we're in sync or we risk omitting some
        # values.
        self._datamodel_in_sync = False

    def _create(self, ipset_id):
        _log.info("Creating ipset for pre-calculated selector %s",
                  ipset_id)
        ipset_name = ipset_id[:MAX_NAME_LENGTH]
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

    def _on_object_started(self, ipset_id, active_ipset):
        _log.debug("RefCountedIpsetActor actor for %s started", ipset_id)
        # Fill the ipset in with its members, this will trigger its first
        # programming, after which it will call us back to tell us it is ready.
        # We can't use self._dirty_tags to defer this in case the set becomes
        # unreferenced before _finish_msg_batch() is called.
        assert self._is_starting_or_live(ipset_id)
        assert self._datamodel_in_sync
        active_ipset = self.objects_by_id[ipset_id]
        members = frozenset(self._pre_calc_ipsets_by_id.get(ipset_id, set()))
        active_ipset.replace_members(members, async=True)

    def _update_dirty_active_ipsets(self):
        """
        Updates the members of any live TagIpsets that are dirty.

        Clears the index of dirty TagIpsets as a side-effect.
        """
        # Add in the pre-calculated IPs from the etcd driver.
        _log.debug("Incorporating pre-calculated ipsets")
        for sel_id, added_ips in self._pre_calc_added_ips_by_id.iteritems():
            self._pre_calc_ipsets_by_id[sel_id].update(added_ips) #uncovered
        for sel_id, removed_ips in self._pre_calc_removed_ips_by_id.iteritems():
            self._pre_calc_ipsets_by_id[sel_id].difference_update(removed_ips) #uncovered
            if not self._pre_calc_ipsets_by_id[sel_id]:
                del self._pre_calc_ipsets_by_id[sel_id]

        num_updates = 0
        for tag_id, removed_ips in self._pre_calc_removed_ips_by_id.iteritems():
            if self._is_starting_or_live(tag_id): #uncovered
                assert self._datamodel_in_sync
                active_ipset = self.objects_by_id[tag_id]
                active_ipset.remove_members(removed_ips, async=True)
                num_updates += 1
            self._maybe_yield()
        for tag_id, added_ips in self._pre_calc_added_ips_by_id.iteritems():
            if self._is_starting_or_live(tag_id): #uncovered
                assert self._datamodel_in_sync
                active_ipset = self.objects_by_id[tag_id]
                active_ipset.add_members(added_ips, async=True)
                num_updates += 1
            self._maybe_yield()

        self._pre_calc_removed_ips_by_id.clear()
        self._pre_calc_added_ips_by_id.clear()

        if num_updates > 0:
            _log.info("Sent %s updates to updated tags", num_updates) #uncovered

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

        # Filter deletion candidates to only ipsets that we could have created.
        felix_ipsets = set()
        for ipset in all_ipsets:
            print "ipset: %s" % ipset
            for prefix in ALL_FELIX_PREFIXES[self.ip_type]:
                print "prefix: %s" % prefix
                if ipset.startswith(prefix):
                    print "matched"
                    felix_ipsets.add(ipset)

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
        print "Whitelisted ipsets: %s" % whitelist
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
                _log.info("All ipsets: %s", all_ipsets)
                _log.info("Whitelist: %s", whitelist)
                _log.info("ipsets to delete: %s", ipsets_to_delete)

    @actor_message()
    def on_ipset_update(self, ipset_id, members): #uncovered
        _log.debug("IP set %s now active.", ipset_id)
        filtered_members = self._pre_calc_ipsets_by_id[ipset_id]
        filtered_members.clear()
        for ip in members:
            if (":" in ip) != (self.ip_type == IPV6):
                # Skip IPs of incorrect type.
                continue
            filtered_members.add(ip)
        if not filtered_members:
            self._pre_calc_ipsets_by_id.pop(ipset_id)
        self._pre_calc_added_ips_by_id.pop(ipset_id, None)
        self._pre_calc_removed_ips_by_id.pop(ipset_id, None)

        if self._is_starting_or_live(ipset_id):
            ipset = self.objects_by_id[ipset_id]
            ipset.replace_members(frozenset(filtered_members), async=True)

    @actor_message()
    def on_ipset_removed(self, ipset_id): #uncovered
        _log.debug("IP set %s no longer active.", ipset_id)

        self._pre_calc_ipsets_by_id.pop(ipset_id, None)
        self._pre_calc_added_ips_by_id.pop(ipset_id, None)
        self._pre_calc_removed_ips_by_id.pop(ipset_id, None)

        if self._is_starting_or_live(ipset_id):
            ipset = self.objects_by_id[ipset_id]
            ipset.replace_members(frozenset(), async=True)

    @actor_message()
    def on_ipset_delta_update(self, ipset_id, added_ips, removed_ips): #uncovered
        skipped = 0
        processed = 0
        for ip in added_ips:
            if (":" in ip) != (self.ip_type == IPV6):
                # Skip IPs of incorrect type.
                skipped += 1
                continue
            processed += 1
            self._pre_calc_added_ips_by_id[ipset_id].add(ip)
            self._pre_calc_removed_ips_by_id[ipset_id].discard(ip)
        for ip in removed_ips:
            if (":" in ip) != (self.ip_type == IPV6):
                # Skip IPs of incorrect type.
                skipped += 1
                continue
            processed += 1
            self._pre_calc_added_ips_by_id[ipset_id].discard(ip)
            self._pre_calc_removed_ips_by_id[ipset_id].add(ip)
        _log.debug("Processed %s IP updates, %s skipped", processed, skipped)

    def _finish_msg_batch(self, batch, results):
        """
        Called after a batch of messages is finished, processes any
        pending RefCountedIpsetActor member updates.

        Doing that here allows us to lots of updates into one replace
        operation.  It also avoid wasted effort if tags are flapping.
        """
        super(IpsetManager, self)._finish_msg_batch(batch, results)
        self._update_dirty_active_ipsets()


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
        _log.info("Replacing members of ipset %s with %s IPs", self,
                  len(members))
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
        if self.changes is None:
            _log.warning("Haven't received initial snapshot yet.") #uncovered
            return

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
            _log.info("Completed force-rewrite of ipset %s", self)
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
        except FailedSystemCall as e: #uncovered
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
            _log.debug("Main set doesn't exist, creating it...") #uncovered
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
