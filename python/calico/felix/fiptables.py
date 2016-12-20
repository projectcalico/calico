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
felix.fiptables
~~~~~~~~~~~~

IP tables management functions.
"""
from collections import defaultdict
import copy
import logging
import random
import time
import itertools
import re

from gevent import subprocess
import gevent
import sys

from calico.felix import futils
from calico.felix.actor import (
    Actor, actor_message, ResultOrExc, SplitBatchAndRetry
)
from calico.felix.frules import FELIX_PREFIX
from calico.felix.futils import FailedSystemCall, StatCounter

_log = logging.getLogger(__name__)

_correlators = ("ipt-%s" % ii for ii in itertools.count())
MAX_IPT_RETRIES = 10
MAX_IPT_BACKOFF = 0.2


class IptablesUpdater(Actor):
    """
    Actor that owns and applies updates to a particular iptables table.
    Supports batching updates for performance and dependency tracking
    between chains.

    iptables safety
    ~~~~~~~~~~~~~~~

    Concurrent access to the same table is not allowed by the
    underlying iptables architecture so there should be one instance of
    this class for each table.  Each IP version has its own set of
    non-conflicting tables.

    However, this class tries to be robust against concurrent access
    from outside the process by detecting and retrying such errors.

    iptables manipulation guidelines
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Since any update to iptables is implemented by the iptables commands
    as a read-modify-write of the entire table, we try to batch (see below)
    as many updates into one call to iptables as possible.

    Rather than using individual iptables commands, we make use of
    iptables-restore to rewrite entire chains (or multiple chains) as a
    single atomic operation.

    This also allows us to avoid reading individual rules from iptables,
    which is a very tricky thing to get right (because iptables internally
    normalises rules, they don't always read back as-written).

    Batching support
    ~~~~~~~~~~~~~~~~

    This actor supports batching of multiple updates. It applies updates that
    are on the queue in one atomic batch. This is dramatically faster than
    issuing single iptables requests.

    If a request fails, it does a binary chop using the SplitBatchAndRetry
    mechanism to report the error to the correct request.  To allow a batch
    to be retried, the per-batch state is tracked using a dedicated
    _Transaction object, which can simply be thrown away if the batch fails.

    Dependency tracking
    ~~~~~~~~~~~~~~~~~~~

    To offload a lot of coordination complexity from the classes that
    use this one, this class supports tracking dependencies between chains
    and programming stubs for missing chains:

    * When calling rewrite_chains() the caller must supply a dict that
      maps from chain to a set of chains it requires (i.e. the chains
      that appear in its --jump and --goto targets).

    * Any chains that are required but not present are created as "stub"
      chains, which (by default) drop all traffic. They are marked as such
      in the iptables rules with an iptables comment.  To facilitate graceful
      restart after a failure, the default behaviour for a missing chain can
      be pre-configured via set_missing_chain_override().

    * When a required chain is later explicitly created, the stub chain is
      replaced with the required contents of the chain.

    * If a required chain is explicitly deleted, it is rewritten as a stub
      chain.

    * If a chain exists only as a stub chain to satisfy a dependency, then it
      is cleaned up when the dependency is removed.

    """

    def __init__(self, table, config, ip_version=4):
        super(IptablesUpdater, self).__init__(qualifier="v%d-%s" %
                                                        (ip_version, table))
        self.table = table
        self.refresh_interval = config.REFRESH_INTERVAL
        self.iptables_generator = config.plugins["iptables_generator"]
        self.chain_insert_mode = config.CHAIN_INSERT_MODE
        self.ip_version = ip_version
        if ip_version == 4:
            self._restore_cmd = "iptables-restore"
            self._save_cmd = "iptables-save"
            self._iptables_cmd = "iptables"
        else:
            assert ip_version == 6
            self._restore_cmd = "ip6tables-restore"
            self._save_cmd = "ip6tables-save"
            self._iptables_cmd = "ip6tables"

        self._chains_in_dataplane = None
        """
        Set of chains that we know are actually in the dataplane.  Loaded
        at start of day and then kept in sync.
        """
        self._grace_period_finished = False
        """
        Flag that is set after the graceful restart window is over.
        """

        self._programmed_chain_contents = {}
        """Map from chain name to chain contents, only contains chains that
        have been explicitly programmed."""
        self._inserted_rule_fragments = set()
        """Special-case rule fragments that we've explicitly inserted."""
        self._removed_rule_fragments = set()
        """Special-case rule fragments that we've explicitly removed.
        We need to cache this to defend against other processes accidentally
        reverting our removal."""
        self._missing_chain_overrides = {}
        """Overrides for chain contents when we need to program a chain but
        it's missing."""

        self._required_chains = defaultdict(set)
        """Map from chain name to the set of names of chains that it
        depends on."""
        self._requiring_chains = defaultdict(set)
        """Map from chain to the set of chains that depend on it.
        Inverse of self.required_chains."""

        # Since it's fairly complex to keep track of the changes required
        # for a particular batch and still be able to roll-back the changes
        # to our data structures, we delegate to a per-batch object that
        # does that calculation.
        self._txn = None
        """:type _Transaction: object used to track index changes
        for this batch."""
        self._completion_callbacks = None
        """List of callbacks to issue once the current batch completes."""

        # Diagnostic counters.
        self._stats = StatCounter("IPv%s %s iptables updater" %
                                  (ip_version, table))

        # Avoid duplicating init logic.
        self._reset_batched_work()
        self._load_chain_names_from_iptables(async=True)

        # Optionally, start periodic refresh timer.
        if self.refresh_interval > 0:
            _log.info("Periodic iptables refresh enabled, starting "
                      "resync greenlet")
            refresh_greenlet = gevent.spawn(self._periodic_refresh)
            refresh_greenlet.link_exception(self._on_worker_died)

    @property
    def _explicitly_prog_chains(self):
        return set(self._programmed_chain_contents.keys())

    def _reset_batched_work(self):
        """Reset the per-batch state in preparation for a new batch."""
        self._txn = _Transaction(self._programmed_chain_contents,
                                 self._required_chains,
                                 self._requiring_chains)
        self._completion_callbacks = []

    @actor_message(needs_own_batch=True)
    def _load_chain_names_from_iptables(self):
        """
        Loads the set of (our) chains that already exist from iptables.

        Populates self._chains_in_dataplane.
        """
        _log.debug("Loading chain names for iptables table %s, using "
                   "command %s", self.table, self._save_cmd)
        self._stats.increment("Refreshed chain list")
        raw_ipt_output = subprocess.check_output([self._save_cmd, "--table",
                                                  self.table])
        self._chains_in_dataplane = _extract_our_chains(self.table,
                                                        raw_ipt_output)

    def _get_unreferenced_chains(self):
        """
        Reads the list of chains in the dataplane which are not referenced.

        :returns list[str]: list of chains currently in the dataplane that
            are not referenced by other chains.
        """
        raw_ipt_output = subprocess.check_output(
            [self._iptables_cmd,
             "--list",  # Action to perform.
             "--numeric",  # Avoid DNS lookups.
             "--table", self.table])
        return _extract_our_unreffed_chains(raw_ipt_output)

    @actor_message()
    def rewrite_chains(self, update_calls_by_chain,
                       dependent_chains, callback=None):
        """
        Atomically apply a set of updates to the table.

        :param update_calls_by_chain: map from chain name to list of
               iptables-style update calls,
               e.g. {"chain_name": ["-A chain_name -j ACCEPT"]}. Chain will
               be flushed.
        :param dependent_chains: map from chain name to a set of chains
               that that chain requires to exist. They will be created
               (with a default drop) if they don't exist.
        :raises FailedSystemCall if a problem occurred.
        """
        # We actually apply the changes in _finish_msg_batch().  Index the
        # changes by table and chain.
        _log.info("iptables update to chains %s", update_calls_by_chain.keys())
        _log.debug("iptables update: %s", update_calls_by_chain)
        _log.debug("iptables deps: %s", dependent_chains)
        self._stats.increment("Chain rewrites")
        for chain, updates in update_calls_by_chain.iteritems():
            # TODO: double-check whether this flush is needed.
            updates = ["--flush %s" % chain] + updates
            deps = dependent_chains.get(chain, set())
            self._txn.store_rewrite_chain(chain, updates, deps)
        if callback:
            self._completion_callbacks.append(callback)

    @actor_message()
    def set_missing_chain_override(self, chain_name, fragments):
        """Sets the contents to program if the given chain is required but
        it hasn't yet been written.

        This is useful for graceful restart at start of day, where we want
        to leave a chain in place for as long as possible, but if it's
        missing, we need it to be default-RETURN.

        Must be called before the chain is used as a dependency.

        :param chain_name: name of the chain.
        :param fragments: list of iptables fragments, as used by
               rewrite_chains().
        """
        _log.info("Storing missing chain override for %s", chain_name)
        assert fragments is not None, "Removal of overrides not implemented"
        assert chain_name not in self._requiring_chains, \
            "Missing chain override set after chain in use"
        self._missing_chain_overrides[chain_name] = fragments

    # Does direct table manipulation, forbid batching with other messages.
    @actor_message(needs_own_batch=True)
    def ensure_rule_inserted(self, rule_fragment):
        """
        Runs the given rule fragment, prefixed with --insert or --append
        depending on the configuration. If the rule was already present,
        it is removed and reinserted at the start (or end) of the chain.

        This covers the case where we need to insert a rule into the
        pre-existing kernel chains (only). For chains that are owned by Felix,
        use the more robust approach of rewriting the whole chain using
        rewrite_chains().

        :param rule_fragment: fragment to be inserted. For example,
           "INPUT --jump felix-INPUT"
        """
        self._stats.increment("Rule inserts")
        _log.info("Inserting rule %r", rule_fragment)
        self._inserted_rule_fragments.add(rule_fragment)
        self._removed_rule_fragments.discard(rule_fragment)
        if self.chain_insert_mode == "insert":
            self._insert_rule(rule_fragment)
        else:
            self._append_rule(rule_fragment)

    def _insert_rule(self, rule_fragment, log_level=logging.INFO):
        """
        Execute the iptables commands to atomically (re)insert the
        given rule fragment into iptables.

        Has the side-effect of moving the rule to the top of the
        chain.

        :param rule_fragment: A rule fragment, starting with the chain
            name; will be prefixed with "--insert ", for example, to
            create the actual iptables line to execute.
        """
        try:
            # Do an atomic delete + insert of the rule.  If the rule already
            # exists then the rule will be moved to the start of the chain.
            _log.log(log_level, "Attempting to move any existing instance "
                                "of rule %r to top of chain.", rule_fragment)
            self._execute_iptables(['*%s' % self.table,
                                    '--delete %s' % rule_fragment,
                                    '--insert %s' % rule_fragment,
                                    'COMMIT'],
                                   fail_log_level=logging.DEBUG)
        except FailedSystemCall:
            # Assume the rule didn't exist. Try inserting it.
            _log.log(log_level, "Didn't find any existing instance of rule "
                                "%r, inserting it instead.", rule_fragment)
            self._execute_iptables(['*%s' % self.table,
                                    '--insert %s' % rule_fragment,
                                    'COMMIT'])

    def _append_rule(self, rule_fragment, log_level=logging.INFO):
        """
        Execute the iptables commands to atomically (re)append the
        given rule fragment into iptables.

        Has the side-effect of moving the rule to the end of the
        chain.

        :param rule_fragment: A rule fragment, starting with the chain
            name; will be prefixed with "--append ", for example, to
            create the actual iptables line to execute.
        """
        try:
            # Do an atomic delete + append of the rule.  If the rule already
            # exists then the rule will be moved to the end of the chain.
            _log.log(log_level, "Attempting to move any existing instance "
                                "of rule %r to end of chain.", rule_fragment)
            self._execute_iptables(['*%s' % self.table,
                                    '--delete %s' % rule_fragment,
                                    '--append %s' % rule_fragment,
                                    'COMMIT'],
                                   fail_log_level=logging.DEBUG)
        except FailedSystemCall:
            # Assume the rule didn't exist. Try inserting it.
            _log.log(log_level, "Didn't find any existing instance of rule "
                                "%r, appending it instead.", rule_fragment)
            self._execute_iptables(['*%s' % self.table,
                                    '--append %s' % rule_fragment,
                                    'COMMIT'])

    @actor_message(needs_own_batch=True)
    def ensure_rule_removed(self, rule_fragment):
        """
        If it exists, removes the given rule fragment.  Caches that the
        rule fragment should now not be present.

        WARNING: due to the caching, this is only suitable for a small
        number of static rules.  For example, to add and remove our
        "root" rules, which dispatch to our dynamic chains, from the
        top-level kernel chains.

        The caching is required to defend against other poorly-written
        processes, which use an iptables-save and then iptables-restore
        call to update their rules.  That clobbers our updates (including
        deletions).

        :param rule_fragment: fragment to be deleted. For example,
           "INPUT --jump felix-INPUT"
        """
        _log.info("Removing rule %r", rule_fragment)
        self._stats.increment("Rule removals")
        self._inserted_rule_fragments.discard(rule_fragment)
        self._removed_rule_fragments.add(rule_fragment)
        self._remove_rule(rule_fragment)

    def _remove_rule(self, rule_fragment, log_level=logging.INFO):
        """
        Execute the iptables commands required to (atomically) remove
        the given rule_fragment if it is present.

        :param rule_fragment: A rule fragment, starting with the chain
            name; will be prefixed with "--delete " to create the
            actual iptables line to execute.
        """
        _log.log(log_level, "Ensuring rule is not present %r", rule_fragment)
        num_instances = 0
        try:
            while True:  # Delete all instances of rule.
                self._execute_iptables(['*%s' % self.table,
                                        '--delete %s' % rule_fragment,
                                        'COMMIT'],
                                       fail_log_level=logging.DEBUG)
                num_instances += 1
                assert num_instances < 100, "Too many deletes, infinite loop?"
        except FailedSystemCall as e:
            if num_instances == 0:
                if "line 2 failed" in e.stderr:
                    # Rule was parsed OK but failed to apply, this means that
                    # it wasn't present.
                    _log.log(log_level, "Removal of rule %r rejected; not "
                                        "present?", rule_fragment)
                elif "at line: 2" in e.stderr and "doesn't exist" in e.stderr:
                    # Rule was rejected because some pre-requisite (such as an
                    # ipset) didn't exist.
                    _log.log(log_level, "Removal of rule %r failed due to "
                                        "missing pre-requisite; rule must "
                                        "not be present.", rule_fragment)
                else:
                    _log.exception("Unexpected failure when trying to "
                                   "delete rule %r" % rule_fragment)
                    raise
            else:
                _log.log(log_level, "%s instances of rule %r removed",
                         num_instances, rule_fragment)

    @actor_message()
    def delete_chains(self, chain_names, callback=None):
        """
        Deletes the named chains.

        :raises FailedSystemCall if a problem occurred.
        """
        # We actually apply the changes in _finish_msg_batch().  Index the
        # changes by table and chain.
        _log.info("Deleting chains %s", chain_names)
        self._stats.increment("Chain deletes")
        for chain in chain_names:
            self._txn.store_delete(chain)
        if callback:
            self._completion_callbacks.append(callback)

    # It's much simpler to do cleanup in its own batch so that it doesn't have
    # to worry about in-flight updates.
    @actor_message(needs_own_batch=True)
    def cleanup(self):
        """
        Tries to clean up any left-over chains from a previous run that
        are no longer required.
        """
        _log.info("Cleaning up left-over iptables state.")
        self._stats.increment("Cleanups performed")

        # Start with the current state.
        self._load_chain_names_from_iptables()

        required_chains = set(self._requiring_chains.keys())
        if not self._grace_period_finished:
            # Ensure that all chains that are required but not explicitly
            # programmed are stubs.
            #
            # We have to do this at the end of the graceful restart period
            # during which we may have re-used old chains.
            chains_to_stub = (required_chains -
                              self._explicitly_prog_chains)
            _log.info("Graceful restart window finished, stubbing out "
                      "chains: %s", chains_to_stub)
            try:
                self._stub_out_chains(chains_to_stub)
            except NothingToDo:
                pass
            self._grace_period_finished = True

        # Now the generic cleanup, look for chains that we're not expecting to
        # be there and delete them.
        chains_we_tried_to_delete = set()
        finished = False
        while not finished:
            # Try to delete all the unreferenced chains, we use a loop to
            # ensure that we then clean up any chains that become unreferenced
            # when we delete the previous lot.
            unreferenced_chains = self._get_unreferenced_chains()
            orphans = (unreferenced_chains -
                       self._explicitly_prog_chains -
                       required_chains)
            if not chains_we_tried_to_delete.issuperset(orphans):
                _log.info("Cleanup found these unreferenced chains to "
                          "delete: %s", orphans)
                self._stats.increment("Orphans found during cleanup",
                                      by=len(orphans))
                chains_we_tried_to_delete.update(orphans)
                self._delete_best_effort(orphans)
            else:
                # We've already tried to delete all the chains we found,
                # give up.
                _log.info("Cleanup finished, deleted %d chains, failed to "
                          "delete these chains: %s",
                          len(chains_we_tried_to_delete) - len(orphans),
                          orphans)
                finished = True

        # Then some sanity checks:
        expected_chains = self._chains_in_dataplane
        self._load_chain_names_from_iptables()
        loaded_chains = self._chains_in_dataplane
        missing_chains = ((self._explicitly_prog_chains | required_chains) -
                          self._chains_in_dataplane)
        if expected_chains != self._chains_in_dataplane or missing_chains:
            # This is serious, either there's a bug in our model of iptables
            # or someone else has changed iptables under our feet.
            _log.error("Chains in data plane inconsistent with calculated "
                       "index.  In dataplane but not in index: %s; In index: "
                       "but not dataplane: %s; missing from iptables: %s.  "
                       "Another process may have clobbered our updates.",
                       loaded_chains - expected_chains,
                       expected_chains - loaded_chains,
                       missing_chains)

            # Try to recover: trigger a full refresh of the dataplane to
            # bring it into sync.
            self.refresh_iptables()

    def _periodic_refresh(self):
        while True:
            # Jitter our sleep times by 20%.
            gevent.sleep(self.refresh_interval * (1 + random.random() * 0.2))
            self.refresh_iptables(async=True)

    def _on_worker_died(self, watch_greenlet):
        """
        Greenlet: spawned by the gevent Hub if the etcd watch loop ever
        stops, kills the process.
        """
        _log.critical("Worker greenlet died: %s; exiting.", watch_greenlet)
        sys.exit(1)

    @actor_message()
    def refresh_iptables(self):
        """
        Re-apply our iptables state to the kernel.
        """
        _log.info("Refreshing all our chains")
        self._txn.store_refresh()

    def _start_msg_batch(self, batch):
        self._reset_batched_work()
        return batch

    def _finish_msg_batch(self, batch, results):
        start = time.time()
        try:
            # We use two passes to update the dataplane.  In the first pass,
            # we make any updates, create new chains and replace to-be-deleted
            # chains with stubs (in case we fail to delete them below).
            try:
                input_lines = self._calculate_ipt_modify_input()
            except NothingToDo:
                _log.info("%s no updates in this batch.", self)
            else:
                self._execute_iptables(input_lines)
                _log.info("%s Successfully processed iptables updates.", self)
                self._chains_in_dataplane.update(self._txn.affected_chains)
        except (IOError, OSError, FailedSystemCall) as e:
            if isinstance(e, FailedSystemCall):
                rc = e.retcode
            else:
                rc = "unknown"
            if len(batch) == 1:
                # We only executed a single message, report the failure.
                _log.error("Non-retryable %s failure. RC=%s",
                           self._restore_cmd, rc)
                self._stats.increment("Messages failed due to iptables "
                                      "error")
                if self._completion_callbacks:
                    self._completion_callbacks[0](e)
                final_result = ResultOrExc(None, e)
                results[0] = final_result
            else:
                _log.error("Non-retryable error from a combined batch, "
                           "splitting the batch to narrow down culprit.")
                self._stats.increment("Split batch due to error")
                raise SplitBatchAndRetry()
        else:
            # Modify succeeded, update our indexes for next time.
            self._update_indexes()
            # Make a best effort to delete the chains we no longer want.
            # If we fail due to a stray reference from an orphan chain, we
            # should catch them on the next cleanup().
            self._delete_best_effort(self._txn.chains_to_delete)
            for c in self._completion_callbacks:
                c(None)
            if self._txn.refresh:
                # Re-apply our inserts and deletions.  We do this after the
                # above processing because our inserts typically reference
                # our other chains and if the insert has been "rolled back"
                # by another process then it's likely that the referenced
                # chain was too.
                _log.info("Transaction included a refresh, re-applying our "
                          "inserts and deletions.")
                try:
                    for fragment in self._inserted_rule_fragments:
                        if self.chain_insert_mode == "insert":
                            self._insert_rule(fragment, log_level=logging.DEBUG)
                        else:
                            self._append_rule(fragment, log_level=logging.DEBUG)
                    for fragment in self._removed_rule_fragments:
                        self._remove_rule(fragment, log_level=logging.DEBUG)
                except FailedSystemCall:
                    _log.error("Failed to refresh inserted/removed rules")
        finally:
            self._reset_batched_work()
            self._stats.increment("Batches finished")

        end = time.time()
        _log.debug("Batch time: %.2f %s", end - start, len(batch))

    def _delete_best_effort(self, chains):
        """
        Try to delete all the chains in the input list. Any errors are silently
        swallowed.
        """
        if not chains:
            return
        chain_batches = [list(chains)]
        while chain_batches:
            batch = chain_batches.pop(0)
            try:
                # Try the next batch of chains...
                _log.debug("Attempting to delete chains: %s", batch)
                self._attempt_delete(batch)
            except (IOError, OSError, FailedSystemCall):
                _log.warning("Deleting chains %s failed", batch)
                if len(batch) > 1:
                    # We were trying to delete multiple chains, split the
                    # batch in half and put the batches back on the queue to
                    # try again.
                    _log.info("Batch was of length %s, splitting", len(batch))
                    split_point = len(batch) // 2
                    first_half = batch[:split_point]
                    second_half = batch[split_point:]
                    assert len(first_half) + len(second_half) == len(batch)
                    if chain_batches:
                        chain_batches[0][:0] = second_half
                    else:
                        chain_batches[:0] = [second_half]
                    chain_batches[:0] = [first_half]
                else:
                    # Only trying to delete one chain, give up.  It must still
                    # be referenced.
                    _log.error("Failed to delete chain %s, giving up. Maybe "
                               "it is still referenced?", batch[0])
                    self._stats.increment("Chain delete failures")
            else:
                _log.debug("Deleted chains %s successfully, remaining "
                           "batches: %s", batch, len(chain_batches))

    def _stub_out_chains(self, chains):
        input_lines = self._calculate_ipt_stub_input(chains)
        self._execute_iptables(input_lines)

    def _attempt_delete(self, chains):
        try:
            input_lines = self._calculate_ipt_delete_input(chains)
        except NothingToDo:
            _log.debug("No chains to delete %s", chains)
        else:
            self._execute_iptables(input_lines, fail_log_level=logging.WARNING)
            self._chains_in_dataplane -= set(chains)

    def _update_indexes(self):
        """
        Called after successfully processing a batch, updates the
        indices with the values calculated by the _Transaction.
        """
        self._programmed_chain_contents = self._txn.prog_chains
        self._required_chains = self._txn.required_chns
        self._requiring_chains = self._txn.requiring_chns

    def _calculate_ipt_modify_input(self):
        """
        Calculate the input for phase 1 of a batch, where we only modify and
        create chains.

        :raises NothingToDo: if the batch requires no modify operations.
        """
        # Valid input looks like this.
        #
        # *table
        # :chain_name
        # :chain_name_2
        # -F chain_name
        # -A chain_name -j ACCEPT
        # COMMIT
        #
        # The chains are created if they don't exist.
        input_lines = []
        # Track the chains that we decide we need to touch so that we can
        # prepend the appropriate iptables header for each chain.
        modified_chains = set()
        # Generate rules to stub out chains.  We stub chains out if they're
        # referenced by another chain but they're not present for some reason.
        for chain in self._txn.chains_to_stub_out:
            if (self._grace_period_finished or
                    chain in self._txn.explicit_deletes or
                    chain not in self._chains_in_dataplane):
                # During graceful restart, we only stub out chains if
                # * the chain is genuinely missing from the dataplane, or
                # * we were told to delete the chain explicitly (but decided
                #   we couldn't because it was still referenced), implying
                #   that we now know the state of that chain and we should not
                #   wait for the end of graceful restart to clean it up.
                modified_chains.add(chain)
                input_lines.extend(self._missing_chain_stub_rules(chain))

        # Generate rules to stub out chains that we're about to delete, just
        # in case the delete fails later on.  Stubbing it out also stops it
        # from referencing other chains, accidentally keeping them alive.
        for chain in self._txn.chains_to_delete:
            modified_chains.add(chain)
            input_lines.extend(self._missing_chain_stub_rules(chain))

        # Now add the actual chain updates.
        for chain, chain_updates in self._txn.updates.iteritems():
            modified_chains.add(chain)
            input_lines.extend(chain_updates)

        # Finally, prepend the input with instructions that do an idempotent
        # create-and-flush operation for the chains that we need to create or
        # rewrite.
        input_lines[:0] = [":%s -" % chain for chain in modified_chains]

        if not input_lines:
            raise NothingToDo
        return ["*%s" % self.table] + input_lines + ["COMMIT"]

    def _calculate_ipt_delete_input(self, chains):
        """
        Calculate the input for phase 2 of a batch, where we actually
        try to delete chains.

        :raises NothingToDo: if the batch requires no delete operations.
        """
        input_lines = []
        found_delete = False
        input_lines.append("*%s" % self.table)
        for chain_name in chains:
            # Delete the chain
            input_lines.append(":%s -" % chain_name)
            input_lines.append("--delete-chain %s" % chain_name)
            found_delete = True
        input_lines.append("COMMIT")
        if found_delete:
            return input_lines
        else:
            raise NothingToDo()

    def _calculate_ipt_stub_input(self, chains):
        """
        Calculate input to replace the given chains with stubs.
        """
        input_lines = []
        found_chain_to_stub = False
        input_lines.append("*%s" % self.table)
        for chain_name in chains:
            # Stub the chain
            input_lines.append(":%s -" % chain_name)
            input_lines.extend(self._missing_chain_stub_rules(chain_name))
            found_chain_to_stub = True
        input_lines.append("COMMIT")
        if found_chain_to_stub:
            return input_lines
        else:
            raise NothingToDo()

    def _execute_iptables(self, input_lines, fail_log_level=logging.ERROR):
        """
        Runs ip(6)tables-restore with the given input.  Retries iff
        the COMMIT fails.

        :raises FailedSystemCall: if the command fails on a non-commit
            line or if it repeatedly fails and retries are exhausted.
        """
        backoff = 0.01
        num_tries = 0
        success = False
        while not success:
            input_str = "\n".join(input_lines) + "\n"
            _log.debug("%s input:\n%s", self._restore_cmd, input_str)

            # Run iptables-restore in noflush mode so that it doesn't
            # blow away all the tables we're not touching.
            cmd = [self._restore_cmd, "--noflush", "--verbose"]
            try:
                futils.check_call(cmd, input_str=input_str)
            except FailedSystemCall as e:
                # Parse the output to determine if error is retryable.
                retryable, detail = _parse_ipt_restore_error(input_lines,
                                                             e.stderr)
                num_tries += 1
                if retryable:
                    if num_tries < MAX_IPT_RETRIES:
                        _log.info("%s failed with retryable error. Retry in "
                                  "%.2fs", self._iptables_cmd, backoff)
                        self._stats.increment("iptables commit failure "
                                              "(retryable)")
                        gevent.sleep(backoff)
                        if backoff > MAX_IPT_BACKOFF:
                            backoff = MAX_IPT_BACKOFF
                        backoff *= (1.5 + random.random())
                        continue
                    else:
                        _log.log(
                            fail_log_level,
                            "Failed to run %s.  Out of retries: %s.\n"
                            "Output:\n%s\n"
                            "Error:\n%s\n"
                            "Input was:\n%s",
                            self._restore_cmd, detail, e.stdout, e.stderr,
                            input_str)
                        self._stats.increment("iptables commit failure "
                                              "(out of retries)")
                else:
                    _log.log(
                        fail_log_level,
                        "%s failed with non-retryable error: %s.\n"
                        "Output:\n%s\n"
                        "Error:\n%s\n"
                        "Input was:\n%s",
                        self._restore_cmd, detail, e.stdout, e.stderr,
                        input_str)
                    self._stats.increment("iptables non-retryable failure")
                raise
            else:
                self._stats.increment("iptables success")
                success = True

    def _missing_chain_stub_rules(self, chain_name):
        """
        :return: List of rule fragments to replace the given chain with a
            single drop rule.
        """
        if chain_name in self._missing_chain_overrides:
            _log.debug("Generating missing chain %s; override in place",
                       chain_name)
            fragment = self._missing_chain_overrides[chain_name]
        else:
            fragment = ["--flush %s" % chain_name]
            fragment.extend(self.iptables_generator.drop_rules(
                self.ip_version,
                chain_name,
                None,
                'WARNING Missing chain'))
        return fragment


class _Transaction(object):
    """
    This class keeps track of a sequence of updates to an
    IptablesUpdater's indexing data structures.

    It takes a copy of the data structures at creation and then
    gets fed the sequence of updates and deletes; then, on-demand
    it calculates the dataplane deltas that are required and
    caches the results.

    The general idea is that, if the iptables-restore call fails,
    the Transaction object can be thrown away, leaving the
    IptablesUpdater's state unchanged.

    """
    def __init__(self,
                 old_prog_chain_contents,
                 old_deps,
                 old_requiring_chains):
        # Figure out what stub chains should already be present.
        old_required_chains = set(old_requiring_chains.keys())
        old_explicitly_programmed_chains = set(old_prog_chain_contents.keys())
        self.already_stubbed = (old_required_chains -
                                old_explicitly_programmed_chains)

        # Deltas.
        self.updates = {}
        self.explicit_deletes = set()

        # New state.  These will be copied back to the IptablesUpdater
        # if the transaction succeeds.
        self.prog_chains = old_prog_chain_contents.copy()
        self.required_chns = copy.deepcopy(old_deps)
        self.requiring_chns = copy.deepcopy(old_requiring_chains)

        # Memoized values of the properties below.  See chains_to_stub(),
        # affected_chains() and chains_to_delete() below.
        self._chains_to_stub = None
        self._affected_chains = None
        self._chains_to_delete = None

        # Whether to do a refresh.
        self.refresh = False

    def store_delete(self, chain):
        """
        Records the delete of the given chain, updating the per-batch
        indexes as required.
        """
        _log.debug("Storing delete of chain %s", chain)
        assert chain is not None
        # Clean up dependency index.
        self._update_deps(chain, set())
        # Mark for deletion.
        self.explicit_deletes.add(chain)
        # Remove any now-stale rewrite state.
        self.updates.pop(chain, None)
        self.prog_chains.pop(chain, None)
        self._invalidate_cache()

    def store_rewrite_chain(self, chain, updates, dependencies):
        """
        Records the rewrite of the given chain, updating the per-batch
        indexes as required.
        """
        _log.debug("Storing updates to chain %s", chain)
        assert chain is not None
        assert updates is not None
        assert dependencies is not None
        # Clean up reverse dependency index.
        self._update_deps(chain, dependencies)
        # Remove any deletion, if present.
        self.explicit_deletes.discard(chain)
        # Store off the update.
        self.updates[chain] = updates
        self.prog_chains[chain] = updates
        self._invalidate_cache()

    def store_refresh(self):
        """
        Records that we should refresh all chains as part of this transaction.
        """
        # Copy the whole state over to the delta for this transaction so it
        # all gets reapplied.  The dependency index should already be correct.
        self.updates.update(self.prog_chains)
        self.refresh = True
        self._invalidate_cache()

    def _update_deps(self, chain, new_deps):
        """
        Updates the forward/backward dependency indexes for the given
        chain.
        """
        # Remove all the old deps from the reverse index..
        old_deps = self.required_chns.get(chain, set())
        for dependency in old_deps:
            self.requiring_chns[dependency].discard(chain)
            if not self.requiring_chns[dependency]:
                del self.requiring_chns[dependency]
        # Add in the new deps to the reverse index.
        for dependency in new_deps:
            self.requiring_chns[dependency].add(chain)
        # And store them off in the forward index.
        if new_deps:
            self.required_chns[chain] = new_deps
        else:
            self.required_chns.pop(chain, None)

    def _invalidate_cache(self):
        self._chains_to_stub = None
        self._affected_chains = None
        self._chains_to_delete = None

    @property
    def affected_chains(self):
        """
        The set of chains that are touched by this update (whether
        deleted, modified, or to be stubbed).
        """
        if self._affected_chains is None:
            updates = set(self.updates.keys())
            stubs = self.chains_to_stub_out
            deletes = self.chains_to_delete
            _log.debug("Affected chains: deletes=%s, updates=%s, stubs=%s",
                       deletes, updates, stubs)
            self._affected_chains = deletes | updates | stubs
        return self._affected_chains

    @property
    def chains_to_stub_out(self):
        """
        The set of chains that need to be stubbed as part of this update.
        """
        if self._chains_to_stub is None:
            # Don't stub out chains that we're now explicitly programming.
            impl_required_chains = (self.referenced_chains -
                                    set(self.prog_chains.keys()))
            if self.refresh:
                # Re-stub all chains that should be stubbed.
                _log.debug("Refresh in progress, re-stub all stubbed chains.")
                self._chains_to_stub = impl_required_chains
            else:
                # Don't stub out chains that are already stubbed.
                _log.debug("No refresh in progress.")
                self._chains_to_stub = (impl_required_chains -
                                        self.already_stubbed)
        return self._chains_to_stub

    @property
    def chains_to_delete(self):
        """
        The set of chains to actually delete from the dataplane.  Does
        not include the chains that we need to stub out.
        """
        if self._chains_to_delete is None:
            # We'd like to get rid of these chains if we can.
            chains_we_dont_want = self.explicit_deletes | self.already_stubbed
            _log.debug("Chains we'd like to delete: %s", chains_we_dont_want)
            # But we need to keep the chains that are explicitly programmed
            # or referenced.
            chains_we_need = (set(self.prog_chains.keys()) |
                              self.referenced_chains)
            _log.debug("Chains we still need for some reason: %s",
                       chains_we_need)
            self._chains_to_delete = chains_we_dont_want - chains_we_need
            _log.debug("Chains we can delete: %s", self._chains_to_delete)
        return self._chains_to_delete

    @property
    def referenced_chains(self):
        """
        Set of chains referred to by other chains.

        Does not include chains that are explicitly programmed but not
        referenced by anything else.
        """
        return set(self.requiring_chns.keys())


def _extract_our_chains(table, raw_ipt_save_output):
    """
    Parses the output from iptables-save to extract the set of
    felix-programmed chains.
    """
    chains = set()
    current_table = None
    for line in raw_ipt_save_output.splitlines():
        line = line.strip()
        if line.startswith("*"):
            current_table = line[1:]
        elif line.startswith(":") and current_table == table:
            chain = line[1:line.index(" ")]
            if chain.startswith(FELIX_PREFIX):
                chains.add(chain)
    return chains


def _extract_our_unreffed_chains(raw_ipt_output):
    """
    Parses the output from "ip(6)tables --list" to find the set of
    felix-programmed chains that are not referenced.
    """
    chains = set()
    last_line = None
    for line in raw_ipt_output.splitlines():
        # Look for lines that look like this after a blank line.
        # Chain ufw-user-output (1 references)
        if ((not last_line or not last_line.strip()) and
                line.startswith("Chain")):
            if "policy" in line:
                _log.debug("Skipping root-level chain")
                continue
            m = re.match(r'^Chain ([^ ]+) \((\d+).+\)', line)
            assert m, "Regex failed to match Chain line %r" % line
            chain_name = m.group(1)
            ref_count = int(m.group(2))
            _log.debug("Found chain %s, ref count %s", chain_name, ref_count)
            if chain_name.startswith(FELIX_PREFIX) and ref_count == 0:
                chains.add(chain_name)
        last_line = line
    return chains


def _parse_ipt_restore_error(input_lines, err):
    """
    Parses the stderr output from an iptables-restore call.

    :param input_lines: list of lines of input that we passed to
        iptables-restore.  (Used for debugging.)
    :param str err: captures stderr from iptables-restore.
    :return tuple[bool,str]: tuple, the first (bool) element indicates
        whether the error is retryable; the second is a detail message.
    """
    match = (re.search(r"line (\d+) failed", err) or
             re.search(r"Error occurred at line: (\d+)", err))
    if match:
        # Have a line number, work out if this was a commit
        # failure, which is caused by concurrent access and is
        # retryable.
        line_number = int(match.group(1))
        _log.debug("ip(6)tables-restore failure on line %s", line_number)
        line_index = line_number - 1
        offending_line = input_lines[line_index]
        if offending_line.strip() == "COMMIT":
            return True, "COMMIT failed; likely concurrent access."
        else:
            return False, "Line %s failed: %r" % (line_number, offending_line)
    else:
        return False, "ip(6)tables-restore failed with output: %s" % err


class NothingToDo(Exception):
    pass


class IptablesInconsistent(Exception):
    pass
