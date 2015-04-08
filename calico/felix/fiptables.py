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
felix.fiptables
~~~~~~~~~~~~

IP tables management functions.
"""
from collections import defaultdict
import copy
import logging
import random
from subprocess import CalledProcessError
import time
import itertools
import re

from gevent import subprocess
import gevent

from calico.felix import frules
from calico.felix.actor import (Actor, actor_message, ResultOrExc,
                                SplitBatchAndRetry)
from calico.felix.frules import FELIX_PREFIX


_log = logging.getLogger(__name__)

_correlators = ("ipt-%s" % ii for ii in itertools.count())
MAX_IPT_RETRIES = 10
MAX_IPT_BACKOFF = 0.2


class IptablesUpdater(Actor):
    """
    Actor that maintains an iptables-restore subprocess for injecting rules
    into iptables.

    Note: due to the internal architecture of iptables, multiple concurrent
    calls to iptables-restore can clobber each other.  Use one instance of this
    class for IP v4 and one for IP v6.
    """

    queue_size = 1000
    batch_delay = 0.1

    def __init__(self, table, ip_version=4):
        super(IptablesUpdater, self).__init__(qualifier="v%d" % ip_version)
        self.table = table
        if ip_version == 4:
            self.restore_cmd = "iptables-restore"
            self.iptables_cmd = "iptables"
        else:
            assert ip_version == 6
            self.restore_cmd = "ip6tables-restore"
            self.iptables_cmd = "ip6tables"

        self.explicitly_prog_chains = set()

        self.required_chains = defaultdict(set)
        """Map from chain name to the set of chains that it depends on."""
        self.requiring_chains = defaultdict(set)
        """Map from chain to the set of chains that depend on it."""

        self._batch = None
        self._completion_callbacks = None

        self._reset_batched_work()  # Avoid duplicating init logic.

    def _reset_batched_work(self):
        self._batch = UpdateBatch(self.explicitly_prog_chains,
                                  self.required_chains,
                                  self.requiring_chains)
        self._completion_callbacks = []

    def _load_unreferenced_chains(self):
        """
        Populates the chains_in_dataplane dict with the current set of
        chains from the dataplane.
        """
        raw_ipt_output = subprocess.check_output([self.iptables_cmd, "--list",
                                                  "--table", self.table])
        return extract_unreffed_chains(raw_ipt_output)

    @actor_message()
    def rewrite_chains(self, update_calls_by_chain,
                       dependent_chains, callback=None, suppress_exc=False):
        """
        Atomically apply a set of updates to the table.

        :param update_calls_by_chain: map from chain name to list of
               iptables-style update calls,
               e.g. {"chain_name": ["-A chain_name -j ACCEPT"]}.  Chain will
               be flushed.
        :param dependent_chains: map from chain name to a set of chains
               that that chain requires to exist.  They will be created
               (with a default drop) if they don't exist.
        :returns CalledProcessError if a problem occurred.
        """
        # We actually apply the changes in _finish_msg_batch().  Index the
        # changes by table and chain.
        _log.debug("Iptables update: %s\n%s", update_calls_by_chain,
                   dependent_chains)
        for chain, updates in update_calls_by_chain.iteritems():
            # TODO: double-check whether this flush is needed.
            updates = ["--flush %s" % chain] + updates
            deps = dependent_chains.get(chain, set())
            self._batch.store_rewrite_chain(chain, updates, deps)
        if callback:
            self._completion_callbacks.append(callback)

    # Does direct table manipulation, forbid batching with other messages.
    @actor_message(needs_own_batch=True)
    def ensure_rule_inserted(self, rule_fragment):
        """
        Runs the given rule fragment, prefixed with --insert.  If the
        rule was already inserted, it is removed and reinserted at the
        start of the chain.

        This is intended to cover the start-up corner case where we need to
        insert a rule into the pre-existing kernel chains.  Most code
        should use the more robust approach of rewriting the whole chain
        using rewrite_chains().
        """
        try:
            # Make an atomic delete + insert of the rule.  If the rule already
            # exists then this will have no effect.
            self._execute_iptables(['*%s' % self.table,
                                    '--delete %s' % rule_fragment,
                                    '--insert %s' % rule_fragment,
                                    'COMMIT'])
        except CalledProcessError:
            # Assume the rule didn't exist, try inserting it.
            _log.debug("Failed to do atomic delete/insert, assuming rule "
                       "wasn't programmed.")
            self._execute_iptables(['*%s' % self.table,
                                    '--insert %s' % rule_fragment,
                                    'COMMIT'])

    @actor_message()
    def delete_chains(self, chain_names, callback=None):
        # We actually apply the changes in _finish_msg_batch().  Index the
        # changes by table and chain.
        _log.info("Deleting chains %s", chain_names)
        for chain in chain_names:
            self._batch.store_delete(chain)
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
        # TODO: Best effort and repeat to clean up now-unreffed chains
        # FIXME: until we can do best-effort, only delete unreferenced chains
        unreferenced_chains = self._load_unreferenced_chains()
        orphans = unreferenced_chains - self.explicitly_prog_chains
        # Filter out chains that are already touched by this batch.  Note:
        # We do not try to filter out chains that are referenced but not
        # explicitly programmed, we'll catch those in _finish_msg_batch()
        # and reprogram them as a stub.
        chains_to_delete = [c for c in orphans if c.startswith(FELIX_PREFIX)]
        # SMC: It'd be nice if we could do a best-effort delete on these
        # chains but that's hard to do since they'll all be processed as
        # one atomic iptables-restore.
        _log.info("Found these chains to clean up: %s", chains_to_delete)
        self.delete_chains(chains_to_delete)

    def _start_msg_batch(self, batch):
        self._reset_batched_work()
        return batch

    def _finish_msg_batch(self, batch, results):
        start = time.time()
        modify_succeeded = False
        try:
            input_lines = self._calculate_ipt_modify_input()
            self._execute_iptables(input_lines)
            modify_succeeded = True
            try:
                input_lines = self._calculate_ipt_delete_input()
            except NothingToDo:
                pass
            else:
                self._execute_iptables(input_lines)
        except CalledProcessError as e:
            if len(batch) == 1:
                # We only executed a single message, see what remedial action
                # we can take.
                try:
                    cb = self._completion_callbacks[0]
                except IndexError:
                    cb = None

                if modify_succeeded:
                    # We succeeded in modifying the chain(s) but failed to
                    # delete some chains.  The chain(s) that we were trying to
                    # delete will have been re-written as safe DROP chains.
                    # Such chains will be cleaned up next time we run cleanup.
                    #
                    # We can get here at start of day, before we've done our
                    # first cleanup.
                    _log.error("Failed to delete some chains.  Rewrote them "
                               "as stubs.")
                    e = None
                    final_result = ResultOrExc(None, None)
                    self._update_indexes()
                else:
                    _log.error("Non-retryable %s failure. RC=%s",
                               self.restore_cmd, e.returncode)
                    if batch[0].method.keywords.get("suppress_exc"):
                        final_result = ResultOrExc(None, None)
                    else:
                        final_result = ResultOrExc(None, e)
                if cb:
                    if batch[0].method.keywords.get("suppress_exc"):
                        cb(None)
                    else:
                        cb(e)
                results[0] = final_result
            else:
                _log.error("Non-retryable error from a combined batch, "
                           "splitting the batch to narrow down culprit.")
                raise SplitBatchAndRetry()
        else:
            self._update_indexes()
            for c in self._completion_callbacks:
                if c:
                    c(None)
        finally:
            self._reset_batched_work()

        end = time.time()
        _log.debug("Batch time: %.2f %s", end - start, len(batch))

    def _update_indexes(self):
        self.explicitly_prog_chains = self._batch.expl_prog_chains
        self.required_chains = self._batch.required_chns
        self.requiring_chains = self._batch.requiring_chns

    def _calculate_ipt_modify_input(self):
        """
        Calculate the input for phase 1 of a batch, where we only modify and
        create chains.
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
        input_lines = ["*%s" % self.table]
        for chain in self._batch.affected_chains:
            input_lines.append(":%s -" % chain)
        for chain_name in self._batch.chains_to_stub_out:
            input_lines.extend(_stub_drop_rules(chain_name))
        for chain_name, chain_updates in self._batch.updates.iteritems():
            input_lines.extend(chain_updates)
        input_lines.append("COMMIT")
        return input_lines

    def _calculate_ipt_delete_input(self):
        """
        Calculate the input for phase 2 of a batch, where we actually
        try to delete chains.
        """
        input_lines = []
        found_delete = False
        input_lines.append("*%s" % self.table)
        for chain_name in self._batch.chains_to_delete:
            # Delete the chain
            input_lines.append(":%s -" % chain_name)
            input_lines.append("--delete-chain %s" % chain_name)
            found_delete = True
        input_lines.append("COMMIT")
        if found_delete:
            return input_lines
        else:
            raise NothingToDo()

    def _execute_iptables(self, input_lines):
        """
        Runs ip(6)tables-restore with the given input.  Retries iff
        the COMMIT fails.

        :raises CalledProcessError: if the command fails on a non-commit
            line or if it repeatedly fails and retries are exhausted.
        """
        backoff = 0.01
        num_tries = 0
        success = False
        while not success:
            input_str = "\n".join(input_lines) + "\n"
            _log.debug("%s input:\n%s", self.restore_cmd, input_str)

            # Run iptables-restore in noflush mode so that it doesn't
            # blow away all the tables we're not touching.
            cmd = [self.restore_cmd, "--noflush", "--verbose"]
            iptables_proc = subprocess.Popen(cmd,
                                             stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)
            out, err = iptables_proc.communicate(input_str)
            rc = iptables_proc.wait()
            _log.debug("%s completed with RC=%s", self.restore_cmd, rc)
            num_tries += 1
            if rc == 0:
                success = True
            else:
                # Parse the output to determine if error is retryable.
                match = re.search(r"line (\d+) failed", err)
                if match:
                    # Have a line number, work out if this was a commit
                    # failure, which is caused by concurrent access and is
                    # retryable.
                    line_number = int(match.group(1))
                    _log.debug("%s failure on line %s", self.restore_cmd,
                               line_number)
                    line_index = line_number - 1
                    offending_line = input_lines[line_index]
                    if (num_tries < MAX_IPT_RETRIES and
                            offending_line.strip() == "COMMIT"):
                        _log.info("Failure occurred on COMMIT line, error is "
                                  "retryable. Retry in %.2fs", backoff)
                        gevent.sleep(backoff)
                        if backoff > MAX_IPT_BACKOFF:
                            backoff = MAX_IPT_BACKOFF
                        backoff *= (1.5 + random.random())
                        continue
                    elif num_tries >= MAX_IPT_RETRIES:
                        _log.error("Failed to run %s.\nOutput:\n%s\n"
                                   "Error:\n%s\nInput was:\n%s",
                                   self.restore_cmd, out, err, input_str)
                        _log.error("Out of retries.  Error occurred on line "
                                   "%s: %r", line_number, offending_line)
                    else:
                        _log.error("Failed to run %s.\nOutput:\n%s\n"
                                   "Error:\n%s\nInput was:\n%s",
                                   self.restore_cmd, out, err, input_str)
                        _log.error("Non-retryable error on line %s: %r",
                                   line_number, offending_line)
                else:
                    _log.error("%s completed with output:\n%s\n%s",
                               self.restore_cmd, out, err)
                raise CalledProcessError(cmd=cmd, returncode=rc)


class UpdateBatch(object):
    def __init__(self,
                 old_expl_prog_chains,
                 old_deps,
                 old_requiring_chains):
        # Original state, read-only.
        self.old_expl_prog_chains = old_expl_prog_chains
        self.old_requiring_chains = old_requiring_chains

        # Figure out what stub chains should already be present.
        self.already_stubbed = (set(self.old_requiring_chains.keys()) -
                                self.old_expl_prog_chains)

        # Deltas.
        self.updates = {}
        self._deletes = set()

        # New state.
        self.expl_prog_chains = copy.deepcopy(old_expl_prog_chains)
        self.required_chns = copy.deepcopy(old_deps)
        self.requiring_chns = copy.deepcopy(old_requiring_chains)

        self._chains_to_stub = None

    def store_delete(self, chain):
        _log.debug("Storing delete of chain %s", chain)
        assert chain is not None
        # Clean up dependency index.
        self._update_deps(chain, set())
        # Mark for deletion.
        self._deletes.add(chain)
        # Remove any now-stale rewrite state.
        self.updates.pop(chain, None)
        self.expl_prog_chains.discard(chain)
        self._chains_to_stub = None  # Defensive, this is now out-of-date

    def store_rewrite_chain(self, chain, updates, dependencies):
        _log.debug("Storing updates to chain %s", chain)
        assert chain is not None
        assert updates is not None
        assert dependencies is not None
        # Clean up reverse dependency index.
        self._update_deps(chain, dependencies)
        # Remove any deletion, if present.
        self._deletes.discard(chain)
        # Store off the update.
        self.updates[chain] = updates
        self.expl_prog_chains.add(chain)
        self._chains_to_stub = None  # Defensive, this is now out-of-date

    def _update_deps(self, chain, new_deps):
        # Remove all the old deps.
        old_deps = self.required_chns.get(chain, set())
        for dependency in old_deps:
            self.requiring_chns[dependency].discard(chain)
            if not self.requiring_chns[dependency]:
                del self.requiring_chns[dependency]
        # Add in the new.
        for dependency in new_deps:
            self.requiring_chns[dependency].add(chain)
        self.required_chns[chain] = new_deps

    @property
    def affected_chains(self):
        updates = set(self.updates.keys())
        stubs = self.chains_to_stub_out
        _log.debug("Affected chains: deletes=%s, updates=%s, stubs=%s",
                   self._deletes, updates, stubs)
        return self._deletes | updates | stubs

    @property
    def chains_to_stub_out(self):
        """
        Calculates the set of chains that now need to be stubbed.
        """
        if self._chains_to_stub is not None:
            return self._chains_to_stub
        all_required_chains = set(self.requiring_chns.keys())
        # Don't stub out chains that we're now explicitly programming.
        impl_required_chains = all_required_chains - self.expl_prog_chains
        chains_to_stub = impl_required_chains - self.already_stubbed
        self._chains_to_stub = chains_to_stub
        return chains_to_stub

    @property
    def chains_to_delete(self):
        chains_we_dont_want = self._deletes | self.already_stubbed
        chains_we_need = self.chains_to_stub_out | self.expl_prog_chains
        return chains_we_dont_want - chains_we_need


def _stub_drop_rules(chain):
    """
    :return: List of rule fragments to replace the given chain with a
        single drop rule.
    """
    return ["--flush %s" % chain,
            frules.commented_drop_fragment(chain,
                                           'WARNING Missing chain DROP:')]


def extract_unreffed_chains(raw_save_output):
    """
    Parses the output from iptables-save to extract the set of
    unreferenced chains, which should be safe to delete.
    """
    chains = set()
    last_line = None
    for line in raw_save_output.splitlines():
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
            if ref_count == 0:
                chains.add(chain_name)
        last_line = line
    return chains


class NothingToDo(Exception):
    pass
