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
import functools
import logging
import random
from subprocess import CalledProcessError
import time
import itertools
from calico.felix import frules

from calico.felix.actor import Actor, actor_event, ResultOrExc, SplitBatchAndRetry
from calico.felix.frules import (CHAIN_TO_ENDPOINT,
                                 CHAIN_FROM_ENDPOINT)
from gevent import subprocess
import gevent
import re
from types import StringTypes


_log = logging.getLogger(__name__)


class DispatchChains(Actor):
    """
    Actor that owns the felix-TO/FROM-ENDPOINT chains, which we use to
    dispatch to endpoint-specific chains.

    LocalEndpoint Actors give us kicks as they come and go so we can
    add/remove them from the chains.
    """

    queue_size = 1000
    batch_delay = 0.1

    def __init__(self, config, ip_version, iptables_updater):
        super(DispatchChains, self).__init__(qualifier="v%d" % ip_version)
        self.config = config
        self.ip_version = ip_version
        self.iptables_updater = iptables_updater
        self.iface_to_ep_id = {}
        self._dirty = False

    @actor_event
    def on_endpoint_added(self, iface_name, endpoint_id):
        """
        Message sent to us by the LocalEndpoint to tell us its
        endpoint-specific chain is in place and we should add it
        to the dispatch chain.

        :param iface_name: name of the linux interface.
        :param endpoint_id: ID of the endpoint, used to form the chain names.
        """
        _log.debug("%s ready: %s/%s", self, iface_name, endpoint_id)
        if self.iface_to_ep_id.get(iface_name) != endpoint_id:
            self.iface_to_ep_id[iface_name] = endpoint_id
            self._dirty = True

    @actor_event
    def on_endpoint_removed(self, iface_name):
        _log.debug("%s asked to remove dispatch rule %s", self, iface_name)
        # It should be present but be defensive and reprogram the chain
        # just in case if not.
        self.iface_to_ep_id.pop(iface_name, None)
        self._dirty = True

    def _finish_msg_batch(self, batch, results):
        if self._dirty:
            self._update_chains()
            self._dirty = False

    def _update_chains(self):
        _log.info("%s Updating dispatch chain, num entries: %s", self,
                  len(self.iface_to_ep_id))
        to_upds = []
        from_upds = []
        updates = {CHAIN_TO_ENDPOINT: to_upds,
                   CHAIN_FROM_ENDPOINT: from_upds}
        to_deps = set()
        from_deps = set()
        dependencies = {CHAIN_TO_ENDPOINT: to_deps,
                        CHAIN_FROM_ENDPOINT: from_deps}
        from calico.felix.endpoint import chain_names, interface_to_suffix
        for iface in self.iface_to_ep_id:
            # Add rule to global chain to direct traffic to the
            # endpoint-specific one.  Note that we use --goto, which means
            # that the endpoint-specific chain will return to our parent
            # rather than to this chain.
            ep_suffix = interface_to_suffix(self.config, iface)
            to_chain_name, from_chain_name = chain_names(ep_suffix)
            from_upds.append("--append %s --in-interface %s --goto %s" %
                             (CHAIN_FROM_ENDPOINT, iface, from_chain_name))
            from_deps.add(from_chain_name)
            to_upds.append("--append %s --out-interface %s --goto %s" %
                           (CHAIN_TO_ENDPOINT, iface, to_chain_name))
            to_deps.add(to_chain_name)
        to_upds.append("--append %s --jump DROP" % CHAIN_TO_ENDPOINT)
        from_upds.append("--append %s --jump DROP" % CHAIN_FROM_ENDPOINT)
        self.iptables_updater.rewrite_chains("filter", updates, dependencies,
                                             async=False)

    def __str__(self):
        return self.__class__.__name__ + "<ipv%s,entries=%s>" % \
            (self.ip_version, len(self.iface_to_ep_id))


_correlators = ("ipt-%s" % ii for ii in itertools.count())
MAX_IPT_RETRIES = 10
MAX_IPT_BACKOFF = 0.2


def _stub_drop_rules(chain):
    return ["--flush %s" % chain,
            frules.commented_drop_fragment(chain,
                                           'WARNING Missing chain DROP:')]


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

    def __init__(self, ip_version=4):
        super(IptablesUpdater, self).__init__(qualifier="v%d" % ip_version)
        if ip_version == 4:
            self.restore_cmd = "iptables-restore"
            self.save_cmd = "iptables-save"
        else:
            assert ip_version == 6
            self.restore_cmd = "ip6tables-restore"
            self.save_cmd = "ip6tables-save"

        self.chains_in_dataplane = defaultdict(set)
        """Mapping from table to set of present chains.  Loaded at start
           of day and then kept in sync."""

        self.explicitly_programmed_chains = defaultdict(set)

        self.required_chains = defaultdict(lambda: defaultdict(set))
        """Map from table to map from chain to the set of chains that it
           depends on."""
        self.requiring_chains = defaultdict(lambda: defaultdict(set))
        """Map from chain to the set of chains that depend on it."""

        # Structures managing batches.  The first three objects are all default
        # dicts keyed on table. The value stored is as follows.
        #
        # bch_affected_chains : set of chains in this batch
        # bch_updates : defaultdict mapping chain to list of updates for that
        #               chain or None to indicate a deletion.
        # bch_dependencies : defaultdict mapping chain to set of chains which
        #                    that chain requires to exist
        #

        # PLW: Surely better to combine these three and the next two into one
        # single structure keyed on table? Think that would be more readable,
        # so you do the table lookup once rather than have to do it every time
        # on every single one of these five objects - especially in the 99%
        # case where the table is the same for the entire batch. I'd actually
        # even go further and say to put all the objects which are default
        # dicts based on table into a single structure; think that would be way
        # easier to read and manage.
        self.bch_affected_chains = None
        self.bch_updates = None
        self.bch_dependencies = None

        # default dict from table to set of explicitly programmed chains,
        self.bch_new_expl_prog_chains = None
        # default dict from table to another default dict, which in turn maps
        # from chain to set of chains that explicitly depend on it (i.e. the
        # inverse of bch_dependencies above)
        self.bch_requiring_chain_upds = None

        self.completion_callbacks = None
        self._reset_batched_work()  # Avoid duplicating init logic.

        self._load_from_dataplane()

    def _reset_batched_work(self):
        self.bch_affected_chains = defaultdict(set)
        self.bch_updates = defaultdict(dict)
        self.bch_dependencies = defaultdict(lambda: defaultdict(set))
        self.bch_new_expl_prog_chains = None
        self.bch_requiring_chain_upds = None

        self.completion_callbacks = []

    def _load_from_dataplane(self):
        """
        Populates the chains_in_dataplane dict with the current set of
        chains from the dataplane.
        """
        raw_save_output = subprocess.check_output([self.save_cmd])
        new_chains = parse_ipt_save(raw_save_output)
        self.chains_in_dataplane = new_chains

    @actor_event
    def rewrite_chains(self, table_name, update_calls_by_chain,
                       dependent_chains, callback=None, suppress_exc=False):
        """
        Atomically apply a set of updates to an iptables table.

        :param table_name: one of "raw" "mangle" "filter" "nat".
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
            self.bch_affected_chains[table_name].add(chain)
            deps = dependent_chains.get(chain, set([]))
            self.bch_dependencies[table_name][chain] = deps
            updates = ["--flush %s" % chain] + updates
            self.bch_updates[table_name][chain] = updates
        if callback:
            self.completion_callbacks.append(callback)

    @actor_event
    def ensure_rule_inserted(self, table, rule_fragment):
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
            self._execute_iptables(['*%s' % table,
                                    '--delete %s' % rule_fragment,
                                    '--insert %s' % rule_fragment,
                                    'COMMIT'])
        except CalledProcessError:
            # Assume the rule didn't exist, try inserting it.
            _log.debug("Failed to do atomic delete/insert, assuming rule "
                       "wasn't programmed.")
            self._execute_iptables(['*%s' % table,
                                    '--insert %s' % rule_fragment,
                                    'COMMIT'])

    @actor_event
    def delete_chains(self, table_name, chain_names, callback=None):
        # We actually apply the changes in _finish_msg_batch().  Index the
        # changes by table and chain.
        _log.info("Deleting chains %s:%s", table_name, chain_names)
        # Put an explicit None in the index to mark it for deletion.
        self.bch_affected_chains[table_name].update(chain_names)
        for chain_name in chain_names:
            self.bch_updates[table_name][chain_name] = None
            self.bch_dependencies[table_name][chain_name] = set()
        if callback:
            self.completion_callbacks.append(callback)

    def _start_msg_batch(self, batch):
        self._reset_batched_work()
        return batch

    def _finish_msg_batch(self, batch, results):
        start = time.time()

        try:
            self._calculate_index_changes()
            input_lines = self._calculate_ipt_input()
            self._execute_iptables(input_lines)
        except CalledProcessError as e:
            if len(batch) == 1:
                _log.error("Non-retryable %s failure. RC=%s", self.restore_cmd,
                           e.returncode)
                cb = self.completion_callbacks[0]
                if batch[0].method.keywords.get("suppress_exc"):
                    final_result = ResultOrExc(None, None)
                else:
                    final_result = ResultOrExc(None, e)
                if cb:
                    if batch[0].method.keywords.get("suppress_exc"):
                        gevent.spawn(cb, None)
                    else:
                        gevent.spawn(e, None)
                results[0] = final_result
            else:
                _log.error("Non-retryable error from a combined batch, "
                           "splitting the batch to narrow down culprit.")
                raise SplitBatchAndRetry()
        else:
            self._update_indexes()
            for c in self.completion_callbacks:
                if c:
                    c(None)
        finally:
            self._reset_batched_work()

        end = time.time()
        _log.debug("Batch time: %.2f %s", end - start, len(batch))

    def _calculate_index_changes(self):
        # Stage 1: Calculate the new (complete) set of explicitly-programmed
        # chains.  We'll use it below to decide
        # - whether we need to write a stub chain for a required chain.
        # - whether it's safe to delete a chain that's no longer referenced.
        new_expl_prog_chains = defaultdict(
            set,
            self.explicitly_programmed_chains)
        for table, table_upds in self.bch_updates.iteritems():
            for chain, upds in table_upds.iteritems():
                if upds is not None:
                    new_expl_prog_chains[table].add(chain)
                else:
                    new_expl_prog_chains[table].discard(chain)
        self.bch_new_expl_prog_chains = new_expl_prog_chains

        # Stage 2: Calculate the changes to the reverse index that tracks
        # which chains refer to a particular chain.  We use this to determine
        # when a chain is no longer referenced and may be cleaned up.
        bch_reqrng_chns = defaultdict(lambda: defaultdict(set))
        for table in self.bch_dependencies:
            for chain, new_deps in self.bch_dependencies[table].iteritems():
                # Make sure that any required chains are already present or
                # are going to be programmed.
                for dep in new_deps:
                    bch_updates = self.bch_updates[table]
                    if dep not in new_expl_prog_chains[table]:
                        # Dependency isn't explicitly programmed, write a
                        # stub chain in its place.  Note: this may overwrite
                        # a deletion of that chain.
                        bch_updates[dep] = _stub_drop_rules(dep)
                        self.bch_affected_chains[table].add(dep)
                # Calculate updates to our index of requiring chains.  If any
                # of the requiring chain sets become empty, we may GC that
                # chain.
                old_deps = self.required_chains[table][chain]
                added_deps = new_deps - old_deps
                removed_deps = old_deps - new_deps
                old_req_chns = self.requiring_chains[table]
                for added_dep in added_deps:
                    if added_dep not in bch_reqrng_chns[table]:
                        bch_reqrng_chns[table][added_dep] = \
                            old_req_chns.get(added_dep, set())
                    bch_reqrng_chns[table][added_dep].add(chain)
                for removed in removed_deps:
                    if removed not in bch_reqrng_chns[table]:
                        bch_reqrng_chns[table][removed] = \
                            old_req_chns.get(removed, set())
                    bch_reqrng_chns[table][removed].discard(chain)

        # Stage 3: look for any chains that we've been asked to delete but
        # which are still required as dependencies.
        for table, table_upds in self.bch_updates.iteritems():
            for chain, upds in table_upds.iteritems():
                if upds is None:
                    # Deletion for this chain, check that no-one else requires
                    # it.
                    if ((chain in bch_reqrng_chns[table] and
                         bch_reqrng_chns[table][chain]) or
                        (chain not in bch_reqrng_chns[table] and
                         chain in self.requiring_chains[table] and
                         self.requiring_chains[table][chain])):
                        # Chain is required, swap out the deletion operation
                        # for a stub DROP chain.
                        table_upds[chain] = _stub_drop_rules(chain)

        # Stage 4: queue updates for chains that are no longer required.
        for table in bch_reqrng_chns:
            bch_updts = self.bch_updates[table]
            for chain, reqing_chns in bch_reqrng_chns[table].iteritems():
                if (not reqing_chns and
                        chain not in new_expl_prog_chains[table]):
                    # Nothing depends on this chain and we haven't been told
                    # to program it explicitly, clean it up.
                    bch_updts[chain] = None
                    self.bch_affected_chains[table].add(chain)

        self.bch_requiring_chain_upds = bch_reqrng_chns

    def _update_indexes(self):
        self.explicitly_programmed_chains = self.bch_new_expl_prog_chains
        for table in self.bch_requiring_chain_upds:
            for chain, reqng_chains in self.bch_requiring_chain_upds[table].iteritems():
                if reqng_chains:
                    self.requiring_chains[table][chain] = reqng_chains
                else:
                    self.requiring_chains[table].pop(chain, None)
        for table, chain_to_deps in self.bch_dependencies.iteritems():
            for chain, deps in chain_to_deps.iteritems():
                if deps:
                    self.required_chains[table][chain] = deps
                else:
                    self.required_chains[table].pop(chain, None)
        for table, table_upds in self.bch_updates.iteritems():
            for chain, upds in table_upds.iteritems():
                if upds is None:
                    self.chains_in_dataplane[table].discard(chain)
                else:
                    self.chains_in_dataplane[table].add(chain)

    def _calculate_ipt_input(self):
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
        for table, chains in self.bch_updates.iteritems():
            input_lines.append("*%s" % table)
            for c in self.bch_affected_chains[table]:
                input_lines.append(":%s -" % c if isinstance(c, StringTypes)
                                               else ":%s %s" % c)
            for chain_name, chain_updates in chains.iteritems():
                if chain_updates is None:
                    # Delete the chain
                    input_lines.append("--delete-chain %s" % chain_name)
                else:
                    input_lines.extend(chain_updates)
            input_lines.append("COMMIT")
        return input_lines

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
                raise CalledProcessError(cmd=cmd, returncode=rc)


def parse_ipt_save(raw_save_output):
    """
    Parses the output from iptables-save to extract the set of
    currently-active chains.
    :return: dict mapping table name to set of chain names in that table.
    """
    chains = defaultdict(set)
    table = None
    for line in raw_save_output.splitlines():
        if line.startswith("*"):
            table_name = line[1:]
            table = chains[table_name]
        if line.startswith(":"):
            chain_name = line[1:].split(" ")[0]
            table.add(chain_name)
    return chains
