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
felix.dispatch
~~~~~~~~~~~~~~

Actor that controls the top-level dispatch chains that dispatch to
per-endpoint chains.
"""
from collections import defaultdict
import logging
from calico.felix.actor import Actor, actor_message, wait_and_check
from calico.felix.frules import (
    CHAIN_TO_PREFIX, CHAIN_FROM_PREFIX, interface_to_chain_suffix,
    WORKLOAD_DISPATCH_CHAINS,
    HOST_DISPATCH_CHAINS)
from calico.felix.futils import find_longest_prefix

_log = logging.getLogger(__name__)


class _DispatchChains(Actor):
    """
    Actor that owns the felix-TO/FROM-xxx chains, which we use to
    dispatch to endpoint/iface-specific chains.

    Endpoint Actors give us kicks as they come and go so we can
    add/remove them from the chains.
    """

    chain_names = None

    def __init__(self, config, ip_version, iptables_updater):
        super(_DispatchChains, self).__init__(qualifier="v%d" % ip_version)
        self.config = config
        self.ip_version = ip_version
        self.iptables_updater = iptables_updater
        self.iptables_generator = self.config.plugins["iptables_generator"]
        self.chain_to_root = self.chain_names["to_root"]
        self.chain_from_root = self.chain_names["from_root"]
        self.chain_to_leaf = self.chain_names["to_leaf"]
        self.chain_from_leaf = self.chain_names["from_leaf"]
        self.ifaces = set()
        self.programmed_leaf_chains = set()
        self._dirty = False
        self._datamodel_in_sync = False

    @actor_message()
    def apply_snapshot(self, ifaces):
        """
        Replaces all known interfaces with the given snapshot and rewrites the
        chain.

        :param set[str] ifaces: The interface
        """
        _log.info("Applying dispatch chains snapshot.")
        self.ifaces = set(ifaces)  # Take a copy.
        # Always reprogram the chain, even if it's empty.  This makes sure that
        # we resync and it stops the iptables layer from marking our chain as
        # missing.
        self._dirty = True

        if not self._datamodel_in_sync:
            _log.info("Datamodel in sync, unblocking dispatch chain updates")
            self._datamodel_in_sync = True

    @actor_message()
    def on_endpoint_added(self, iface_name):
        """
        Message sent to us by the WorkloadEndpoint to tell us we should
        add it to the dispatch chain.

        Idempotent: does nothing if the mapping is already in the
        chain.

        :param iface_name: name of the linux interface.
        """
        _log.debug("%s ready: %s", self, iface_name)
        if iface_name in self.ifaces:
            return

        self.ifaces.add(iface_name)
        self._dirty = True

    @actor_message()
    def on_endpoint_removed(self, iface_name):
        """
        Removes the mapping for the given interface name.

        Idempotent: does nothing if there is no mapping.
        """
        _log.debug("%s asked to remove dispatch rule %s", self, iface_name)
        # It should be present but be defensive and reprogram the chain
        # just in case if not.
        try:
            self.ifaces.remove(iface_name)
        except KeyError:
            _log.warning(
                'Attempted to remove unmanaged interface %s', iface_name
            )
        else:
            self._dirty = True

    def _finish_msg_batch(self, batch, results):
        if self._dirty and self._datamodel_in_sync:
            _log.debug("Interface mapping changed, reprogramming chains.")
            self._reprogram_chains()
            self._dirty = False

    def _calculate_update(self, ifaces):
        """
        Calculates the iptables update to rewrite our chains.

        To avoid traversing lots of dispatch rules to find the right one,
        we build a tree of chains.  Currently, the tree can only be
        two layers deep: a root chain and a layer of leaves.

        Interface names look like this: "prefix1234abc".  The "prefix"
        part is always the same so we ignore it.  We call "1234abc", the
        "suffix".

        The root chain contains two sorts of rules:

        * where there are multiple interfaces whose suffixes start with
          the same character, it contains a rule that matches on
          that prefix of the "suffix"(!) and directs the packet to a
          leaf chain for that prefix.

        * as an optimization, if there is only one interface whose
          suffix starts with a given character, it contains a dispatch
          rule for that exact interface name.

        For example, if we have interface names "tapA1" "tapB1" "tapB2",
        we'll get (in pseudo code):

        Root chain:

        if interface=="tapA1" then goto chain for endpoint tapA1
        if interface.startswith("tapB") then goto leaf chain for prefix "tapB"

        tapB leaf chain:

        if interface=="tapB1" then goto chain for endpoint tapB1
        if interface=="tapB2" then goto chain for endpoint tapB2

        :param set[str] ifaces: The list of interfaces to generate a
            dispatch chain for.
        :returns Tuple: to_delete, deps, updates, new_leaf_chains:

            * set of leaf chains that are no longer needed for deletion
            * chain dependency dict.
            * chain updates dict.
            * complete set of leaf chains that are now required.
        """

        # iptables update fragments/dependencies for the root chains.
        updates = defaultdict(list)
        root_to_upds = updates[self.chain_to_root]
        root_from_upds = updates[self.chain_from_root]

        dependencies = defaultdict(set)
        root_to_deps = dependencies[self.chain_to_root]
        root_from_deps = dependencies[self.chain_from_root]

        # Separate the interface names by their prefixes so we can count them
        # and decide whether to program a leaf chain or not.
        interfaces_by_prefix = defaultdict(set)
        iface_prefix = find_longest_prefix(ifaces)
        for iface in ifaces:
            ep_suffix = iface[len(iface_prefix):]
            prefix = ep_suffix[:1]
            interfaces_by_prefix[prefix].add(iface)

        # Spin through the interfaces by prefix.  Either add them directly
        # to the root chain or create a leaf and add them there.
        new_leaf_chains = set()
        for prefix, interfaces in interfaces_by_prefix.iteritems():
            use_root_chain = len(interfaces) == 1
            if use_root_chain:
                # Optimization: there's only one interface with this prefix,
                # don't program a leaf chain.
                disp_to_chain = self.chain_to_root
                disp_from_chain = self.chain_from_root
                to_deps = root_to_deps
                from_deps = root_from_deps
                to_upds = root_to_upds
                from_upds = root_from_upds
            else:
                # There's more than one interface with this prefix, program
                # a leaf chain.
                disp_to_chain = self.chain_to_leaf + "-" + prefix
                disp_from_chain = self.chain_from_leaf + "-" + prefix
                to_upds = updates[disp_to_chain]
                from_upds = updates[disp_from_chain]
                to_deps = dependencies[disp_to_chain]
                from_deps = dependencies[disp_from_chain]
                new_leaf_chains.add(disp_from_chain)
                new_leaf_chains.add(disp_to_chain)
                # Root chain depends on its leaves.
                root_from_deps.add(disp_to_chain)
                root_to_deps.add(disp_from_chain)
                # Point root chain at prefix chain.
                iface_match = iface_prefix + prefix + "+"
                root_from_upds.append(
                    "--append %s --in-interface %s --goto %s" %
                    (self.chain_from_root, iface_match, disp_from_chain)
                )
                root_to_upds.append(
                    "--append %s --out-interface %s --goto %s" %
                    (self.chain_to_root, iface_match, disp_to_chain)
                )

            # Common processing, add the per-endpoint rules to whichever
            # chain we decided above.
            for iface in interfaces:
                # Add rule to leaf or global chain to direct traffic to the
                # endpoint-specific one.  Note that we use --goto, which means
                # that the endpoint-specific chain will return to our parent
                # rather than to this chain.
                ep_suffix = interface_to_chain_suffix(self.config, iface)

                to_chain_name = CHAIN_TO_PREFIX + ep_suffix
                from_chain_name = CHAIN_FROM_PREFIX + ep_suffix

                from_upds.append("--append %s --in-interface %s --goto %s" %
                                 (disp_from_chain, iface, from_chain_name))
                from_deps.add(from_chain_name)
                to_upds.append("--append %s --out-interface %s --goto %s" %
                               (disp_to_chain, iface, to_chain_name))
                to_deps.add(to_chain_name)

            if not use_root_chain:
                # Add a default drop to the end of the leaf chain.
                # Add a default drop to the end of the leaf chain.
                from_upds.extend(
                    self.end_of_chain_rules(disp_from_chain, "From"))
                to_upds.extend(
                    self.end_of_chain_rules(disp_to_chain, "To"))

        # Both TO and FROM chains end with a DROP so that interfaces that
        # we don't know about yet can't bypass our rules.
        root_from_upds.extend(
            self.end_of_chain_rules(self.chain_from_root, "From"))
        root_to_upds.extend(
            self.end_of_chain_rules(self.chain_to_root, "To"))

        chains_to_delete = self.programmed_leaf_chains - new_leaf_chains
        _log.debug("New chains: %s; to delete: %s",
                   new_leaf_chains, chains_to_delete)

        return chains_to_delete, dependencies, updates, new_leaf_chains

    def end_of_chain_rules(self, chain_name, direction):
        raise NotImplementedError()  # pragma: no cover

    def _reprogram_chains(self):
        """
        Recalculates the chains and writes them to iptables.

        Synchronous, doesn't return until the chain is in place.
        """
        _log.info("%s Updating dispatch chain, num entries: %s", self,
                  len(self.ifaces))
        update = self._calculate_update(self.ifaces)
        to_delete, deps, updates, new_leaf_chains = update
        futures = [
            self.iptables_updater.rewrite_chains(updates, deps,
                                                 async=True),
            self.iptables_updater.delete_chains(to_delete,
                                                async=True),
        ]
        wait_and_check(futures)

        # Track our chains so we can clean them up.
        self.programmed_leaf_chains = new_leaf_chains

    def __str__(self):
        return (
            self.__class__.__name__ + "<ipv%s,entries=%s>" %
            (self.ip_version, len(self.ifaces))
        )


class WorkloadDispatchChains(_DispatchChains):
    """Chains for dispatching to workload endpoint chains.

    Packets that do not match a known endpoint are dropped.
    """
    chain_names = WORKLOAD_DISPATCH_CHAINS

    def end_of_chain_rules(self, chain_name, direction):
        # For workload chains, we want to drop traffic if it is from/to an
        # unknown workload so we put a default drop at the end of the chain.
        return self.iptables_generator.drop_rules(
            self.ip_version,
            chain_name,
            None,
            "%s unknown endpoint" % direction)


class HostEndpointDispatchChains(_DispatchChains):
    """Chains for dispatching to host endpoint chains.

    Packets that do not match a known endpoint are returned.

    Users must call configure_iptables() at start-of-day or graceful restart
    will fail.
    """
    chain_names = HOST_DISPATCH_CHAINS

    @actor_message()
    def configure_iptables(self):
        missing_from_chain_rules = [
            '--append %s --jump RETURN --match comment '
            '--comment "Not ready yet, allowing host traffic"' %
            self.chain_from_root
        ]
        self.iptables_updater.set_missing_chain_override(
            self.chain_from_root,
            missing_from_chain_rules,
            async=True
        )
        missing_to_chain_rules = [
            '--append %s --jump RETURN --match comment '
            '--comment "Not ready yet, allowing host traffic"' %
            self.chain_to_root
        ]
        self.iptables_updater.set_missing_chain_override(
            self.chain_to_root,
            missing_to_chain_rules,
            async=True
        )

    def end_of_chain_rules(self, chain_name, direction):
        # For host endpoints, we only configure the interfaces we've been
        # asked to and then we defer to the host's remaining iptables rules
        # for unknown interfaces.
        return ['--append %s --jump RETURN --match comment '
                '--comment "Unknown interface, return"' %
                chain_name]
