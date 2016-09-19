# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
# Copyright (c) 2015 Cisco Systems.  All Rights Reserved.
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
felix.endpoint
~~~~~~~~~~~~~~

Endpoint management.
"""
from collections import OrderedDict, defaultdict
import logging

import gevent
import sys
from netaddr.ip.sets import IPSet

from calico.calcollections import MultiDict
from calico.common import nat_key
from calico.datamodel_v1 import (
    ENDPOINT_STATUS_UP, ENDPOINT_STATUS_DOWN, ENDPOINT_STATUS_ERROR,
    WloadEndpointId, ResolvedHostEndpointId)
from calico.felix import devices, futils
from calico.felix.actor import actor_message
from calico.felix.futils import FailedSystemCall
from calico.felix.futils import IPV4, IP_TYPE_TO_VERSION
from calico.felix.labels import LabelValueIndex, LabelInheritanceIndex
from calico.felix.refcount import ReferenceManager, RefCountedActor, RefHelper
from calico.felix.profilerules import RulesManager
from calico.felix.frules import interface_to_chain_suffix

_log = logging.getLogger(__name__)


class EndpointManager(ReferenceManager):
    def __init__(self, config, ip_type,
                 iptables_updater,
                 workload_disp_chains,
                 host_disp_chains,
                 rules_manager,
                 fip_manager,
                 status_reporter):
        super(EndpointManager, self).__init__(qualifier=ip_type)

        # Configuration and version to use
        self.config = config
        self.ip_type = ip_type
        self.ip_version = futils.IP_TYPE_TO_VERSION[ip_type]

        # Peers/utility classes.
        self.iptables_updater = iptables_updater
        self.workload_disp_chains = workload_disp_chains
        self.host_disp_chains = host_disp_chains
        self.rules_mgr = rules_manager
        self.status_reporter = status_reporter
        self.fip_manager = fip_manager

        # All endpoint dicts that are on this host.
        self.endpoints_by_id = {}
        # Dict that maps from interface name ("tap1234") to endpoint ID.
        self.endpoint_id_by_iface_name = {}

        # Cache of IPs applied to host endpoints.  (I.e. any interfaces that
        # aren't workload interfaces.)
        self.host_ep_ips_by_iface = {}
        # Host interface dicts by ID.  We'll resolve these with the IPs above
        # and inject the (resolved) ones as endpoints.
        self.host_eps_by_id = {}
        # Cache of interfaces that we've resolved and injected as endpoints.
        self.resolved_host_eps = {}

        # Set of endpoints that are live on this host.  I.e. ones that we've
        # increffed.
        self.local_endpoint_ids = set()

        # Index tracking what policy applies to what endpoints.
        self.policy_index = LabelValueIndex()
        self.policy_index.on_match_started = self.on_policy_match_started
        self.policy_index.on_match_stopped = self.on_policy_match_stopped
        self._label_inherit_idx = LabelInheritanceIndex(self.policy_index)
        # Tier orders by tier ID.  We use this to look up the order when we're
        # sorting the tiers.
        self.tier_orders = {}
        # Cache of the current ordering of tier IDs.
        self.tier_sequence = []
        # And their associated orders.
        self.profile_orders = {}
        # Set of profile IDs to apply to each endpoint ID.
        self.pol_ids_by_ep_id = MultiDict()
        self.endpoints_with_dirty_policy = set()

        self._data_model_in_sync = False
        self._iface_poll_greenlet = gevent.Greenlet(self._interface_poll_loop)
        self._iface_poll_greenlet.link_exception(self._on_worker_died)

    def _on_actor_started(self):
        _log.info("Endpoint manager started, spawning interface poll worker.")
        self._iface_poll_greenlet.start()

    def _create(self, combined_id):
        """
        Overrides ReferenceManager._create()
        """
        if isinstance(combined_id, WloadEndpointId):
            return WorkloadEndpoint(self.config,
                                    combined_id,
                                    self.ip_type,
                                    self.iptables_updater,
                                    self.workload_disp_chains,
                                    self.rules_mgr,
                                    self.fip_manager,
                                    self.status_reporter)
        elif isinstance(combined_id, ResolvedHostEndpointId):
            return HostEndpoint(self.config,
                                combined_id,
                                self.ip_type,
                                self.iptables_updater,
                                self.host_disp_chains,
                                self.rules_mgr,
                                self.fip_manager,
                                self.status_reporter)
        else:
            raise RuntimeError("Unknown ID type: %s" % combined_id)

    @actor_message()
    def on_tier_data_update(self, tier, data):
        """
        Message received when the metadata for a policy tier is updated
        in etcd.

        :param str tier: The name of the tier.
        :param dict|NoneType data: The dict or None, for a deletion.
        """
        _log.debug("Data for policy tier %s updated to %s", tier, data)

        # Currently, the only data we care about is the order.
        order = None if data is None else data["order"]
        if self.tier_orders.get(tier) == order:
            _log.debug("No change, ignoring")
            return

        if order is not None:
            self.tier_orders[tier] = order
        else:
            del self.tier_orders[tier]

        new_tier_sequence = sorted(self.tier_orders.iterkeys(),
                                   key=lambda k: (self.tier_orders[k], k))
        if self.tier_sequence != new_tier_sequence:
            _log.info("Sequence of profile tiers changed, refreshing all "
                      "endpoints")
            self.tier_sequence = new_tier_sequence
            self.endpoints_with_dirty_policy.update(
                self.endpoints_by_id.keys()
            )
            self._update_dirty_policy()

    @actor_message()
    def on_prof_labels_set(self, profile_id, labels):
        _log.debug("Profile labels updated for %s: %s", profile_id, labels)
        # Defer to the label index, which will call us back synchronously
        # with any match changes.
        self._label_inherit_idx.on_parent_labels_update(profile_id, labels)
        # Process any match changes that we've recorded in the callbacks.
        self._update_dirty_policy()

    @actor_message()
    def on_policy_selector_update(self, policy_id, selector_or_none,
                                  order_or_none):
        _log.debug("Policy %s selector updated to %s (%s)", policy_id,
                   selector_or_none, order_or_none)
        # Defer to the label index, which will call us back synchronously
        # via on_policy_match_started and on_policy_match_stopped.
        self.policy_index.on_expression_update(policy_id,
                                               selector_or_none)

        # Before we update the policies, check if the order has changed,
        # which would mean we need to refresh all endpoints with this policy
        # too.
        if order_or_none != self.profile_orders.get(policy_id):
            if order_or_none is not None:
                self.profile_orders[policy_id] = order_or_none
            else:
                del self.profile_orders[policy_id]
            self.endpoints_with_dirty_policy.update(
                self.policy_index.matches_by_expr_id.iter_values(policy_id)
            )

        # Finally, flush any updates to our waiting endpoints.
        self._update_dirty_policy()

    def on_policy_match_started(self, expr_id, item_id):
        """Called by the label index when a new match is started.

        Records the update but processing is deferred to
        the next call to self._update_dirty_policy().
        """
        _log.info("Policy %s now applies to endpoint %s", expr_id, item_id)
        self.pol_ids_by_ep_id.add(item_id, expr_id)
        self.endpoints_with_dirty_policy.add(item_id)

    def on_policy_match_stopped(self, expr_id, item_id):
        """Called by the label index when a match stops.

        Records the update but processing is deferred to
        the next call to self._update_dirty_policy().
        """
        _log.info("Policy %s no longer applies to endpoint %s",
                  expr_id, item_id)
        self.pol_ids_by_ep_id.discard(item_id, expr_id)
        self.endpoints_with_dirty_policy.add(item_id)

    def _on_object_started(self, endpoint_id, obj):
        """
        Callback from a LocalEndpoint to report that it has started.
        Overrides ReferenceManager._on_object_started
        """
        ep = self.endpoints_by_id.get(endpoint_id)
        obj.on_endpoint_update(ep, async=True)
        self._update_tiered_policy(endpoint_id)

    @actor_message()
    def on_datamodel_in_sync(self):
        if not self._data_model_in_sync:
            _log.info("%s: First time we've been in-sync with the datamodel,"
                      "sending snapshot to DispatchChains and FIPManager.",
                      self)
            self._data_model_in_sync = True

            # Tell the dispatch chains about the local endpoints in advance so
            # that we don't flap the dispatch chain at start-of-day.  Note:
            # the snapshot may contain information that is ahead of the
            # state that our individual LocalEndpoint actors are sending to the
            # DispatchChains actor.  That is OK!  The worst that can happen is
            # that a LocalEndpoint undoes part of our update and then goes on
            # to re-apply the update when it catches up to the snapshot.
            workload_ifaces = set()
            host_eps = set()
            for if_name, ep_id in self.endpoint_id_by_iface_name.iteritems():
                if isinstance(ep_id, WloadEndpointId):
                    workload_ifaces.add(if_name)
                else:
                    host_eps.add(if_name)
            self.workload_disp_chains.apply_snapshot(
                frozenset(workload_ifaces), async=True
            )
            self.host_disp_chains.apply_snapshot(
                frozenset(host_eps), async=True
            )
            self._update_dirty_policy()

            nat_maps = {}
            for ep_id, ep in self.endpoints_by_id.iteritems():
                if ep_id in self.local_endpoint_ids:
                    nat_map = ep.get(nat_key(self.ip_type), None)
                    if nat_map:
                        nat_maps[ep_id] = nat_map
            self.fip_manager.apply_snapshot(nat_maps, async=True)

    @actor_message()
    def on_host_ep_update(self, combined_id, data):
        if combined_id.host != self.config.HOSTNAME:
            _log.debug("Skipping endpoint %s; not on our host.", combined_id)
            return
        if data is not None:
            self.host_eps_by_id[combined_id] = data
        else:
            self.host_eps_by_id.pop(combined_id, None)
        self._resolve_host_eps()

    @actor_message()
    def on_endpoint_update(self, endpoint_id, endpoint, force_reprogram=False):
        """
        Event to indicate that an endpoint has been updated (including
        creation or deletion).

        :param EndpointId endpoint_id: The endpoint ID in question.
        :param dict[str]|NoneType endpoint: Dictionary of all endpoint
            data or None if the endpoint is to be deleted.
        """
        if endpoint_id.host != self.config.HOSTNAME:
            _log.debug("Skipping endpoint %s; not on our host.", endpoint_id)
            return

        old_ep = self.endpoints_by_id.get(endpoint_id, {})
        old_iface_name = old_ep.get("name")
        new_iface_name = (endpoint or {}).get("name")

        if (old_iface_name is not None and
                new_iface_name is not None and
                old_iface_name != new_iface_name):
            # Special-case: if the interface name of an active endpoint
            # changes we need to clean up routes and iptables and start from
            # scratch.  Force that through the deletion path so that we don't
            # introduce any more complexity in LocalEndpoint.
            _log.info("Name of interface for endpoint %s changed from %s "
                      "to %s.  Forcing a delete/re-add.",
                      endpoint_id, old_iface_name, new_iface_name)
            self._on_endpoint_update_internal(endpoint_id, None,
                                              force_reprogram)

        self._on_endpoint_update_internal(endpoint_id, endpoint, force_reprogram)

    def _on_endpoint_update_internal(self, endpoint_id, endpoint, force_reprogram=False):
        """Handles a single update or deletion of an endpoint.

        Increfs/decrefs the actor as appropriate and forwards on the update
        if the endpoint is active.

        :param EndpointId endpoint_id: The endpoint ID in question.
        :param dict[str]|NoneType endpoint: Dictionary of all endpoint
            data or None if the endpoint is to be deleted.
        """
        if self._is_starting_or_live(endpoint_id):
            # Local endpoint thread is running; tell it of the change.
            _log.info("Update for live endpoint %s", endpoint_id)
            self.objects_by_id[endpoint_id].on_endpoint_update(
                endpoint, force_reprogram=force_reprogram, async=True)

        old_ep = self.endpoints_by_id.pop(endpoint_id, {})
        # Interface name shouldn't change but popping it now is correct for
        # deletes and we add it back in below on create/modify.
        old_iface_name = old_ep.get("name")
        self.endpoint_id_by_iface_name.pop(old_iface_name, None)
        if endpoint is None:
            # Deletion. Remove from the list.
            _log.info("Endpoint %s deleted", endpoint_id)
            if endpoint_id in self.local_endpoint_ids:
                self.decref(endpoint_id)
                self.local_endpoint_ids.remove(endpoint_id)
                self._label_inherit_idx.on_item_update(endpoint_id, None, None)
                assert endpoint_id not in self.pol_ids_by_ep_id
        else:
            # Creation or modification
            _log.info("Endpoint %s modified or created", endpoint_id)
            self.endpoints_by_id[endpoint_id] = endpoint
            self.endpoint_id_by_iface_name[endpoint["name"]] = endpoint_id
            if endpoint_id not in self.local_endpoint_ids:
                # This will trigger _on_object_activated to pass the endpoint
                # we just saved off to the endpoint.
                _log.debug("Endpoint wasn't known before, increffing it")
                self.local_endpoint_ids.add(endpoint_id)
                self.get_and_incref(endpoint_id)
            self._label_inherit_idx.on_item_update(
                endpoint_id,
                endpoint.get("labels", {}),
                endpoint.get("profile_ids", [])
            )

        self._update_dirty_policy()

    @actor_message()
    def on_interface_update(self, name, iface_up):
        """
        Called when an interface is created or changes state.

        The interface may be any interface on the host, not necessarily
        one managed by any endpoint of this server.
        """
        try:
            endpoint_id = self.endpoint_id_by_iface_name[name]
        except KeyError:
            _log.debug("Update on interface %s that we do not care about",
                       name)
        else:
            _log.info("Endpoint %s received interface update for %s",
                      endpoint_id, name)
            if self._is_starting_or_live(endpoint_id):
                # LocalEndpoint is running, so tell it about the change.
                ep = self.objects_by_id[endpoint_id]
                ep.on_interface_update(iface_up, async=True)

    def _interface_poll_loop(self):
        """Greenlet: Polls host endpoints for changes to their IP addresses.

        Sends updates to the EndpointManager via the _on_iface_ips_update()
        message.

        If polling is disabled, then it reads the interfaces once and then
        stops.
        """
        known_interfaces = {}
        while True:
            known_interfaces = self._poll_interfaces(known_interfaces)
            if self.config.HOST_IF_POLL_INTERVAL_SECS <= 0:
                _log.info("Host interface polling disabled, stopping after "
                          "initial read. Further changes to host endpoint "
                          "IPs will be ignored.")
                break
            gevent.sleep(self.config.HOST_IF_POLL_INTERVAL_SECS)

    def _poll_interfaces(self, known_interfaces):
        """Does a single poll of the host interfaces, looking for IP changes.

        Sends updates to the EndpointManager via the _on_iface_ips_update()
        message.

        This is broken out form the loop above to make it easier to test.

        :param known_interfaces:
        :return:
        """
        # We only care about host interfaces, not workload ones.
        exclude_prefixes = self.config.IFACE_PREFIX
        # Get the IPs for each interface.
        ips_by_iface = devices.list_ips_by_iface(self.ip_type)
        for iface, ips in ips_by_iface.items():
            ignore_iface = any(iface.startswith(prefix)
                             for prefix in exclude_prefixes)
            if ignore_iface:
                # Ignore non-host interfaces.
                ips_by_iface.pop(iface)
            else:
                # Compare with the set of IPs that were there before.
                # We pop interfaces that we see so that we can clean up
                # deletions below.
                old_ips = known_interfaces.pop(iface, None)
                if old_ips != ips:
                    _log.debug("IPs of interface %s changed to %s",
                               iface, ips)
                    self._on_iface_ips_update(iface, ips, async=True)
        # Clean up deletions.  Anything left in known_interfaces has
        # been deleted.
        for iface, ips in known_interfaces.iteritems():
            self._on_iface_ips_update(iface, None, async=True)
        # Update our cache of known interfaces for the next loop.
        return ips_by_iface

    @actor_message()
    def _on_iface_ips_update(self, iface_name, ip_addrs):
        """Message sent by _poll_interface_ips when it detects a change.

        :param iface_name: Name of the interface that has been updated.
        :param ip_addrs: set of IP addresses, or None if the interface no
               longer exists (or has no IPs).
        """
        _log.info("Interface %s now has IPs %s", iface_name, ip_addrs)
        if ip_addrs is not None:
            self.host_ep_ips_by_iface[iface_name] = ip_addrs
        else:
            self.host_ep_ips_by_iface.pop(iface_name, None)
        # Since changes to IPs can change which host endpoint objects apply to
        # which interfaces, we need to resolve IPs and host endpoints.
        self._resolve_host_eps()

    def _resolve_host_eps(self):
        """Resolves the host endpoint data we've learned from etcd with
        IP addresses and interface names learned from the kernel.

        Host interfaces that have matching IPs get combined with interface
        name learned from the kernel and updated via on_endpoint_update().

        In the case where multiple interfaces have the same IP address,
        a copy of the host endpoint will be resolved with each interface.
        """
        # Invert the interface name to IP mapping to allow us to do an IP to
        # interface name lookup.
        iface_names_by_ip = defaultdict(set)
        for iface, ips in self.host_ep_ips_by_iface.iteritems():
            for ip in ips:
                iface_names_by_ip[ip].add(iface)
        # Iterate over the host endpoints, looking for corresponding IPs.
        resolved_ifaces = {}
        iface_name_to_id = {}
        # For repeatability, we sort the endpoint data.  We don't care what
        # the sort order is, only that it's stable so we just use the repr()
        # of the ID.
        for combined_id, host_ep in sorted(self.host_eps_by_id.iteritems(),
                                           key=lambda h: repr(h[0])):
            addrs_key = "expected_ipv%s_addrs" % self.ip_version
            if "name" in host_ep:
                # This interface has an explicit name in the data so it's
                # already resolved.
                resolved_id = combined_id.resolve(host_ep["name"])
                resolved_ifaces[resolved_id] = host_ep
            elif addrs_key in host_ep:
                # No explicit name, look for an interface with a matching IP.
                expected_ips = IPSet(host_ep[addrs_key])
                for ip, iface_names in sorted(iface_names_by_ip.iteritems()):
                    if ip in expected_ips:
                        # This endpoint matches the IP, loop over the (usually
                        # one) interface with that IP.  Sort the names to avoid
                        # non-deterministic behaviour if there are multiple
                        # conflicting matches.
                        _log.debug("Host endpoint %s matches interfaces: %s",
                                   combined_id, iface_names)
                        for iface_name in sorted(iface_names):
                            # Check for conflicting matches.
                            prev_match = iface_name_to_id.get(iface_name)
                            if prev_match == combined_id:
                                # Already matched this interface by a different
                                # IP address.
                                continue
                            elif prev_match is not None:
                                # Already matched a different interface.
                                # First match wins.
                                _log.warn("Interface %s matched with multiple "
                                          "entries in datamodel; using %s",
                                          iface_name, prev_match)
                                continue
                            else:
                                # Else, this is the first match, record it.
                                iface_name_to_id[iface_name] = combined_id
                            # Got a match.  Since it's possible to match
                            # multiple interfaces by IP, we add the interface
                            # name into the ID to disambiguate.
                            resolved_id = combined_id.resolve(iface_name)
                            resolved_data = host_ep.copy()
                            resolved_data["name"] = iface_name
                            resolved_ifaces[resolved_id] = resolved_data
        # Fire in deletions for interfaces that no longer resolve.
        for resolved_id in self.resolved_host_eps.keys():
            if resolved_id not in resolved_ifaces:
                _log.debug("%s no longer matches", resolved_id)
                self.on_endpoint_update(resolved_id, None)
        # Fire in the updates for the new data.
        for resolved_id, data in resolved_ifaces.iteritems():
            if self.resolved_host_eps.get(resolved_id) != data:
                _log.debug("Updating data for %s", resolved_id)
                self.on_endpoint_update(resolved_id, data)
        # Update the cache so we can calculate deltas next time.
        self.resolved_host_eps = resolved_ifaces

    def _update_dirty_policy(self):
        if not self._data_model_in_sync:
            _log.debug("Datamodel not in sync, postponing update to policy")
            return
        _log.debug("Endpoints with dirty policy: %s",
                   self.endpoints_with_dirty_policy)
        while self.endpoints_with_dirty_policy:
            ep_id = self.endpoints_with_dirty_policy.pop()
            if self._is_starting_or_live(ep_id):
                self._update_tiered_policy(ep_id)

    def _update_tiered_policy(self, ep_id):
        """
        Sends an updated list of tiered policy to an endpoint.

        Recalculates the list.
        :param ep_id: ID of the endpoint to send an update to.
        """
        _log.debug("Updating policies for %s from %s", ep_id,
                   self.pol_ids_by_ep_id)
        # Order the profiles by tier and profile order, using the name of the
        # tier and profile as a tie-breaker if the orders are the same.
        profiles = []
        for pol_id in self.pol_ids_by_ep_id.iter_values(ep_id):
            try:
                tier_order = self.tier_orders[pol_id.tier]
            except KeyError:
                _log.warn("Ignoring policy %s because its tier metadata is "
                          "missing.", pol_id)
                continue
            profile_order = self.profile_orders[pol_id]
            profiles.append((tier_order, pol_id.tier,
                             profile_order, pol_id.policy_id,
                             pol_id))
        profiles.sort()
        # Convert to an ordered dict from tier to list of profiles.
        pols_by_tier = OrderedDict()
        for _, tier, _, _, pol_id in profiles:
            pols_by_tier.setdefault(tier, []).append(pol_id)

        endpoint = self.objects_by_id[ep_id]
        endpoint.on_tiered_policy_update(pols_by_tier, async=True)

    def _on_worker_died(self, watch_greenlet):
        """
        Greenlet: spawned by the gevent Hub if our worker thread dies.
        """
        _log.critical("Worker greenlet died: %s; exiting.", watch_greenlet)
        sys.exit(1)


class LocalEndpoint(RefCountedActor):

    def __init__(self, config, combined_id, ip_type, iptables_updater,
                 dispatch_chains, rules_manager, fip_manager, status_reporter):
        """
        Controls a single local endpoint.

        :param combined_id: EndpointId for this endpoint.
        :param ip_type: IP type for this endpoint (IPv4 or IPv6)
        :param iptables_updater: IptablesUpdater to use
        :param dispatch_chains: DispatchChains to use
        :param rules_manager: RulesManager to use
        :param fip_manager: FloatingIPManager to use
        """
        super(LocalEndpoint, self).__init__(qualifier="%s(%s)" %
                                             (combined_id.endpoint, ip_type))
        assert isinstance(rules_manager, RulesManager)

        self.config = config
        self.iptables_generator = config.plugins["iptables_generator"]

        self.combined_id = combined_id
        self.ip_type = ip_type

        # Other actors we need to talk to.
        self.iptables_updater = iptables_updater
        self.dispatch_chains = dispatch_chains
        self.rules_mgr = rules_manager
        self.status_reporter = status_reporter
        self.fip_manager = fip_manager

        # Helper for acquiring/releasing profiles.
        self._rules_ref_helper = RefHelper(self, rules_manager,
                                           self._on_profiles_ready)

        # List of global policies that we care about.
        self._pol_ids_by_tier = OrderedDict()

        # List of explicit profile IDs that we've processed.
        self._explicit_profile_ids = None

        # Per-batch state.
        self._pending_endpoint = None
        self._endpoint_update_pending = False
        self._mac_changed = False
        # IPs that no longer belong to this endpoint and need cleaning up.
        self._removed_ips = set()

        # Current endpoint data.
        self.endpoint = None

        # Will be filled in as we learn about the OS interface and the
        # endpoint config.
        self._mac = None
        self._iface_name = None
        self._suffix = None

        # Track the success/failure of our dataplane programming.
        self._chains_programmed = False
        self._iptables_in_sync = False
        self._device_in_sync = False
        self._profile_ids_dirty = False

        # Oper-state of the Linux interface.
        self._device_is_up = None  # Unknown

        # Our last status report.  Used for de-dupe.
        self._last_status = None

        # One-way flags to indicate that we should clean up/have cleaned up.
        self._unreferenced = False
        self._added_to_dispatch_chains = False
        self._cleaned_up = False

    @property
    def nets_key(self):
        if self.ip_type == IPV4:
            return "ipv4_nets"
        else:
            return "ipv6_nets"

    @property
    def nat_key(self):
        return nat_key(self.ip_type)

    @property
    def _admin_up(self):
        return (not self._unreferenced and
                self.endpoint and
                self.endpoint.get("state", "active") == "active")

    @actor_message()
    def on_endpoint_update(self, endpoint, force_reprogram=False):
        """
        Called when this endpoint has received an update.
        :param dict[str]|NoneType endpoint: endpoint parameter dictionary.
        """
        _log.info("%s updated: %s", self, endpoint)
        assert not self._unreferenced, "Update after being unreferenced"

        # Store off the update, to be handled in _finish_msg_batch.
        self._pending_endpoint = endpoint
        self._endpoint_update_pending = True
        if force_reprogram:
            self._iptables_in_sync = False
            self._device_in_sync = False

    @actor_message()
    def on_tiered_policy_update(self, pols_by_tier):
        """Called to update the ordered set of tiered policies that apply.

        :param OrderedDict pols_by_tier: Ordered mapping from tier name to
               list of policies to apply in that tier.
        """
        _log.debug("New policy IDs for %s: %s", self.combined_id,
                   pols_by_tier)
        if pols_by_tier != self._pol_ids_by_tier:
            self._pol_ids_by_tier = pols_by_tier
            self._iptables_in_sync = False
            self._profile_ids_dirty = True

    @actor_message()
    def on_interface_update(self, iface_up):
        """
        Actor event to report that the interface is either up or changed.
        """
        _log.info("Endpoint %s received interface kick: %s",
                  self.combined_id, iface_up)
        assert not self._unreferenced, "Interface kick after unreference"

        # Use a flag so that we coalesce any duplicate updates in
        # _finish_msg_batch.
        self._device_in_sync = False
        self._device_is_up = iface_up

    @actor_message()
    def on_unreferenced(self):
        """
        Overrides RefCountedActor:on_unreferenced.
        """
        _log.info("%s now unreferenced, cleaning up", self)
        assert not self._unreferenced, "Duplicate on_unreferenced() call"

        # We should be deleted before being unreferenced.
        assert self.endpoint is None or (self._pending_endpoint is None and
                                         self._endpoint_update_pending)

        # Defer the processing to _finish_msg_batch.
        self._unreferenced = True

    def _finish_msg_batch(self, batch, results):
        if self._cleaned_up:
            # This can occur if we get a callback from a profile via the
            # RefHelper after we've already been deleted.
            _log.warn("_finish_msg_batch() called after being unreferenced,"
                      "ignoring.  Batch: %s", batch)
            return

        if self._endpoint_update_pending:
            # Copy the pending update into our data structures.  May work out
            # that iptables or the device is now out of sync.
            _log.debug("Endpoint update pending: %s", self._pending_endpoint)
            self._apply_endpoint_update()

        if self._profile_ids_dirty:
            _log.debug("Profile references need updating")
            self._update_profile_references()

        if not self._iptables_in_sync:
            # Try to update iptables, if successful, will set the
            # _iptables_in_sync flag.
            _log.debug("iptables is out-of-sync, trying to update it")
            if self._admin_up:
                _log.info("%s is 'active', (re)programming chains.", self)
                self._update_chains()
            elif self._chains_programmed:
                # No longer active but our chains are still in place.  Remove
                # them.
                _log.info("%s is not 'active', removing chains.", self)
                self._remove_chains()

        if not self._device_in_sync and self._iface_name:
            # Try to update the device configuration.  If successful, will set
            # the _device_in_sync flag.
            if self._admin_up:
                # Endpoint is supposed to be live, try to configure it.
                _log.debug("Device is out-of-sync, trying to configure it")
                self._configure_interface()
            else:
                # We've been deleted, de-configure the interface.
                _log.debug("Device is out-of-sync, trying to de-configure it")
                self._deconfigure_interface()

        if self._removed_ips:
            # Some IPs have been removed, clean up conntrack.
            _log.debug("Some IPs were removed, cleaning up conntrack")
            self._clean_up_conntrack_entries()

        if self._unreferenced:
            # Endpoint is being removed, clean up...
            _log.debug("Cleaning up after endpoint unreferenced")
            self.dispatch_chains.on_endpoint_removed(self._iface_name,
                                                     async=True)
            self._rules_ref_helper.discard_all()
            self._notify_cleanup_complete()
            self._cleaned_up = True
        elif not self._added_to_dispatch_chains and self._iface_name:
            # This must be the first batch, add ourself to the dispatch chains.
            _log.debug("Adding endpoint to dispatch chain")
            self.dispatch_chains.on_endpoint_added(self._iface_name,
                                                   async=True)
            self._added_to_dispatch_chains = True

        # If changed, report our status back to the datastore.
        self._maybe_update_status()

    def _maybe_update_status(self):
        if not self.config.REPORT_ENDPOINT_STATUS:
            _log.debug("Status reporting disabled. Not reporting status.")
            return

        status, reason = self.oper_status()

        if self._unreferenced or status != self._last_status:
            _log.info("%s: updating status to %s", reason, status)
            if self._unreferenced:
                _log.debug("Unreferenced, reporting status = None")
                status_dict = None
            else:
                _log.debug("Endpoint oper state changed to %s", status)
                status_dict = {"status": status}
            self.status_reporter.on_endpoint_status_changed(
                self.combined_id,
                self.ip_type,
                status_dict,
                async=True,
            )
            self._last_status = status

    def oper_status(self):
        """Calculate the oper status of the endpoint.

        :returns a tuple containing the status and a human-readable reason."""
        if not self._device_is_up:
            # Check this first because we won't try to sync the device if it's
            # oper down.
            reason = "Interface is oper-down"
            status = ENDPOINT_STATUS_DOWN
        elif not self.endpoint:
            reason = "No endpoint data"
            status = ENDPOINT_STATUS_DOWN
        elif not self._iptables_in_sync:
            # Definitely an error, the iptables command failed.
            reason = "Failed to update iptables"
            status = ENDPOINT_STATUS_ERROR
        elif not self._device_in_sync:
            reason = "Failed to update device config"
            status = ENDPOINT_STATUS_ERROR
        elif not self._admin_up:
            # After the tests for being in sync because we handle admin down
            # by removing the configuration from the dataplane.
            reason = "Endpoint is admin down"
            status = ENDPOINT_STATUS_DOWN
        else:
            # All checks passed.  We're up!
            reason = "In sync and device is up"
            status = ENDPOINT_STATUS_UP
        return status, reason

    def _apply_endpoint_update(self):
        pending_endpoint = self._pending_endpoint
        if pending_endpoint == self.endpoint:
            _log.debug("Endpoint hasn't changed, nothing to do")
            return

        # Calculate the set of IPs that we had before this update.  Needed on
        # the update and delete code paths below.
        if self.endpoint:
            old_ips = set(futils.net_to_ip(n) for n in
                          self.endpoint.get(self.nets_key, []))
            old_nat_mappings = self.endpoint.get(self.nat_key, [])
        else:
            old_ips = set()
            old_nat_mappings = []
        all_old_ips = old_ips | set([n["ext_ip"] for n in old_nat_mappings])

        if pending_endpoint:
            # Update/create.
            if pending_endpoint.get('mac') != self._mac:
                # Either we have not seen this MAC before, or it has changed.
                _log.debug("Endpoint MAC changed to %s",
                           pending_endpoint.get("mac"))
                self._mac = pending_endpoint.get('mac')
                self._mac_changed = True
                # MAC change requires refresh of iptables rules and ARP table.
                self._iptables_in_sync = False
                self._device_in_sync = False

            new_iface_name = pending_endpoint["name"]
            # Interface renames are handled in the EndpointManager by
            # simulating a delete then an add.  We shouldn't see one here.
            assert (self.endpoint is None or
                    self._iface_name == new_iface_name), (
                "Unexpected change of interface name."
            )
            if self.endpoint is None:
                # This is the first time we have seen the endpoint, so extract
                # the interface name and endpoint ID.
                self._iface_name = new_iface_name
                self._suffix = interface_to_chain_suffix(self.config,
                                                         self._iface_name)
                _log.debug("Learned interface name/suffix: %s/%s",
                           self._iface_name, self._suffix)
                # First time through, need to program everything.
                self._iptables_in_sync = False
                self._device_in_sync = False
                if self._device_is_up is None:
                    _log.debug("Learned interface name, checking if device "
                               "is up.")
                    self._device_is_up = (
                        devices.interface_exists(self._iface_name) and
                        devices.interface_up(self._iface_name)
                    )

            # Check if the profile ID or IP addresses have changed, requiring
            # a refresh of the dataplane.
            profile_ids = set(pending_endpoint.get("profile_ids", []))
            if profile_ids != self._explicit_profile_ids:
                # Profile ID update requires iptables update but not device
                # update.
                _log.debug("Profile IDs changed from %s to %s, need to update "
                           "iptables", self._rules_ref_helper.required_refs,
                           profile_ids)
                self._explicit_profile_ids = profile_ids
                self._iptables_in_sync = False
                self._profile_ids_dirty = True

            # Check for changes to values that require a device update.
            if self.endpoint:
                if self.endpoint.get("state") != pending_endpoint.get("state"):
                    _log.debug("Desired interface state updated.")
                    self._device_in_sync = False
                    self._iptables_in_sync = False
                new_ips = set(futils.net_to_ip(n) for n in
                              pending_endpoint.get(self.nets_key, []))
                if old_ips != new_ips:
                    # IP addresses have changed, need to update the routing
                    # table.
                    _log.debug("IP addresses changed, need to update routing")
                    self._device_in_sync = False
                new_nat_mappings = pending_endpoint.get(self.nat_key, [])
                if old_nat_mappings != new_nat_mappings:
                    _log.debug("NAT mappings have changed, refreshing.")
                    self._device_in_sync = False
                    self._iptables_in_sync = False
                all_new_ips = new_ips | set([n["ext_ip"] for n in
                                             new_nat_mappings])
                if all_old_ips != all_new_ips:
                    # Ensure we clean up any conntrack entries for IPs that
                    # have been removed.
                    _log.debug("Set of all IPs changed from %s to %s",
                               all_old_ips, all_new_ips)
                    self._removed_ips |= all_old_ips
                    self._removed_ips -= all_new_ips
        else:
            # Delete of the endpoint.  Need to resync everything.
            self._profile_ids_dirty = True
            self._iptables_in_sync = False
            self._device_in_sync = False
            self._removed_ips |= all_old_ips

        self.endpoint = pending_endpoint
        self._endpoint_update_pending = False
        self._pending_endpoint = None

    def _update_profile_references(self):
        if self.endpoint:
            # Combine the explicit profile IDs with the set of policy IDs
            # for our matching selectors.
            profile_ids = set(self._explicit_profile_ids)
            for pol_ids in self._pol_ids_by_tier.itervalues():
                profile_ids.update(pol_ids)
        else:
            profile_ids = set()
        # Note: we don't actually need to wait for the activation to finish
        # due to the dependency management in the iptables layer.
        self._rules_ref_helper.replace_all(profile_ids)
        self._profile_ids_dirty = False

    def _update_chains(self):
        updates, deps = self._endpoint_updates()
        try:
            self.iptables_updater.rewrite_chains(updates, deps, async=False)
            self.fip_manager.update_endpoint(
                self.combined_id,
                self.endpoint.get(self.nat_key, None),
                async=True
            )
        except FailedSystemCall:
            _log.exception("Failed to program chains for %s. Removing.", self)
            try:
                self.iptables_updater.delete_chains(
                    self.iptables_generator.endpoint_chain_names(self._suffix),
                    async=False)
                self.fip_manager.update_endpoint(self.combined_id, None,
                                                 async=True)
            except FailedSystemCall:
                _log.exception("Failed to remove chains after original "
                               "failure")
        else:
            self._iptables_in_sync = True
            self._chains_programmed = True

    def _endpoint_updates(self):
        raise NotImplementedError()  # pragma: no cover

    def _remove_chains(self):
        try:
            self.iptables_updater.delete_chains(
                self.iptables_generator.endpoint_chain_names(self._suffix),
                async=False)
            self.fip_manager.update_endpoint(self.combined_id, None,
                                             async=True)
        except FailedSystemCall:
            _log.exception("Failed to delete chains for %s", self)
        else:
            self._iptables_in_sync = True
            self._chains_programmed = False

    def _configure_interface(self):
        """
        Called to apply IP/sysctl config to the interface.

        This base implementation does nothing apart from setting the
        _device_in_sync flag.
        """
        _log.info("Interface %s configured", self._iface_name)
        self._device_in_sync = True

    def _deconfigure_interface(self):
        """
        Called to remove IP/sysctl config from the interface.

        This base implementation does nothing apart from setting the
        _device_in_sync flag.
        """
        _log.info("Interface %s deconfigured", self._iface_name)
        self._device_in_sync = True

    def _clean_up_conntrack_entries(self):
        """Removes conntrack entries for all the IPs in self._removed_ips."""
        _log.debug("Cleaning up conntrack for old IPs: %s", self._removed_ips)
        devices.remove_conntrack_flows(
            self._removed_ips,
            IP_TYPE_TO_VERSION[self.ip_type]
        )
        # We could use self._removed_ips.clear() but it's hard to UT because
        # the UT sees the update.
        self._removed_ips = set()

    def _on_profiles_ready(self):
        # We don't actually need to talk to the profiles, just log.
        _log.info("Endpoint %s acquired all required profile references",
                  self.combined_id)

    def __str__(self):
        return ("LocalEndpoint<%s,id=%s,iface=%s>" %
                (self.ip_type, self.combined_id,
                 self._iface_name or "unknown"))


class WorkloadEndpoint(LocalEndpoint):

    def _configure_interface(self):
        """
        Applies sysctls and routes to the interface.
        """
        if not self._device_is_up:
            _log.debug("Device is known to be down, skipping attempt to "
                       "configure it.")
            return
        try:
            if self.ip_type == IPV4:
                devices.configure_interface_ipv4(self._iface_name)
                reset_arp = self._mac_changed
            else:
                ipv6_gw = self.endpoint.get("ipv6_gateway", None)
                devices.configure_interface_ipv6(self._iface_name, ipv6_gw)
                reset_arp = False

            ips = set()
            for ip in self.endpoint.get(self.nets_key, []):
                ips.add(futils.net_to_ip(ip))
            for nat_map in self.endpoint.get(nat_key(self.ip_type), []):
                ips.add(nat_map['ext_ip'])
            devices.set_routes(self.ip_type, ips,
                               self._iface_name,
                               self.endpoint.get("mac"),
                               reset_arp=reset_arp)

        except (IOError, FailedSystemCall) as e:
            if not devices.interface_exists(self._iface_name):
                _log.info("Interface %s for %s does not exist yet",
                          self._iface_name, self.combined_id)
            elif not devices.interface_up(self._iface_name):
                _log.info("Interface %s for %s is not up yet",
                          self._iface_name, self.combined_id)
            else:
                # Either the interface flapped back up after the failure (in
                # which case we'll retry when the event reaches us) or there
                # was a genuine failure due to bad data or some other factor.
                #
                # Since the former is fairly common, we log at warning level
                # rather than error, which avoids false positives.
                _log.warning("Failed to configure interface %s for %s: %r.  "
                             "Either the interface is flapping or it is "
                             "misconfigured.", self._iface_name,
                             self.combined_id, e)
        else:
            _log.info("Interface %s configured", self._iface_name)
            super(WorkloadEndpoint, self)._configure_interface()

    def _deconfigure_interface(self):
        """
        Removes routes from the interface.
        """
        try:
            devices.set_routes(self.ip_type, set(), self._iface_name, None)
        except (IOError, FailedSystemCall):
            if not devices.interface_exists(self._iface_name):
                # Deleted under our feet - so the rules are gone.
                _log.info("Interface %s for %s already deleted",
                          self._iface_name, self.combined_id)
            else:
                # An error deleting the routes. Log and continue.
                _log.exception("Cannot delete routes for interface %s for %s",
                               self._iface_name, self.combined_id)
        else:
            _log.info("Interface %s deconfigured", self._iface_name)
            super(WorkloadEndpoint, self)._deconfigure_interface()

    def _endpoint_updates(self):
        updates, deps = self.iptables_generator.endpoint_updates(
            IP_TYPE_TO_VERSION[self.ip_type],
            self.combined_id.endpoint,
            self._suffix,
            self._mac,
            self.endpoint["profile_ids"],
            self._pol_ids_by_tier)
        return updates, deps


class HostEndpoint(LocalEndpoint):
    def _endpoint_updates(self):
        return self.iptables_generator.host_endpoint_updates(
            ip_version=IP_TYPE_TO_VERSION[self.ip_type],
            endpoint_id=self.combined_id.endpoint,
            suffix=self._suffix,
            profile_ids=self.endpoint["profile_ids"],
            pol_ids_by_tier=self._pol_ids_by_tier,
        )
