# -*- coding: utf-8 -*-
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.
"""Scope objects describing what a resync should cover."""

import dataclasses
from typing import Optional, Set


@dataclasses.dataclass
class Scope:
    """What to resync.

    A Scope with ``is_all=True`` requests a resync of every Calico
    resource that this driver writes to etcd.  Otherwise the resync is
    limited to the listed IDs, after expansion (see ``ExpandedScope``):

      * each network in ``network_ids`` expands to that network plus
        every subnet and port within it;
      * each subnet in ``subnet_ids`` expands to that subnet plus every
        port on it;
      * each port in ``port_ids`` is resynced as-is.

    If ``include_security_groups_for_ports`` is true, the security
    groups bound to each (expanded) port are added to the security
    group set.  Default is false because port-to-SG coupling in Calico
    is loose: a port carries SG labels and the policy selectors match
    them, so a port-only resync is usually enough to repair port
    incidents without touching SG NetworkPolicy resources.
    """

    network_ids: Set[str] = dataclasses.field(default_factory=set)
    subnet_ids: Set[str] = dataclasses.field(default_factory=set)
    port_ids: Set[str] = dataclasses.field(default_factory=set)
    security_group_ids: Set[str] = dataclasses.field(default_factory=set)
    include_security_groups_for_ports: bool = False
    is_all: bool = False

    @classmethod
    def all(cls) -> "Scope":
        return cls(is_all=True)

    def to_dict(self) -> dict:
        return {
            "all": self.is_all,
            "networks": sorted(self.network_ids),
            "subnets": sorted(self.subnet_ids),
            "ports": sorted(self.port_ids),
            "security_groups": sorted(self.security_group_ids),
            "include_sgs_for_ports": self.include_security_groups_for_ports,
        }


@dataclasses.dataclass
class ExpandedScope:
    """A Scope after resolving network -> subnet/port and subnet -> port.

    Used internally by the runner.  ``network_ids`` and ``subnet_ids``
    are kept too so the result can report what was visited at each
    resource type, even though the syncers only act on subnets and
    ports/SGs.  ``is_all`` is preserved verbatim from the input Scope.
    """

    network_ids: Set[str] = dataclasses.field(default_factory=set)
    subnet_ids: Set[str] = dataclasses.field(default_factory=set)
    port_ids: Set[str] = dataclasses.field(default_factory=set)
    security_group_ids: Set[str] = dataclasses.field(default_factory=set)
    is_all: bool = False

    def to_dict(self) -> dict:
        return {
            "all": self.is_all,
            "networks": len(self.network_ids),
            "subnets": len(self.subnet_ids),
            "ports": len(self.port_ids),
            "security_groups": len(self.security_group_ids),
        }


def expand(scope: Scope, db, context) -> ExpandedScope:
    """Resolve a Scope's network/subnet IDs to the contained subnets/ports.

    For all-scope this returns an ExpandedScope with ``is_all=True`` and
    no IDs filled in; the runner takes the full-resync code path
    instead of iterating IDs, so the contents are unused.
    """
    if scope.is_all:
        return ExpandedScope(is_all=True)

    network_ids = set(scope.network_ids)
    subnet_ids = set(scope.subnet_ids)
    port_ids = set(scope.port_ids)
    security_group_ids = set(scope.security_group_ids)

    # Resync of a network includes its subnets and ports.  Track the
    # subnets we discover here so the subnet block below can skip
    # them: their ports were already added via the network_id port
    # query.
    network_subnet_ids = set()
    if network_ids:
        for subnet in db.get_subnets(
            context, filters={"network_id": list(network_ids)}
        ):
            network_subnet_ids.add(subnet["id"])
        for port in db.get_ports(context, filters={"network_id": list(network_ids)}):
            port_ids.add(port["id"])
    subnet_ids |= network_subnet_ids

    # Resync of a subnet includes its ports.  Ports don't have a
    # subnet_id field directly; we have to go via fixed_ips.  We only
    # need to do this for subnets that weren't already covered by the
    # network expansion above; for those we know we already added all
    # their ports.  Narrow the get_ports query down to the remaining
    # subnets' networks (a port is always on exactly one network) so
    # we don't drag in every port in OpenStack.
    remaining_subnet_ids = subnet_ids - network_subnet_ids
    if remaining_subnet_ids:
        subnet_network_ids = {
            s["network_id"]
            for s in db.get_subnets(context, filters={"id": list(remaining_subnet_ids)})
        }
        if subnet_network_ids:
            for port in db.get_ports(
                context, filters={"network_id": list(subnet_network_ids)}
            ):
                for fixed_ip in port.get("fixed_ips", []) or []:
                    if fixed_ip.get("subnet_id") in remaining_subnet_ids:
                        port_ids.add(port["id"])
                        break

    if scope.include_security_groups_for_ports and port_ids:
        for port in db.get_ports(context, filters={"id": list(port_ids)}):
            for sg_id in port.get("security_groups", []) or []:
                security_group_ids.add(sg_id)

    return ExpandedScope(
        network_ids=network_ids,
        subnet_ids=subnet_ids,
        port_ids=port_ids,
        security_group_ids=security_group_ids,
        is_all=False,
    )


def from_args(
    all_: bool = False,
    networks: Optional[list] = None,
    subnets: Optional[list] = None,
    ports: Optional[list] = None,
    security_groups: Optional[list] = None,
    include_security_groups_for_ports: bool = False,
) -> Scope:
    """Build a Scope from CLI-style argument lists."""
    if all_ or not any([networks, subnets, ports, security_groups]):
        return Scope.all()
    return Scope(
        network_ids=set(networks or []),
        subnet_ids=set(subnets or []),
        port_ids=set(ports or []),
        security_group_ids=set(security_groups or []),
        include_security_groups_for_ports=include_security_groups_for_ports,
    )
