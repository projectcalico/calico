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
felix.frules
~~~~~~~~~~~~

Functions for generating iptables rules.  This covers our top-level
chains as well as low-level conversion from our datamodel rules to
iptables format.

iptables background
~~~~~~~~~~~~~~~~~~~

iptables configuration is split into multiple tables, which each support
different types of rules.  Each table contains multiple chains, which
are sequences of rules.  At certain points in packet processing the
packet is handed to one of the always-present kernel chains in a
particular table.  The kernel chains have default behaviours but they
can be modified to add or remove rules, including inserting a jump to
another chain.

Felix is mainly concerned with the "filter" table, which is used for
imposing policy rules.  There are multiple kernel chains in the filter
table.  After the routing decision has been made, packets enter

* the INPUT chain if they are destined for the host itself
* the OUTPUT chain if they are being sent by the host itself
* the FORWARD chain if they are to be forwarded between two interfaces.

Note: packets that are being forwarded do not traverse the INPUT or
OUTPUT chains at all.  INPUT and OUTPUT are only used for packets that
the host itself is to receive/send.

Packet paths
~~~~~~~~~~~~

There are a number of possible paths through the filter chains that we
care about:

* Packets from a local workload to another local workload traverse the
  FORWARD chain only.  Felix must ensure that those packets have *both*
  the outbound policy of the sending workload and the inbound policy
  of the receiving workload applied.

* Packets from a local workload to a remote address traverse the FORWARD
  chain only.  Felix must ensure that those packets have the outbound
  policy of the local workload applied.

* Packets from a remote address to a local workload traverse the FORWARD
  chain only.  Felix must apply the inbound policy of the local workload.

* Packets from a local workload to the host itself traverse the INPUT
  chain.  Felix must apply the outbound policy of the workload.

Chain structure
~~~~~~~~~~~~~~~

Rather than adding many rules to the kernel chains, which are a shared
resource (and hence difficult to unpick), Felix creates its own delegate
chain for each kernel chain and inserts a single jump rule into the
kernel chain:

* INPUT -> felix-INPUT
* FORWARD -> felix-FORWARD

The top-level felix-XXX chains are static and configured at start-of-day.

The felix-FORWARD chain sends packet that arrive from a local workload to
the felix-FROM-ENDPOINT chain, which applies inbound policy.  Packets that
are denied by policy are dropped immediately.  However, accepted packets
are returned to the felix-FORWARD chain in case they need to be processed
further.  felix-FORWARD then directs packets that are going to local
endpoints to the felix-TO-ENDPOINT chain, which applies inbound policy.
Similarly, felix-TO-ENDPOINT either drops or returns the packet.  Finally,
if both the FROM-ENDPOINT and TO-ENDPOINT chains allow the packet,
felix-FORWARD accepts the packet and allows it through.

The felix-INPUT sends packets from local workloads to the (shared)
felix-FROM-ENDPOINT chain, which applies outbound policy.  Then it
(optionally) accepts packets that are returned.

Since workloads come and go, the TO/FROM-ENDPOINT chains are dynamic and
consist of dispatch tables based on device name.  Those chains are managed
by dispatch.py.

The dispatch chains direct packets to per-endpoint ("felix-to/from")
chains, which are responsible for policing IP addresses.  Those chains are
managed by endpoint.py.  Since the actual policy rules can be shared by
multiple endpoints, we put each set of policy rules in its own chain and
the per-endpoint chains send packets to the relevant policy
(felix-p-xxx-i/o) chains in turn.  Policy profile chains are managed by
profilerules.py.

Since an endpoint may be in multiple profiles and we execute the policy
chains of those profiles in sequence, the policy chains need to
communicate three different "return values"; for this we use the packet
MARK:

* Packet was matched by a deny rule.  In this case the packet is immediately
  dropped.
* Packet was matched by an allow rule.  In this case the packet is returned
  with MARK==1.  The calling chain can then return the packet to its caller
  for further processing.
* Packet was not matched at all.  In this case, the packet is returned with
  MARK==0.  The calling chain can then send the packet through the next
  profile chain.

"""
import logging

import time

from calico.felix import devices
from calico.felix import futils
from calico.felix.futils import FailedSystemCall
from calico.felix.ipsets import HOSTS_IPSET_V4

_log = logging.getLogger(__name__)

FELIX_PREFIX = "felix-"

# Maximum number of port entries in a "multiport" match rule.  Ranges count for
# 2 entries.
MAX_MULTIPORT_ENTRIES = 15

# Name of the global, stateless IP-in-IP device name.
IP_IN_IP_DEV_NAME = "tunl0"

# Chain names
CHAIN_TO_ENDPOINT = FELIX_PREFIX + "TO-ENDPOINT"
CHAIN_FROM_ENDPOINT = FELIX_PREFIX + "FROM-ENDPOINT"
CHAIN_TO_LEAF = FELIX_PREFIX + "TO-EP-PFX"
CHAIN_FROM_LEAF = FELIX_PREFIX + "FROM-EP-PFX"
CHAIN_TO_PREFIX = FELIX_PREFIX + "to-"
CHAIN_FROM_PREFIX = FELIX_PREFIX + "from-"
CHAIN_PREROUTING = FELIX_PREFIX + "PREROUTING"
CHAIN_INPUT = FELIX_PREFIX + "INPUT"
CHAIN_FORWARD = FELIX_PREFIX + "FORWARD"


def install_global_rules(config, v4_filter_updater, v6_filter_updater,
                         v4_nat_updater, v6_raw_updater):
    """
    Set up global iptables rules. These are rules that do not change with
    endpoint, and are expected never to change (such as the rules that send all
    traffic through the top level Felix chains).

    This method therefore :

    - ensures that all the required global tables are present;
    - applies any changes required.
    """

    # The interface matching string; for example, if interfaces start "tap"
    # then this string is "tap+".
    iface_match = config.IFACE_PREFIX + "+"

    # If enabled, create the IP-in-IP device
    if config.IP_IN_IP_ENABLED:
        _log.info("IP-in-IP enabled, ensuring device exists.")
        try:
            _configure_ipip_device(config)
        except FailedSystemCall:
            # We've seen this fail occasionally if the kernel is concurrently
            # starting the tunl0 device.  Retry.
            _log.exception("Failed to configure IPIP device, retrying...")
            time.sleep(1)
            _configure_ipip_device(config)

    # Ensure that Calico-controlled IPv6 hosts cannot spoof their IP addresses.
    # (For IPv4, this is controlled by a per-interface sysctl.)
    iptables_generator = config.plugins["iptables_generator"]
    v6_raw_prerouting_chain, v6_raw_prerouting_deps = (
        iptables_generator.raw_rpfilter_failed_chain(ip_version=6)
    )

    v6_raw_updater.rewrite_chains({CHAIN_PREROUTING: v6_raw_prerouting_chain},
                                  {CHAIN_PREROUTING: v6_raw_prerouting_deps},
                                  async=False)

    v6_raw_updater.ensure_rule_inserted(
        "PREROUTING --in-interface %s --match rpfilter --invert "
        "--jump %s" %
        (iface_match, CHAIN_PREROUTING),
        async=False)

    # The IPV4 nat table first. This must have a felix-PREROUTING chain.
    # Write the chain first and then udpate the v4 NAT kernel chain to
    # reference it.
    prerouting_chain, prerouting_deps = (
        iptables_generator.nat_prerouting_chain(ip_version=4)
    )
    v4_nat_updater.rewrite_chains({CHAIN_PREROUTING: prerouting_chain},
                                  {CHAIN_PREROUTING: prerouting_deps},
                                  async=False)

    v4_nat_updater.ensure_rule_inserted(
        "PREROUTING --jump %s" % CHAIN_PREROUTING, async=False)

    # Now the filter table. This needs to have felix-FORWARD and felix-INPUT
    # chains, which we must create before adding any rules that send to them.
    for ip_version, iptables_updater, hosts_set in [
            (4, v4_filter_updater, HOSTS_IPSET_V4),
                # FIXME support IP-in-IP for IPv6.
            (6, v6_filter_updater, None)]:

        if hosts_set and config.IP_IN_IP_ENABLED:
            hosts_set_name = hosts_set.set_name
            hosts_set.ensure_exists()
        else:
            hosts_set_name = None

        input_chain, input_deps = (
            iptables_generator.filter_input_chain(ip_version, hosts_set_name)
        )
        forward_chain, forward_deps = (
            iptables_generator.filter_forward_chain(ip_version)
        )

        iptables_updater.rewrite_chains(
            {
                CHAIN_FORWARD: forward_chain,
                CHAIN_INPUT: input_chain,
            },
            {
                CHAIN_FORWARD: forward_deps,
                CHAIN_INPUT: input_deps,
            },
            async=False)

        iptables_updater.ensure_rule_inserted(
            "INPUT --jump %s" % CHAIN_INPUT,
            async=False)
        iptables_updater.ensure_rule_inserted(
            "FORWARD --jump %s" % CHAIN_FORWARD,
            async=False)


def _configure_ipip_device(config):
    """Creates and enables the IPIP tunnel device.
    :raises FailedSystemCall on failure.
    """
    if not devices.interface_exists(IP_IN_IP_DEV_NAME):
        # Make sure the IP-in-IP device exists; since we use the global
        # device, this command actually creates it as a side-effect of
        # initialising the kernel module rather than explicitly creating
        # it.
        _log.info("Tunnel device didn't exist; creating.")
        futils.check_call(["ip", "tunnel", "add", IP_IN_IP_DEV_NAME,
                           "mode", "ipip"])
    futils.check_call(["ip", "link", "set", IP_IN_IP_DEV_NAME, "mtu",
                       str(config.IP_IN_IP_MTU)])
    if not devices.interface_up(IP_IN_IP_DEV_NAME):
        _log.info("Tunnel device wasn't up; enabling.")
        futils.check_call(["ip", "link", "set", IP_IN_IP_DEV_NAME, "up"])
    _log.info("Configured IPIP device.")


def interface_to_suffix(config, iface_name):
    """
    Extracts the suffix from a given interface name, uniquely shortening it
    to 16 characters if necessary.
    :param iface_name: The interface name
    :returns string: the suffix (shortened if necessary)
    """
    suffix = iface_name.replace(config.IFACE_PREFIX, "", 1)
    # The suffix is surely not very long, but make sure.
    suffix = futils.uniquely_shorten(suffix, 16)
    return suffix
