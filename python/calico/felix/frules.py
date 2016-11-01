# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
# Copyright (c) 2015 Cisco Systems.  All Rights Reserved.
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
Accept MARK (a configured bit in the MARK space):

* Packet was matched by a deny rule.  In this case the packet is immediately
  dropped.
* Packet was matched by an allow rule.  In this case the packet is returned
  with Accept MARK==1.  The calling chain can then return the packet to its
  caller for further processing.
* Packet was not matched at all.  In this case, the packet is returned with
  Accept MARK==0.  The calling chain can then send the packet through the next
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

# Rule to catch packets that are being sent down the IPIP tunnel from an
# incorrect local IP address of the host.  This happens if:
#
# - the user explicitly binds their socket to the wrong source IP accidentally
# - the user sends traffic to, for example, a Kubernetes service IP, which is
#   implemented via NAT instead of routing, leading the kernel to choose the
#   wrong source IP.
#
# We NAT the source of the packet to use the tunnel IP.  We assume that
# non-local IPs have been correctly routed.  Since Calico-assigned IPs are
# non-local (because they're down a veth), they won't get caught by the rule.
# Other remote sources will only reach the tunnel if they're being NATted
# already (for example, a Kubernetes "NodePort").  The kernel will then
# choose the correct source on its own.
POSTROUTING_LOCAL_NAT_FRAGMENT = (
    "POSTROUTING "
    # Only match if the packet is going out via the tunnel.
    "--out-interface %s "
    # Match packets that don't have the correct source address.  This matches
    # local addresses (i.e. ones assigned to this host) limiting the match to
    # the output interface (which we matched above as the tunnel).  Avoiding
    # embedding the IP address lets us use a static rule, which is easier to
    # manage.
    "-m addrtype ! --src-type LOCAL --limit-iface-out "
    # Only match if the IP is also some local IP on the box.  This prevents
    # us from matching packets from workloads, which are remote as far as the
    # routing table is concerned.
    "-m addrtype --src-type LOCAL "
    # NAT them to use the source IP of the tunnel.  Using MASQUERADE means
    # the kernel chooses the source automatically.
    "-j MASQUERADE" % IP_IN_IP_DEV_NAME
)

# Chain names

# Dispatch chains to and from workload endpoints.
CHAIN_TO_ENDPOINT = FELIX_PREFIX + "TO-ENDPOINT"
CHAIN_FROM_ENDPOINT = FELIX_PREFIX + "FROM-ENDPOINT"
CHAIN_TO_LEAF = FELIX_PREFIX + "TO-EP-PFX"
CHAIN_FROM_LEAF = FELIX_PREFIX + "FROM-EP-PFX"
WORKLOAD_DISPATCH_CHAINS = {
    "to_root": CHAIN_TO_ENDPOINT,
    "from_root": CHAIN_FROM_ENDPOINT,
    "to_leaf": CHAIN_TO_LEAF,
    "from_leaf": CHAIN_FROM_LEAF,
}

# Ditto for host endpoints.
CHAIN_TO_IFACE = FELIX_PREFIX + "TO-HOST-IF"
CHAIN_FROM_IFACE = FELIX_PREFIX + "FROM-HOST-IF"
CHAIN_TO_IFACE_LEAF = FELIX_PREFIX + "TO-IF-PFX"
CHAIN_FROM_IFACE_LEAF = FELIX_PREFIX + "FROM-IF-PFX"
HOST_DISPATCH_CHAINS = {
    "to_root": CHAIN_TO_IFACE,
    "from_root": CHAIN_FROM_IFACE,
    "to_leaf": CHAIN_TO_IFACE_LEAF,
    "from_leaf": CHAIN_FROM_IFACE_LEAF,
}

# Failsafe whitelist chains.
CHAIN_FAILSAFE_IN = FELIX_PREFIX + "FAILSAFE-IN"
CHAIN_FAILSAFE_OUT = FELIX_PREFIX + "FAILSAFE-OUT"

# Per-endpoint/interface chain prefixes.
CHAIN_TO_PREFIX = FELIX_PREFIX + "to-"
CHAIN_FROM_PREFIX = FELIX_PREFIX + "from-"

# Top-level felix chains.
CHAIN_PREROUTING = FELIX_PREFIX + "PREROUTING"
CHAIN_POSTROUTING = FELIX_PREFIX + "POSTROUTING"
CHAIN_INPUT = FELIX_PREFIX + "INPUT"
CHAIN_OUTPUT = FELIX_PREFIX + "OUTPUT"
CHAIN_FORWARD = FELIX_PREFIX + "FORWARD"
CHAIN_FIP_DNAT = FELIX_PREFIX + 'FIP-DNAT'
CHAIN_FIP_SNAT = FELIX_PREFIX + 'FIP-SNAT'


def load_nf_conntrack():
    """
    Try to force the nf_conntrack_netlink kernel module to be loaded.
    """
    _log.info("Running conntrack command to force load of "
              "nf_conntrack_netlink module.")
    try:
        # Run a conntrack command to trigger it to load the kernel module if
        # it's not already compiled in.  We list rules with a randomly-chosen
        # link local address.  That makes it very unlikely that we generate
        # any wasteful output.  We used to use "-S" (show stats) here but it
        # seems to be bugged on some platforms, generating an error.
        futils.check_call(["conntrack", "-L", "-s", "169.254.45.169"])
    except FailedSystemCall:
        _log.exception("Failed to execute conntrack command to force load of "
                       "nf_conntrack_netlink module.  conntrack commands may "
                       "fail later.")


def install_global_rules(config, filter_updater, nat_updater, ip_version,
                         raw_updater=None):
    """
    Set up global iptables rules. These are rules that do not change with
    endpoint, and are expected never to change (such as the rules that send all
    traffic through the top level Felix chains).

    This method therefore :

    - ensures that all the required global tables are present;
    - applies any changes required.
    """

    # If enabled, create the IP-in-IP device, but only for IPv4
    if ip_version == 4:
        if config.IP_IN_IP_ENABLED:
            _log.info("IP-in-IP enabled, ensuring device exists.")
            try:
                _configure_ipip_device(config)
            except FailedSystemCall:
                # We've seen this fail occasionally if the kernel is
                # concurrently starting the tunl0 device.  Retry.
                _log.exception("Failed to configure IPIP device, retrying...")
                time.sleep(1)
                _configure_ipip_device(config)

        if config.IP_IN_IP_ENABLED and config.IP_IN_IP_ADDR:
            # Add a rule to catch packets originated by this host that are
            # going down the tunnel with the wrong source address.  NAT them
            # to use the address of the tunnel device instead.  See comment
            # on the constant for more details.
            _log.info("IPIP enabled and tunnel address set: inserting "
                      "MASQUERADE rule to ensure tunnelled packets have "
                      "correct source.")
            nat_updater.ensure_rule_inserted(POSTROUTING_LOCAL_NAT_FRAGMENT,
                                                async=False)
        else:
            # Clean up the rule that we insert above if IPIP is enabled.
            _log.info("IPIP disabled or no tunnel address set: removing "
                      "MASQUERADE rule.")
            nat_updater.ensure_rule_removed(POSTROUTING_LOCAL_NAT_FRAGMENT,
                                            async=False)

    # Ensure that Calico-controlled IPv6 hosts cannot spoof their IP addresses.
    # (For IPv4, this is controlled by a per-interface sysctl.)
    iptables_generator = config.plugins["iptables_generator"]

    if raw_updater:
        raw_prerouting_chain, raw_prerouting_deps = (
            iptables_generator.raw_rpfilter_failed_chain(ip_version=ip_version)
        )
        raw_updater.rewrite_chains({CHAIN_PREROUTING: raw_prerouting_chain},
                                   {CHAIN_PREROUTING: raw_prerouting_deps},
                                   async=False)

        for iface_prefix in config.IFACE_PREFIX:
            # The interface matching string; for example,
            # if interfaces start "tap" then this string is "tap+".
            iface_match = iface_prefix + '+'
            raw_updater.ensure_rule_inserted(
                "PREROUTING --in-interface %s --match rpfilter --invert "
                "--jump %s" %
                (iface_match, CHAIN_PREROUTING),
                async=False)

    # Both IPV4 and IPV6 nat tables need felix-PREROUTING and
    # felix-POSTROUTING, along with the dependent DNAT and SNAT tables
    # required for NAT/floating IP support.

    prerouting_chain, prerouting_deps = (
        iptables_generator.nat_prerouting_chain(ip_version=ip_version)
    )
    postrouting_chain, postrouting_deps = (
        iptables_generator.nat_postrouting_chain(ip_version=ip_version)
    )
    nat_updater.rewrite_chains({CHAIN_PREROUTING: prerouting_chain,
                                CHAIN_POSTROUTING: postrouting_chain,
                                CHAIN_FIP_DNAT: [],
                                CHAIN_FIP_SNAT: []},
                               {CHAIN_PREROUTING: prerouting_deps,
                                CHAIN_POSTROUTING: postrouting_deps},
                               async=False)

    nat_updater.ensure_rule_inserted(
        "PREROUTING --jump %s" % CHAIN_PREROUTING, async=False)
    nat_updater.ensure_rule_inserted(
        "POSTROUTING --jump %s" % CHAIN_POSTROUTING, async=False)

    # Now the filter table. This needs to have felix-FORWARD and felix-INPUT
    # chains, which we must create before adding any rules that send to them.
    if ip_version == 4 and config.IP_IN_IP_ENABLED:
        hosts_set_name = HOSTS_IPSET_V4.set_name
        HOSTS_IPSET_V4.ensure_exists()
    else:
        hosts_set_name = None

    input_chain, input_deps = (
        iptables_generator.filter_input_chain(ip_version, hosts_set_name)
    )
    output_chain, output_deps = (
        iptables_generator.filter_output_chain(ip_version)
    )
    forward_chain, forward_deps = (
        iptables_generator.filter_forward_chain(ip_version)
    )
    failsafe_in_chain, failsafe_in_deps = (
        iptables_generator.failsafe_in_chain()
    )
    failsafe_out_chain, failsafe_out_deps = (
        iptables_generator.failsafe_out_chain()
    )

    filter_updater.rewrite_chains(
        {
            CHAIN_FORWARD: forward_chain,
            CHAIN_INPUT: input_chain,
            CHAIN_OUTPUT: output_chain,
            CHAIN_FAILSAFE_IN: failsafe_in_chain,
            CHAIN_FAILSAFE_OUT: failsafe_out_chain,
        },
        {
            CHAIN_FORWARD: forward_deps,
            CHAIN_INPUT: input_deps,
            CHAIN_OUTPUT: output_deps,
            CHAIN_FAILSAFE_IN: failsafe_in_deps,
            CHAIN_FAILSAFE_OUT: failsafe_out_deps,
        },
        async=False)

    filter_updater.ensure_rule_inserted(
        "INPUT --jump %s" % CHAIN_INPUT,
        async=False)
    filter_updater.ensure_rule_inserted(
        "OUTPUT --jump %s" % CHAIN_OUTPUT,
        async=False)
    filter_updater.ensure_rule_inserted(
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
    # Allow an IP address to be added to the tunnel.  This is useful to
    # allow the host to have an IP on a private IPIP network so that it can
    # originate traffic and have it routed correctly.
    _log.info("Setting IPIP device IP to %s", config.IP_IN_IP_ADDR)
    tunnel_addrs = [config.IP_IN_IP_ADDR] if config.IP_IN_IP_ADDR else []
    devices.set_interface_ips(futils.IPV4, IP_IN_IP_DEV_NAME,
                              set(tunnel_addrs))
    _log.info("Configured IPIP device.")


def interface_to_chain_suffix(config, iface_name):
    """
    Extracts the suffix from a given interface name, uniquely shortening it
    to 16 characters if necessary.
    :param iface_name: The interface name
    :returns string: the suffix (shortened if necessary)
    """
    for prefix in sorted(config.IFACE_PREFIX, reverse=True):
        if iface_name.startswith(prefix):
            iface_name = iface_name[len(prefix):]
            break
    iface_name = futils.uniquely_shorten(iface_name, 16)
    return iface_name
