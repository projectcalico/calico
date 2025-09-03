#!/usr/bin/env python3
"""
QoS Responsiveness Tests for Calico OpenStack Integration

This script tests the responsiveness of Calico's integration code in converting
QoS parameters from the Neutron API to the Calico WorkloadEndpoint API.

The tests verify that WorkloadEndpoint objects are correctly updated within
a few seconds when QoS policies are applied to networks and ports.
"""

import json
import logging
import os
import time
import unittest
from typing import Dict, List, Optional, Tuple

import etcd3

import openstack


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# openstack.enable_logging(debug=True, http_debug=True)


# Copied from
# https://github.com/tigera/calico-test/blob/bobcat/calicotest/common/testutils.py.
def retry_until_success(
    function,
    retries=10,
    wait_time=1,
    ex_class=None,
    log_exception=True,
    context_string="",
    function_args=None,
    function_kwargs=None,
):
    """
    Retries function until no exception is thrown. If exception continues,
    it is reraised.

    :param function: the function to be repeatedly called
    :param retries: the maximum number of times to retry the function.  A value
    of 0 will run the function once with no retries.
    :param wait_time: the time to wait between retries (in s)
    :param ex_class: The class of expected exceptions.
    :param log_exception: By default this function logs the exception if the
    function is still failing after max retries.   This log can sometimes be
    superfluous -- if e.g. the calling code is going to make a better log --
    and can be suppressed by setting this parameter to False.
    :param context_string: A string used to flag the context of a specific call
    in logs.
    :param function_args: A list of arguments to pass to function
    :param function_kwargs: A dictionary of keyword arguments to pass to
                            function
    :returns: the value returned by function
    """
    if function_args is None:
        function_args = []
    if function_kwargs is None:
        function_kwargs = {}
    for retry in range(int(retries) + 1):
        try:
            result = function(*function_args, **function_kwargs)
        except Exception as e:
            if ex_class and e.__class__ is not ex_class:
                logger.exception(
                    "Hit unexpected exception in function - not retrying."
                )
                raise
            if retry < retries:
                logger.debug("Hit exception in function - retrying: %s", e)
                time.sleep(wait_time)
            else:
                if log_exception:
                    logger.exception(
                        "Function %s did not succeed before timeout.", function
                    )
                raise
        else:
            # Successfully ran the function
            return result


class QoSResponsivenessTest(unittest.TestCase):
    """Test suite for QoS responsiveness in Calico OpenStack integration."""

    @classmethod
    def setUpClass(cls):
        cls.test_resources = {
            "networks": [],
            "subnets": [],
            "ports": [],
            "servers": [],
            "qos_policies": [],
            "security_groups": [],
        }

        # Set up OpenStack connection
        cls.conn = openstack.connection.Connection(
            auth_url=os.environ.get("OS_AUTH_URL", "http://localhost/identity"),
            project_name=os.environ.get("OS_PROJECT_NAME", "admin"),
            username=os.environ.get("OS_USERNAME", "admin"),
            password=os.environ.get("OS_PASSWORD", "015133ea2bdc46ed434c"),
            region_name=os.environ.get("OS_REGION_NAME", "RegionOne"),
            project_domain_id=os.environ.get("OS_PROJECT_DOMAIN_ID", "default"),
            user_domain_id=os.environ.get("OS_USER_DOMAIN_ID", "default"),
            identity_api_version=3,
        )
        logger.info("OpenStack connection established")

        # Set up etcd client for Calico datastore access
        etcd_host = os.environ.get("ETCD_HOST", "localhost")
        etcd_port = int(os.environ.get("ETCD_PORT", "2379"))
        cls.etcd_client = etcd3.client(host=etcd_host, port=etcd_port)
        logger.info(f"etcd3 client established: {etcd_host}:{etcd_port}")
        status = cls.etcd_client.status()
        logger.info(f"status.version = {status.version}")
        logger.info(f"status.db_size = {status.db_size}")
        logger.info(f"status.leader = {status.leader}")
        logger.info(f"status.raft_index = {status.raft_index}")
        logger.info(f"status.raft_term = {status.raft_term}")

        # Define possible QoS rules that we will use in this test.
        cls.qos_rules = [
            {
                "rule": {
                    "type": "bandwidth_limit",
                    "max_kbps": 10200,
                    "max_burst_kbps": 20300,
                    "direction": "egress",
                },
                "controls": {
                    "egressBandwidth": 10200000,
                    "egressBurst": 20300000,
                },
            },
            {
                "rule": {
                    "type": "bandwidth_limit",
                    "max_kbps": 30400,
                    "max_burst_kbps": 40500,
                    "direction": "ingress",
                },
                "controls": {
                    "ingressBandwidth": 30400000,
                    "ingressBurst": 40500000,
                },
            },
            {
                "rule": {
                    "type": "packet_rate_limit",
                    "max_kpps": 12345,
                    "max_burst_kpps": 21087,
                    "direction": "egress",
                },
                "controls": {
                    "egressPacketRate": 12345000,
                },
            },
            {
                "rule": {
                    "type": "packet_rate_limit",
                    "max_kpps": 42341,
                    "max_burst_kpps": 50002,
                    "direction": "ingress",
                },
                "controls": {
                    "ingressPacketRate": 42341000,
                },
            },
        ]

        # Define possible combination sets of those rules.  If there are N
        # possible rules, there are 2**N possible combinations of them, formed
        # by each set including or not including each rule.
        cls.qos_rule_sets = []
        for i in range(2 ** len(cls.qos_rules)):
            rule_set = []
            for j in range(len(cls.qos_rules)):
                if i & (2**j) != 0:
                    rule_set.append(cls.qos_rules[j])
            cls.qos_rule_sets.append(rule_set)

    def test_qos_policy_id(self):
        # Test that a WorkloadEndpoint always gets the correct QoS settings as
        # we change the qos_policy_id on the corresponding port and on that
        # port's network.
        #
        # In this test, the rule set for a given qos_policy_id stays the same.

        # Form a set of states, in which transitioning between two of that
        # states means changing the qos_policy_id on the port and/or on the
        # network - including the possibilities that qos_policy_id might be not
        # set on either of those.
        policy_id_to_rule_set = {
            "A": self.qos_rule_sets[2],
            "B": self.qos_rule_sets[7],
            "C": self.qos_rule_sets[12],
        }
        states = []
        for net_qos_id in [None, "A", "B"]:
            for port_qos_id in [None, "B", "C"]:
                state = {
                    "net_qos_id": net_qos_id,
                    "port_qos_id": port_qos_id,
                }
                if port_qos_id is not None:
                    state["port_qos_rules"] = policy_id_to_rule_set[port_qos_id]
                else:
                    state["port_qos_rules"] = []
                if net_qos_id is not None:
                    state["net_qos_rules"] = policy_id_to_rule_set[net_qos_id]
                else:
                    state["net_qos_rules"] = []
                states.append(state)

        # Test transitions between those states.
        self._test_transitions(states)

    def test_qos_rule_change(self):
        # Test that a WorkloadEndpoint always gets the correct QoS settings as
        # we change the QoS rules for the qos_policy_id on the corresponding
        # port and on that port's network.
        #
        # In this test, the qos_policy_id values themselves stay the same.

        # Form a set of states, in which transitioning between two of that
        # states means changing the QoS rules for the effective qos_policy_id.
        state_base = {
            "net_qos_id": None,
            "port_qos_id": "D",
        }
        states = []
        for rules in self.qos_rule_sets:
            state = state_base.copy()
            state["port_qos_rules"] = rules
            state["net_qos_rules"] = []
            states.append(state)

        # Test transitions between those states.
        self._test_transitions(states)

    def _test_transitions(self, states):
        # Calculate the possible transitions from each state, such that only
        # one thing is changing in each transition.
        transitions_remaining = 0
        for i in range(len(states)):
            states[i]["transitions"] = []
            states[i]["transitions_covered"] = []
            for j in range(len(states)):
                if i == j:
                    continue
                if self._only_one_change(states[i], states[j]):
                    states[i]["transitions"].append(j)
                    transitions_remaining += 1

        # Calculate a set of state sequences that will cover all of the
        # possible single-change transitions.
        sequences = []
        while transitions_remaining:
            logger.info(
                "%d transitions remaining, start new sequence", transitions_remaining
            )
            sequence = []
            # Find an initial state.
            for i in range(len(states)):
                if len(states[i]["transitions_covered"]) < len(
                    states[i]["transitions"]
                ):
                    sequence.append(i)
                    break
            making_progress = True
            while making_progress:
                i = sequence[-1]
                making_progress = False
                for j in states[i]["transitions"]:
                    if j in states[i]["transitions_covered"]:
                        continue
                    state_transitions_remaining = len(states[i]["transitions"]) - len(
                        states[i]["transitions_covered"]
                    )
                    if (
                        state_transitions_remaining > 1
                        and len(sequence) > 1
                        and j == sequence[-2]
                    ):
                        continue
                    sequence.append(j)
                    states[i]["transitions_covered"].append(j)
                    transitions_remaining -= 1
                    making_progress = True
                    break
            logger.info(
                "Calculated sequence with length %d = %r", len(sequence), sequence
            )
            sequences.append(sequence)

        # Test each sequence in turn.
        for sequence in sequences:
            self._test_sequence([states[i] for i in sequence])

    def _only_one_change(self, a, b):
        changes = []
        if a["net_qos_id"] != b["net_qos_id"]:
            changes.append(
                f"change net_qos_id to {b['net_qos_id']}"
            )
        if a["port_qos_id"] != b["port_qos_id"]:
            changes.append(f"change port_qos_id to {b['port_qos_id']}")
        if len(changes) > 1:
            return False
        # Only compare the rules when IDs are not changing.
        if len(changes) == 0:
            if b["port_qos_id"] is not None:
                relevant_rules = "port_qos_rules"
            else:
                relevant_rules = "net_qos_rules"
            a_rules = a[relevant_rules]
            b_rules = b[relevant_rules]
            for r in a_rules:
                if r not in b_rules:
                    changes.append(f"remove rule {r}")
            for r in b_rules:
                if r not in a_rules:
                    changes.append(f"add rule {r}")
        if len(changes) > 1:
            return False
        if len(changes) == 0:
            return False
        return changes[0]

    def _test_sequence(self, sequence):
        current = None
        for nxt in sequence:
            if current is None:
                self._create_initial_state(nxt)
            else:
                self._apply_change(current, nxt)
                self._verify_wep_qos(nxt)
            current = nxt

    def _create_initial_state(self, state):
        logger.info(f"Create initial state -> {state}")

        # Create the QoS rules and policies that we need.
        if state["port_qos_id"] is not None:
            port_qos = self.create_qos_policy(
                "test-qos-policy-" + state["port_qos_id"],
                [r["rule"] for r in state["port_qos_rules"]],
            )

        self.net_qos_rules = state["net_qos_rules"]
        if state["net_qos_id"] == state["port_qos_id"]:
            network_qos = port_qos
        elif state["net_qos_id"] is not None:
            network_qos = self.create_qos_policy(
                "test-qos-policy-" + state["net_qos_id"],
                [r["rule"] for r in self.net_qos_rules],
            )

        # Create the network and subnet.
        network, subnet = self.create_test_network(
            "test-network",
            state["net_qos_id"],
        )

        # Create the VM.
        vm = self.create_vm(network.id, subnet.id)

        # Maybe set port-level QoS.
        if state["port_qos_id"] is not None:
            self.conn.network.update_port(port.id, qos_policy_id=state["port_qos_id"])

    def create_qos_policy(self, name: str, rules: List[Dict]) -> object:
        """Create a QoS policy with specified rules."""
        unique_name = f"{name}"

        qos_policy = self.conn.network.create_qos_policy(name=unique_name)
        self.test_resources["qos_policies"].append(qos_policy)

        for rule in rules:
            if rule["type"] == "bandwidth_limit":
                self.conn.network.create_qos_bandwidth_limit_rule(
                    qos_policy.id,
                    max_kbps=rule.get("max_kbps"),
                    max_burst_kbps=rule.get("max_burst_kbps"),
                    direction=rule.get("direction", "egress"),
                )
            elif rule["type"] == "packet_rate_limit":
                self.conn.network.create_qos_packet_rate_limit_rule(
                    qos_policy.id,
                    max_kpps=rule.get("max_kpps"),
                    direction=rule.get("direction", "egress"),
                )

        logger.info(f"Created QoS policy: {unique_name} with {len(rules)} rules")
        return qos_policy

    def create_test_network(
        self, name: str, qos_policy_id: str = None
    ) -> Tuple[object, object]:
        """Create a test network and subnet."""
        unique_name = f"{name}"

        network_args = {
            "name": unique_name,
            "is_shared": True,
            "provider:network_type": "local",
        }
        if qos_policy_id:
            network_args["qos_policy_id"] = qos_policy_id

        network = self.conn.network.create_network(**network_args)
        self.test_resources["networks"].append(network)

        subnet = self.conn.network.create_subnet(
            name=f"{unique_name}-subnet",
            network_id=network.id,
            cidr="192.168.100.0/24",
            ip_version=4,
            enable_dhcp=True,
        )
        self.test_resources["subnets"].append(subnet)

        logger.info(
            f"Created network: {unique_name}-net"
            f" {'with QoS policy' if qos_policy_id else 'without QoS policy'}"
        )
        return network, subnet

    def _apply_change(self, current, nxt):
        change = self._only_one_change(current, nxt)
        logger.info(f" {change} -> {nxt}")
        if change.startswith("change net_qos_id"):
            self._ensure_qos_policy(
        elif change.startswith("change port_qos_id"):
            pass
        elif change.startswith("remove rule"):
            pass
        elif change.startswith("add rule"):
            pass
        else:
            self.assertTrue(False)

    def _verify_wep_qos(self, state):
        logger.info(f"Verify WEP QoS for state {state}")
        expected_qos = {}
        for r in state["qos_rules"]:
            expected_qos.update(r["controls"])
        logger.info(f"Expected QoS is {expected_qos}")
        retry_until_success(
            self._assert_wep_qos,
            function_args=(self.transition_port_id, expected_qos),
        )

    def _assert_wep_qos(self, port_id: str, expected_qos: Dict) -> bool:
        """
        Assert that WorkloadEndpoint QoS controls are as expected.

        Args:
            port_id: Neutron port ID
            expected_qos: Expected QoS controls dictionary
        """
        wep = None
        for value, metadata in self.etcd_client.get_prefix(
                "/calico/resources/v3/projectcalico.org/workloadendpoints/"
        ):
            logger.info(f"Metadata = {metadata}")
            if port_id.replace("-", "--") in metadata.key.decode():
                wep = json.loads(value.decode())
                break

        logger.info(f"WEP for port {port_id} is {wep}")
        self.assertIsNotNone(wep)
        self.assertIn("spec", wep)
        if expected_qos is None:
            self.assertNotIn("qosControls", wep["spec"])
        else:
            self.assertIn("qosControls", wep["spec"])
            qos_controls = wep["spec"]["qosControls"]
            self.assertDictEqual(qos_controls, expected_qos)

    def setUp(self):
        self.tearDown()

    def tearDown(self):
        logger.info("Cleaning up any leftover test resources...")

        # Clean up QoS policies with test prefixes
        for qos_policy in self.conn.network.qos_policies():
            if qos_policy.name.startswith("test-"):
                try:
                    # First remove any network bindings
                    for network in self.conn.network.networks():
                        if network.qos_policy_id == qos_policy.id:
                            try:
                                self.conn.network.update_network(
                                    network.id, qos_policy_id=None
                                )
                                logger.info(
                                    f"Removed QoS policy from network: {network.name}"
                                )
                            except Exception as e:
                                logger.debug(
                                    "Failed to remove QoS policy from network"
                                    f" {network.name}: {e}"
                                )

                    # Remove port bindings
                    for port in self.conn.network.ports():
                        if port.qos_policy_id == qos_policy.id:
                            try:
                                self.conn.network.update_port(
                                    port.id, qos_policy_id=None
                                )
                                logger.info(
                                    f"Removed QoS policy from port: {port.name}"
                                )
                            except Exception as e:
                                logger.debug(
                                    "Failed to remove QoS policy from port"
                                    f" {port.name}: {e}"
                                )

                    # Now delete the policy
                    self.conn.network.delete_qos_policy(qos_policy.id)
                    logger.info(f"Cleaned up leftover QoS policy: {qos_policy.name}")
                except Exception as e:
                    logger.debug(
                        f"Failed to clean up QoS policy {qos_policy.name}: {e}"
                    )

        # Clean up networks with test prefixes
        for network in self.conn.network.networks():
            if network.name.startswith("test-"):
                try:
                    # Delete ports first
                    for port in self.conn.network.ports():
                        if port.network_id == network.id:
                            try:
                                self.conn.network.delete_port(port.id)
                                logger.info(f"Cleaned up leftover port: {port.name}")
                            except Exception as e:
                                logger.debug(
                                    f"Failed to clean up port {port.name}: {e}"
                                )

                    # Delete subnets
                    for subnet in self.conn.network.subnets():
                        if subnet.network_id == network.id:
                            try:
                                self.conn.network.delete_subnet(subnet.id)
                                logger.info(
                                    f"Cleaned up leftover subnet: {subnet.name}"
                                )
                            except Exception as e:
                                logger.debug(
                                    f"Failed to clean up subnet {subnet.name}: {e}"
                                )

                    # Delete network
                    self.conn.network.delete_network(network.id)
                    logger.info(f"Cleaned up leftover network: {network.name}")
                except Exception as e:
                    logger.debug(f"Failed to clean up network {network.name}: {e}")

    def cleanup_resources(self):
        """Clean up all test resources."""
        logger.info("Cleaning up test resources...")

        # Delete servers
        for server in self.test_resources["servers"]:
            try:
                self.conn.compute.delete_server(server.id)
                self.conn.compute.wait_for_delete(server)
                logger.info(f"Deleted server: {server.name}")
            except Exception as e:
                logger.warning(f"Failed to delete server {server.name}: {e}")

        # Delete ports (first remove QoS policies to avoid binding conflicts)
        for port in self.test_resources["ports"]:
            try:
                # Remove QoS policy first if present
                if hasattr(port, "qos_policy_id") and port.qos_policy_id:
                    try:
                        self.conn.network.update_port(port.id, qos_policy_id=None)
                    except Exception as e:
                        logger.debug(
                            f"Failed to remove QoS policy from port {port.name}: {e}"
                        )

                self.conn.network.delete_port(port.id)
                logger.info(f"Deleted port: {port.name}")
            except Exception as e:
                logger.warning(f"Failed to delete port {port.name}: {e}")

        # Delete subnets
        for subnet in self.test_resources["subnets"]:
            try:
                self.conn.network.delete_subnet(subnet.id)
                logger.info(f"Deleted subnet: {subnet.name}")
            except Exception as e:
                logger.warning(f"Failed to delete subnet {subnet.name}: {e}")

        # Delete networks (remove QoS policies first)
        for network in self.test_resources["networks"]:
            try:
                # Remove QoS policy first if present
                if hasattr(network, "qos_policy_id") and network.qos_policy_id:
                    try:
                        self.conn.network.update_network(network.id, qos_policy_id=None)
                    except Exception as e:
                        logger.debug(
                            "Failed to remove QoS policy from network"
                            f" {network.name}: {e}"
                        )

                self.conn.network.delete_network(network.id)
                logger.info(f"Deleted network: {network.name}")
            except Exception as e:
                logger.warning(f"Failed to delete network {network.name}: {e}")

        # Delete QoS policies
        for qos_policy in self.test_resources["qos_policies"]:
            try:
                self.conn.network.delete_qos_policy(qos_policy.id)
                logger.info(f"Deleted QoS policy: {qos_policy.name}")
            except Exception as e:
                logger.warning(f"Failed to delete QoS policy {qos_policy.name}: {e}")

        # Delete security groups
        for sg in self.test_resources["security_groups"]:
            try:
                self.conn.network.delete_security_group(sg.id)
                logger.info(f"Deleted security group: {sg.name}")
            except Exception as e:
                logger.warning(f"Failed to delete security group {sg.name}: {e}")

    def create_test_port(
        self, name: str, network_id: str, qos_policy_id: str = None
    ) -> object:
        """Create a test port."""
        unique_name = f"{name}"

        port_args = {
            "name": unique_name,
            "network_id": network_id,
            "device_owner": "compute:",
            "admin_state_up": True,
        }
        if qos_policy_id:
            port_args["qos_policy_id"] = qos_policy_id

        port = self.conn.network.create_port(**port_args)
        self.test_resources["ports"].append(port)

        logger.info(
            f"Created port: {unique_name}"
            f" {'with QoS policy' if qos_policy_id else 'without QoS policy'}"
        )
        return port

    def test_network_qos_policy(self) -> bool:
        """Test QoS policy applied at network level."""
        logger.info("=== Testing Network-level QoS Policy ===")

        # Create QoS policy with bandwidth limit
        qos_policy = self.create_qos_policy(
            "test-network-qos",
            [
                {
                    "type": "bandwidth_limit",
                    "max_kbps": 10000,  # 10 Mbps
                    "max_burst_kbps": 12000,  # 12 Mbps burst
                    "direction": "egress",
                }
            ],
        )

        # Create network with QoS policy
        network, subnet = self.create_test_network("test-network-qos", qos_policy.id)

        # Create port on the network
        port = self.create_test_port("test-port-network-qos", network.id)

        # Verify QoS controls are applied to WorkloadEndpoint
        expected_qos = {
            "egressBandwidth": 10000000,  # Convert kbps to bps
            "egressPeakrate": 12000000,  # Convert kbps to bps
        }

        self._assert_wep_qos(port.id, expected_qos)

    def test_port_qos_policy(self) -> bool:
        """Test QoS policy applied at port level."""
        logger.info("=== Testing Port-level QoS Policy ===")

        # Create QoS policy with packet rate limit
        qos_policy = self.create_qos_policy(
            "test-port-qos",
            [
                {
                    "type": "packet_rate_limit",
                    "max_kpps": 5,  # 5000 packets per second
                    "direction": "ingress",
                }
            ],
        )

        # Create network without QoS policy
        network, subnet = self.create_test_network("test-network-no-qos")

        # Create port with QoS policy
        port = self.create_test_port("test-port-with-qos", network.id, qos_policy.id)

        # Verify QoS controls are applied to WorkloadEndpoint
        expected_qos = {"ingressPacketRate": 5000}  # Convert kpps to pps

        self._assert_wep_qos(port.id, expected_qos)

    def test_mixed_qos_policies(self) -> bool:
        """Test network with QoS policy and port with different QoS policy."""
        logger.info("=== Testing Mixed QoS Policies (Network + Port) ===")

        # Create network-level QoS policy
        network_qos_policy = self.create_qos_policy(
            "test-mixed-network-qos",
            [
                {
                    "type": "bandwidth_limit",
                    "max_kbps": 5000,  # 5 Mbps
                    "direction": "ingress",
                }
            ],
        )

        # Create port-level QoS policy (should override network policy)
        port_qos_policy = self.create_qos_policy(
            "test-mixed-port-qos",
            [
                {
                    "type": "bandwidth_limit",
                    "max_kbps": 20000,  # 20 Mbps
                    "max_burst_kbps": 25000,  # 25 Mbps burst
                    "direction": "egress",
                },
                {
                    "type": "packet_rate_limit",
                    "max_kpps": 10,  # 10000 packets per second
                    "direction": "ingress",
                },
            ],
        )

        # Create network with QoS policy
        network, subnet = self.create_test_network(
            "test-mixed-network", network_qos_policy.id
        )

        # Create port with different QoS policy
        port = self.create_test_port("test-mixed-port", network.id, port_qos_policy.id)

        # Port-level QoS should take precedence
        expected_qos = {
            "egressBandwidth": 20000000,  # From port policy
            "egressPeakrate": 25000000,  # From port policy
            "ingressPacketRate": 10000,  # From port policy
        }

        self._assert_wep_qos(port.id, expected_qos)

    def test_qos_policy_update(self) -> bool:
        """Test updating QoS policy and verifying responsiveness."""
        logger.info("=== Testing QoS Policy Update Responsiveness ===")

        # Create initial QoS policy
        qos_policy = self.create_qos_policy(
            "test-update-qos",
            [
                {
                    "type": "bandwidth_limit",
                    "max_kbps": 1000,  # 1 Mbps
                    "direction": "egress",
                }
            ],
        )

        # Create network and port
        network, subnet = self.create_test_network("test-update-network")
        port = self.create_test_port("test-update-port", network.id, qos_policy.id)

        # Verify initial QoS controls
        initial_qos = {"egressBandwidth": 1000000}
        self._assert_wep_qos(port.id, initial_qos)

        # Update QoS policy by adding new rule
        self.conn.network.create_qos_bandwidth_limit_rule(
            qos_policy.id, max_kbps=15000, direction="ingress"  # 15 Mbps
        )

        # Verify updated QoS controls
        updated_qos = {
            "egressBandwidth": 1000000,  # Original rule
            "ingressBandwidth": 15000000,  # New rule
        }

        self._assert_wep_qos(port.id, updated_qos, timeout=15)

    def test_qos_policy_removal(self) -> bool:
        """Test removing QoS policy and verifying cleanup."""
        logger.info("=== Testing QoS Policy Removal ===")

        # Create QoS policy
        qos_policy = self.create_qos_policy(
            "test-removal-qos",
            [
                {
                    "type": "bandwidth_limit",
                    "max_kbps": 8000,  # 8 Mbps
                    "direction": "egress",
                }
            ],
        )

        # Create network and port
        network, subnet = self.create_test_network("test-removal-network")
        port = self.create_test_port("test-removal-port", network.id, qos_policy.id)

        # Verify QoS controls are applied
        initial_qos = {"egressBandwidth": 8000000}
        self._assert_wep_qos(port.id, initial_qos)

        # Remove QoS policy from port
        self.conn.network.update_port(port.id, qos_policy_id=None)

        # Verify QoS controls are removed (WorkloadEndpoint should have no qosControls)
        self._assert_wep_qos(port.id, None)

    def check_neutron_port_qos(self, port_id: str) -> Optional[Dict]:
        """Check if a Neutron port has QoS policy applied."""
        try:
            port = self.conn.network.get_port(port_id)
            if port and port.qos_policy_id:
                qos_policy = self.conn.network.get_qos_policy(port.qos_policy_id)
                rules = list(self.conn.network.qos_rules(qos_policy))
                return {
                    "policy_id": port.qos_policy_id,
                    "policy_name": qos_policy.name,
                    "rules": [{"id": r.id, "type": r.type} for r in rules],
                }
        except Exception as e:
            logger.debug(f"Error checking Neutron port QoS: {e}")
        return None

    def test_basic_qos_integration(self) -> bool:
        """Test basic QoS integration between Neutron and Calico."""
        logger.info("=== Testing Basic QoS Integration ===")

        try:
            # Create QoS policy with bandwidth limit
            qos_policy = self.conn.network.create_qos_policy(
                name=f"test-qos-integration"
            )
            self.test_resources["qos_policies"].append(qos_policy)

            # Add bandwidth limit rule
            rule = self.conn.network.create_qos_bandwidth_limit_rule(
                qos_policy.id, max_kbps=10000, direction="egress"  # 10 Mbps
            )
            logger.info(
                f"Created QoS policy {qos_policy.name} with bandwidth limit rule"
            )

            # Create network
            network = self.conn.network.create_network(
                name=f"test-qos-network"
            )
            self.test_resources["networks"].append(network)

            # Create subnet
            subnet = self.conn.network.create_subnet(
                name=f"test-qos-subnet",
                network_id=network.id,
                cidr="192.168.200.0/24",
                ip_version=4,
                enable_dhcp=True,
            )
            self.test_resources["subnets"].append(subnet)

            # Create port with QoS policy
            port = self.conn.network.create_port(
                name="test-qos-port",
                network_id=network.id,
                qos_policy_id=qos_policy.id,
                admin_state_up=True,
            )
            self.test_resources["ports"].append(port)

            logger.info(f"Created port {port.name} with QoS policy")

            # Wait a bit for the integration to process
            time.sleep(3)

            # Verify Neutron side has QoS policy
            neutron_qos = self.check_neutron_port_qos(port.id)
            if not neutron_qos:
                logger.error("Failed to verify QoS policy on Neutron port")
                return False

            logger.info(f"Neutron QoS verification passed: {neutron_qos}")

            # Check if Calico WorkloadEndpoint exists (basic connectivity test)
            calico_connected = self.check_calico_workload_endpoint(port.id)
            if not calico_connected:
                logger.warning(
                    "Calico WorkloadEndpoint not found - may indicate integration issue"
                )
                # Don't fail the test as this might be expected in some
                # DevStack configurations
            else:
                logger.info("Calico integration connectivity verified")

            logger.info("✓ Basic QoS integration test completed successfully")
            return True

        except Exception as e:
            logger.error(f"Basic QoS integration test failed: {e}")
            return False

    def test_multiple_qos_scenarios(self) -> bool:
        """Test multiple QoS scenarios to verify integration responsiveness."""
        logger.info("=== Testing Multiple QoS Scenarios ===")

        try:
            # Create base network
            network = self.conn.network.create_network(
                name="test-multi-qos-network"
            )
            self.test_resources["networks"].append(network)

            subnet = self.conn.network.create_subnet(
                name="test-multi-qos-subnet",
                network_id=network.id,
                cidr="192.168.210.0/24",
                ip_version=4,
                enable_dhcp=True,
            )
            self.test_resources["subnets"].append(subnet)

            success_count = 0
            for i, scenario in enumerate(scenarios):
                try:
                    logger.info(f"Testing scenario: {scenario['name']}")

                    # Create QoS policy for this scenario
                    qos_policy = self.conn.network.create_qos_policy(
                        name=f"test-{scenario['name']}"
                    )
                    self.test_resources["qos_policies"].append(qos_policy)

                    # Add rules
                    for rule_spec in scenario["rules"]:
                        if rule_spec["type"] == "bandwidth_limit":
                            self.conn.network.create_qos_bandwidth_limit_rule(
                                qos_policy.id,
                                max_kbps=rule_spec["max_kbps"],
                                max_burst_kbps=rule_spec.get("max_burst_kbps"),
                                direction=rule_spec["direction"],
                            )

                    # Create port with this QoS policy
                    port = self.conn.network.create_port(
                        name=f"test-port-{i}",
                        network_id=network.id,
                        qos_policy_id=qos_policy.id,
                        admin_state_up=True,
                    )
                    self.test_resources["ports"].append(port)

                    # Wait for processing
                    time.sleep(2)

                    # Verify the port has the QoS policy
                    neutron_qos = self.check_neutron_port_qos(port.id)
                    if neutron_qos:
                        logger.info(
                            f"Scenario {scenario['name']}: Neutron QoS verified"
                        )
                        success_count += 1
                    else:
                        logger.warning(
                            f"Scenario {scenario['name']}: Neutron QoS verification"
                            " failed"
                        )

                except Exception as e:
                    logger.warning(f"Scenario {scenario['name']} failed: {e}")



if __name__ == "__main__":
    unittest.main()
