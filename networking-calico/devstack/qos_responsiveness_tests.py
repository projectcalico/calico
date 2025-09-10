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
                logger.exception("Hit unexpected exception in function - not retrying.")
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
        cls.next_subnet_byte = 0

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
                    "egressPeakrate": 20300000,
                    "egressBurst": 4294967296,
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
                    "ingressPeakrate": 40500000,
                    "ingressBurst": 4294967296,
                },
            },
        ]
        # The Yoga version of openstacksdk does not support creating packet
        # rate limit rules.  Caracal and onwards do support this.
        if hasattr(cls.conn.network, "create_qos_packet_rate_limit_rule"):
            logger.info("openstacksdk can create packet rate limit rules")
            cls.qos_rules.extend(
                [
                    {
                        "rule": {
                            "type": "packet_rate_limit",
                            "max_kpps": 6,
                            "direction": "egress",
                        },
                        "controls": {
                            "egressPacketRate": 6000,
                            "egressPacketBurst": 5,
                        },
                    },
                    {
                        "rule": {
                            "type": "packet_rate_limit",
                            "max_kpps": 7,
                            "direction": "ingress",
                        },
                        "controls": {
                            "ingressPacketRate": 7000,
                            "ingressPacketBurst": 5,
                        },
                    },
                ]
            )

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
            "A": self.qos_rule_sets[1],
            "B": self.qos_rule_sets[2],
            "C": self.qos_rule_sets[3],
        }
        states = []
        for net_qos_name in [None, "A", "B"]:
            for port_qos_name in [None, "B", "C"]:
                state = {
                    "net_qos_name": net_qos_name,
                    "port_qos_name": port_qos_name,
                }
                if port_qos_name is not None:
                    state["port_qos_rules"] = policy_id_to_rule_set[port_qos_name]
                else:
                    state["port_qos_rules"] = []
                if net_qos_name is not None:
                    state["net_qos_rules"] = policy_id_to_rule_set[net_qos_name]
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
            "net_qos_name": None,
            "port_qos_name": "D",
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
        if a["net_qos_name"] != b["net_qos_name"]:
            changes.append(f"change net_qos_name to {b['net_qos_name']}")
        if a["port_qos_name"] != b["port_qos_name"]:
            changes.append(f"change port_qos_name to {b['port_qos_name']}")
        if len(changes) > 1:
            return False
        # Only compare the rules when IDs are not changing.
        if len(changes) == 0:
            if b["port_qos_name"] is not None:
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
                port_id = self._create_initial_state(nxt)
            else:
                self._apply_change(current, nxt)
                self._verify_wep_qos(port_id, nxt)
            current = nxt
        self.tearDown()

    def _create_initial_state(self, state):
        logger.info(f"Create initial state -> {state}")

        # Create the QoS rules and policies that we need.
        if state["port_qos_name"] is not None:
            port_qos_id = self._ensure_qos_policy(
                state["port_qos_name"],
                state["port_qos_rules"],
            )
        else:
            port_qos_id = None

        if state["net_qos_name"] is not None:
            net_qos_id = self._ensure_qos_policy(
                state["net_qos_name"],
                state["net_qos_rules"],
            )
        else:
            net_qos_id = None

        # Create the network and subnet.
        network, subnet = self.create_test_network("test-network", net_qos_id)

        # Create the VM.
        cirros = [i for i in self.conn.image.images() if i.name.startswith("cirros")][0]
        tiny = [i for i in self.conn.compute.flavors() if "tiny" in i.name][0]
        vm = self.conn.compute.create_server(
            name="test-vm",
            image_id=cirros.id,
            flavor_id=tiny.id,
            networks=[{"uuid": network.id}],
        )
        vm = self.conn.compute.wait_for_server(vm)
        port = list(self.conn.network.ports(device_id=vm.id))[0]

        # Maybe set port-level QoS.
        if port_qos_id is not None:
            self.conn.network.update_port(port.id, qos_policy_id=port_qos_id)

        return port.id

    def _ensure_qos_policy(self, name, rules):
        full_name = "test-qos-policy" + name
        qos_policy = self.conn.network.find_qos_policy(full_name)
        if qos_policy is None:
            qos_policy = self.conn.network.create_qos_policy(name=full_name)

        significant_keys = [
            "type",
            "direction",
            "max_burst_kbps",
            "max_kbps",
            "max_kpps",
        ]
        existing_rules = [
            {k: v for k, v in r.items() if k in significant_keys}
            for r in qos_policy.rules
        ]
        desired_rules = [
            {k: v for k, v in r["rule"].items() if k in significant_keys} for r in rules
        ]

        for i, r in enumerate(existing_rules):
            if r not in desired_rules:
                logger.info(f"Delete rule {r} for policy {name}")
                if r["type"] == "bandwidth_limit":
                    self.conn.network.delete_qos_bandwidth_limit_rule(
                        qos_policy.rules[i]["id"], qos_policy.id
                    )
                elif r["type"] == "packet_rate_limit":
                    self.conn.network.delete_qos_packet_rate_limit_rule(
                        qos_policy.rules[i]["id"], qos_policy.id
                    )

        for r in desired_rules:
            if r not in existing_rules:
                logger.info(f"Add rule {r} for policy {name}")
                if r["type"] == "bandwidth_limit":
                    r2 = r.copy()
                    del r2["type"]
                    self.conn.network.create_qos_bandwidth_limit_rule(
                        qos_policy.id, **r2
                    )
                elif r["type"] == "packet_rate_limit":
                    r2 = r.copy()
                    del r2["type"]
                    self.conn.network.create_qos_packet_rate_limit_rule(
                        qos_policy.id, **r2
                    )

        return qos_policy.id

    def create_test_network(self, name, qos_policy_id=None):
        """Create a test network and subnet."""
        network_args = {
            "name": name,
            "shared": True,
            "provider:network_type": "local",
        }
        if qos_policy_id:
            network_args["qos_policy_id"] = qos_policy_id

        network = self.conn.network.create_network(**network_args)

        subnet = self.conn.network.create_subnet(
            name=f"{name}-subnet",
            network_id=network.id,
            cidr="10.63.%d.0/24" % self.next_subnet_byte,
            ip_version=4,
            enable_dhcp=True,
        )
        logger.info(
            f"Created network: {name}"
            f" {'with QoS policy' if qos_policy_id else 'without QoS policy'}"
        )
        self.next_subnet_byte += 1
        self.assertLess(self.next_subnet_byte, 256)

        return network, subnet

    def _apply_change(self, current, nxt):
        change = self._only_one_change(current, nxt)
        logger.info(f" {change} -> {nxt}")
        if change.startswith("change net_qos_name"):
            if nxt["net_qos_name"] is not None:
                net_qos_id = self._ensure_qos_policy(
                    nxt["net_qos_name"], nxt["net_qos_rules"]
                )
            else:
                net_qos_id = None
            network = self.conn.network.find_network("test-network")
            self.conn.network.update_network(network.id, qos_policy_id=net_qos_id)
        elif change.startswith("change port_qos_name"):
            if nxt["port_qos_name"] is not None:
                port_qos_id = self._ensure_qos_policy(
                    nxt["port_qos_name"], nxt["port_qos_rules"]
                )
            else:
                port_qos_id = None
            vm = self.conn.compute.find_server("test-vm")
            port = list(self.conn.network.ports(device_id=vm.id))[0]
            self.conn.network.update_port(port.id, qos_policy_id=port_qos_id)
        elif change.startswith("remove rule") or change.startswith("add rule"):
            if nxt["net_qos_name"] is not None:
                self._ensure_qos_policy(nxt["net_qos_name"], nxt["net_qos_rules"])
            if nxt["port_qos_name"] is not None:
                self._ensure_qos_policy(nxt["port_qos_name"], nxt["port_qos_rules"])

    def _verify_wep_qos(self, port_id, state):
        logger.info(f"Verify WEP QoS for state {state}")
        expected_qos = {}
        if state["port_qos_name"] is not None:
            for r in state["port_qos_rules"]:
                expected_qos.update(r["controls"])
        elif state["net_qos_name"] is not None:
            for r in state["net_qos_rules"]:
                expected_qos.update(r["controls"])
        logger.info(f"Expected QoS is {expected_qos}")
        retry_until_success(
            self._assert_wep_qos,
            function_args=(port_id, expected_qos),
        )

    def _assert_wep_qos(self, port_id, expected_qos):
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
        if expected_qos:
            self.assertIn("qosControls", wep["spec"])
            qos_controls = wep["spec"]["qosControls"]
            self.assertDictEqual(qos_controls, expected_qos)
        else:
            self.assertNotIn("qosControls", wep["spec"])

    def setUp(self):
        self.tearDown()

    def tearDown(self):
        logger.info("Delete VM")
        vm = self.conn.compute.find_server("test-vm")
        if vm is not None:
            self.conn.compute.delete_server(vm.id)
            retry_until_success(
                lambda: self.assertIsNone(self.conn.compute.find_server("test-vm")),
                wait_time=5,
            )

        logger.info("Delete subnet")
        subnet = self.conn.network.find_subnet("test-network-subnet")
        if subnet is not None:
            self.conn.network.delete_subnet(subnet.id)

        logger.info("Delete network")
        network = self.conn.network.find_network("test-network")
        if network is not None:
            self.conn.network.delete_network(network.id)

        logger.info("Delete QoS")
        for name in ["A", "B", "C", "D"]:
            full_name = "test-qos-policy" + name
            policy = self.conn.network.find_qos_policy(full_name)
            if policy:
                self.conn.network.delete_qos_policy(policy.id)


if __name__ == "__main__":
    unittest.main()
