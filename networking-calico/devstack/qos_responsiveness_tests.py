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
import subprocess
import sys
import time
import uuid
from typing import Dict, List, Optional, Tuple

# OpenStack client imports
import openstack

# Calico client imports
import etcd3


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# openstack.enable_logging(debug=True, http_debug=True)


class QoSResponsivenessTest:
    """Test suite for QoS responsiveness in Calico OpenStack integration."""

    def __init__(self):
        """Initialize the test environment."""
        self.conn = None
        self.etcd_client = None
        # Add unique suffix to avoid conflicts with previous test runs
        self.test_suffix = str(uuid.uuid4())[:8]
        self.test_resources = {
            'networks': [],
            'subnets': [],
            'ports': [],
            'servers': [],
            'qos_policies': [],
            'security_groups': []
        }
        self.setup_clients()
        self.cleanup_previous_test_resources()

    def setup_clients(self):
        """Set up OpenStack and Calico clients."""
        # Set up OpenStack connection
        try:
            self.conn = openstack.connection.Connection(
                auth_url=os.environ.get('OS_AUTH_URL', 'http://localhost/identity'),
                project_name=os.environ.get('OS_PROJECT_NAME', 'admin'),
                username=os.environ.get('OS_USERNAME', 'admin'),
                password=os.environ.get('OS_PASSWORD', '015133ea2bdc46ed434c'),
                region_name=os.environ.get('OS_REGION_NAME', 'RegionOne'),
                project_domain_id=os.environ.get('OS_PROJECT_DOMAIN_ID', 'default'),
                user_domain_id=os.environ.get('OS_USER_DOMAIN_ID', 'default'),
                identity_api_version=3,
            )
            logger.info("OpenStack connection established")
        except Exception as e:
            logger.error(f"Failed to establish OpenStack connection: {e}")
            sys.exit(1)

        # Set up etcd client for Calico datastore access
        try:
            etcd_host = os.environ.get('ETCD_HOST', 'localhost')
            etcd_port = int(os.environ.get('ETCD_PORT', '2379'))
            self.etcd_client = etcd3.client(host=etcd_host, port=etcd_port)
            logger.info(f"etcd3 client established: {etcd_host}:{etcd_port}")
            status = self.etcd_client.status()
            logger.info(f"status.version = {status.version}")
            logger.info(f"status.db_size = {status.db_size}")
            logger.info(f"status.leader = {status.leader}")
            logger.info(f"status.raft_index = {status.raft_index}")
            logger.info(f"status.raft_term = {status.raft_term}")
        except Exception as e:
            logger.warning(f"Failed to establish etcd connection: {e}")
            self.etcd_client = None

    def cleanup_previous_test_resources(self):
        """Clean up any leftover resources from previous test runs."""
        logger.info("Cleaning up any leftover test resources...")

        try:
            # Clean up QoS policies with test prefixes
            for qos_policy in self.conn.network.qos_policies():
                if qos_policy.name.startswith('test-'):
                    try:
                        # First remove any network bindings
                        for network in self.conn.network.networks():
                            if network.qos_policy_id == qos_policy.id:
                                try:
                                    self.conn.network.update_network(network.id, qos_policy_id=None)
                                    logger.info(f"Removed QoS policy from network: {network.name}")
                                except Exception as e:
                                    logger.debug(f"Failed to remove QoS policy from network {network.name}: {e}")

                        # Remove port bindings
                        for port in self.conn.network.ports():
                            if port.qos_policy_id == qos_policy.id:
                                try:
                                    self.conn.network.update_port(port.id, qos_policy_id=None)
                                    logger.info(f"Removed QoS policy from port: {port.name}")
                                except Exception as e:
                                    logger.debug(f"Failed to remove QoS policy from port {port.name}: {e}")

                        # Now delete the policy
                        self.conn.network.delete_qos_policy(qos_policy.id)
                        logger.info(f"Cleaned up leftover QoS policy: {qos_policy.name}")
                    except Exception as e:
                        logger.debug(f"Failed to clean up QoS policy {qos_policy.name}: {e}")

            # Clean up networks with test prefixes
            for network in self.conn.network.networks():
                if network.name.startswith('test-'):
                    try:
                        # Delete ports first
                        for port in self.conn.network.ports():
                            if port.network_id == network.id:
                                try:
                                    self.conn.network.delete_port(port.id)
                                    logger.info(f"Cleaned up leftover port: {port.name}")
                                except Exception as e:
                                    logger.debug(f"Failed to clean up port {port.name}: {e}")

                        # Delete subnets
                        for subnet in self.conn.network.subnets():
                            if subnet.network_id == network.id:
                                try:
                                    self.conn.network.delete_subnet(subnet.id)
                                    logger.info(f"Cleaned up leftover subnet: {subnet.name}")
                                except Exception as e:
                                    logger.debug(f"Failed to clean up subnet {subnet.name}: {e}")

                        # Delete network
                        self.conn.network.delete_network(network.id)
                        logger.info(f"Cleaned up leftover network: {network.name}")
                    except Exception as e:
                        logger.debug(f"Failed to clean up network {network.name}: {e}")

        except Exception as e:
            logger.warning(f"Error during preliminary cleanup: {e}")
            # Don't fail the test if cleanup has issues

    def cleanup_resources(self):
        """Clean up all test resources."""
        logger.info("Cleaning up test resources...")

        # Delete servers
        for server in self.test_resources['servers']:
            try:
                self.conn.compute.delete_server(server.id)
                self.conn.compute.wait_for_delete(server)
                logger.info(f"Deleted server: {server.name}")
            except Exception as e:
                logger.warning(f"Failed to delete server {server.name}: {e}")

        # Delete ports (first remove QoS policies to avoid binding conflicts)
        for port in self.test_resources['ports']:
            try:
                # Remove QoS policy first if present
                if hasattr(port, 'qos_policy_id') and port.qos_policy_id:
                    try:
                        self.conn.network.update_port(port.id, qos_policy_id=None)
                    except Exception as e:
                        logger.debug(f"Failed to remove QoS policy from port {port.name}: {e}")

                self.conn.network.delete_port(port.id)
                logger.info(f"Deleted port: {port.name}")
            except Exception as e:
                logger.warning(f"Failed to delete port {port.name}: {e}")

        # Delete subnets
        for subnet in self.test_resources['subnets']:
            try:
                self.conn.network.delete_subnet(subnet.id)
                logger.info(f"Deleted subnet: {subnet.name}")
            except Exception as e:
                logger.warning(f"Failed to delete subnet {subnet.name}: {e}")

        # Delete networks (remove QoS policies first)
        for network in self.test_resources['networks']:
            try:
                # Remove QoS policy first if present
                if hasattr(network, 'qos_policy_id') and network.qos_policy_id:
                    try:
                        self.conn.network.update_network(network.id, qos_policy_id=None)
                    except Exception as e:
                        logger.debug(f"Failed to remove QoS policy from network {network.name}: {e}")

                self.conn.network.delete_network(network.id)
                logger.info(f"Deleted network: {network.name}")
            except Exception as e:
                logger.warning(f"Failed to delete network {network.name}: {e}")

        # Delete QoS policies
        for qos_policy in self.test_resources['qos_policies']:
            try:
                self.conn.network.delete_qos_policy(qos_policy.id)
                logger.info(f"Deleted QoS policy: {qos_policy.name}")
            except Exception as e:
                logger.warning(f"Failed to delete QoS policy {qos_policy.name}: {e}")

        # Delete security groups
        for sg in self.test_resources['security_groups']:
            try:
                self.conn.network.delete_security_group(sg.id)
                logger.info(f"Deleted security group: {sg.name}")
            except Exception as e:
                logger.warning(f"Failed to delete security group {sg.name}: {e}")

    def get_workload_endpoint(self, port_id: str, timeout: int = 30) -> Optional[Dict]:
        """
        Get WorkloadEndpoint from Calico datastore for a given port.

        Args:
            port_id: Neutron port ID
            timeout: Maximum time to wait for endpoint to appear

        Returns:
            WorkloadEndpoint data or None if not found
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if self.etcd_client:
                    # Use etcd3 client directly
                    # Calico stores WorkloadEndpoints under /calico/
                    for value, metadata in self.etcd_client.get_prefix('/calico/resources/v3/projectcalico.org/workloadendpoints/'):
                        logger.info(f"Metadata = {metadata}")
                        if port_id.replace("-", "--") in metadata.key.decode():
                            try:
                                data = json.loads(value.decode())
                                if 'spec' in data and ('interfaceName' in data['spec'] or 'endpoint' in data['spec']):
                                    return data
                            except json.JSONDecodeError:
                                continue
                else:
                    # Use calicoctl command line
                    try:
                        result = subprocess.run(
                            ['calicoctl', 'get', 'workloadendpoint', '-o', 'json'],
                            capture_output=True, text=True, timeout=10
                        )
                        if result.returncode == 0:
                            endpoints_data = json.loads(result.stdout)
                            if 'items' in endpoints_data:
                                for ep in endpoints_data['items']:
                                    if port_id in ep.get('metadata', {}).get('name', ''):
                                        return ep
                    except (subprocess.TimeoutExpired, json.JSONDecodeError, subprocess.SubprocessError):
                        pass
            except Exception as e:
                logger.debug(f"Error querying WorkloadEndpoint: {e}")

            time.sleep(1)

        return None

    def verify_qos_update(self, port_id: str, expected_qos: Dict, timeout: int = 10) -> bool:
        """
        Verify that WorkloadEndpoint QoS controls match expected values.

        Args:
            port_id: Neutron port ID
            expected_qos: Expected QoS controls dictionary
            timeout: Maximum time to wait for update

        Returns:
            True if QoS controls match expected values within timeout
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            wep = self.get_workload_endpoint(port_id)
            logger.info(f"WEP for port {port_id} is {wep}")
            if wep and 'spec' in wep and 'qosControls' in wep['spec']:
                qos_controls = wep['spec']['qosControls']

                # Check each expected QoS parameter
                match = True
                for key, expected_value in expected_qos.items():
                    if key not in qos_controls or qos_controls[key] != expected_value:
                        match = False
                        break

                if match:
                    logger.info(f"QoS controls verified for port {port_id}: {qos_controls}")
                    return True
                else:
                    logger.debug(f"QoS controls mismatch for port {port_id}. Expected: {expected_qos}, Got: {qos_controls}")

            time.sleep(0.5)

        logger.error(f"QoS controls verification failed for port {port_id} after {timeout}s")
        return False

    def create_qos_policy(self, name: str, rules: List[Dict]) -> object:
        """Create a QoS policy with specified rules."""
        # Add unique suffix to avoid conflicts
        unique_name = f"{name}-{self.test_suffix}"

        qos_policy = self.conn.network.create_qos_policy(name=unique_name)
        self.test_resources['qos_policies'].append(qos_policy)

        for rule in rules:
            if rule['type'] == 'bandwidth_limit':
                self.conn.network.create_qos_bandwidth_limit_rule(
                    qos_policy.id,
                    max_kbps=rule.get('max_kbps'),
                    max_burst_kbps=rule.get('max_burst_kbps'),
                    direction=rule.get('direction', 'egress')
                )
            elif rule['type'] == 'packet_rate_limit':
                self.conn.network.create_qos_packet_rate_limit_rule(
                    qos_policy.id,
                    max_kpps=rule.get('max_kpps'),
                    direction=rule.get('direction', 'egress')
                )

        logger.info(f"Created QoS policy: {unique_name} with {len(rules)} rules")
        return qos_policy

    def create_test_network(self, name: str, qos_policy_id: str = None) -> Tuple[object, object]:
        """Create a test network and subnet."""
        # Add unique suffix to avoid conflicts
        unique_name = f"{name}-{self.test_suffix}"

        network_args = {
            'name': unique_name + "-net",
            'is_shared': True,
            'provider:network_type': 'local',
        }
        if qos_policy_id:
            network_args['qos_policy_id'] = qos_policy_id

        network = self.conn.network.create_network(**network_args)
        self.test_resources['networks'].append(network)

        subnet = self.conn.network.create_subnet(
            name=f"{unique_name}-subnet",
            network_id=network.id,
            cidr="192.168.100.0/24",
            ip_version=4,
            enable_dhcp=True
        )
        self.test_resources['subnets'].append(subnet)

        logger.info(f"Created network: {unique_name}-net {'with QoS policy' if qos_policy_id else 'without QoS policy'}")
        return network, subnet

    def create_test_port(self, name: str, network_id: str, qos_policy_id: str = None) -> object:
        """Create a test port."""
        # Add unique suffix to avoid conflicts
        unique_name = f"{name}-{self.test_suffix}"

        port_args = {
            'name': unique_name,
            'network_id': network_id,
            'device_owner': 'compute:',
            'admin_state_up': True
        }
        if qos_policy_id:
            port_args['qos_policy_id'] = qos_policy_id

        port = self.conn.network.create_port(**port_args)
        self.test_resources['ports'].append(port)

        logger.info(f"Created port: {unique_name} {'with QoS policy' if qos_policy_id else 'without QoS policy'}")
        return port

    def test_network_qos_policy(self) -> bool:
        """Test QoS policy applied at network level."""
        logger.info("=== Testing Network-level QoS Policy ===")

        # Create QoS policy with bandwidth limit
        qos_policy = self.create_qos_policy("test-network-qos", [
            {
                'type': 'bandwidth_limit',
                'max_kbps': 10000,  # 10 Mbps
                'max_burst_kbps': 12000,  # 12 Mbps burst
                'direction': 'egress'
            }
        ])

        # Create network with QoS policy
        network, subnet = self.create_test_network("test-network-qos", qos_policy.id)

        # Create port on the network
        port = self.create_test_port("test-port-network-qos", network.id)

        # Verify QoS controls are applied to WorkloadEndpoint
        expected_qos = {
            'egressBandwidth': 10000000,  # Convert kbps to bps
            'egressPeakrate': 12000000    # Convert kbps to bps
        }

        success = self.verify_qos_update(port.id, expected_qos)

        if success:
            logger.info("✓ Network-level QoS policy test PASSED")
        else:
            logger.error("✗ Network-level QoS policy test FAILED")

        return success

    def test_port_qos_policy(self) -> bool:
        """Test QoS policy applied at port level."""
        logger.info("=== Testing Port-level QoS Policy ===")

        # Create QoS policy with packet rate limit
        qos_policy = self.create_qos_policy("test-port-qos", [
            {
                'type': 'packet_rate_limit',
                'max_kpps': 5,  # 5000 packets per second
                'direction': 'ingress'
            }
        ])

        # Create network without QoS policy
        network, subnet = self.create_test_network("test-network-no-qos")

        # Create port with QoS policy
        port = self.create_test_port("test-port-with-qos", network.id, qos_policy.id)

        # Verify QoS controls are applied to WorkloadEndpoint
        expected_qos = {
            'ingressPacketRate': 5000  # Convert kpps to pps
        }

        success = self.verify_qos_update(port.id, expected_qos)

        if success:
            logger.info("✓ Port-level QoS policy test PASSED")
        else:
            logger.error("✗ Port-level QoS policy test FAILED")

        return success

    def test_mixed_qos_policies(self) -> bool:
        """Test network with QoS policy and port with different QoS policy."""
        logger.info("=== Testing Mixed QoS Policies (Network + Port) ===")

        # Create network-level QoS policy
        network_qos_policy = self.create_qos_policy("test-mixed-network-qos", [
            {
                'type': 'bandwidth_limit',
                'max_kbps': 5000,  # 5 Mbps
                'direction': 'ingress'
            }
        ])

        # Create port-level QoS policy (should override network policy)
        port_qos_policy = self.create_qos_policy("test-mixed-port-qos", [
            {
                'type': 'bandwidth_limit',
                'max_kbps': 20000,  # 20 Mbps
                'max_burst_kbps': 25000,  # 25 Mbps burst
                'direction': 'egress'
            },
            {
                'type': 'packet_rate_limit',
                'max_kpps': 10,  # 10000 packets per second
                'direction': 'ingress'
            }
        ])

        # Create network with QoS policy
        network, subnet = self.create_test_network("test-mixed-network", network_qos_policy.id)

        # Create port with different QoS policy
        port = self.create_test_port("test-mixed-port", network.id, port_qos_policy.id)

        # Port-level QoS should take precedence
        expected_qos = {
            'egressBandwidth': 20000000,    # From port policy
            'egressPeakrate': 25000000,     # From port policy
            'ingressPacketRate': 10000      # From port policy
        }

        success = self.verify_qos_update(port.id, expected_qos)

        if success:
            logger.info("✓ Mixed QoS policies test PASSED")
        else:
            logger.error("✗ Mixed QoS policies test FAILED")

        return success

    def test_qos_policy_update(self) -> bool:
        """Test updating QoS policy and verifying responsiveness."""
        logger.info("=== Testing QoS Policy Update Responsiveness ===")

        # Create initial QoS policy
        qos_policy = self.create_qos_policy("test-update-qos", [
            {
                'type': 'bandwidth_limit',
                'max_kbps': 1000,  # 1 Mbps
                'direction': 'egress'
            }
        ])

        # Create network and port
        network, subnet = self.create_test_network("test-update-network")
        port = self.create_test_port("test-update-port", network.id, qos_policy.id)

        # Verify initial QoS controls
        initial_qos = {'egressBandwidth': 1000000}
        if not self.verify_qos_update(port.id, initial_qos):
            logger.error("✗ Initial QoS policy application failed")
            return False

        # Update QoS policy by adding new rule
        self.conn.network.create_qos_bandwidth_limit_rule(
            qos_policy.id,
            max_kbps=15000,  # 15 Mbps
            direction='ingress'
        )

        # Verify updated QoS controls
        updated_qos = {
            'egressBandwidth': 1000000,   # Original rule
            'ingressBandwidth': 15000000  # New rule
        }

        success = self.verify_qos_update(port.id, updated_qos, timeout=15)

        if success:
            logger.info("✓ QoS policy update responsiveness test PASSED")
        else:
            logger.error("✗ QoS policy update responsiveness test FAILED")

        return success

    def test_qos_policy_removal(self) -> bool:
        """Test removing QoS policy and verifying cleanup."""
        logger.info("=== Testing QoS Policy Removal ===")

        # Create QoS policy
        qos_policy = self.create_qos_policy("test-removal-qos", [
            {
                'type': 'bandwidth_limit',
                'max_kbps': 8000,  # 8 Mbps
                'direction': 'egress'
            }
        ])

        # Create network and port
        network, subnet = self.create_test_network("test-removal-network")
        port = self.create_test_port("test-removal-port", network.id, qos_policy.id)

        # Verify QoS controls are applied
        initial_qos = {'egressBandwidth': 8000000}
        if not self.verify_qos_update(port.id, initial_qos):
            logger.error("✗ Initial QoS policy application failed")
            return False

        # Remove QoS policy from port
        self.conn.network.update_port(port.id, qos_policy_id=None)

        # Verify QoS controls are removed (WorkloadEndpoint should have no qosControls)
        start_time = time.time()
        timeout = 10
        while time.time() - start_time < timeout:
            wep = self.get_workload_endpoint(port.id)
            if wep and 'spec' in wep:
                qos_controls = wep['spec'].get('qosControls', {})
                if not qos_controls or 'egressBandwidth' not in qos_controls:
                    logger.info("✓ QoS policy removal test PASSED")
                    return True
            time.sleep(0.5)

        logger.error("✗ QoS policy removal test FAILED - QoS controls not removed")
        return False

    def run_all_tests(self) -> bool:
        """Run all QoS responsiveness tests."""
        logger.info("Starting QoS Responsiveness Tests...")

        test_results = []

        try:
            # Run individual tests
            test_results.append(self.test_network_qos_policy())
            test_results.append(self.test_port_qos_policy())
            test_results.append(self.test_mixed_qos_policies())
            test_results.append(self.test_qos_policy_update())
            test_results.append(self.test_qos_policy_removal())

        except Exception as e:
            logger.error(f"Test execution failed: {e}")
            return False
        finally:
            # Always clean up resources
            self.cleanup_resources()

        # Summarize results
        passed_tests = sum(test_results)
        total_tests = len(test_results)

        logger.info(f"\n=== Test Summary ===")
        logger.info(f"Total tests: {total_tests}")
        logger.info(f"Passed: {passed_tests}")
        logger.info(f"Failed: {total_tests - passed_tests}")

        if passed_tests == total_tests:
            logger.info("🎉 All QoS responsiveness tests PASSED!")
            return True
        else:
            logger.error("❌ Some QoS responsiveness tests FAILED!")
            return False


# Possible rules that a QoS policy can have.
possible_qos_rules = [
    {
        "bandwidth_limit_rule": {
            "max_kbps": 10200,
            "max_burst_kbps": 20300,
            "direction": "egress",
        },
    },
    {
        "bandwidth_limit_rule": {
            "max_kbps": 30400,
            "max_burst_kbps": 40500,
            "direction": "ingress",
        },
    },
    {
        "packet_rate_limit_rule": {
            "max_kpps": 12345,
            "max_burst_kpps": 21087,
            "direction": "egress",
        },
    },
    {
        "packet_rate_limit_rule": {
            "max_kpps": 42341,
            "max_burst_kpps": 50002,
            "direction": "ingress",
        },
    },
]


# Given that a QoS policy exists, generate its possible states in terms of the
# rules within it (including the empty set).
def possible_qos_rule_sets():
    states = []
    for i in range(2**len(possible_qos_rules)):
        state_rules = []
        for j in range(len(possible_qos_rules)):
            if i & (2**j) != 0:
                state_rules.append(possible_qos_rules[j])
        states.append(state_rules)
    return states


# Given that a port exists - on a network, whose ID we assume cannot change
# post-creation - generate its possible states in terms of
# - whether its network has a QoS policy
# - if so, the ID and rules in the network QoS policy
# - whether the port itself has a QoS policy
# - if so, the ID and rules in the port QoS policy
def possible_port_states():
    states = []
    rule_sets = possible_qos_rule_sets()
    for network_qos_policy_id in [None, 'A', 'B']:
        for port_qos_policy_id in [None, 'A', 'B']:
            state_base = {
                'network_qos_policy_id': network_qos_policy_id,
                'port_qos_policy_id': port_qos_policy_id,
            }
            if network_qos_policy_id is None and port_qos_policy_id is None:
                states.append(state_base)
                continue
            for rules in rule_sets:
                state = state_base.copy()
                state['qos_rules'] = rules
                states.append(state)
    return states


def only_one_change(a, b):
    changes = []
    if a['network_qos_policy_id'] != b['network_qos_policy_id']:
        changes.append(f"change network_qos_policy_id to {b['network_qos_policy_id']}")
    if a['port_qos_policy_id'] != b['port_qos_policy_id']:
        changes.append(f"change port_qos_policy_id to {b['port_qos_policy_id']}")
    if len(changes) > 1:
        return False
    # Only compare the rules when IDs are not changing.
    if len(changes) == 0:
        a_rules = a.get('qos_rules', [])
        b_rules = b.get('qos_rules', [])
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


# Calculate a set of sequences for passing through all of the possible port
# states, but with only one thing changing on each transition.
def calculate_sequences():
    possible_states = possible_port_states()
    remaining_arrival_states = possible_states.copy()
    used_arrival_states = []
    sequences = []
    making_progress = True
    while making_progress:
        logger.info("Try new sequence")
        # Try to calculate a new sequence to pass through some of the remaining
        # arrival states.
        current_state = possible_states[0]
        sequence = []
        making_progress = False
        continue_current_sequence = True
        while continue_current_sequence:
            logger.info("Continue current sequence")
            continue_current_sequence = False
            for possible_next in remaining_arrival_states:
                if only_one_change(current_state, possible_next):
                    making_progress = True
                    sequence.append(possible_next)
                    remaining_arrival_states.remove(possible_next)
                    used_arrival_states.append(possible_next)
                    current_state = possible_next
                    continue_current_sequence = True
                    break
            for possible_next in used_arrival_states:
                if possible_next in sequence:
                    continue
                if only_one_change(current_state, possible_next):
                    sequence.append(possible_next)
                    current_state = possible_next
                    continue_current_sequence = True
                    break
        if making_progress:
            sequences.append(sequence)
            # making_progress = False
    logger.info(f"Calculated {len(sequences)} sequences")
    logger.info(f"Covered {len(used_arrival_states)} arrival states, missed {len(remaining_arrival_states)}")
    return sequences


def main():
    """Main entry point for QoS responsiveness tests."""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print(__doc__)
        return 0

    # port_states = possible_port_states()
    # logger.info("There are %d possible port states", len(port_states))
    # for s in port_states:
    #     logger.info(f"{s}")
    #
    # sequences = calculate_sequences()
    # for sequence in sequences:
    #     logger.info("New sequence with length %d:", len(sequence))
    #     current_state = port_states[0]
    #     for nxt in sequence:
    #         change = only_one_change(current_state, nxt)
    #         logger.info(f" {change} -> {nxt}")
    #         current_state = nxt

    logger.info("Initializing QoS Responsiveness Test Suite...")

    test_suite = QoSResponsivenessTest()
    success = test_suite.run_all_tests()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
