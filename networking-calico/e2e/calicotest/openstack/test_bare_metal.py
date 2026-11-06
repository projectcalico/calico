# Copyright (c) 2016-2026 Tigera, Inc. All rights reserved.
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

import copy
import functools
import logging
from subprocess import CalledProcessError, check_call
import time

from calicotest.common import datamodel_v3
from calicotest.common import etcdv3
from calicotest.common.testutils import retry_until_success, run
from calicotest.openstack.basetest import LOGS_IGNORE_ALL_TESTS
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.topology import TopologyBasic

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)

# We want to test for access to a known TCP port on each compute node,
# and it is convenient to use Felix's Prometheus metrics port for this
# purpose.  (We can ensure that that port exists just by enabling it
# in Felix's config, whereas otherwise we'd need to set up some extra
# service.  We used to use the rpcbind port (111) here, but for some
# reason this appears to have become unreliable.)
TEST_PORT = 9091

# Canned policies, all of which should apply to all the computes.  We use
# a variety of selectors just to hit different code paths.
POLICY_ALLOW_CALICO_TRAFFIC_COMPUTE = {
    "selector": "role == 'compute'",
    "order": 0,
    "ingress": [
        # Allow BGP, etcd and AMQP.
        {
            "protocol": "TCP",
            "action": "Allow",
            "destination": {
                "ports": [
                    179,  # BGP
                    2379,  # etcd
                    2380,  # etcd
                    4001,  # etcd
                    5672,  # AMQP
                ],
                "selector": "role == 'compute' || role == 'control'",
            },
        },
    ],
    "egress": [
        {
            "protocol": "TCP",
            "action": "Allow",
            "destination": {
                "ports": [
                    179,  # BGP
                    2379,  # etcd
                    2380,  # etcd
                    4001,  # etcd
                    5672,  # AMQP
                ],
                "selector": "role == 'compute' || role == 'control'",
            },
        },
    ],
}
POLICY_ALLOW_CALICO_TRAFFIC_CONTROL = {
    "selector": "role == 'control'",
    "order": 0,
    "ingress": [
        {
            "protocol": "TCP",
            "action": "Allow",
            "destination": {
                "ports": [
                    80,  # Horizon UI
                    443,  # Horizon UI
                    2379,  # etcd
                    2380,  # etcd
                    4001,  # etcd
                    5672,  # AMQP
                    5000,  # keystone
                    8773,  # nova
                    8774,  # nova
                    8775,  # nova
                    9191,  # glance registry
                    9292,  # glance api
                    9696,  # neutron
                    35357,  # keystone (openstack api)
                ],
                "selector": "role == 'control'",
            },
        },
        {"protocol": "UDP", "action": "Allow"},
    ],
    "egress": [
        {
            "protocol": "TCP",
            "action": "Allow",
            "destination": {
                "ports": [
                    2379,  # etcd
                    2380,  # etcd
                    4001,  # etcd
                    5672,  # AMQP
                ],
                "selector": "role == 'compute' || role == 'control'",
            },
        },
        {"protocol": "UDP", "action": "Allow"},
    ],
}
POLICY_ALLOW_ALL = {
    "selector": "role == 'compute'",
    "order": 10,
    "ingress": [{"action": "Allow"}],
    "egress": [{"action": "Allow"}],
}
POLICY_DENY_ALL = {
    "selector": "role != 'control'",
    "order": 10,
    "ingress": [{"action": "Deny"}],
    "egress": [{"action": "Deny"}],
}
POLICY_NONE_ALL = {
    "selector": "all()",
    "order": 10,
    "ingress": [],
    "egress": [],
}


class _BareMetalPolicyTest(TopologyBasic):
    client = None

    @classmethod
    def setUpClass(cls):
        _log.info("Running %s.setUpClass", cls.__name__)

        # Start with no policy in place.
        cls.cleanups = []
        cls.clean_up_policy_and_endpoints()

        # Defer to the superclass to create VMs etc.
        super(_BareMetalPolicyTest, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)

        cls.clean_up_policy_and_endpoints()

        super(_BareMetalPolicyTest, cls).tearDownClass()

    @classmethod
    def clean_up_policy_and_endpoints(cls):
        cls.cleanups.reverse()
        for cleanup in cls.cleanups:
            try:
                cleanup()
            except etcdv3.KeyNotFound:
                pass
        cls.cleanups = []

    def remove_policy_and_check_connectivity(self):
        # Then remove all the policy, should be able to access again.
        self.clean_up_policy_and_endpoints()
        retry_until_success(self.assert_can_access_tcp_service)
        retry_until_success(self.assert_can_ping_computes)
        retry_until_success(self.assert_can_ssh_to_computes)
        self.check_mutual_connectivity(self.vms)

    def set_policy(self, policy_name, data, order=None, corrupt=False):
        """Write data, a v3 GlobalNetworkPolicy spec, as policy_name."""
        data = copy.deepcopy(data)
        if order is not None:
            data["order"] = order

        # All policies go in the default tier.
        full_name = "default." + policy_name
        datamodel_v3.put("GlobalNetworkPolicy", full_name, data, corrupt=corrupt)
        self.cleanups.append(
            functools.partial(datamodel_v3.delete, "GlobalNetworkPolicy", full_name)
        )

    def config_host_endpoint(
        self,
        hostname,
        role,
        if_name,
        expected_ipv4_addrs,
        profile_ids,
    ):
        spec = {"node": hostname}
        if if_name:
            spec["interfaceName"] = if_name
        if expected_ipv4_addrs:
            spec["expectedIPs"] = expected_ipv4_addrs
        if profile_ids is not None:
            spec["profiles"] = profile_ids
        datamodel_v3.put(
            "HostEndpoint",
            hostname + "-endpoint1",
            spec,
            labels={"role": role, "hostname": hostname},
        )
        self.cleanups.append(
            functools.partial(
                datamodel_v3.delete, "HostEndpoint", hostname + "-endpoint1"
            )
        )

    def configure_host_endpoints_and_calico_policy(
        self, use_if_name=False, profile_ids=None
    ):
        _log.info("Configuring host endpoints")

        # Add some policy to allow calico traffic before we create endpoints.
        self.set_policy("calico-compute", POLICY_ALLOW_CALICO_TRAFFIC_COMPUTE)
        self.set_policy("calico-control", POLICY_ALLOW_CALICO_TRAFFIC_CONTROL)

        def _config_host_ep(node, role, use_if_name, profile_ids):
            if_name = None
            expected_ipv4_addrs = []
            if use_if_name:
                if_name = node.get_if_name(node.get_ipv4())
            else:
                expected_ipv4_addrs = [node.get_ipv4()]

            self.config_host_endpoint(
                node.hostname,
                role,
                if_name,
                expected_ipv4_addrs,
                profile_ids,
            )

        for node in LAYOUT.compute_nodes:
            _config_host_ep(node, "compute", use_if_name, profile_ids)

        _config_host_ep(LAYOUT.control_node, "control", use_if_name, None)

        # Restart BIRD to make sure the BGP policy is in place.
        self.restart_bird()

    def assert_can_access_tcp_service(self, port=TEST_PORT):
        """Checks that the test host can access the service on all
        computes."""
        self.check_access_tcp_service(success=True, port=port)

    def assert_cannot_access_tcp_service(self, port=TEST_PORT):
        """Checks that the test host cannot access the service on all
        computes."""
        self.check_access_tcp_service(success=False, port=port)

    def check_access_tcp_service(self, success=True, port=TEST_PORT):
        """Checks to see if test host can access the service on all computes.
        :param success: bool - whether we expect the test to succeed or not
        :param port: int - port number to check
        :return: None.
        """
        _log.debug("LAYOUT.compute_nodes: %s", LAYOUT.compute_nodes)
        for node in LAYOUT.compute_nodes:
            addr = node.get_ipv4()
            _log.debug("Node: %s", addr)
            _log.debug(
                "Expect to %s to %s:%s/",
                "connect" if success else "fail to connect",
                addr,
                port,
            )
            if success:
                self.run_nmap(port, addr)
            else:
                try:
                    self.run_nmap(port, addr)
                except CalledProcessError:
                    continue
                else:
                    self.fail(
                        "Incorrectly could access service on %s:%s" % (node, port)
                    )

    def run_nmap(self, port, addr):
        nmap_command = "/usr/bin/nmap -Pn -T2 -p%s %s" % (port, addr)
        nmap_output = run(nmap_command)
        port_open = False
        for line in nmap_output.splitlines():
            words = line.split()
            _log.debug("nmap line words: %r", words)
            if len(words) >= 2 and ("%s" % port) in words[0]:
                _log.debug("found line for port %s", port)
                if words[1] == "open":
                    port_open = True
        if not port_open:
            raise CalledProcessError(99, nmap_command, "port %s is not open" % port)

    def assert_can_ssh_to_computes(self):
        """Checks that this host can ssh to the computes."""
        for node in LAYOUT.compute_nodes:
            node.disconnect()
            node.connect()
            rc, stdout, stderr = node.execute("echo OK")
            self.assertEqual(rc, 0)

    def assert_can_ping_computes(self):
        """Checks that this host can ping all the computes."""
        for node in LAYOUT.compute_nodes:
            _log.info("Checking we can ping %s", node)
            self.ping_node(node)

    def assert_cannot_ping_computes(self):
        for node in LAYOUT.compute_nodes:
            _log.info("Checking we can ping %s", node)
            try:
                self.ping_node(node)
            except CalledProcessError:
                pass
            else:
                self.fail("Succeeded in pinging %s" % node)

    def ping_node(self, node):
        check_call(["ping", "-c", "1", "-W", "2", node.get_ipv4()])


class TestBareMetalPolicyOpenSource(_BareMetalPolicyTest):

    # These logs come from those tests which create corrupt policy
    IGNORE_LOGS_LIST = LOGS_IGNORE_ALL_TESTS + [
        "Validation failed for policy pol-b/pol-1",
        "Validation failed for policy pol-2/pol-1",
        "Watch error received from Upstream",
    ]

    def setUp(self):
        pass

    def tearDown(self):
        _log.debug("Test finished, clear up policy and check connectivity")
        self.remove_policy_and_check_connectivity()

    def test_simple_mainline_inbound(self):
        """Simple mainline tests with a single policy.

        - Checks initial connectivity.
        - Creates policy to allow only TCP to the test port.
        - Adjusts the policy to block that traffic.
        """
        # No policy in place to start with, should be able to ping, ssh and
        # access test port.
        _log.info("Checking can ping with no policy in place")
        self.check_mutual_connectivity(self.vms)
        retry_until_success(self.assert_can_ping_computes)
        retry_until_success(self.assert_can_ssh_to_computes)
        retry_until_success(self.assert_can_access_tcp_service)

        # Configure endpoints.
        self.configure_host_endpoints_and_calico_policy()
        retry_until_success(
            self.assert_open_ports,
            function_args=(LAYOUT.compute_nodes, {"22/tcp", "179/tcp"}),
        )

        # Insert policy that allows access to test port.
        _log.info("Inserting policy that allows access to test port")
        compute_policy = {
            "selector": "role == 'compute'",
            "order": 10,
            "ingress": [
                {
                    "protocol": "TCP",
                    "action": "Allow",
                    "destination": {"ports": [TEST_PORT]},
                },
            ],
            "egress": [
                {"action": "Allow"},
            ],
        }
        self.set_policy("allow-tcpservice", compute_policy)

        # Should now be able to connect.
        retry_until_success(self.assert_can_access_tcp_service)
        retry_until_success(
            self.assert_open_ports,
            function_args=(
                LAYOUT.compute_nodes,
                {"22/tcp", "179/tcp", "%s/tcp" % TEST_PORT},
            ),
        )

        # VM connectivity should be unaffected.
        _log.debug("Checking VMs can connect to each other")
        self.check_mutual_connectivity(self.vms)

        # Sleep to let the ICMP conntrack flows expire.
        time.sleep(30)
        _log.debug("Checking we cannot ping the computes")
        self.assert_cannot_ping_computes()

        # Now stop access to test port but allow ICMP.
        compute_policy = {
            "selector": "role == 'compute'",
            "order": 10,
            "ingress": [{"protocol": "ICMP", "action": "Allow"}],
            "egress": [
                {"action": "Allow"},
            ],
        }
        _log.debug("Allowing pings, but not tcp to test port")
        self.set_policy("allow-tcpservice", compute_policy)
        retry_until_success(self.assert_cannot_access_tcp_service)
        retry_until_success(self.assert_can_ping_computes)
        # ssh always allowed by failsafe rules.
        retry_until_success(self.assert_can_ssh_to_computes)
        retry_until_success(
            self.assert_open_ports,
            function_args=(LAYOUT.compute_nodes, {"22/tcp", "179/tcp"}),
        )
        self.check_mutual_connectivity(self.vms)

    def test_untracked_inbound(self):
        """Simple tests with an untracked inbound policy.

        - Checks initial connectivity.
        - Creates policy to allow only TCP to the test port.
        - Adjusts the policy to block that traffic.
        """
        # No policy in place to start with, should be able to ping, ssh and
        # access test port.
        _log.info("Checking can ping with no policy in place")
        self.check_mutual_connectivity(self.vms)
        retry_until_success(self.assert_can_ping_computes)
        retry_until_success(self.assert_can_ssh_to_computes)
        retry_until_success(self.assert_can_access_tcp_service)

        # Configure endpoints.
        self.configure_host_endpoints_and_calico_policy()
        retry_until_success(
            self.assert_open_ports,
            function_args=(LAYOUT.compute_nodes, {"22/tcp", "179/tcp"}),
        )

        # Insert policy that allows access to test port.
        _log.info("Next test: TEST_PORT untracked")
        _log.info("Inserting policy that allows access to test port")
        compute_policy = {
            "selector": "role == 'compute'",
            "order": 10,
            "ingress": [
                {
                    "protocol": "TCP",
                    "action": "Allow",
                    "destination": {"ports": [TEST_PORT]},
                },
            ],
            "egress": [
                {
                    "protocol": "TCP",
                    "action": "Allow",
                    "source": {"ports": [TEST_PORT]},
                },
            ],
            "doNotTrack": True,
        }
        self.set_policy("allow-tcpservice", compute_policy)

        # Flush any conntrack state for TEST_PORT, and also iptables counters.
        for node in LAYOUT.compute_nodes:
            node.execute("sudo conntrack -D -p tcp --orig-port-src %s" % TEST_PORT)
            node.execute("sudo conntrack -D -p tcp --orig-port-dst %s" % TEST_PORT)
            node.execute("sudo conntrack -D -p tcp --reply-port-src %s" % TEST_PORT)
            node.execute("sudo conntrack -D -p tcp --reply-port-dst %s" % TEST_PORT)

        # Should now be able to connect.
        retry_until_success(self.assert_can_access_tcp_service)
        retry_until_success(
            self.assert_open_ports,
            function_args=(
                LAYOUT.compute_nodes,
                {"22/tcp", "179/tcp", "%s/tcp" % TEST_PORT},
            ),
        )

        # Check conntrack state and iptables counters now.
        for node in LAYOUT.compute_nodes:
            rc, stdout, stderr = node.execute(
                "sudo conntrack -L -p tcp --dport %s" % TEST_PORT
            )
            self.assertNotIn("dport=%s" % TEST_PORT, stdout)

        # VM connectivity should be unaffected.
        _log.debug("Checking VMs can connect to each other")
        self.check_mutual_connectivity(self.vms)

        # Sleep to let the ICMP conntrack flows expire.
        _log.info("Next test: TEST_PORT normal")
        time.sleep(30)
        _log.debug("Checking we cannot ping the computes")
        self.assert_cannot_ping_computes()

        # Now change the policy to be a normal (i.e. tracked) one.
        compute_policy = {
            "selector": "role == 'compute'",
            "order": 10,
            "ingress": [
                {
                    "protocol": "TCP",
                    "action": "Allow",
                    "destination": {"ports": [TEST_PORT]},
                },
            ],
            "egress": [
                {"action": "Allow"},
            ],
        }
        _log.debug("Change untracked->normal")
        self.set_policy("allow-tcpservice", compute_policy)
        retry_until_success(self.assert_can_access_tcp_service)

        # Check conntrack state now.
        def check_conntrack_state():
            ok = True
            for node in LAYOUT.compute_nodes:
                rc, stdout, stderr = node.execute(
                    "sudo conntrack -L -p tcp --dport %s" % TEST_PORT
                )
                if "dport=%s" % TEST_PORT not in stdout:
                    ok = False
            return ok

        retry_until_success(check_conntrack_state, retries=5)

        # ssh always allowed by failsafe rules.
        retry_until_success(self.assert_can_ssh_to_computes)
        retry_until_success(
            self.assert_open_ports,
            function_args=(
                LAYOUT.compute_nodes,
                {"22/tcp", "179/tcp", "%s/tcp" % TEST_PORT},
            ),
        )
        self.check_mutual_connectivity(self.vms)

        # Now add an untracked policy for another port ('XPORT'), and
        # a normal policy to allow ICMP.  We use port 8775, of the
        # Nova metadata service, because it's the only other
        # predictable port that is known (in this test suite) to be
        # running on each compute, and that isn't already allowed by
        # Felix's failsafe list.
        _log.info("Next test: 8775 untracked, TEST_PORT and ICMP normal")

        XPORT = 8775
        compute_policy = {
            "selector": "role == 'compute'",
            "order": 11,
            "ingress": [
                {
                    "protocol": "TCP",
                    "action": "Allow",
                    "destination": {"ports": [XPORT]},
                },
            ],
            "egress": [
                {"protocol": "TCP", "action": "Allow", "source": {"ports": [XPORT]}},
            ],
            "doNotTrack": True,
        }
        ping_policy = {
            "selector": "role == 'compute'",
            "order": 12,
            "ingress": [
                {"protocol": "ICMP", "action": "Allow"},
            ],
            "egress": [
                {"action": "Allow"},
            ],
        }
        _log.debug("Add untracked for XPORT, and normal ICMP")
        self.set_policy("allow-tcpXPORT", compute_policy)
        self.set_policy("allow-icmp", ping_policy)

        # Flush any conntrack state for port XPORT, and also iptables counters.
        for node in LAYOUT.compute_nodes:
            node.execute("sudo conntrack -D -p tcp --orig-port-src %s" % XPORT)
            node.execute("sudo conntrack -D -p tcp --orig-port-dst %s" % XPORT)
            node.execute("sudo conntrack -D -p tcp --reply-port-src %s" % XPORT)
            node.execute("sudo conntrack -D -p tcp --reply-port-dst %s" % XPORT)

        retry_until_success(self.assert_can_access_tcp_service)
        retry_until_success(
            self.assert_can_access_tcp_service, function_kwargs={"port": XPORT}
        )

        # Check conntrack state now.
        def check_conntrack_state():
            ok = True
            for node in LAYOUT.compute_nodes:
                rc, stdout, stderr = node.execute(
                    "sudo conntrack -L -p tcp --dport %s" % TEST_PORT
                )
                if "dport=%s" % TEST_PORT not in stdout:
                    ok = False
                rc, stdout, stderr = node.execute(
                    "sudo conntrack -L -p tcp --dport %s" % XPORT
                )
                if "dport=%s" % XPORT in stdout:
                    ok = False
            return ok

        retry_until_success(check_conntrack_state, retries=5)

        retry_until_success(self.assert_can_ping_computes)
        # ssh always allowed by failsafe rules.
        retry_until_success(self.assert_can_ssh_to_computes)
        retry_until_success(
            self.assert_open_ports,
            function_args=(
                LAYOUT.compute_nodes,
                {"22/tcp", "179/tcp", "%s/tcp" % TEST_PORT, "%s/tcp" % XPORT},
            ),
        )

        self.check_mutual_connectivity(self.vms)

    def test_simple_mainline_outbound(self):
        """Checks single outbound policy with selectors is applied."""
        control_node = LAYOUT.control_node
        compute_node = LAYOUT.compute_nodes[1]

        # No endpoints, should be able to ping.
        retry_until_success(
            self.assert_node_can_ping_other_node,
            function_args=(control_node, compute_node),
        )

        # Install endpoints, traffic should now be blocked by default.
        self.configure_host_endpoints_and_calico_policy()
        # Sleep to let any conntrack flows expire.
        time.sleep(30)
        _log.debug("Checking that control cannot ping compute node")
        retry_until_success(
            self.assert_node_cannot_ping_other_node,
            function_args=(control_node, compute_node),
        )

        # Install some outbound policy to allow ping from control
        # to compute.
        policy = {
            "selector": "role == 'control'",
            "order": 10,
            "ingress": [],
            "egress": [
                {
                    "protocol": "ICMP",
                    "action": "Allow",
                    "destination": {"selector": "role == 'compute'"},
                }
            ],
        }
        self.set_policy("control", policy)
        policy = {
            "selector": "role == 'compute'",
            "order": 10,
            "ingress": [
                {
                    "protocol": "ICMP",
                    "action": "Allow",
                    "source": {"selector": "role == 'control'"},
                }
            ],
            "egress": [],
        }
        self.set_policy("compute", policy)
        # Should now be able to ping.
        _log.debug("Checking that control can now ping compute node")
        retry_until_success(
            self.assert_node_can_ping_other_node,
            function_args=(control_node, compute_node),
        )
        retry_until_success(
            self.assert_open_ports,
            function_args=(LAYOUT.compute_nodes, {"22/tcp", "179/tcp"}),
        )
        # But only in one direction.
        retry_until_success(
            self.assert_node_cannot_ping_other_node,
            function_args=(compute_node, control_node),
        )

    def test_policy_ordering_explicit(self):
        """Check correct ordering of policies by their explicit order
        field."""
        self._do_policy_order_test("pol-c", 1, "pol-b", 2, "pol-a", 3)

    def test_policy_ordering_implicit(self):
        """Check correct ordering of policies by name as tie-breaker."""
        self._do_policy_order_test("pol-1", 1, "pol-2", 1, "pol-3", 1)

    def _do_policy_order_test(
        self,
        first_pol,
        first_pol_order,
        second_pol,
        second_pol_order,
        third_pol,
        third_pol_order,
    ):
        """Checks that policies are ordered correctly."""
        # Note that the following tests need to check that connectivity to
        # the test port alternates between succeeding and failing so
        # that we spot if felix hasn't actually changed anything.

        _log.info("Check we start with connectivity.")
        self.assert_can_access_tcp_service()
        _log.info("Create policy and endpoints.")
        self.configure_host_endpoints_and_calico_policy()
        _log.info("Check we now cannot access tcp service")
        retry_until_success(self.assert_cannot_access_tcp_service)
        _log.info("Allow in first policy only, should allow.")
        self.set_policy(first_pol, POLICY_ALLOW_ALL, order=first_pol_order)
        self.set_policy(second_pol, POLICY_DENY_ALL, order=second_pol_order)
        self.set_policy(third_pol, POLICY_DENY_ALL, order=third_pol_order)
        retry_until_success(self.assert_can_access_tcp_service)

        _log.info("first policy = deny, corrupt second policy, should still deny")
        self.set_policy(first_pol, POLICY_DENY_ALL, order=first_pol_order)
        self.set_policy(
            second_pol,
            POLICY_DENY_ALL,
            order=second_pol_order,
            corrupt=True,
        )
        retry_until_success(self.assert_cannot_access_tcp_service)

        _log.info("first policy = allow, corrupt second policy, should still allow")
        self.set_policy(first_pol, POLICY_ALLOW_ALL, order=first_pol_order)
        retry_until_success(self.assert_can_access_tcp_service)

        # Fix up second policy
        self.set_policy(second_pol, POLICY_DENY_ALL, order=second_pol_order)

        # Deny in all policies, should drop.
        _log.info("Deny in all policies, should drop.")
        self.set_policy(first_pol, POLICY_DENY_ALL, order=first_pol_order)
        retry_until_success(self.assert_cannot_access_tcp_service)

        # Allow in first policy, should allow.
        _log.info("Allow in first policy, should allow.")
        self.set_policy(first_pol, POLICY_ALLOW_ALL, order=first_pol_order)
        retry_until_success(self.assert_can_access_tcp_service)

        # Switch, now the first policy drops but the later ones allow.
        _log.info("Switch, now the first policy drops but the later ones allow.")
        self.set_policy(first_pol, POLICY_DENY_ALL, order=first_pol_order)
        self.set_policy(second_pol, POLICY_ALLOW_ALL, order=second_pol_order)
        self.set_policy(third_pol, POLICY_ALLOW_ALL, order=third_pol_order)
        retry_until_success(self.assert_cannot_access_tcp_service)

        # Fall through to second policy.
        _log.info("Fall through to second policy.")
        self.set_policy(first_pol, POLICY_NONE_ALL, order=first_pol_order)
        retry_until_success(self.assert_can_access_tcp_service)

        # Swap the second policy for a drop.
        _log.info("Swap the second policy for a drop.")
        self.set_policy(second_pol, POLICY_DENY_ALL, order=second_pol_order)
        retry_until_success(self.assert_cannot_access_tcp_service)

    def test_host_ep_name_selector(self):
        """Tests that host endpoint selectors can select endpoints based on
        their name (e.g. eth0, l2tpeth3, etc)
        """
        _log.info(
            "Starting test_host_ep_name_selector.  \n"
            "Check we can get to test port before starting."
        )
        self.assert_can_access_tcp_service()
        _log.info("Configure policy and endpoints using NAMES, not IPs.")
        self.configure_host_endpoints_and_calico_policy(use_if_name=True)
        _log.info("Checking that with no rules in place we cannot get to the test port")
        retry_until_success(self.assert_cannot_access_tcp_service)
        _log.info("test_host_ep_name_selector complete.")

    def test_src_dst_tag(self):
        """Tests that rules can match on a label that a profile applies.

        This began as a test of Calico v1 tags, which a profile gave to all of its
        endpoints, and which rules matched with src_tag and dst_tag.  In v3 the
        profile applies a label instead (labelsToApply), and the rules select on
        has(test_tag).
        """
        datamodel_v3.put("Profile", "testprofile", {"labelsToApply": {"test_tag": ""}})
        self.cleanups.append(
            functools.partial(datamodel_v3.delete, "Profile", "testprofile")
        )

        _log.info(
            "Starting test_src_dst_tag.\nCheck we can get to test port before starting."
        )
        self.assert_can_access_tcp_service()

        _log.info("Configure policy and endpoints with the profile id")
        self.configure_host_endpoints_and_calico_policy(profile_ids=["testprofile"])

        # configure_host_endpoints_and_calico_policy configures the
        # compute hosts, but not the test host.  Let's do that.
        self.config_host_endpoint(
            "testnode", "test", None, [self.my_ipv4], ["testprofile"]
        )

        # Create a policy containing allow rules using the label.
        policy = {
            "selector": "role == 'compute'",
            "order": 10,
            "ingress": [
                {
                    "protocol": "TCP",
                    "action": "Allow",
                    "source": {"selector": "has(test_tag)"},
                    "destination": {"ports": [TEST_PORT]},
                },
            ],
            "egress": [
                {
                    "protocol": "TCP",
                    "action": "Allow",
                    "destination": {"ports": [TEST_PORT], "selector": "has(test_tag)"},
                },
            ],
        }
        retry_until_success(self.assert_cannot_access_tcp_service)
        self.set_policy("my_policy", policy)
        retry_until_success(self.assert_can_access_tcp_service)

        _log.info("Remove label from test endpoint and check we can no longer connect")
        self.config_host_endpoint("testnode", "test", None, [self.my_ipv4], None)
        retry_until_success(self.assert_cannot_access_tcp_service)
        _log.info("test_src_dst_tag complete.")
