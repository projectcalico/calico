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
import json
import re
import subprocess
import logging

from netaddr import IPAddress, IPNetwork
from nose_parameterized import parameterized
from time import sleep

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.constants import DEFAULT_IPV4_POOL_CIDR
from tests.st.utils.route_reflector import RouteReflectorCluster
from tests.st.utils.utils import check_bird_status, retry_until_success, \
        update_bgp_config

from .peer import create_bgp_peer

logger = logging.getLogger(__name__)

"""
Test calico IPIP behaviour.
"""

class TestIPIP(TestBase):
    def tearDown(self):
        self.remove_tunl_ip()

    @parameterized.expand([
        ('bird',),
    ])
    def test_ipip(self, backend):
        """
        Test IPIP routing with the different IPIP modes.

        This test modifies the working IPIP mode of the pool and monitors the
        traffic flow to ensure it either is or is not going over the IPIP
        tunnel as expected.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host2:

            # Create an IP pool with IP-in-IP disabled.
            self.pool_action(host1, "create", DEFAULT_IPV4_POOL_CIDR, ipip_mode="Never")

            # Autodetect the IP addresses - this should ensure the subnet is
            # correctly configured.
            host1.start_calico_node("--ip=autodetect --backend={0}".format(backend))
            host2.start_calico_node("--ip=autodetect --backend={0}".format(backend))

            # Create a network and a workload on each host.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1",
                                                   network=network1)
            workload_host2 = host2.create_workload("workload2",
                                                   network=network1)

            # Allow network to converge.
            self.assert_true(
                workload_host1.check_can_ping(workload_host2.ip, retries=10))

            # Check connectivity in both directions
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip])

            # Note in the following we are making a number of configuration
            # changes and testing whether or not IPIP is being used.
            # The order of tests is deliberately chosen to flip between IPIP
            # and no IPIP because it is easier to look for a change of state
            # than to look for state remaining the same.

            # Turn on IPIP and check that the IPIP tunnel is being used.
            self.pool_action(host1, "replace", DEFAULT_IPV4_POOL_CIDR, ipip_mode="Always")
            self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                     True)

            # Turn off IPIP and check that IPIP tunnel is not being used.
            self.pool_action(host1, "replace", DEFAULT_IPV4_POOL_CIDR, ipip_mode="Never")
            self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                     False)

            # Turn on IPIP, default mode (which is always use IPIP), and check
            # IPIP tunnel is being used.
            self.pool_action(host1, "replace", DEFAULT_IPV4_POOL_CIDR, ipip_mode="Always")
            self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                     True)

            # Turn off IPIP and check IPIP tunnel is not being used.
            self.pool_action(host1, "replace", DEFAULT_IPV4_POOL_CIDR, ipip_mode="Never")
            self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                     False)

            # Turn on IPIP mode "always", and check IPIP tunnel is being used.
            self.pool_action(host1, "replace", DEFAULT_IPV4_POOL_CIDR, ipip_mode="Always")
            self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                     True)

            # Turn on IPIP mode "cross-subnet", since both hosts will be on the
            # same subnet, IPIP should not be used.
            self.pool_action(host1, "replace", DEFAULT_IPV4_POOL_CIDR, ipip_mode="CrossSubnet")
            self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                     False)

            # Set the BGP subnet on both node resources to be a /32.  This will
            # fool Calico into thinking they are on different subnets.  IPIP
            # routing should be used.
            self.pool_action(host1, "replace", DEFAULT_IPV4_POOL_CIDR, ipip_mode="CrossSubnet")
            self.modify_subnet(host1, 32)
            self.modify_subnet(host2, 32)
            self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                     True)

    def test_ipip_addr_assigned(self):
        with DockerHost('host', dind=False, start_calico=False) as host:
            # Set up first pool before Node is started, to ensure we get tunl IP on boot
            ipv4_pool = IPNetwork("10.0.1.0/24")
            self.pool_action(host, "create", ipv4_pool, ipip_mode="Always")
            host.start_calico_node()
            self.assert_tunl_ip(host, ipv4_pool, expect=True)

            # Disable the IP Pool, and make sure the tunl IP is not from this IP pool anymore.
            self.pool_action(host, "apply", ipv4_pool, ipip_mode="Always", disabled=True)
            self.assert_tunl_ip(host, ipv4_pool, expect=False)

            # Re-enable the IP pool and make sure the tunl IP is assigned from that IP pool again.
            self.pool_action(host, "apply", ipv4_pool, ipip_mode="Always")
            self.assert_tunl_ip(host, ipv4_pool, expect=True)

            # Set IPIP encapsulation to "Never" and make sure the tunl IP is not from this IP pool anymore
            self.pool_action(host, "apply", ipv4_pool, ipip_mode="Never")
            # This triggers a felix restart, so use assert_tunl_ip_consistently()
            self.assert_tunl_ip_consistently(host, ipv4_pool, expect=False)

            # Set IPIP encapsulation back to "Always" and make sure the tunl IP is assigned from that IP pool again
            self.pool_action(host, "apply", ipv4_pool, ipip_mode="Always")
            self.assert_tunl_ip(host, ipv4_pool, expect=True)

            # Test that removing the pool removes the tunl IP.
            self.pool_action(host, "delete", ipv4_pool, ipip_mode="Always")
            # This triggers a felix restart, so use assert_tunl_ip_consistently()
            self.assert_tunl_ip_consistently(host, ipv4_pool, expect=False)

            # Test that re-adding the pool triggers the confd watch and we get an IP
            self.pool_action(host, "create", ipv4_pool, ipip_mode="Always")
            self.assert_tunl_ip(host, ipv4_pool, expect=True)

            # Test that by adding another pool, then deleting the first,
            # we remove the original IP, and allocate a new one from the new pool
            new_ipv4_pool = IPNetwork("192.168.0.0/16")
            self.pool_action(host, "create", new_ipv4_pool, ipip_mode="Always", pool_name="pool-b")
            self.pool_action(host, "delete", ipv4_pool)
            self.assert_tunl_ip(host, new_ipv4_pool)

    @parameterized.expand([
        ('bird',),
    ])
    def test_issue_1584(self, backend):
        """
        Test cold start of bgp daemon correctly fixes tunl/non-tunl routes.

        This test modifies the working IPIP mode of the pool and monitors the
        traffic flow to ensure it either is or is not going over the IPIP
        tunnel as expected.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        start_calico=False) as host1, \
                DockerHost('host2',
                           additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                           start_calico=False) as host2:

            # Create an IP pool with IP-in-IP disabled.
            self.pool_action(host1, "create", DEFAULT_IPV4_POOL_CIDR, ipip_mode="Never")

            # Autodetect the IP addresses - this should ensure the subnet is
            # correctly configured.
            host1.start_calico_node("--ip=autodetect --backend={0}".format(backend))
            host2.start_calico_node("--ip=autodetect --backend={0}".format(backend))

            # Create a network and a workload on each host.
            network1 = host1.create_network("subnet1")
            workload_host1 = host1.create_workload("workload1",
                                                   network=network1)
            workload_host2 = host2.create_workload("workload2",
                                                   network=network1)

            # Allow network to converge.
            self.assert_true(
                workload_host1.check_can_ping(workload_host2.ip, retries=10))

            # Check connectivity in both directions
            self.assert_ip_connectivity(workload_list=[workload_host1,
                                                       workload_host2],
                                        ip_pass_list=[workload_host1.ip,
                                                      workload_host2.ip])

            # Turn on IPIP and check that IPIP tunnel is being used.
            self.pool_action(host1, "replace", DEFAULT_IPV4_POOL_CIDR, ipip_mode="Always")
            self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                     True)

            # Toggle the IPIP mode between being expecting IPIP and not.  Only the mode
            # "Always" should result in IPIP tunnel being used in these tests.
            modes = ["Always"]
            for mode in ["CrossSubnet", "Always", "Never", "Always"]:
                # At the start of this loop we should have connectivity.
                logger.info("New mode setting: %s" % mode)
                logger.info("Previous mode settings: %s" % modes)

                # Shutdown the calico-node on host1, we should still have connectivity because
                # the node was shut down without removing the routes.  Check tunnel usage based
                # on the current IPIP mode (only a mode of Always will use the tunnel).
                host1.execute("docker rm -f calico-node")
                self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                         modes[-1] == "Always")

                # Update the IPIP mode.
                self.pool_action(host1, "replace", DEFAULT_IPV4_POOL_CIDR, ipip_mode=mode)
                modes.append(mode)

                # At this point, since we are toggling between IPIP connectivity and no IPIP
                # connectivity, there will be a mistmatch between the two nodes because host1
                # does not have the BGP daemon running on it.
                self.assert_ip_connectivity(workload_list=[workload_host1],
                                            ip_pass_list=[],
                                            ip_fail_list=[workload_host2.ip],
                                            retries=10)

                # Start the calico-node.  Connectivity should be restored once the BGP daemon
                # on host1 fixes the route.
                host1.start_calico_node("--ip=autodetect --backend={0}".format(backend))
                self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                         modes[-1] == "Always")

    @staticmethod
    def pool_action(host, action, cidr,
                    disabled=False, ipip_mode=None, nat_outgoing=None, pool_name=None):
        """
        Perform an ipPool action.
        """
        pool_name = "test.ippool" if pool_name is None else pool_name
        testdata = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'IPPool',
            'metadata': {
                'name': pool_name,
            },
            'spec': {
                'cidr': str(cidr),
                'disabled': disabled,
            }
        }

        # Add optional fields if needed
        # ipip_mode could be Never, Always, CrossSubnet or not specified (defaults to Always)
        if ipip_mode is not None:
            testdata['spec']['ipipMode'] = ipip_mode
        # nat_outgoing could be True, False or not specified (defaults to False)
        if nat_outgoing is not None:
            testdata['spec']['natOutgoing'] = nat_outgoing
        host.writejson("testfile", testdata)
        host.calicoctl("%s -f testfile" % action)

    def assert_tunl_ip(self, host, ip_network, expect=True):
        """
        Helper function to make assertions on whether or not the tunl interface
        on the Host has been assigned an IP or not. This function will retry
        8 times, ensuring that our 5 second confd watch will trigger.

        :param host: DockerHost object
        :param ip_network: IPNetwork object which describes the ip-range we do (or do not)
        expect to see an IP from on the tunl interface.
        :param expect: Whether or not we are expecting to see an IP from IPNetwork on the tunl
                       interface.
        :return:
        """
        retries = 8
        for retry in range(retries):
            try:
                output = host.execute("ip addr show tunl0")
                match = re.search(r'inet ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', output)
                if match:
                    ip_address = IPAddress(match.group(1))
                    if expect:
                        self.assertIn(ip_address, ip_network)
                    else:
                        self.assertNotIn(ip_address, ip_network)
                else:
                    self.assertFalse(expect, "No IP address assigned to tunl interface.")
            except Exception as e:
                if retry < retries:
                    sleep(1)
                else:
                    raise e
            else:
                return

    def assert_tunl_ip_consistently(self, host, ip_network, expect=True):
        """
        Helper function to make assertions on whether or not the tunl interface
        on the Host consistently keeps get an assigned IP or not.
        This function will first call assert_tunl_ip() to reach the expected
        state, then it will assert that the reached state does not change for
        5 seconds, checking every 1 second.

        :param host: DockerHost object
        :param ip_network: IPNetwork object which describes the ip-range we do (or do not)
        expect to see an IP from on the tunl interface.
        :param expect: Whether or not we are expecting to see an IP from IPNetwork on the tunl
                       interface.
        :return:
        """
        # First wait until the expected state is reached (retrying if needed)
        self.assert_tunl_ip(host, ip_network, expect=expect)

        # Then make sure it stays consistently this way for 'duration' seconds,
        # checking every 1 second
        duration = 5
        for n in range(duration):
            output = host.execute("ip addr show tunl0")
            match = re.search(r'inet ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', output)
            if match:
                ip_address = IPAddress(match.group(1))
                if expect:
                    self.assertIn(ip_address, ip_network)
                else:
                    self.assertNotIn(ip_address, ip_network)
            else:
                self.assertFalse(expect, "No IP address assigned to tunl interface.")
            sleep(1)

    @staticmethod
    def remove_tunl_ip():
        """
        Remove the host tunl IP address if assigned.
        """
        try:
            output = subprocess.check_output(["ip", "addr", "show", "tunl0"])
        except subprocess.CalledProcessError:
            return

        match = re.search(r'inet ([\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3})', output)
        if not match:
            return

        ipnet = str(IPNetwork(match.group(1)))

        try:
            subprocess.check_output(["ip", "addr", "del", ipnet, "dev", "tunl0"])
        except subprocess.CalledProcessError:
            return

    @staticmethod
    def modify_subnet(host, prefixlen):
        """
        Update the calico node resource to use the specified prefix length.

        Returns the current mask size.
        """
        node = json.loads(host.calicoctl(
            "get node %s --output=json" % host.get_hostname()))

        # Get the current network and prefix len
        ipnet = IPNetwork(node["spec"]["bgp"]["ipv4Address"])
        current_prefix_len = ipnet.prefixlen

        # Update the prefix length
        ipnet.prefixlen = prefixlen
        node["spec"]["bgp"]["ipv4Address"] = str(ipnet)

        # Write the data back again.
        host.writejson("new_data", node)
        host.calicoctl("apply -f new_data")
        return current_prefix_len

    def assert_ipip_routing(self, host1, workload_host1, workload_host2, expect_ipip):
        """
        Test whether IPIP is being used as expected on host1 when pinging workload_host2
        from workload_host1.
        """
        def check():
            orig_tx = self.get_tunl_tx(host1)
            workload_host1.execute("ping -c 2 -W 1 %s" % workload_host2.ip)
            if expect_ipip:
                self.assertEqual(self.get_tunl_tx(host1), orig_tx + 2)
            else:
                self.assertEqual(self.get_tunl_tx(host1), orig_tx)
        retry_until_success(check, retries=10)

    @staticmethod
    def get_tunl_tx(host):
        """
        Get the tunl TX count
        """
        try:
            output = host.execute("ifconfig tunl0")
        except subprocess.CalledProcessError:
            return

        match = re.search(r'RX packets:(\d+) ',
                          output)
        return int(match.group(1))

    @parameterized.expand([
        (False,),
        (True,),
    ])
    def test_gce(self, with_ipip, backend='bird'):
        """Test with and without IP-in-IP routing on simulated GCE instances.

        In this test we simulate GCE instance routing, where there is a router
        between the instances, and each instance has a /32 address that appears
        not to be directly connected to any subnet.  With that setup,
        connectivity between workloads on different hosts _should_ require
        IP-in-IP to be enabled.  We test that we do get connectivity _with_
        IP-in-IP, that we don't get connectivity _without_ IP-in-IP, and that
        the situation updates dynamically if we toggle IP-in-IP with workloads
        already existing.

        Note that this test targets the BGP implementation, to check that it
        does IP-in-IP routing correctly, and handles the underlying GCE
        routing, and switches dynamically between IP-in-IP and normal routing
        as directed by calicoctl.  (In the BIRD case, these are all points for
        which we've patched the upstream BIRD code.)  But naturally it also
        involves calicoctl and confd, so it isn't _only_ about the BGP code.
        """
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        simulate_gce_routing=True,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        simulate_gce_routing=True,
                        start_calico=False) as host2:

            self._test_gce_int(with_ipip, backend, host1, host2, None)

    @parameterized.expand([
        (False,),
        (True,),
    ])
    def test_gce_rr(self, with_ipip):
        """As test_gce except with a route reflector instead of mesh config."""
        with DockerHost('host1',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        simulate_gce_routing=True,
                        start_calico=False) as host1, \
             DockerHost('host2',
                        additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                        simulate_gce_routing=True,
                        start_calico=False) as host2, \
             RouteReflectorCluster(1, 1) as rrc:

            rr_ip = None
            for rr in rrc.get_redundancy_group():
                rr_ip = rr.ip
            self._test_gce_int(with_ipip, 'bird', host1, host2, rr_ip)

    def _test_gce_int(self, with_ipip, backend, host1, host2, rr_ip):

        host1.start_calico_node("--backend={0}".format(backend))
        host2.start_calico_node("--backend={0}".format(backend))

        # Before creating any workloads, set the initial IP-in-IP state.
        host1.set_ipip_enabled(with_ipip)

        if rr_ip:
            # Set the default AS number - as this is used by the RR mesh,
            # and turn off the node-to-node mesh (do this from any host).
            update_bgp_config(host1, asNum=64513, nodeMesh=False)
            # Peer from each host to the route reflector.
            for host in [host1, host2]:
                create_bgp_peer(host, "node", rr_ip, 64513, metadata={'name':host.name})

        # Create a network and a workload on each host.
        network1 = host1.create_network("subnet1")
        workload_host1 = host1.create_workload("workload1",
                                               network=network1)
        workload_host2 = host2.create_workload("workload2",
                                               network=network1)

        for _ in [1, 2]:
            # Check we do or don't have connectivity between the workloads,
            # according to the IP-in-IP setting.
            if with_ipip:
                # Allow network to converge.
                self.assert_true(
                    workload_host1.check_can_ping(workload_host2.ip, retries=10))

                # Check connectivity in both directions
                self.assert_ip_connectivity(workload_list=[workload_host1,
                                                           workload_host2],
                                            ip_pass_list=[workload_host1.ip,
                                                          workload_host2.ip])

                for host in [host1, host2]:

                    # Check that we are using IP-in-IP for some routes.
                    assert "tunl0" in host.execute("ip r")

                    # Get current links and addresses, as a baseline for the
                    # following changes test.
                    host.execute("ip l")
                    host.execute("ip a")

                    if rr_ip:
                        # Check that this host has received the /26 route from
                        # the route reflector.  Otherwise this could show up
                        # during the following monitoring, as it might be a
                        # little slower than what is needed for the workload
                        # connectivity tested above.
                        expected_route_string = "/26 via " + rr_ip
                        def check():
                            self.assertIn(expected_route_string,
                                          host.execute("ip r"))
                        retry_until_success(check, retries=10)

                    # Check that routes are not flapping, on either host, by
                    # running 'ip monitor' for 10s and checking that it does
                    # not indicate any changes other than those associated with
                    # an IP address being added to the tunl0 device.
                    ip_changes = host.execute("timeout -t 10 ip -t monitor 2>&1 || true")
                    lines = ip_changes.split("\n")
                    assert len(lines) >= 1, "No output from ip monitor"
                    expected_lines_following = 0
                    for line in lines:
                        if expected_lines_following > 0:
                            expected_lines_following -= 1
                        elif "Terminated" in line:
                            # "Terminated"
                            pass
                        elif "Timestamp" in line:
                            # e.g. "Timestamp: Wed Nov  1 18:02:38 2017 689895 usec"
                            pass
                        elif ": tunl0" in line:
                            # e.g. "2: tunl0    inet 192.168.128.1/32 scope global tunl0"
                            #      "       valid_lft forever preferred_lft forever"
                            # Indicates IP address being added to the tunl0 device.
                            expected_lines_following = 1
                        elif line.startswith("local") and "dev tunl0" in line:
                            # e.g. "local 192.168.128.1 dev tunl0 table local ..."
                            # Local routing table entry associated with tunl0
                            # device IP address.
                            pass
                        elif "172.17.0.1 dev eth0 lladdr" in line:
                            # Ex: "172.17.0.1 dev eth0 lladdr 02:03:04:05:06:07 REACHABLE"
                            # Indicates that the host just learned the MAC
                            # address of its default gateway.
                            pass
                        else:
                            assert False, "Unexpected ip monitor line: %r" % line

            else:
                # Expect non-connectivity between workloads on different hosts.
                self.assert_false(
                    workload_host1.check_can_ping(workload_host2.ip, retries=10))

            if not rr_ip:
                # Check the BGP status on each host.
                check_bird_status(host1, [("node-to-node mesh", host2.ip, "Established")])
                check_bird_status(host2, [("node-to-node mesh", host1.ip, "Established")])

            # Flip the IP-in-IP state for the next iteration.
            with_ipip = not with_ipip
            host1.set_ipip_enabled(with_ipip)

TestIPIP.batchnumber = 4  # Add batch label to these tests for parallel running
