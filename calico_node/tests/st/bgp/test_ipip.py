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
import yaml

from netaddr import IPAddress, IPNetwork
from nose_parameterized import parameterized
from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.constants import DEFAULT_IPV4_POOL_CIDR
from tests.st.utils.route_reflector import RouteReflectorCluster
from tests.st.utils.utils import check_bird_status, retry_until_success, \
        update_bgp_config
from time import sleep
from unittest import skip

from .peer import create_bgp_peer, clear_bgp_peers

"""
Test calico IPIP behaviour.
"""


class TestIPIP(TestBase):
    def tearDown(self):
        self.remove_tunl_ip()

    @parameterized.expand([
        ('bird',),
        # TODO: Add back when gobgp is updated to work with libcalico-go v2 api
        # ('gobgp',),
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

            # Before starting the node, create the default IP pool using the
            # v1.0.2 calicoctl.  For calicoctl v1.1.0+, a new IPIP mode field
            # is introduced - by testing with an older pool version validates
            # the IPAM BIRD templates function correctly without the mode field.
            self.pool_action(host1, "create", DEFAULT_IPV4_POOL_CIDR, ipip_mode="Never",)
                             # comment this out for now because we don't support upgrading data yet
                             # calicoctl_version="v1.0.2")

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

            # Turn on IPIP with a v1.0.2 calicoctl and check that the
            # IPIP tunnel is being used.
            self.pool_action(host1, "replace", DEFAULT_IPV4_POOL_CIDR, ipip_mode="Always",)
                             # comment this out for now because we don't support upgrading data yet
                             # calicoctl_version="v1.0.2")
            self.assert_ipip_routing(host1, workload_host1, workload_host2,
                                     True)

            # Turn off IPIP using the latest version of calicoctl and check that
            # IPIP tunnel is not being used.  We'll use the latest version of
            # calicoctl for the remaining tests.
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

            # Test that removing pool removes the tunl IP.
            self.pool_action(host, "delete", ipv4_pool, ipip_mode="Always")
            self.assert_tunl_ip(host, ipv4_pool, expect=False)

            # Test that re-adding the pool triggers the confd watch and we get an IP
            self.pool_action(host, "create", ipv4_pool, ipip_mode="Always")
            self.assert_tunl_ip(host, ipv4_pool, expect=True)

            # Test that by adding another pool, then deleting the first,
            # we remove the original IP, and allocate a new one from the new pool
            new_ipv4_pool = IPNetwork("192.168.0.0/16")
            self.pool_action(host, "create", new_ipv4_pool, ipip_mode="Always", pool_name="pool-b")
            self.pool_action(host, "delete", ipv4_pool)
            self.assert_tunl_ip(host, new_ipv4_pool)

    @staticmethod
    def pool_action(host, action, cidr,
                    disabled=False, ipip_mode=None, calicoctl_version=None, nat_outgoing=None, pool_name=None):
        """
        Perform an ipPool action.
        """
        pool_name = "test.ippool" if pool_name is None else pool_name
        testdata = {
            'apiVersion': 'projectcalico.org/v2',
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
        host.writefile("testfile.yaml", yaml.dump(testdata))
        host.calicoctl("%s -f testfile.yaml" % action, version=calicoctl_version)

    def assert_tunl_ip(self, host, ip_network, expect=True):
        """
        Helper function to make assertions on whether or not the tunl interface
        on the Host has been assigned an IP or not. This function will retry
        7 times, ensuring that our 5 second confd watch will trigger.

        :param host: DockerHost object
        :param ip_network: IPNetwork object which describes the ip-range we do (or do not)
        expect to see an IP from on the tunl interface.
        :param expect: Whether or not we are expecting to see an IP from IPNetwork on the tunl
                       interface.
        :return:
        """
        retries = 7
        for retry in range(retries + 1):
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

    #@parameterized.expand([
    #    (False,),
    #    (True,),
    #    # TODO: Add back when gobgp is updated to work with libcalico-go v2 api
    #    #(False, 'gobgp',),
    #    #(True, 'gobgp',),
    #])
    @skip("Disabled until we understand the tunl0 recreation here")
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

            self._test_gce_int(with_ipip, backend, host1, host2, False)

    #@parameterized.expand([
    #    (False,),
    #    (True,),
    #])
    @skip("Skipping until route reflector is updated with libcalico-go v2 support")
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

            self._test_gce_int(with_ipip, 'bird', host1, host2, rrc)

    def _test_gce_int(self, with_ipip, backend, host1, host2, rrc):

        clear_bgp_peers(host1)

        host1.start_calico_node("--backend={0}".format(backend))
        host2.start_calico_node("--backend={0}".format(backend))

        # Before creating any workloads, set the initial IP-in-IP state.
        host1.set_ipip_enabled(with_ipip)

        if rrc:
            # Set the default AS number - as this is used by the RR mesh,
            # and turn off the node-to-node mesh (do this from any host).
            update_bgp_config(host1, asNum=64513, nodeMesh=False)
            # Peer from each host to the route reflector.
            for host in [host1, host2]:
                for rr in rrc.get_redundancy_group():
                    create_bgp_peer(host, "node", rr.ip, 64513, metadata={'name':host.name})

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

                # Check that we are using IP-in-IP for some routes.
                assert "tunl0" in host1.execute("ip r")
                assert "tunl0" in host2.execute("ip r")

                # Check that routes are not flapping: the following shell
                # script checks that there is no output for 10s from 'ip
                # monitor', on either host.  The "-le 1" is to allow for
                # something (either 'timeout' or 'ip monitor', not sure) saying
                # 'Terminated' when the 10s are up.  (Note that all commands
                # here are Busybox variants; I tried 'grep -v' to eliminate the
                # Terminated line, but for some reason it didn't work.)
                for host in [host1, host2]:
                    host.execute("changes=`timeout -t 10 ip -t monitor 2>&1`; " +
                                 "echo \"$changes\"; " +
                                 "test `echo \"$changes\" | wc -l` -le 1")
            else:
                # Expect non-connectivity between workloads on different hosts.
                self.assert_false(
                    workload_host1.check_can_ping(workload_host2.ip, retries=10))

            if not rrc:
                # Check the BGP status on each host.
                check_bird_status(host1, [("node-to-node mesh", host2.ip, "Established")])
                check_bird_status(host2, [("node-to-node mesh", host1.ip, "Established")])

            # Flip the IP-in-IP state for the next iteration.
            with_ipip = not with_ipip
            host1.set_ipip_enabled(with_ipip)

TestIPIP.batchnumber = 4  # Add batch label to these tests for parallel running
