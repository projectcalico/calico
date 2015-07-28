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
import re
import uuid

from nose.plugins.attrib import attr

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import (DockerHost, CommandExecError)

"""
Test "calicoctl bgp" and "calicoctl node bgp" commands.

Testing should be focused around the different topologies that we claim to support.
    Mesh is covered (a little) by existing multi host tests
    Single RR cluster
    AS per ToR
    AS per calico node

Test IPv4 and IPv6
Two threads to the testing:
    Function of the commands (which we already are testing) - see below
    BGP functionality in the different topologies

TODO - rework BGP tests.
"""


class TestBGP(TestBase):

    @attr('slow')
    def test_defaults(self):
        """
        Test default BGP configuration commands.
        """
        with DockerHost('host', start_calico=False, dind=False) as host:
            # Check default AS command
            self.assertEquals(host.calicoctl("bgp default-node-as"), "64511")
            host.calicoctl("bgp default-node-as 12345")
            self.assertEquals(host.calicoctl("bgp default-node-as"), "12345")
            with self.assertRaises(CommandExecError):
                host.calicoctl("bgp default-node-as 99999999999999999999999")
            with self.assertRaises(CommandExecError):
                host.calicoctl("bgp default-node-as abcde")

            # Check BGP mesh command
            self.assertEquals(host.calicoctl("bgp node-mesh"), "on")
            host.calicoctl("bgp node-mesh off")
            self.assertEquals(host.calicoctl("bgp node-mesh"), "off")
            host.calicoctl("bgp node-mesh on")
            self.assertEquals(host.calicoctl("bgp node-mesh"), "on")

    @attr('slow')
    def test_as_num(self):
        """
        Test using different AS number for the node-to-node mesh.

        We run a multi-host test for this as we need to set up real BGP peers.
        """
        with DockerHost('host1', start_calico=False) as host1, \
             DockerHost('host2', start_calico=False) as host2:

            # Set the default AS number.
            host1.calicoctl("bgp default-node-as 64512")

            # Start host1 using the inherited AS, and host2 using a specified
            # AS (same as default).
            host1.start_calico_node()
            host1.assert_driver_up()
            host2.start_calico_node(as_num="64512")
            host2.assert_driver_up()

            # Create the network on host1, but it should be usable from all
            # hosts.
            net = host1.create_network(str(uuid.uuid4()))

            workload_host1 = host1.create_workload("workload1", network=net)
            workload_host2 = host2.create_workload("workload2", network=net)

            # Allow network to converge
            workload_host1.assert_can_ping(workload_host2.ip, retries=10)

            # And check connectivity in both directions.
            self.assert_connectivity(pass_list=[workload_host1,
                                                workload_host2])

            # Check the BGP status on each host.
            self._check_status(host1, [("node-to-node mesh", host2.ip, "Established")])
            self._check_status(host2, [("node-to-node mesh", host1.ip, "Established")])

    @attr('slow')
    def test_node_peers(self):
        """
        Test per-node BGP peer configuration by turning off the mesh and
        configuring the mesh as a set of per node peers.
        """
        with DockerHost('host1', start_calico=False) as host1, \
             DockerHost('host2', start_calico=False) as host2:

            # Start both hosts using specific AS numbers.
            host1.start_calico_node(as_num="64513")
            host1.assert_driver_up()
            host2.start_calico_node(as_num="64513")
            host2.assert_driver_up()

            # Create the network on host1, but it should be usable from all
            # hosts.
            net = host1.create_network(str(uuid.uuid4()))
            workload_host1 = host1.create_workload("workload1", network=net)
            workload_host2 = host2.create_workload("workload2", network=net)

            # Allow network to converge
            workload_host1.assert_can_ping(workload_host2.ip, retries=10)

            # Turn the node-to-node mesh off and wait for connectivity to drop.
            host1.calicoctl("bgp node-mesh off")
            workload_host1.assert_cant_ping(workload_host2.ip, retries=10)

            # Configure per-node peers to explicitly set up a mesh.
            host1.calicoctl("node bgp peer add %s as 64513" % host2.ip)
            host2.calicoctl("node bgp peer add %s as 64513" % host1.ip)

            # Allow network to converge
            workload_host1.assert_can_ping(workload_host2.ip, retries=10)

            # And check connectivity in both directions.
            self.assert_connectivity(pass_list=[workload_host1,
                                                workload_host2])

            # Check the BGP status on each host.
            self._check_status(host1, [("node specific", host2.ip, "Established")])
            self._check_status(host2, [("node specific", host1.ip, "Established")])

    @attr('slow')
    def test_global_peers(self):
        """
        Test global BGP peer configuration by turning off the mesh and
        configuring the mesh as a set of global peers.
        """
        with DockerHost('host1', start_calico=False) as host1, \
             DockerHost('host2', start_calico=False) as host2:

            # Start both hosts using specific AS numbers.
            host1.start_calico_node(as_num="64513")
            host1.assert_driver_up()
            host2.start_calico_node(as_num="64513")
            host2.assert_driver_up()

            # Create the network on host1, but it should be usable from all
            # hosts.
            net = host1.create_network(str(uuid.uuid4()))
            workload_host1 = host1.create_workload("workload1", network=net)
            workload_host2 = host2.create_workload("workload2", network=net)

            # Allow network to converge
            workload_host1.assert_can_ping(workload_host2.ip, retries=10)

            # Turn the node-to-node mesh off and wait for connectivity to drop.
            host1.calicoctl("bgp node-mesh off")
            workload_host1.assert_cant_ping(workload_host2.ip, retries=10)

            # Configure global peers to explicitly set up a mesh.  This means
            # each node will try to peer with itself which will fail.
            host1.calicoctl("bgp peer add %s as 64513" % host2.ip)
            host1.calicoctl("bgp peer add %s as 64513" % host1.ip)

            # Allow network to converge
            workload_host1.assert_can_ping(workload_host2.ip, retries=10)

            # And check connectivity in both directions.
            self.assert_connectivity(pass_list=[workload_host1,
                                                workload_host2])

            # Check the BGP status on each host.  Connections from a node to
            # itself will be idle since this is invalid BGP configuration.
            self._check_status(host1, [("global", host1.ip, "Idle"),
                                       ("global", host2.ip, "Established")])
            self._check_status(host2, [("global", host1.ip, "Established"),
                                       ("global", host2.ip, "Idle")])

    def _check_status(self, host, expected):
        """
        Check the BIRD status on a particular host to see if it contains the
        expected BGP status.

        :param host: The host object to check.
        :param expected: A list of tuples containing:
            (peertype, ip address, state)
        where 'peertype' is one of "Global", "Mesh", "Node",  'ip address' is
        the IP address of the peer, and state is the expected BGP state (e.g.
        "Established" or "Idle").
        """
        output = host.calicoctl("status")
        lines = output.split("\n")
        for (peertype, ipaddr, state) in expected:
            for line in lines:
                # Status table format is of the form:
                # +--------------+-------------------+-------+----------+-------------+
                # | Peer address |     Peer type     | State |  Since   |     Info    |
                # +--------------+-------------------+-------+----------+-------------+
                # | 172.17.42.21 | node-to-node mesh |   up  | 16:17:25 | Established |
                # | 10.20.30.40  |       global      | start | 16:28:38 |   Connect   |
                # |  192.10.0.0  |   node specific   | start | 16:28:57 |   Connect   |
                # +--------------+-------------------+-------+----------+-------------+
                #
                # Splitting based on | separators results in an array of the
                # form:
                # ['', 'Peer address', 'Peer type', 'State', 'Since', 'Info', '']
                columns = re.split("\s*\|\s*", line.strip())
                if len(columns) != 7:
                    continue

                # Find the entry matching this peer.
                if columns[1] == ipaddr and columns[2] == peertype:

                    # Check that the connection state is as expected.  We check
                    # that the state starts with the expected value since there
                    # may be additional diagnostic information included in the
                    # info field.
                    if columns[5].startswith(state):
                        break
                    else:
                        msg = "Error in BIRD status for peer %s:\n" \
                              "Expected: %s; Actual: %s\n" \
                              "Output:\n%s" % (ipaddr, state, columns[5],
                                               output)
                        raise AssertionError(msg)
            else:
                msg = "Error in BIRD status for peer %s:\n" \
                      "Type: %s\n" \
                      "Expected: %s\n" \
                      "Output: \n%s" % (ipaddr, peertype, state, output)
                raise AssertionError(msg)
