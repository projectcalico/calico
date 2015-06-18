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
from sh import ErrorReturnCode_1, ErrorReturnCode_255

from test_base import TestBase
from docker_host import DockerHost


class TestArgParsing(TestBase):
    def test_arg_parsing(self):
        """
        Test that calicoctl correctly accepts or rejects given argument.
        """
        host = DockerHost('host', start_calico=False)

        # Run various commands with invalid IPs.
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl('node --ip=127.a.0.1')
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl('node --ip=aa:bb::cc')
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl('node --ip=127.0.0.1 --ip6=127.0.0.1')
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl('node --ip=127.0.0.1 --ip6=aa:bb::zz')
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("bgppeer add 127.a.0.1 as 12345")
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("bgppeer add aa:bb::zz as 12345")
        with self.assertRaises(ErrorReturnCode_255):
            host.calicoctl("pool add 127.a.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("pool add aa:bb::zz")
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("container node1 ip add 127.a.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("container node1 ip add aa:bb::zz")
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("container add node1 127.a.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("container add node1 aa:bb::zz")

        # Add some pools and BGP peers and check the show commands
        examples = [
            ["1.2.3.4", 4],
            ["aa:bb::ff", 6],
        ]
        for [peer, version] in examples:
            host.calicoctl("bgppeer add %s as 12345" % peer)
            self.assertIn(peer, host.calicoctl("bgppeer show").stdout.rstrip())
            self.assertIn(peer, host.calicoctl("bgppeer show --ipv%s" % version).stdout.rstrip())
            self.assertNotIn(peer, host.calicoctl("bgppeer show --ipv%s" % self.ip_not(version)).stdout.rstrip())
            host.calicoctl("bgppeer remove %s" % peer)
            self.assertNotIn(peer, host.calicoctl("bgppeer show").stdout.rstrip())
            with self.assertRaises(ErrorReturnCode_1):
                host.calicoctl("bgppeer remove %s" % peer)

        examples = [
            ["1.2.3.4", "1.2.3.4/32", 4],
            ["1.2.3.0/24", "1.2.3.0/24", 4],
            ["aa:bb::ff", "aa:bb::ff/128", 6],
        ]
        for [ip, subnet, version] in examples:
            host.calicoctl("pool add %s" % ip)
            self.assertIn(subnet, host.calicoctl("pool show").stdout.rstrip())
            self.assertIn(subnet, host.calicoctl("pool show --ipv%s" % version).stdout.rstrip())
            self.assertNotIn(subnet, host.calicoctl("pool show --ipv%s" % self.ip_not(version)).stdout.rstrip())
            host.calicoctl("pool remove %s" % subnet)
            self.assertNotIn(subnet, host.calicoctl("pool show").stdout.rstrip())

        # Check default AS command
        self.assertEquals("64511",
                          host.calicoctl("default-node-as").stdout.strip())
        host.calicoctl("default-node-as 12345")
        self.assertEquals("12345",
                          host.calicoctl("default-node-as").stdout.strip())
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("default-node-as 99999999999999999999999")
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("default-node-as abcde")

        # Check BGP mesh command
        self.assertEquals("on",
                          host.calicoctl("bgp-node-mesh").stdout.strip())
        host.calicoctl("bgp-node-mesh off")
        self.assertEquals("off",
                          host.calicoctl("bgp-node-mesh").stdout.strip())
        host.calicoctl("bgp-node-mesh on")
        self.assertEquals("on",
                          host.calicoctl("bgp-node-mesh").stdout.strip())

        # Spin up calicoctl specifying an AS number.
        host2 = DockerHost('host2', as_num=64512)

        # Add some peers
        examples = [
            ["1.2.3.4", 4],
            ["aa:cc::ff", 6],
        ]
        for [peer, version] in examples:
            host2.calicoctl("node bgppeer add %s as 12345" % peer)
            self.assertIn(peer, host2.calicoctl("node bgppeer show").stdout.rstrip())
            self.assertIn(peer, host2.calicoctl("node bgppeer show --ipv%s" % version).stdout.rstrip())
            self.assertNotIn(peer, host2.calicoctl("node bgppeer show --ipv%s" % self.ip_not(version)).stdout.rstrip())
            host2.calicoctl("node bgppeer remove %s" % peer)
            self.assertNotIn(peer, host2.calicoctl("node bgppeer show").stdout.rstrip())
            with self.assertRaises(ErrorReturnCode_1):
                host2.calicoctl("node bgppeer remove %s" % peer)


    def ip_not(self, version):
        self.assertIn(version, [4, 6])
        if version == 4:
            return 6
        if version == 6:
            return 4
