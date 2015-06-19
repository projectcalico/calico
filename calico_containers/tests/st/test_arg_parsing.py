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
from subprocess import CalledProcessError

from nose.plugins.attrib import attr

from test_base import TestBase
from calico_containers.tests.st.utils.docker_host import DockerHost

class TestArgParsing(TestBase):
    @attr('slow')
    def test_arg_parsing(self):
        """
        Test that calicoctl correctly accepts or rejects given argument.
        """
        with DockerHost('host', start_calico=False, dind=False) as host:
            # Run various commands with invalid IPs.
            cases = [("node --ip=127.a.0.1", 1),
                     ("node --ip=aa:bb::cc", 1),
                     ("node --ip=127.0.0.1 --ip6=127.0.0.1", 1),
                     ("node --ip=127.0.0.1 --ip6=aa:bb::zz", 1),
                     ("bgppeer rr add 127.a.0.1", 1),
                     ("bgppeer rr add aa:bb::zz", 1),
                     ("pool add 127.a.0.1", 1),
                     ("pool add aa:bb::zz", 1),
                     ("container node1 ip add 127.a.0.1", 1),
                     ("container node1 ip add aa:bb::zz", 1),
                     ("container add node1 127.a.0.1", 1),
                     ("container add node1 aa:bb::zz", 1)]
            for cmd, rc in cases:
                with self.assertRaises(CalledProcessError) as cm:
                    host.calicoctl(cmd)
                self.assertEqual(cm.exception.returncode, rc,
                                 "calicoctl %s returned code %s "
                                 "but we expected %s" %
                                 (cmd, cm.exception.returncode, rc))

            # Add some pools and BGP peers and check the show commands
            examples = [
                ["1.2.3.4", 4],
                ["aa:bb::ff", 6],
            ]
            for [peer, version] in examples:
                host.calicoctl("bgppeer rr add %s" % peer)
                self.assertIn(peer, host.calicoctl("bgppeer rr show"))
                self.assertIn(peer,
                              host.calicoctl("bgppeer rr show --ipv%s" %
                                             version))
                self.assertNotIn(peer,
                                 host.calicoctl("bgppeer rr show --ipv%s" %
                                                self.ip_not(version)))
                host.calicoctl("bgppeer rr remove %s" % peer)
                self.assertNotIn(peer, host.calicoctl("bgppeer rr show"))

            examples = [
                ["1.2.3.4", "1.2.3.4/32", 4],
                ["1.2.3.0/24", "1.2.3.0/24", 4],
                ["aa:bb::ff", "aa:bb::ff/128", 6],
            ]
            for [ip, subnet, version] in examples:
                host.calicoctl("pool add %s" % ip)
                self.assertIn(subnet, host.calicoctl("pool show"))
                self.assertIn(subnet,
                              host.calicoctl("pool show --ipv%s" % version))
                self.assertNotIn(subnet,
                                 host.calicoctl("pool show --ipv%s" %
                                                self.ip_not(version)))
                host.calicoctl("pool remove %s" % subnet)
                self.assertNotIn(subnet, host.calicoctl("pool show"))

        # TODO - Need rewriting
        # # Check default AS command
        # self.assertEquals("64511",
        #                   host.calicoctl("default-node-as").stdout.strip())
        # host.calicoctl("default-node-as 12345")
        # self.assertEquals("12345",
        #                   host.calicoctl("default-node-as").stdout.strip())
        # with self.assertRaises(ErrorReturnCode_1):
        #     host.calicoctl("default-node-as 99999999999999999999999")
        # with self.assertRaises(ErrorReturnCode_1):
        #     host.calicoctl("default-node-as abcde")
        #
        # # Check BGP mesh command
        # self.assertEquals("on",
        #                   host.calicoctl("bgp-node-mesh").stdout.strip())
        # host.calicoctl("bgp-node-mesh off")
        # self.assertEquals("off",
        #                   host.calicoctl("bgp-node-mesh").stdout.strip())
        # host.calicoctl("bgp-node-mesh on")
        # self.assertEquals("on",
        #                   host.calicoctl("bgp-node-mesh").stdout.strip())
        #
        # # Spin up calicoctl specifying an AS number.
        # host2 = DockerHost('host2', as_num=64512)
        #
        # # Add some peers
        # examples = [
        #     ["1.2.3.4", 4],
        #     ["aa:cc::ff", 6],
        # ]
        # for [peer, version] in examples:
        #     host2.calicoctl("node bgppeer add %s as 12345" % peer)
        #     self.assertIn(peer, host2.calicoctl("node bgppeer show").stdout.rstrip())
        #     self.assertIn(peer, host2.calicoctl("node bgppeer show --ipv%s" % version).stdout.rstrip())
        #     self.assertNotIn(peer, host2.calicoctl("node bgppeer show --ipv%s" % self.ip_not(version)).stdout.rstrip())
        #     host2.calicoctl("node bgppeer remove %s" % peer)
        #     self.assertNotIn(peer, host2.calicoctl("node bgppeer show").stdout.rstrip())
        #     with self.assertRaises(ErrorReturnCode_1):
        #         host2.calicoctl("node bgppeer remove %s" % peer)


    def ip_not(self, version):
        self.assertIn(version, [4, 6])
        if version == 4:
            return 6
        if version == 6:
            return 4
