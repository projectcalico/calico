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
            host.start_calico_node(ip="127.a.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.start_calico_node(ip="aa:bb::cc")
        with self.assertRaises(ErrorReturnCode_1):
            host.start_calico_node(ip="127.0.0.1", ip6="127.0.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.start_calico_node(ip="127.0.0.1", ip6="aa:bb::zz")
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("bgppeer rr add 127.a.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.calicoctl("bgppeer rr add aa:bb::zz")
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
            host.calicoctl("bgppeer rr add %s" % peer)
            self.assertIn(peer, host.calicoctl("bgppeer rr show").stdout.rstrip())
            self.assertIn(peer, host.calicoctl("bgppeer rr show --ipv%s" % version).stdout.rstrip())
            self.assertNotIn(peer, host.calicoctl("bgppeer rr show --ipv%s" % self.ip_not(version)).stdout.rstrip())
            host.calicoctl("bgppeer rr remove %s" % peer)
            self.assertNotIn(peer, host.calicoctl("bgppeer rr show").stdout.rstrip())

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

    def ip_not(self, version):
        self.assertIn(version, [4, 6])
        if version == 4:
            return 6
        if version == 6:
            return 4
