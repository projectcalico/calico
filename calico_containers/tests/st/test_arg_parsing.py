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

        # Add some pools and BGP peers and check the show commands"
        host.calicoctl("bgppeer rr add 1.2.3.4")
        self.assertIn("1.2.3.4", host.calicoctl("bgppeer rr show").stdout.rstrip())
        self.assertIn("1.2.3.4", host.calicoctl("bgppeer rr show --ipv4").stdout.rstrip())
        self.assertNotIn("1.2.3.4", host.calicoctl("bgppeer rr show --ipv6").stdout.rstrip())
        host.calicoctl("bgppeer rr remove 1.2.3.4")
        self.assertNotIn("1.2.3.4", host.calicoctl("bgppeer rr show").stdout.rstrip())

        host.calicoctl("bgppeer rr add aa:bb::ff")
        self.assertIn("aa:bb::ff", host.calicoctl("bgppeer rr show").stdout.rstrip())
        self.assertNotIn("aa:bb::ff", host.calicoctl("bgppeer rr show --ipv4").stdout.rstrip())
        self.assertIn("aa:bb::ff", host.calicoctl("bgppeer rr show --ipv6").stdout.rstrip())
        host.calicoctl("bgppeer rr remove aa:bb::ff")
        self.assertNotIn("aa:bb::ff", host.calicoctl("bgppeer rr show").stdout.rstrip())

        host.calicoctl("pool add 1.2.3.4")
        self.assertIn("1.2.3.4/32", host.calicoctl("pool show").stdout.rstrip())
        self.assertIn("1.2.3.4/32", host.calicoctl("pool show --ipv4").stdout.rstrip())
        self.assertNotIn("1.2.3.4/32", host.calicoctl("pool show --ipv6").stdout.rstrip())
        host.calicoctl("pool remove 1.2.3.4")
        self.assertNotIn("1.2.3.4/32", host.calicoctl("pool show").stdout.rstrip())

        host.calicoctl("pool add 1.2.3.0/24")
        self.assertIn("1.2.3.0/24", host.calicoctl("pool show").stdout.rstrip())
        self.assertIn("1.2.3.0/24", host.calicoctl("pool show --ipv4").stdout.rstrip())
        self.assertNotIn("1.2.3.0/24", host.calicoctl("pool show --ipv6").stdout.rstrip())
        host.calicoctl("pool remove 1.2.3.0/24")
        self.assertNotIn("1.2.3.0/24", host.calicoctl("pool show").stdout.rstrip())

        host.calicoctl("pool add aa:bb::ff")
        self.assertIn("aa:bb::ff/128", host.calicoctl("pool show").stdout.rstrip())
        self.assertNotIn("aa:bb::ff/128", host.calicoctl("pool show --ipv4").stdout.rstrip())
        self.assertIn("aa:bb::ff/128", host.calicoctl("pool show --ipv6").stdout.rstrip())
        host.calicoctl("pool remove aa:bb::ff/128")
        self.assertNotIn("aa:bb::ff/128", host.calicoctl("pool show").stdout.rstrip())
