from subprocess import CalledProcessError

from test_base import TestBase
from docker_host import DockerHost


class TestArgParsing(TestBase):
    def test_arg_parsing(self):
        """
        Test that calicoctl correctly accepts or rejects given argument.
        """
        host = DockerHost('host', start_calico=False)

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
                             "but we expected %s" % (cmd,
                                                     cm.exception.returncode,
                                                     rc))

        # Add some pools and BGP peers and check the show commands"
        host.calicoctl("bgppeer rr add 1.2.3.4")
        self.assertIn("1.2.3.4", host.calicoctl("bgppeer rr show").rstrip())
        self.assertIn("1.2.3.4", host.calicoctl("bgppeer rr show --ipv4").rstrip())
        self.assertNotIn("1.2.3.4", host.calicoctl("bgppeer rr show --ipv6").rstrip())
        host.calicoctl("bgppeer rr remove 1.2.3.4")
        self.assertNotIn("1.2.3.4", host.calicoctl("bgppeer rr show").rstrip())

        host.calicoctl("bgppeer rr add aa:bb::ff")
        self.assertIn("aa:bb::ff", host.calicoctl("bgppeer rr show").rstrip())
        self.assertNotIn("aa:bb::ff", host.calicoctl("bgppeer rr show --ipv4").rstrip())
        self.assertIn("aa:bb::ff", host.calicoctl("bgppeer rr show --ipv6").rstrip())
        host.calicoctl("bgppeer rr remove aa:bb::ff")
        self.assertNotIn("aa:bb::ff", host.calicoctl("bgppeer rr show").rstrip())

        host.calicoctl("pool add 1.2.3.4")
        self.assertIn("1.2.3.4/32", host.calicoctl("pool show").rstrip())
        self.assertIn("1.2.3.4/32", host.calicoctl("pool show --ipv4").rstrip())
        self.assertNotIn("1.2.3.4/32", host.calicoctl("pool show --ipv6").rstrip())
        host.calicoctl("pool remove 1.2.3.4")
        self.assertNotIn("1.2.3.4/32", host.calicoctl("pool show").rstrip())

        host.calicoctl("pool add 1.2.3.0/24")
        self.assertIn("1.2.3.0/24", host.calicoctl("pool show").rstrip())
        self.assertIn("1.2.3.0/24", host.calicoctl("pool show --ipv4").rstrip())
        self.assertNotIn("1.2.3.0/24", host.calicoctl("pool show --ipv6").rstrip())
        host.calicoctl("pool remove 1.2.3.0/24")
        self.assertNotIn("1.2.3.0/24", host.calicoctl("pool show").rstrip())

        host.calicoctl("pool add aa:bb::ff")
        self.assertIn("aa:bb::ff/128", host.calicoctl("pool show").rstrip())
        self.assertNotIn("aa:bb::ff/128", host.calicoctl("pool show --ipv4").rstrip())
        self.assertIn("aa:bb::ff/128", host.calicoctl("pool show --ipv6").rstrip())
        host.calicoctl("pool remove aa:bb::ff/128")
        self.assertNotIn("aa:bb::ff/128", host.calicoctl("pool show").rstrip())
