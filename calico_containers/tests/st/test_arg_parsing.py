from subprocess import CalledProcessError

from test_base import TestBase
from docker_host import DockerHost
from nose.plugins.attrib import attr

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

    def ip_not(self, version):
        self.assertIn(version, [4, 6])
        if version == 4:
            return 6
        if version == 6:
            return 4
