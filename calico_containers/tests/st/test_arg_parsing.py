from sh import ErrorReturnCode_1, ErrorReturnCode_255

from test_base import TestBase
from docker_host import DockerHost


class TestArgParsing(TestBase):
    def test_arg_parsing(self):
        """
        Test that calicoctl correctly accepts or rejects given argument.
        """
        host = DockerHost('host')

        calicoctl = "/code/dist/calicoctl %s"

        # Run various commands with invalid IPs.
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "node --ip=127.a.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "node --ip=aa:bb::cc")
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "node --ip=127.0.0.1 --ip6=127.0.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "node --ip=127.0.0.1 --ip6=aa:bb::zz")
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "bgppeer rr add 127.a.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "bgppeer rr add aa:bb::zz")
        with self.assertRaises(ErrorReturnCode_255):
            host.execute(calicoctl % "pool add 127.a.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "pool add aa:bb::zz")
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "container node1 ip add 127.a.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "container node1 ip add aa:bb::zz")
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "container add node1 127.a.0.1")
        with self.assertRaises(ErrorReturnCode_1):
            host.execute(calicoctl % "container add node1 aa:bb::zz")

        # Add some pools and BGP peers and check the show commands"
        host.execute(calicoctl % "bgppeer rr add 1.2.3.4")
        host.execute(calicoctl % "bgppeer rr show")
        host.execute(calicoctl % "bgppeer rr show --ipv4")
        host.execute(calicoctl % "bgppeer rr show --ipv6")
        assert "1.2.3.4" in host.execute(calicoctl % "bgppeer rr show").stdout.rstrip()
        assert "1.2.3.4" in host.execute(calicoctl % "bgppeer rr show --ipv4").stdout.rstrip()
        assert "1.2.3.4" not in host.execute(calicoctl % "bgppeer rr show --ipv6").stdout.rstrip()
        host.execute(calicoctl % "bgppeer rr remove 1.2.3.4")
        assert "1.2.3.4" not in host.execute(calicoctl % "bgppeer rr show").stdout.rstrip()

        host.execute(calicoctl % "bgppeer rr add aa:bb::ff")
        host.execute(calicoctl % "bgppeer rr show")
        host.execute(calicoctl % "bgppeer rr show --ipv4")
        host.execute(calicoctl % "bgppeer rr show --ipv6")
        assert "aa:bb::ff" in host.execute(calicoctl % "bgppeer rr show").stdout.rstrip()
        assert "aa:bb::ff" not in host.execute(calicoctl % "bgppeer rr show --ipv4").stdout.rstrip()
        assert "aa:bb::ff" in host.execute(calicoctl % "bgppeer rr show --ipv6").stdout.rstrip()
        host.execute(calicoctl % "bgppeer rr remove aa:bb::ff")
        assert "aa:bb::ff" not in host.execute(calicoctl % "bgppeer rr show").stdout.rstrip()

        host.execute(calicoctl % "pool add 1.2.3.4")
        host.execute(calicoctl % "pool show")
        host.execute(calicoctl % "pool show --ipv4")
        host.execute(calicoctl % "pool show --ipv6")
        assert "1.2.3.4/32" in host.execute(calicoctl % "pool show").stdout.rstrip()
        assert "1.2.3.4/32" in host.execute(calicoctl % "pool show --ipv4").stdout.rstrip()
        assert "1.2.3.4/32" not in host.execute(calicoctl % "pool show --ipv6").stdout.rstrip()
        host.execute(calicoctl % "pool remove 1.2.3.4")
        assert "1.2.3.4/32" not in host.execute(calicoctl % "pool show").stdout.rstrip()

        host.execute(calicoctl % "pool add 1.2.3.0/24")
        host.execute(calicoctl % "pool show")
        host.execute(calicoctl % "pool show --ipv4")
        host.execute(calicoctl % "pool show --ipv6")
        assert "1.2.3.0/24" in host.execute(calicoctl % "pool show").stdout.rstrip()
        assert "1.2.3.0/24" in host.execute(calicoctl % "pool show --ipv4").stdout.rstrip()
        assert "1.2.3.0/24" not in host.execute(calicoctl % "pool show --ipv6").stdout.rstrip()
        host.execute(calicoctl % "pool remove 1.2.3.0/24")
        assert "1.2.3.0/24" not in host.execute(calicoctl % "pool show").stdout.rstrip()

        host.execute(calicoctl % "pool add aa:bb::ff")
        host.execute(calicoctl % "pool show")
        host.execute(calicoctl % "pool show --ipv4")
        host.execute(calicoctl % "pool show --ipv6")
        assert "aa:bb::ff/128" in host.execute(calicoctl % "pool show").stdout.rstrip()
        assert "aa:bb::ff/128" not in host.execute(calicoctl % "pool show --ipv4").stdout.rstrip()
        assert "aa:bb::ff/128" in host.execute(calicoctl % "pool show --ipv6").stdout.rstrip()
        host.execute(calicoctl % "pool remove aa:bb::ff/128")
        assert "aa:bb::ff/128" not in host.execute(calicoctl % "pool show").stdout.rstrip()

        # Not used anywhere else in the tests; added here for completeness.
        host.execute(calicoctl % "profile add TEST_PROFILE")
        host.execute(calicoctl % "profile TEST_PROFILE tag add TEST_TAG")
        host.execute(calicoctl % "profile TEST_PROFILE tag remove TEST_TAG")
        host.execute(calicoctl % "profile TEST_PROFILE tag show")
        host.execute(calicoctl % "profile TEST_PROFILE rule json")
        host.execute(calicoctl % "profile TEST_PROFILE rule show")
