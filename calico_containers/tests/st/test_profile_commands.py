from test_base import TestBase
from docker_host import DockerHost


class TestProfileCommands(TestBase):
    def test_profile_commands(self):
        """
        Test that the profile rule update command successfully updates.
        """
        host = DockerHost('host')
        host.start_etcd()

        calicoctl = "/code/dist/calicoctl %s"
        host.execute(calicoctl % "profile add TEST_PROFILE")

        json = '{ "id": "TEST_PROFILE", "inbound_rules": [ { "action": "allow", "src_tag": "TEST_PROFILE" }, { "action": "deny" } ], "outbound_rules": [ { "action": "deny" } ] }'
        host.execute("echo '%s' | " % json + calicoctl % "profile TEST_PROFILE rule update")

        assert '1 deny' in host.execute(calicoctl % "profile TEST_PROFILE rule show").stdout.rstrip()

        # Test that adding and removing a tag works.
        assert "TEST_TAG" not in host.execute(calicoctl % "profile TEST_PROFILE tag show").stdout.rstrip()
        host.execute(calicoctl % "profile TEST_PROFILE tag add TEST_TAG")
        assert "TEST_TAG" in host.execute(calicoctl % "profile TEST_PROFILE tag show").stdout.rstrip()
        host.execute(calicoctl % "profile TEST_PROFILE tag remove TEST_TAG")
        assert "TEST_TAG" not in host.execute(calicoctl % "profile TEST_PROFILE tag show").stdout.rstrip()
