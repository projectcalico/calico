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
import json

from nose.plugins.attrib import attr

from test_base import TestBase
from calico_containers.tests.st.utils.docker_host import DockerHost


class TestProfileCommands(TestBase):
    @attr('slow')
    def test_profile_commands(self):
        """
        Test that the profile rule update command successfully updates.
        """
        with DockerHost('host', start_calico=False) as host:

            host.calicoctl("profile add TEST_PROFILE")

            json_dict = {"id": "TEST_PROFILE",
                         "inbound_rules": [
                             {"action": "allow",
                              "src_tag": "TEST_PROFILE"},
                             {"action": "deny"}
                         ],
                         "outbound_rules": [{"action": "deny",
                                             "dst_net": "192.168.0.0/16"},
                                            {
                                                "action": "allow"
                                            }]}

            update = json.dumps(json_dict)
            cmd = "/code/dist/calicoctl profile TEST_PROFILE rule update"
            host.execute("echo '%s' | %s" % (update, cmd))

            self.assertIn('1 deny',
                          host.calicoctl("profile TEST_PROFILE rule show"))

            result = host.calicoctl("profile TEST_PROFILE rule json")
            rules = json.loads(result)
            self.assertDictEqual(rules, json_dict)

            # Test that adding and removing a tag works.
            self.assertNotIn("TEST_TAG", self.show_tag(host))
            host.calicoctl("profile TEST_PROFILE tag add TEST_TAG")
            self.assertIn("TEST_TAG", self.show_tag(host))
            host.calicoctl("profile TEST_PROFILE tag remove TEST_TAG")
            self.assertNotIn("TEST_TAG", self.show_tag(host))

    def show_tag(self, host):
        return host.calicoctl("profile TEST_PROFILE tag show").rstrip()
