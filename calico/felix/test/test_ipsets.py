# -*- coding: utf-8 -*-
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
"""
felix.test.test_ipsets
~~~~~~~~~~~~~~~~~~~~~~

Unit tests for the IpsetManager.
"""
from collections import defaultdict

import logging
from mock import *
from calico.datamodel_v1 import EndpointId
from calico.felix.futils import IPV4, FailedSystemCall
from calico.felix.ipsets import (EndpointData,  IpsetManager, TagIpset,
                                 EMPTY_ENDPOINT_DATA, Ipset)
from calico.felix.refcount import CREATED
from calico.felix.test.base import BaseTestCase


# Logger
_log = logging.getLogger(__name__)


EP_ID_1_1 = EndpointId("host1", "orch", "wl1_1", "ep1_1")
EP_1_1 = {
    "profile_ids": ["prof1", "prof2"],
    "ipv4_nets": ["10.0.0.1/32"],
}
EP_DATA_1_1 = EndpointData(["prof1", "prof2"], ["10.0.0.1"])
EP_1_1_NEW_IP = {
    "profile_ids": ["prof1", "prof2"],
    "ipv4_nets": ["10.0.0.2/32", "10.0.0.3/32"],
}
EP_1_1_NEW_PROF_IP = {
    "profile_ids": ["prof3"],
    "ipv4_nets": ["10.0.0.3/32"],
}
EP_ID_1_2 = EndpointId("host1", "orch", "wl1_2", "ep1_2")
EP_ID_2_1 = EndpointId("host2", "orch", "wl2_1", "ep2_1")
EP_2_1 = {
    "profile_ids": ["prof1"],
    "ipv4_nets": ["10.0.0.1/32"],
}
EP_2_1_NO_NETS = {
    "profile_ids": ["prof1"],
}
EP_2_1_IPV6 = {
    "profile_ids": ["prof1"],
    "ipv6_nets": ["dead:beef::/128"],
}
EP_DATA_2_1 = EndpointData(["prof1"], ["10.0.0.1"])


class TestIpsetManager(BaseTestCase):
    def setUp(self):
        super(TestIpsetManager, self).setUp()
        self.reset()

    def reset(self):
        self.created_refs = defaultdict(list)
        self.acquired_refs = {}
        self.mgr = IpsetManager(IPV4)
        self.m_create = Mock(spec=self.mgr._create,
                             side_effect = self.m_create)
        self.mgr._create = self.m_create

    def m_create(self, tag_id):
        _log.info("Creating ipset %s", tag_id)
        ipset = Mock(spec=TagIpset)

        ipset._manager = None
        ipset._id = None
        ipset.ref_mgmt_state = CREATED
        ipset.ref_count = 0
        ipset.owned_ipset_names.return_value = ["felix-v4-" + tag_id,
                                                "felix-v4-tmp-" + tag_id]

        ipset.tag = tag_id
        self.created_refs[tag_id].append(ipset)
        return ipset

    def test_tag_then_endpoint(self):
        # Send in the messages.
        self.mgr.on_tags_update("prof1", ["tag1"], async=True)
        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1, async=True)
        # Let the actor process them.
        self.step_mgr()
        self.assert_one_ep_one_tag()

    def test_endpoint_then_tag(self):
        # Send in the messages.
        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1, async=True)
        self.mgr.on_tags_update("prof1", ["tag1"], async=True)
        # Let the actor process them.
        self.step_mgr()
        self.assert_one_ep_one_tag()

    def test_endpoint_then_tag_idempotent(self):
        for _ in xrange(3):
            # Send in the messages.
            self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1, async=True)
            self.mgr.on_tags_update("prof1", ["tag1"], async=True)
            # Let the actor process them.
            self.step_mgr()
            self.assert_one_ep_one_tag()

    def assert_one_ep_one_tag(self):
        self.assertEqual(self.mgr.endpoint_data_by_ep_id, {
            EP_ID_1_1: EP_DATA_1_1,
        })
        self.assertEqual(self.mgr.ip_owners_by_tag, {
            "tag1": {
                "10.0.0.1": {
                    "prof1": set([
                        EP_ID_1_1
                    ])
                }
            }
        })

    def test_change_ip(self):
        # Initial set-up.
        self.mgr.on_tags_update("prof1", ["tag1"], async=True)
        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1, async=True)
        self.step_mgr()
        # Update the endpoint's IPs:
        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1_NEW_IP, async=True)
        self.step_mgr()

        self.assertEqual(self.mgr.ip_owners_by_tag, {
            "tag1": {
                "10.0.0.2": {
                    "prof1": set([
                        EP_ID_1_1
                    ])
                },
                "10.0.0.3": {
                    "prof1": set([
                        EP_ID_1_1
                    ])
                }
            }
        })

    def test_tag_updates(self):
        # Initial set-up.
        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1, async=True)
        self.mgr.on_tags_update("prof1", ["tag1"], async=True)
        self.step_mgr()

        # Add a tag, keep a tag.
        self.mgr.on_tags_update("prof1", ["tag1", "tag2"], async=True)
        self.step_mgr()
        self.assertEqual(self.mgr.ip_owners_by_tag, {
            "tag1": {
                "10.0.0.1": {
                    "prof1": set([
                        EP_ID_1_1
                    ])
                }
            },
            "tag2": {
                "10.0.0.1": {
                    "prof1": set([
                        EP_ID_1_1
                    ])
                }
            }
        })
        self.assertEqual(self.mgr.tags_by_prof_id, {"prof1": ["tag1", "tag2"]})

        # Remove a tag.
        self.mgr.on_tags_update("prof1", ["tag2"], async=True)
        self.step_mgr()
        self.assertEqual(self.mgr.ip_owners_by_tag, {
            "tag2": {
                "10.0.0.1": {
                    "prof1": set([
                        EP_ID_1_1
                    ])
                }
            }
        })

        # Delete the tags:
        self.mgr.on_tags_update("prof1", None, async=True)
        self.step_mgr()
        self.assertEqual(self.mgr.ip_owners_by_tag, {})
        self.assertEqual(self.mgr.tags_by_prof_id, {})

    def step_mgr(self):
        self.step_actor(self.mgr)
        self.assertEqual(self.mgr._dirty_tags, set())

    def test_update_profile_and_ips(self):
        # Initial set-up.
        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1, async=True)
        self.mgr.on_tags_update("prof1", ["tag1"], async=True)
        self.mgr.on_tags_update("prof3", ["tag3"], async=True)
        self.step_mgr()

        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1_NEW_PROF_IP, async=True)
        self.step_mgr()

        self.assertEqual(self.mgr.ip_owners_by_tag, {
            "tag3": {
                "10.0.0.3": {
                    "prof3": set([
                        EP_ID_1_1
                    ])
                }
            }
        })
        self.assertEqual(self.mgr.endpoint_ids_by_profile_id, {
            "prof3": set([EP_ID_1_1])
        })

    def test_optimize_out_v6(self):
        self.mgr.on_tags_update("prof1", ["tag1"], async=True)
        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1, async=True)
        self.mgr.on_endpoint_update(EP_ID_2_1, EP_2_1_IPV6, async=True)
        self.step_mgr()
        # Index should contain only 1_1:
        self.assertEqual(self.mgr.endpoint_data_by_ep_id, {
            EP_ID_1_1: EP_DATA_1_1,
        })

    def test_optimize_out_no_nets(self):
        self.mgr.on_tags_update("prof1", ["tag1"], async=True)
        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1, async=True)
        self.mgr.on_endpoint_update(EP_ID_2_1, EP_2_1_NO_NETS, async=True)
        self.step_mgr()
        # Index should contain only 1_1:
        self.assertEqual(self.mgr.endpoint_data_by_ep_id, {
            EP_ID_1_1: EP_DATA_1_1,
        })
        # Should be happy to then add it in.
        self.mgr.on_endpoint_update(EP_ID_2_1, EP_2_1, async=True)
        self.step_mgr()
        # Index should contain both:
        self.assertEqual(self.mgr.endpoint_data_by_ep_id, {
            EP_ID_1_1: EP_DATA_1_1,
            EP_ID_2_1: EP_DATA_2_1,
        })

    def test_duplicate_ips(self):
        # Add in two endpoints with the same IP.
        self.mgr.on_tags_update("prof1", ["tag1"], async=True)
        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1, async=True)
        self.mgr.on_endpoint_update(EP_ID_2_1, EP_2_1, async=True)
        self.step_mgr()
        # Index should contain both:
        self.assertEqual(self.mgr.endpoint_data_by_ep_id, {
            EP_ID_1_1: EP_DATA_1_1,
            EP_ID_2_1: EP_DATA_2_1,
        })
        self.assertEqual(self.mgr.ip_owners_by_tag, {
            "tag1": {
                "10.0.0.1": {
                    "prof1": set([
                        EP_ID_1_1,
                        EP_ID_2_1,
                    ])
                }
            }
        })

        # Second profile tags arrive:
        self.mgr.on_tags_update("prof2", ["tag1", "tag2"], async=True)
        self.step_mgr()
        self.assertEqual(self.mgr.ip_owners_by_tag, {
            "tag1": {
                "10.0.0.1": {
                    "prof1": set([
                        EP_ID_1_1,
                        EP_ID_2_1,
                    ]),
                    "prof2": set([
                        EP_ID_1_1,
                    ])
                }
            },
            "tag2": {
                "10.0.0.1": {
                    "prof2": set([
                        EP_ID_1_1,
                    ])
                }
            },
        })

        # Remove one, check the index gets updated.
        self.mgr.on_endpoint_update(EP_ID_2_1, None, async=True)
        self.step_mgr()
        self.assertEqual(self.mgr.endpoint_data_by_ep_id, {
            EP_ID_1_1: EP_DATA_1_1,
        })
        self.assertEqual(self.mgr.ip_owners_by_tag, {
            "tag1": {
                "10.0.0.1": {
                    "prof1": set([
                        EP_ID_1_1,
                    ]),
                    "prof2": set([
                        EP_ID_1_1,
                    ])
                }
            },
            "tag2": {
                "10.0.0.1": {
                    "prof2": set([
                        EP_ID_1_1,
                    ])
                }
            },
        })

        # Remove the other, index should get completely cleaned up.
        self.mgr.on_endpoint_update(EP_ID_1_1, None, async=True)
        self.step_mgr()
        self.assertEqual(self.mgr.endpoint_data_by_ep_id, {})
        self.assertEqual(self.mgr.ip_owners_by_tag, {})

    def on_ref_acquired(self, tag_id, ipset):
        self.acquired_refs[tag_id] = ipset

    @patch("calico.felix.ipsets.list_ipset_names", autospec=True)
    @patch("calico.felix.futils.check_call", autospec=True)
    def test_cleanup(self, m_check_call, m_list_ipsets):
        # Start with a couple ipsets.
        self.mgr.get_and_incref("foo", callback=self.on_ref_acquired,
                                async=True)
        self.mgr.get_and_incref("bar", callback=self.on_ref_acquired,
                                async=True)
        self.step_mgr()
        self.assertEqual(set(self.created_refs.keys()),
                         set(["foo", "bar"]))

        # Notify ready so that the ipsets are marked as started.
        self._notify_ready(["foo", "bar"])
        self.step_mgr()

        # Then decref "bar" so that it gets marked as stopping.
        self.mgr.decref("bar", async=True)
        self.step_mgr()
        self.assertEqual(
            self.mgr.stopping_objects_by_id,
            {"bar": set(self.created_refs["bar"])}
        )

        # Return mix of expected and unexpected ipsets.
        m_list_ipsets.return_value = [
            "not-felix-foo",
            "felix-v6-foo",
            "felix-v6-bazzle",
            "felix-v4-foo",
            "felix-v4-bar",
            "felix-v4-baz",
            "felix-v4-biff",
        ]
        m_check_call.side_effect = iter([
            # Exception on any individual call should be ignored.
            FailedSystemCall("Dummy", [], None, None, None),
            None,
        ])
        self.mgr.cleanup(async=True)
        self.step_mgr()

        # Explicitly check that exactly the right delete calls were made.
        # assert_has_calls would ignore extra calls.
        self.assertEqual(sorted(m_check_call.mock_calls),
                         sorted([
                             call(["ipset", "destroy", "felix-v4-biff"]),
                             call(["ipset", "destroy", "felix-v4-baz"]),
                         ]))

    def test_apply_snapshot_mainline(self):
        self.mgr.apply_snapshot(
            {"prof1": ["tag1"], "prof2": ["B"], "prof3": ["B"]},
            {EP_ID_1_1: EP_1_1,
             EP_ID_2_1: EP_2_1},
            async=True,
        )
        self.mgr.get_and_incref("tag1",
                                callback=self.on_ref_acquired,
                                async=True)
        self.step_mgr()
        self.mgr.on_object_startup_complete("tag1",
                                            self.created_refs["tag1"][0],
                                            async=True)
        self.step_mgr()
        self.mgr.apply_snapshot(
            {"prof1": ["tag1", "tag2"]},
            {EP_ID_1_1: EP_1_1},
            async=True,
        )
        self.step_mgr()
        self.assertEqual(self.mgr.tags_by_prof_id,
                         {"prof1": ["tag1", "tag2"]})
        self.assertEqual(self.mgr.endpoint_data_by_ep_id,
                         {EP_ID_1_1: EP_DATA_1_1})
        ipset = self.acquired_refs["tag1"]
        self.assertEqual(
            ipset.replace_members.mock_calls,
            [
                call(set(['10.0.0.1']), force_reprogram=True, async=True),
                call(set(['10.0.0.1']), force_reprogram=True, async=True),
            ]
        )

    def test_apply_snapshot_forces_reprogram(self):
        # Apply a snapshot but mock the finish call so that we can check that
        # apply_snapshot set the flag...
        self.mgr.apply_snapshot(
            {"prof1": ["A"], "prof2": ["B"]},
            {EP_ID_1_1: EP_1_1,
             EP_ID_2_1: EP_2_1},
            async=True,
        )
        # noinspection PyUnresolvedReferences
        with patch.object(self.mgr, "_finish_msg_batch"):
            self.step_actor(self.mgr)
        self.assertTrue(self.mgr._force_reprogram)

    def test_finish_msg_batch_clears_reprogram_flag(self):
        # Apply a snapshot and step the actor for real, should clear the flag.
        self.mgr.apply_snapshot(
            {"prof1": ["A"]},
            {EP_ID_1_1: EP_1_1},
            async=True,
        )
        self.step_mgr()
        self.assertFalse(self.mgr._force_reprogram)

    def _notify_ready(self, tags):
        for tag in tags:
            self.mgr.on_object_startup_complete(tag, self.created_refs[tag][0],
                                                async=True)
        self.step_mgr()


class TestEndpointData(BaseTestCase):
    def test_repr(self):
        self.assertEqual(repr(EP_DATA_1_1),
                         "EndpointData(('prof1', 'prof2'),('10.0.0.1',))")

    def test_equals(self):
        self.assertEqual(EP_DATA_1_1, EP_DATA_1_1)
        self.assertEqual(EndpointData(["prof2", "prof1"],
                                      ["10.0.0.2", "10.0.0.1"]),
                         EndpointData(["prof2", "prof1"],
                                      ["10.0.0.2", "10.0.0.1"]))
        self.assertEqual(EndpointData(["prof2", "prof1"],
                                      ["10.0.0.2", "10.0.0.1"]),
                         EndpointData(["prof1", "prof2"],
                                      ["10.0.0.1", "10.0.0.2"]))
        self.assertNotEquals(EP_DATA_1_1, None)
        self.assertNotEquals(EP_DATA_1_1, EP_DATA_2_1)
        self.assertNotEquals(EP_DATA_1_1, EMPTY_ENDPOINT_DATA)
        self.assertFalse(EndpointData(["prof2", "prof1"],
                                      ["10.0.0.2", "10.0.0.1"]) !=
                         EndpointData(["prof2", "prof1"],
                                      ["10.0.0.2", "10.0.0.1"]))

    def test_hash(self):
        self.assertEqual(hash(EndpointData(["prof2", "prof1"],
                                           ["10.0.0.2", "10.0.0.1"])),
                         hash(EndpointData(["prof1", "prof2"],
                                           ["10.0.0.1", "10.0.0.2"])))

    def test_really_a_struct(self):
        self.assertFalse(hasattr(EP_DATA_1_1, "__dict__"))


class TestIpset(BaseTestCase):
    def setUp(self):
        super(TestIpset, self).setUp()
        self.ipset = Ipset("foo", "foo-tmp", "inet")

    @patch("calico.felix.futils.check_call", autospec=True)
    def test_mainline(self, m_check_call):
        self.ipset.replace_members(set(["10.0.0.1"]))
        m_check_call.assert_called_once_with(
            ["ipset", "restore"],
            input_str='create foo hash:ip family inet --exist\n'
                      'create foo-tmp hash:ip family inet --exist\n'
                      'flush foo-tmp\n'
                      'add foo-tmp 10.0.0.1\n'
                      'swap foo foo-tmp\n'
                      'destroy foo-tmp\n'
                      'COMMIT\n'
        )

    @patch("calico.felix.futils.check_call", autospec=True)
    def test_ensure_exists(self, m_check_call):
        self.ipset.ensure_exists()
        m_check_call.assert_called_once_with(
            ["ipset", "restore"],
            input_str='create foo hash:ip family inet --exist\n'
                      'COMMIT\n'
        )

    @patch("calico.felix.futils.call_silent", autospec=True)
    def test_delete(self, m_call_silent):
        self.ipset.delete()
        self.assertEqual(
            m_call_silent.mock_calls,
            [
                call(["ipset", "destroy", "foo"]),
                call(["ipset", "destroy", "foo-tmp"]),
            ]
        )
