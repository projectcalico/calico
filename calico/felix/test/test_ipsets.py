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
from pprint import pformat
from mock import *
from netaddr import IPAddress

from calico.datamodel_v1 import EndpointId
from calico.felix.futils import IPV4, FailedSystemCall, CommandOutput
from calico.felix.ipsets import (EndpointData, IpsetManager, IpsetActor,
                                 TagIpset, EMPTY_ENDPOINT_DATA, Ipset,
                                 list_ipset_names)
from calico.felix.refcount import CREATED
from calico.felix.test.base import BaseTestCase


# Logger
_log = logging.getLogger(__name__)

patch.object = getattr(patch, "object")  # Keep PyCharm linter happy.

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

IPSET_LIST_OUTPUT = """Name: felix-v4-calico_net
Type: hash:ip
Revision: 2
Header: family inet hashsize 1024 maxelem 1048576
Size in memory: 16728
References: 1
Members:
10.1.0.28
10.1.0.29
10.1.0.19

Name: felix-v6-calico_net
Type: hash:ip
Revision: 2
Header: family inet6 hashsize 1024 maxelem 1048576
Size in memory: 16504
References: 1
Members:
"""


class TestIpsetManager(BaseTestCase):
    def setUp(self):
        super(TestIpsetManager, self).setUp()
        self.reset()

    def reset(self):
        self.created_refs = defaultdict(list)
        self.acquired_refs = {}
        self.config = Mock()
        self.config.MAX_IPSET_SIZE = 1234
        self.mgr = IpsetManager(IPV4, self.config)
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

    def test_create(self):
        with patch("calico.felix.ipsets.Ipset") as m_Ipset:
            mgr = IpsetManager(IPV4, self.config)
            tag_ipset = mgr._create("tagid")
        self.assertEqual(tag_ipset.tag, "tagid")
        self.assertEqual(tag_ipset.tag, "tagid")
        m_Ipset.assert_called_once_with('felix-v4-tagid',
                                        'felix-tmp-v4-tagid',
                                        'inet', 'hash:ip',
                                        max_elem=1234)

    def test_maybe_start_gates_on_in_sync(self):
        with patch("calico.felix.refcount.ReferenceManager."
                   "_maybe_start") as m_maybe_start:
            self.mgr._maybe_start("tag-123")
            self.assertFalse(m_maybe_start.called)
            self.mgr.on_datamodel_in_sync(async=True)
            self.step_mgr()
            self.mgr._maybe_start("tag-123")
            self.assertEqual(m_maybe_start.mock_calls,
                             [call("tag-123")])

    def test_tag_then_endpoint(self):
        # Send in the messages.
        self.mgr.on_tags_update("prof1", ["tag1"], async=True)
        self.mgr.on_endpoint_update(EP_ID_1_1, EP_1_1, async=True)
        # Let the actor process them.
        self.step_mgr()
        self.assert_one_ep_one_tag()
        # Undo our messages to check that the index is correctly updated,
        self.mgr.on_tags_update("prof1", None, async=True)
        self.mgr.on_endpoint_update(EP_ID_1_1, None, async=True)
        self.step_mgr()
        self.assert_index_empty()

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
                "10.0.0.1": ("prof1", EP_ID_1_1),
            }
        })

    def assert_index_empty(self):
        self.assertEqual(self.mgr.endpoint_data_by_ep_id, {})
        self.assertEqual(self.mgr.ip_owners_by_tag, {})

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
                "10.0.0.2": ("prof1", EP_ID_1_1),
                "10.0.0.3": ("prof1", EP_ID_1_1),
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
                "10.0.0.1": ("prof1", EP_ID_1_1),
            },
            "tag2": {
                "10.0.0.1": ("prof1", EP_ID_1_1),
            }
        })
        self.assertEqual(self.mgr.tags_by_prof_id, {"prof1": ["tag1", "tag2"]})

        # Remove a tag.
        self.mgr.on_tags_update("prof1", ["tag2"], async=True)
        self.step_mgr()
        self.assertEqual(self.mgr.ip_owners_by_tag, {
            "tag2": {
                "10.0.0.1": ("prof1", EP_ID_1_1),
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
                "10.0.0.3": ("prof3", EP_ID_1_1)
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
                "10.0.0.1": set([
                    ("prof1", EP_ID_1_1),
                    ("prof1", EP_ID_2_1),
                ])
            }
        })

        # Second profile tags arrive:
        self.mgr.on_tags_update("prof2", ["tag1", "tag2"], async=True)
        self.step_mgr()
        self.assertEqual(self.mgr.ip_owners_by_tag, {
            "tag1": {
                "10.0.0.1": set([
                    ("prof1", EP_ID_1_1),
                    ("prof1", EP_ID_2_1),
                    ("prof2", EP_ID_1_1),
                ])
            },
            "tag2": {
                "10.0.0.1": ("prof2", EP_ID_1_1),
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
                "10.0.0.1": set([
                    ("prof1", EP_ID_1_1),
                    ("prof2", EP_ID_1_1),
                ])
            },
            "tag2": {
                "10.0.0.1": ("prof2", EP_ID_1_1),
            },
        })

        # Remove the other, index should get completely cleaned up.
        self.mgr.on_endpoint_update(EP_ID_1_1, None, async=True)
        self.step_mgr()
        self.assertEqual(self.mgr.endpoint_data_by_ep_id, {})
        self.assertEqual(self.mgr.ip_owners_by_tag, {},
                         "ip_owners_by_tag should be empty, not %s" %
                         pformat(self.mgr.ip_owners_by_tag))

    def on_ref_acquired(self, tag_id, ipset):
        self.acquired_refs[tag_id] = ipset

    @patch("calico.felix.ipsets.list_ipset_names", autospec=True)
    @patch("calico.felix.futils.check_call", autospec=True)
    def test_cleanup(self, m_check_call, m_list_ipsets):
        # We're testing the in-sync processing
        self.mgr.on_datamodel_in_sync(async=True)
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

    def test_update_dirty(self):
        self.mgr.on_datamodel_in_sync(async=True)
        self.step_mgr()
        self.mgr._dirty_tags.add("tag-123")
        m_ipset = Mock(spec=TagIpset)
        self.mgr.objects_by_id["tag-123"] = m_ipset
        with patch.object(self.mgr, "_is_starting_or_live",
                          autospec=True) as m_sol:
            m_sol.return_value = True
            self.mgr._update_dirty_active_ipsets()
            self.assertEqual(
                m_ipset.replace_members.mock_calls,
                [call(frozenset(), async=True)]
            )

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


class TestIpsetActor(BaseTestCase):
    def setUp(self):
        super(TestIpsetActor, self).setUp()
        self.ipset = Mock(spec=Ipset)
        self.ipset.max_elem = 1234
        self.ipset.set_name = "felix-a_set_name"
        self.ipset.temp_set_name = "felix-a_set_name-tmp"
        self.actor = IpsetActor(self.ipset)

    def test_sync_to_ipset(self):
        members1 = set(["1.2.3.4", "2.3.4.5"])
        members2 = set(["10.1.2.3"])
        members3 = set(["9.9.9.9"])

        # Cause a full update - first time.
        _log.debug("Initial resync of ipset will happen")
        self.actor.members = members1
        self.actor._sync_to_ipset()
        self.ipset.replace_members.assert_called_once_with(members1)
        self.assertFalse(self.ipset.update_members.called)
        self.assertEqual(self.actor.members, members1)
        self.assertEqual(self.actor.programmed_members, self.actor.members)
        self.assertFalse(self.actor._force_reprogram)
        self.ipset.reset_mock()

        # Calls update_members
        _log.debug("Call to update_members should happen")
        self.actor.programmed_members = members1
        self.actor.members = members2
        self.actor._sync_to_ipset()
        self.assertFalse(self.ipset.replace_members.called)
        self.ipset.update_members.assert_called_once_with(members1, members2)
        self.assertEqual(self.actor.members, members2)
        self.assertEqual(self.actor.programmed_members, self.actor.members)
        self.assertFalse(self.actor._force_reprogram)
        self.ipset.reset_mock()

        # Does nothing - already in correct state
        _log.debug("Already in correct state (programmed_members matches)")
        self.actor.programmed_members = members2
        self.actor.members = members2
        self.actor._sync_to_ipset()
        self.assertFalse(self.ipset.replace_members.called)
        self.assertFalse(self.ipset.update_members.called)
        self.assertEqual(self.actor.members, members2)
        self.assertEqual(self.actor.programmed_members, self.actor.members)
        self.assertFalse(self.actor._force_reprogram)
        self.ipset.reset_mock()

        # Cause a full update - forced.
        _log.debug("Force a full ipset update")
        self.actor._force_reprogram = True
        self.actor.members = members3
        self.actor._sync_to_ipset()
        self.ipset.replace_members.assert_called_once_with(members3)
        self.assertFalse(self.ipset.update_members.called)
        self.assertEqual(self.actor.members, members3)
        self.assertEqual(self.actor.programmed_members, self.actor.members)
        self.assertFalse(self.actor._force_reprogram)
        self.ipset.reset_mock()

        # Cause an assert - programmed_members is None, but no resync required.
        _log.debug("Force a full ipset update")
        self.actor._force_reprogram = False
        self.actor.members = members3
        self.actor.programmed_members = None
        with self.assertRaises(AssertionError):
            self.actor._sync_to_ipset()
        self.ipset.reset_mock()

    def test_members_too_big(self):
        members = set([str(IPAddress(x)) for x in range(2000)])
        self.actor.replace_members(members, async=True)
        self.step_actor(self.actor)
        # Check we return early without updating programmed_members.
        self.assertEqual(self.actor.programmed_members, None)

    def test_owned_ipset_names(self):
        self.assertEqual(self.actor.owned_ipset_names(),
                         set(["felix-a_set_name", "felix-a_set_name-tmp"]))


class TestTagIpsetActor(BaseTestCase):
    def setUp(self):
        super(TestTagIpsetActor, self).setUp()
        self.m_ipset = Mock(spec=Ipset)
        self.m_ipset.max_elem = 1234
        self.m_ipset.set_name = "felix-a_set_name"
        self.m_ipset.temp_set_name = "felix-a_set_name-tmp"
        self.tag_ipset = TagIpset("tag-123", "IPv4", max_elem=1024)
        self.tag_ipset._ipset = self.m_ipset
        self.m_mgr = Mock()
        self.tag_ipset._manager = self.m_mgr
        self.tag_ipset._id = "tag-123"

    def test_lifecycle(self):
        self.tag_ipset.replace_members(set(["1.2.3.4"]), async=True)
        self.step_actor(self.tag_ipset)
        self.assertEqual(
            self.m_mgr.on_object_startup_complete.mock_calls,
            [call("tag-123", self.tag_ipset, async=True)]
        )
        self.tag_ipset.on_unreferenced(async=True)
        self.step_actor(self.tag_ipset)
        self.assertEqual(
            self.m_mgr.on_object_cleanup_complete.mock_calls,
            [call("tag-123", self.tag_ipset, async=True)]
        )


class TestIpset(BaseTestCase):
    def setUp(self):
        super(TestIpset, self).setUp()
        self.ipset = Ipset("foo", "foo-tmp", "inet")

    @patch("calico.felix.futils.check_call", autospec=True)
    def test_replace_members(self, m_check_call):
        self.ipset.replace_members(set(["10.0.0.1"]))
        exp_calls = [
            call(["ipset", "destroy", "foo-tmp"]),
            call(["ipset", "list", "foo"]),
            call(
                ["ipset", "restore"],
                input_str='create foo-tmp hash:ip family inet '
                          'maxelem 1048576 --exist\n'
                          'flush foo-tmp\n'
                          'add foo-tmp 10.0.0.1\n'
                          'swap foo foo-tmp\n'
                          'destroy foo-tmp\n'
                          'COMMIT\n'
            )
        ]
        self.assertEqual(m_check_call.mock_calls, exp_calls)

    @patch("calico.felix.futils.check_call", autospec=True)
    def test_replace_members_delete_fails(self, m_check_call):
        m_check_call.side_effect = iter([
            FailedSystemCall("Blah", [], 1, None, "err"),
            None, None, None])
        self.ipset.replace_members(set(["10.0.0.1"]))
        exp_calls = [
            call(["ipset", "destroy", "foo-tmp"]),
            call(['ipset', 'list', 'foo-tmp']),
            call(['ipset', 'list', 'foo']),
            call(
                ["ipset", "restore"],
                input_str='create foo-tmp hash:ip family inet '
                          'maxelem 1048576 --exist\n'
                          'flush foo-tmp\n'
                          'add foo-tmp 10.0.0.1\n'
                          'swap foo foo-tmp\n'
                          'destroy foo-tmp\n'
                          'COMMIT\n'
            )
        ]
        self.assertEqual(m_check_call.mock_calls, exp_calls)

    @patch("calico.felix.futils.check_call", autospec=True)
    def test_update_members(self, m_check_call):
        old = set(["10.0.0.2"])
        new = set(["10.0.0.1", "10.0.0.2"])
        self.ipset.update_members(old, new)

        old = set(["10.0.0.1", "10.0.0.2"])
        new = set(["10.0.0.1", "1.2.3.4"])

        self.ipset.update_members(old, new)

        calls = [call(["ipset", "restore"],
                      input_str='add foo 10.0.0.1\nCOMMIT\n'),
                 call(["ipset", "restore"],
                      input_str='del foo 10.0.0.2\n'
                                 'add foo 1.2.3.4\n'
                                 'COMMIT\n')]

        self.assertEqual(m_check_call.call_count, 2)
        m_check_call.assert_has_calls(calls)

    @patch("calico.felix.futils.check_call", autospec=True,
           side_effect=iter([
               FailedSystemCall("Blah", [], None, None, "err"),
               None,
               FailedSystemCall("No ipset", [], 1, None, "does not exist"),
               None]))
    def test_update_members_err(self, m_check_call):
        # First call to update_members will fail, leading to a retry.
        old = set(["10.0.0.2"])
        new = set(["10.0.0.1"])
        self.ipset.update_members(old, new)

        calls = [
            call(["ipset", "restore"],
                  input_str='del foo 10.0.0.2\n'
                            'add foo 10.0.0.1\n'
                            'COMMIT\n'),
            call(["ipset", "destroy", "foo-tmp"]),
            call(["ipset", "list", "foo"]),
            call(["ipset", "restore"],
                 input_str='create foo hash:ip family inet '
                           'maxelem 1048576 --exist\n'
                           'create foo-tmp hash:ip family inet '
                           'maxelem 1048576 --exist\n'
                           'flush foo-tmp\n'
                           'add foo-tmp 10.0.0.1\n'
                           'swap foo foo-tmp\n'
                           'destroy foo-tmp\n'
                           'COMMIT\n')
        ]

        self.assertEqual(m_check_call.mock_calls, calls)

    @patch("calico.felix.futils.check_call", autospec=True)
    def test_ensure_exists(self, m_check_call):
        self.ipset.ensure_exists()
        m_check_call.assert_called_once_with(
            ["ipset", "restore"],
            input_str='create foo hash:ip family inet maxelem 1048576 --exist\n'
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

    @patch("calico.felix.futils.check_call", autospec=True)
    def test_list_ipset_names(self, m_check_call):
        m_check_call.return_value = CommandOutput(IPSET_LIST_OUTPUT, "")
        self.assertEqual(list_ipset_names(),
                         ['felix-v4-calico_net', 'felix-v6-calico_net'])
