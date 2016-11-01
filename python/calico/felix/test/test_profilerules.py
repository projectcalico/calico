# -*- coding: utf-8 -*-
# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
test_profilerules
~~~~~~~~~~~~~~~~~

Tests for the profilerules module.
"""

import logging

from mock import Mock, call, patch
from calico.felix import refcount
from calico.felix.fiptables import IptablesUpdater
from calico.felix.futils import FailedSystemCall
from calico.felix.ipsets import IpsetManager, RefCountedIpsetActor
from calico.felix.profilerules import ProfileRules, RulesManager

from calico.felix.test.base import BaseTestCase, load_config
from unittest2 import skip

_log = logging.getLogger(__name__)


RULES_1 = {
    "id": "prof1",
    "inbound_rules": [
        {"src_tag": "src-tag"}
    ],
    "outbound_rules": [
        {"dst_tag": "dst-tag"}
    ]
}

RULES_1_CHAINS = {
    'felix-p-prof1-i': [
        '--append felix-p-prof1-i --match set '
            '--match-set src-tag-name src '
            '--jump MARK --set-mark 0x1000000/0x1000000',
        '--append felix-p-prof1-i --match mark '
            '--mark 0x1000000/0x1000000 --jump RETURN',
    ],
    'felix-p-prof1-o': [
        '--append felix-p-prof1-o --match set '
            '--match-set dst-tag-name dst '
            '--jump MARK --set-mark 0x1000000/0x1000000',
        '--append felix-p-prof1-o --match mark '
            '--mark 0x1000000/0x1000000 --jump RETURN',
    ]
}

SELECTOR_1 = "a == 'a1'"
RULES_2 = {
    "id": "prof1",
    "inbound_rules": [
        # Use negated matches to ensure we extract dependencies for negated
        # matches.
        {"!src_tag": "src-tag-added",
         "!src_selector": SELECTOR_1}
    ],
    "outbound_rules": [
        {"dst_tag": "dst-tag"}
    ]
}

RULES_2_CHAINS = {
    'felix-p-prof1-i': [
        '--append felix-p-prof1-i --match set '
            '! --match-set src-tag-added-name src '
            '--match set '
            '! --match-set selector-1-name src '
            '--jump MARK --set-mark 0x1000000/0x1000000',
        '--append felix-p-prof1-i --match mark '
            '--mark 0x1000000/0x1000000 --jump RETURN',
    ],
    'felix-p-prof1-o': [
        '--append felix-p-prof1-o --match set '
            '--match-set dst-tag-name dst '
            '--jump MARK --set-mark 0x1000000/0x1000000',
        '--append felix-p-prof1-o --match mark '
            '--mark 0x1000000/0x1000000 --jump RETURN',
    ]
}


class TestRulesManager(BaseTestCase):
    def setUp(self):
        super(TestRulesManager, self).setUp()
        self.config = load_config("felix_default.cfg")
        self.m_updater = Mock(spec=IptablesUpdater)
        self.m_ipset_mgr = Mock(spec=IpsetManager)
        self.mgr = RulesManager(self.config, 4, self.m_updater, self.m_ipset_mgr)

    def test_create(self):
        pr = self.mgr._create("profile-id")
        self.assertEqual(pr.id, "profile-id")
        self.assertEqual(pr.ip_version, 4)
        self.assertEqual(pr._iptables_updater, self.m_updater)
        self.assertEqual(pr._ipset_mgr, self.m_ipset_mgr)

    def test_on_object_started_unknown(self):
        m_pr = Mock(spec=ProfileRules)
        self.mgr._on_object_started("profile-id", m_pr)
        self.assertEqual(
            m_pr.on_profile_update.mock_calls,
            [call(None, async=True)]
        )

    def test_on_object_started(self):
        m_pr = Mock(spec=ProfileRules)
        self.mgr.rules_by_profile_id["profile-id"] = {"foo": "bar"}
        self.mgr._on_object_started("profile-id", m_pr)
        self.assertEqual(
            m_pr.on_profile_update.mock_calls,
            [call({"foo": "bar"}, async=True)]
        )

    def test_on_datamodel_in_sync(self):
        with patch("calico.felix.refcount.ReferenceManager."
                   "_maybe_start_all", autospec=True) as m_start:
            self.mgr.on_datamodel_in_sync(async=True)
            self.mgr.on_datamodel_in_sync(async=True)
            self.step_actor(self.mgr)
            # Only the first datamodel_in_sync triggers maybe_start_all.
            self.assertEqual(m_start.mock_calls, [call(self.mgr)])

    def test_maybe_start_known_in_sync(self):
        with patch("calico.felix.refcount."
                   "ReferenceManager._maybe_start") as m_maybe_start:
            self.mgr._maybe_start("profile-id", in_sync=True)
            self.assertEqual(
                m_maybe_start.mock_calls,
                [call("profile-id")]
            )

    def test_maybe_start_globally_in_sync(self):
        with patch("calico.felix.refcount."
                   "ReferenceManager._maybe_start") as m_maybe_start:
            self.mgr.on_datamodel_in_sync(async=True)
            self.step_actor(self.mgr)
            self.mgr._maybe_start("profile-id")
            self.assertEqual(
                m_maybe_start.mock_calls,
                [call("profile-id")]
            )

    def test_maybe_start_not_in_sync(self):
        with patch("calico.felix.refcount."
                   "ReferenceManager._maybe_start") as m_maybe_start:
            self.mgr._maybe_start("profile-id", in_sync=False)
            self.assertEqual(m_maybe_start.mock_calls, [])

    def test_on_rules_update_unknown(self):
        with patch("calico.felix.refcount."
                   "ReferenceManager._maybe_start") as m_maybe_start:
            self.mgr.on_rules_update("prof-id", {"foo": "bar"}, async=True)
            self.step_actor(self.mgr)
            # Nothing to try to start.
            self.assertEqual(m_maybe_start.mock_calls, [])

    def test_on_rules_update_not_started(self):
        with patch("calico.felix.refcount."
                   "ReferenceManager._maybe_start") as m_maybe_start:
            self.mgr.on_rules_update("prof-id", {"foo": "bar"}, async=True)
            self.mgr.objects_by_id["prof-id"] = Mock()
            self.step_actor(self.mgr)
            # Should try to start the ProfileRules.
            self.assertEqual(m_maybe_start.mock_calls,
                             [call("prof-id")])

    def test_on_rules_update_started(self):
        with patch("calico.felix.refcount."
                   "ReferenceManager._maybe_start") as m_maybe_start:
            p = {"foo": "bar"}
            self.mgr.on_rules_update("prof-id", p, async=True)
            m_pr = Mock()
            m_pr.ref_mgmt_state = refcount.LIVE
            self.mgr.objects_by_id["prof-id"] = m_pr
            self.step_actor(self.mgr)
            self.assertEqual(m_pr.on_profile_update.mock_calls,
                             [call(p, force_reprogram=False, async=True)])
            # Already started so shouldn't try to start it.
            self.assertEqual(m_maybe_start.mock_calls, [])

    def test_on_rules_delete(self):
        with patch("calico.felix.refcount."
                   "ReferenceManager._maybe_start") as m_maybe_start:
            self.mgr.on_rules_update("prof-id", None, async=True)
            self.mgr.objects_by_id["prof-id"] = Mock()
            self.step_actor(self.mgr)
            # Even though we know it's gone, still try to start it.  If it's
            # referenced this will ensure that the chain is cleaned up.
            self.assertEqual(m_maybe_start.mock_calls,
                             [call("prof-id")])


@skip("golang rewrite")
class TestProfileRules(BaseTestCase):
    def setUp(self):
        super(TestProfileRules, self).setUp()

        self.config = load_config("felix_default.cfg")

        self.m_mgr = Mock(spec=RulesManager)
        self.m_ipt_updater = Mock(spec=IptablesUpdater)
        self.m_ips_mgr = Mock(spec=IpsetManager)
        self.rules = ProfileRules(self.config.plugins["iptables_generator"],
                                  "prof1", 4, self.m_ipt_updater,
                                  self.m_ips_mgr)
        self.rules._manager = self.m_mgr
        self.rules._id = "prof1"

    def test_first_profile_update(self):
        """
        Test initial startup.

        Should acquire ipsets, program iptables and call back.
        """
        self.rules.on_profile_update(RULES_1, async=True)
        self.step_actor(self.rules)
        expected_tags = set(["src-tag", "dst-tag"])
        self.assertEqual(self.rules._ipset_refs.required_refs,
                         expected_tags)
        # Don't have all the ipsets yet.  should still be dirty.
        self.assertTrue(self.rules._dirty)
        # Simulate acquiring the ipsets.
        self._process_ipset_refs(expected_tags)
        # Got all the tags, should no longer be dirty.
        self.assertFalse(self.rules._dirty)
        self.m_ipt_updater.rewrite_chains.assert_called_once_with(
            RULES_1_CHAINS, {}, async=False)
        # Should have called back to the manager.
        self.m_mgr.on_object_startup_complete("prof1",
                                              self.rules,
                                              async=True)

    def test_coalesce_updates(self):
        """
        Test multiple updates in the same batch are squashed and only the
        last one has any effect.
        """
        self.rules.on_profile_update(RULES_1, async=True)
        self.rules.on_profile_update(RULES_2, async=True)
        self.rules.on_profile_update(RULES_1, async=True)
        self.step_actor(self.rules)
        expected_tags = set(["src-tag", "dst-tag"])
        self._process_ipset_refs(expected_tags)
        self.m_ipt_updater.rewrite_chains.assert_called_once_with(
            RULES_1_CHAINS, {}, async=False)
        # Should have called back to the manager.
        self.m_mgr.on_object_startup_complete("prof1",
                                              self.rules,
                                              async=True)

    def test_idempotent_update(self):
        """
        Test that an update that doesn't change the already-programmed
        value is squashed.
        """
        self.rules.on_profile_update(RULES_1, async=True)
        self.step_actor(self.rules)
        self._process_ipset_refs(set(["src-tag", "dst-tag"]))

        self.rules.on_profile_update(RULES_1, async=True)
        self.step_actor(self.rules)
        self._process_ipset_refs(set([]))

        self.m_ipt_updater.rewrite_chains.assert_called_once_with(
            RULES_1_CHAINS, {}, async=False)

    def test_idempotent_update_transient_ipt_error(self):
        """
        Test that the dirty flag is left set if the update fails.  Future
        updates that would normally be squashed trigger a reprogram.
        """
        # First update fails.
        self.m_ipt_updater.rewrite_chains.side_effect = \
            FailedSystemCall("fail", ["foo"], 1, "", "")
        self.rules.on_profile_update(RULES_1, async=True)
        self.step_actor(self.rules)
        self._process_ipset_refs(set(["src-tag", "dst-tag"])) # Steps actor.
        self.m_ipt_updater.rewrite_chains.assert_called_once_with(
            RULES_1_CHAINS, {}, async=False)
        # Failure should leave ProfileRules dirty.
        self.assertTrue(self.rules._dirty)

        # Second update should trigger retry.
        self.m_ipt_updater.reset_mock()
        self.m_ipt_updater.rewrite_chains.side_effect = None
        self.rules.on_profile_update(RULES_1, async=True)
        self.step_actor(self.rules)
        self._process_ipset_refs(set([]))
        self.m_ipt_updater.rewrite_chains.assert_called_once_with(
            RULES_1_CHAINS, {}, async=False)
        # Success clears dirty flag.
        self.assertFalse(self.rules._dirty)

    def test_delete_transient_ipt_error(self):
        """
        Test that the dirty flag is left set if a delete fails.  Future
        deletes that would normally be squashed trigger a retry.
        """
        # First delete fails.
        self.rules.on_profile_update(RULES_1, async=True)
        self.step_actor(self.rules)
        self._process_ipset_refs(set(["dst-tag", "src-tag"]))
        self.m_ipt_updater.delete_chains.side_effect = \
            FailedSystemCall("fail", ["foo"], 1, "", "")
        self.rules.on_profile_update(None, async=True)
        real_discard_all = self.rules._ipset_refs.discard_all
        with patch.object(self.rules._ipset_refs, "discard_all",
                          wraps=real_discard_all) as m_discard:
            self.step_actor(self.rules)
        # Failure should prevent freeing of ipset refs.
        self.assertEqual(m_discard.mock_calls, [])
        self._process_ipset_refs(set([]))
        self.m_ipt_updater.delete_chains.assert_called_once_with(
            set(RULES_1_CHAINS.keys()), async=False)
        # Failure should leave ProfileRules dirty.
        self.assertTrue(self.rules._dirty)

        # Update should trigger retry even though there was no change
        # of data.
        self.m_ipt_updater.reset_mock()
        self.m_ipt_updater.delete_chains.side_effect = None
        self.rules.on_profile_update(None, async=True)
        with patch.object(self.rules._ipset_refs, "discard_all",
                          wraps=real_discard_all) as m_discard:
            self.step_actor(self.rules)
        self.assertEqual(m_discard.mock_calls, [call()])
        self._process_ipset_refs(set([]))
        self.m_ipt_updater.delete_chains.assert_called_once_with(
            set(RULES_1_CHAINS.keys()), async=False)
        # Successful delete leaves profile clean.
        self.assertFalse(self.rules._dirty)

    def test_update(self):
        """
        Test a update changes ipset refs and iptables.
        """
        self.rules.on_profile_update(RULES_1, async=True)
        self.step_actor(self.rules)
        self.rules.on_profile_update(RULES_2, async=True)
        self.step_actor(self.rules)
        # New tag should be added but old tag shouldn't be removed until
        # iptables updated.
        expected_tags = set(["src-tag", "src-tag-added", "dst-tag",
                             SELECTOR_1])
        self.assertEqual(self.rules._ipset_refs.required_refs,
                         expected_tags)
        # But the ref helper will already have sent an incref for "src-tag".
        self._process_ipset_refs(expected_tags | set(["src-tag"]))
        self.m_ipt_updater.rewrite_chains.assert_called_once_with(
            RULES_2_CHAINS, {}, async=False)
        # Processing the ipset refs triggers iptables update, which triggers
        # tag to be freed.
        expected_tags = set(["src-tag-added", "dst-tag", SELECTOR_1])
        self.assertEqual(self.rules._ipset_refs.required_refs,
                         expected_tags)

    def test_early_unreferenced(self):
        """
        Test shutdown with tag references in flight.
        """
        ref_helper = self.rules._ipset_refs
        self.rules.on_profile_update(RULES_1, async=True)
        self.rules.on_unreferenced(async=True)
        self.step_actor(self.rules)
        self.assertTrue(self.rules._ipset_refs is None)
        self.assertEqual(ref_helper.required_refs, set())
        # Early on_unreferenced should have prevented any ipset requests.
        self._process_ipset_refs(set([]))
        self.assertFalse(self.m_ips_mgr.decref.called)
        self.assertTrue(self.rules._dead)
        self.m_ipt_updater.delete_chains.assert_called_once_with(
            set(['felix-p-prof1-i', 'felix-p-prof1-o']), async=False
        )
        # Further calls should be ignored
        self.m_ipt_updater.reset_mock()
        self.rules.on_unreferenced(async=True)
        self.step_actor(self.rules)
        self.assertFalse(self.m_ipt_updater.delete_chains.called)

    def test_unreferenced_after_creation(self):
        """
        Test shutdown after completing initial programming.
        """
        ref_helper = self.rules._ipset_refs
        self.rules.on_profile_update(RULES_1, async=True)
        self.step_actor(self.rules)
        # Tag updates come in before unreferenced.
        self._process_ipset_refs(set(["src-tag", "dst-tag"]))

        # Then simulate a deletion.
        self.rules.on_unreferenced(async=True)
        self.step_actor(self.rules)

        self.assertTrue(self.rules._ipset_refs is None)
        self.assertEqual(ref_helper.required_refs, set())
        self.assertTrue(self.rules._dead)
        self.m_ips_mgr.decref.assert_has_calls(
            [call("src-tag", async=True), call("dst-tag", async=True)],
            any_order=True
        )
        self.m_ipt_updater.delete_chains.assert_called_once_with(
            set(['felix-p-prof1-i', 'felix-p-prof1-o']), async=False
        )

    def test_immediate_deletion(self):
        """
        Test deletion before even doing first programming.
        """
        ref_helper = self.rules._ipset_refs
        self.rules.on_profile_update(None, async=True)
        self.rules.on_unreferenced(async=True)
        self.step_actor(self.rules)
        self.assertTrue(self.rules._ipset_refs is None)
        self.assertEqual(ref_helper.required_refs, set())
        # Should never have acquired any refs.
        self._process_ipset_refs(set())
        self.assertTrue(self.rules._dead)
        self.m_ipt_updater.delete_chains.assert_called_once_with(
            set(['felix-p-prof1-i', 'felix-p-prof1-o']), async=False
        )

    def test_update_chains_no_pending(self):
        """
        _update_chains requires _pending_profile not to be None.
        """
        with self.assertRaisesRegexp(AssertionError,
                                     "called with no _pending_profile"):
            self.rules._update_chains()

    def _process_ipset_refs(self, expected_tags):
        """
        Issues callbacks for all the mock calls to the mock ipset manager's
        get_and_incref.

        Steps the actor as a side-effect.

        Asserts the set of tags that were requested.
        """
        seen_tags = set()
        for name, args, kwargs in self.m_ips_mgr.get_and_incref.mock_calls:
            obj_id = args[0]
            callback = kwargs["callback"]
            seen_tags.add(obj_id)
            m_ipset = Mock(spec=RefCountedIpsetActor)
            if obj_id == SELECTOR_1:
                m_ipset.ipset_name = "selector-1-name"
            else:
                m_ipset.ipset_name = obj_id + "-name"
            callback(obj_id, m_ipset)
            self.step_actor(self.rules)
        self.m_ips_mgr.get_and_incref.reset_mock()
        self.assertEqual(seen_tags, expected_tags)
