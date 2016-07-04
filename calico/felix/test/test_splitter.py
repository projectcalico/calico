# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
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
felix.test.test_splitter
~~~~~~~~~~~~~~~~~~~~~~~~

Tests of the actor that splits update messages to multiple manager actors.
"""
import inspect
import logging

import mock

from calico.felix.test.base import BaseTestCase, load_config
from calico.felix.splitter import UpdateSplitter, CleanupManager

_log = logging.getLogger(__name__)


class TestUpdateSplitter(BaseTestCase):
    """
    Tests for the UpdateSplitter class.
    """
    def setUp(self):
        super(TestUpdateSplitter, self).setUp()
        # Inspect the update splitter to find all its on_... methods then
        # construct a dummy manager class with a matching method for each one.
        self.mgrs_by_method = {}
        mgrs = []
        for attr_name in UpdateSplitter.__dict__:
            if attr_name.startswith("on_"):
                class Mgr(object):
                    locals()[attr_name] = mock.Mock()
                mgr = Mgr()
                self.mgrs_by_method[attr_name] = mgr
                mgrs.append(mgr)
        self.splitter = UpdateSplitter(mgrs)

    def test_pass_through(self):
        """
        Test that the update splitter fans out requests to the correct methods.
        """
        for meth_name, mgr in self.mgrs_by_method.iteritems():
            _log.info("Checking that method %s is passed through to relevant"
                      "managers", meth_name)
            # Extract the splitter's copy of the method and generate some
            # plausible arguments.
            meth = getattr(self.splitter, meth_name)
            arg_spec = inspect.getargspec(meth)
            m_args = [mock.Mock() for _ in arg_spec.args[:-1]]
            # Call the method, we expect it to pass through its arguments to
            # the mock manager.
            meth(*m_args)
            try:
                m_mgr_meth = getattr(mgr, meth_name)
            except:
                raise AttributeError(dir(mgr))
            try:
                # Method should be passed though with additional async=True
                # flag.
                self.assertEqual(m_mgr_meth.mock_calls,
                                 [mock.call(*m_args, async=True)])
            except:
                _log.exception("Failure while checking pass-through of %s",
                               meth_name)
                raise


class TestCleanupManager(BaseTestCase):
    def setUp(self):
        super(TestCleanupManager, self).setUp()

        self.config = load_config("felix_default.cfg",
                                  host_dict={"StartupCleanupDelay": 12})

        # We need to check the order between the iptables and ipsets cleanup
        # calls so make sure they have a common root mock.
        self.m_root_mock = mock.Mock()
        self.m_ipt_updr = self.m_root_mock.m_ipt_updr
        self.m_ips_mgr = self.m_root_mock.m_ips_mgr

        self.mgr = CleanupManager(self.config,
                                  [self.m_ipt_updr],
                                  [self.m_ips_mgr])

    def test_on_datamodel_in_sync(self):
        with mock.patch("gevent.spawn_later", autospec=True) as m_spawn_later:
            self.mgr.on_datamodel_in_sync(async=True)
            self.step_actor(self.mgr)
        self.assertTrue(self.mgr._cleanup_done)
        # Check we got only the expected call to spawn.
        self.assertEqual(m_spawn_later.mock_calls, [mock.call(12, mock.ANY)])
        # Grab the callable.
        do_cleanup = m_spawn_later.call_args[0][1]
        self.assertTrue(callable(do_cleanup))
        # Check it really invokes the cleanup.
        do_cleanup()
        self.step_actor(self.mgr)
        self.assertEqual(
            self.m_root_mock.mock_calls,
            [
                # iptables call should come first.
                mock.call.m_ipt_updr.cleanup(async=False),
                mock.call.m_ips_mgr.cleanup(async=False),
            ]
        )
        # Finally, check that subsequent in-sync calls are ignored.
        with mock.patch("gevent.spawn_later", autospec=True) as m_spawn_later:
            self.mgr.on_datamodel_in_sync(async=True)
            self.step_actor(self.mgr)
        self.assertEqual(m_spawn_later.mock_calls, [])

    def test_cleanup_failure(self):
        self.m_ips_mgr.cleanup.side_effect = RuntimeError
        with mock.patch("os._exit") as m_exit:
            result = self.mgr._do_cleanup(async=True)
            self.step_actor(self.mgr)
        self.assertEqual(m_exit.mock_calls, [mock.call(1)])
        self.assertRaises(RuntimeError, result.get)
