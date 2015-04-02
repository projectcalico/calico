# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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
felix.test.test_endpoint
~~~~~~~~~~~~~~~~~~~~~~~~

Tests of endpoint module.
"""
import logging
import itertools
from contextlib import nested
from calico.felix.endpoint import EndpointManager
from calico.felix.fiptables import IptablesUpdater, DispatchChains
from calico.felix.profilerules import RulesManager
from gevent.event import AsyncResult

import mock
from mock import Mock, MagicMock, patch

from calico.felix.actor import actor_event, ResultOrExc, SplitBatchAndRetry
from calico.felix.test.base import BaseTestCase
from calico.felix import endpoint
from calico.felix import config

_log = logging.getLogger(__name__)


class TestEndpointManager(BaseTestCase):
    def setUp(self):
        super(TestEndpointManager, self).setUp()
        self.m_config = Mock(autospec=config.Config)
        self.m_ipt_upds = {
            4: Mock(autospec=IptablesUpdater),
            6: Mock(autospec=IptablesUpdater),
        }
        self.m_disp_chns = Mock(autospec=DispatchChains)
        self.m_rules_mgr = Mock(autospec=RulesManager)
        self.ep_mgr = EndpointManager(self.m_config, self.m_ipt_upds,
                                      self.m_disp_chns, self.m_rules_mgr)


