# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
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

import logging

from calicotest.openstack.topology import Topology

_log = logging.getLogger(__name__)


class TestTestFailures(Topology):
    """
    Sample tests that immediately fail to test CI failure processing.
    """

    def test_fail(self):
        """
        Fail immediately.
        """
        raise Exception("This test has failed")

    def test_fail2(self):
        """
        Fail immediately.
        """
        raise Exception("This test has failed")


TestTestFailures.fv_test = False


class TestSetupClassFailures(Topology):
    @classmethod
    def setUpClass(cls):
        super(TestSetupClassFailures, cls).setUpClass()
        raise Exception("BOOM!")

    def test_unreachable(self):
        pass


TestSetupClassFailures.fv_test = False


class TestSetupFailures(Topology):
    def setUp(self):
        super(TestSetupFailures, self).setUp()
        raise Exception("BOOM!")

    def test_unreachable(self):
        pass


TestSetupFailures.fv_test = False
