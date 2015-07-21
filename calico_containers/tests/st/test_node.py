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
from unittest import skip

from test_base import TestBase

"""
Test calicoctl node command.

This command gets tested as part of the "mainline" tests. This file is for
testing the alternative ways of invoking it which aren't tested in the
mainline tests.

"""


class TestNode(TestBase):
    @skip("Not written yet")
    def test_autodetect_ip(self):
        """
        Test that the IP can be automatically detected.
        """
        pass
        # TODO define this test.

    @skip("Not written yet")
    def test_image(self):
        """
        Test custom node images.
        """
        pass
        # TODO define this test. Or just UT it?

    @skip("Not written yet")
    def test_force_stop(self):
        """
        Test that the node can be --force stopped.
        """
        pass
        # TODO - write the test.
