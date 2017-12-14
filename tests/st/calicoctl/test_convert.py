# Copyright (c) 2015-2017 Tigera, Inc. All rights reserved.
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
import logging
import copy

from nose_parameterized import parameterized

from tests.st.test_base import TestBase
from tests.st.utils.utils import calicoctl
from tests.st.utils.data import *

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

filebase = "test-data/v1/"

class TestCalicoctlConvert(TestBase):
    """
    Test calicoctl pool
    1) Test the CRUD aspects of the pool commands.
    2) Test IP assignment from pool.
    BGP exported routes are hard to test and aren't expected to change much so
    write tests for them (yet)
    """

    @parameterized.expand([
        ("bgppeer-global.yaml",),
        ("bgppeer-node.yaml",),
        ("bgppeer-node2.yaml",),
        ("multi-resource.yaml",),
        ("node.yaml",),
        ("test3.yaml",),
        ("migration/bgppeer.yaml",),
        ("migration/hostendpoint.yaml",),
        ("migration/ippool.yaml",),
        ("migration/node.yaml",),
        ("migration/policy.yaml",),
        ("migration/profile.yaml",),
        ("migration/workloadendpoint.yaml",),
    ])
    def test_convert_successful(self, filename):
        """
        Test convert successfully
        """
        # Convert the file
        rc = calicoctl("convert -f %s" % filebase+filename)
        rc.assert_no_error()

        # With the converted data to a temp file
        with open("/tmp/converted", 'w') as f:
            f.write(rc.output)

        # Load the converted data
        rc = calicoctl("apply -f /tmp/converted")
        rc.assert_no_error()
