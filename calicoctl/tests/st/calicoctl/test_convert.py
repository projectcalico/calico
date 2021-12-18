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

convert_files = [
        ("test-data/v1/bgppeer-global.yaml",),
        ("test-data/v1/bgppeer-node.yaml",),
        ("test-data/v1/bgppeer-node2.yaml",),
        ("test-data/v1/multi-resource.yaml",),
        ("test-data/v1/node.yaml",),
        ("test-data/v1/test3.yaml",),
        ("test-data/v1/migration/bgppeer.yaml",),
        ("test-data/v1/migration/hostendpoint.yaml",),
        ("test-data/v1/migration/ippool.yaml",),
        ("test-data/v1/migration/node.yaml",),
        ("test-data/v1/migration/policy.yaml",),
        ("test-data/v1/migration/profile.yaml",),
        ("test-data/v1/migration/workloadendpoint.yaml",),
        ("test-data/k8s/k8s-networkpolicy.yaml",),
    ]

class TestCalicoctlConvert(TestBase):
    """
    Test calicoctl convert
    """

    def _test_convert_successful(self, filename, format="yaml"):
        """
        Test convert successfully
        """
        # Convert the file
        rc = calicoctl("convert -o %s -f %s" % (format, filename))
        rc.assert_no_error()

        # With the converted data to a temp file
        with open("/tmp/converted", 'w') as f:
            f.write(rc.output)

        # Load the converted data
        rc = calicoctl("apply -f /tmp/converted")
        rc.assert_no_error()

    @parameterized.expand(convert_files)
    def test_convert_successful_yaml(self, filename):
        """
        Test convert with yaml output.
        """
        self._test_convert_successful(filename, format="yaml")

    @parameterized.expand(convert_files)
    def test_convert_successful_json(self, filename):
        """
        Test convert with json output.
        """
        self._test_convert_successful(filename, format="json")
