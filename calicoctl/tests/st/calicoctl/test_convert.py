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
import os

from nose_parameterized import parameterized

from tests.st.test_base import TestBase
from tests.st.utils.utils import calicoctl
from tests.st.utils.data import *

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

# TODO: applySuccess param relates to 'calicoctl apply' not working correctly
# with a resource of "Kind: List". Once that is fixed, we should be able to
# remove this arg (and consistently check for 'calicoctl apply' success).
convert_files = [
        ("test-data/convert/input/v1/bgppeer-global.yaml", True,),
        ("test-data/convert/input/v1/bgppeer-node.yaml", True,),
        ("test-data/convert/input/v1/bgppeer-node2.yaml", True,),
        ("test-data/convert/input/v1/multi-resource.yaml", False,),
        ("test-data/convert/input/v1/node.yaml", False,),
        ("test-data/convert/input/v1/test3.yaml", True,),
        ("test-data/convert/input/v1/migration/bgppeer.yaml", True,),
        ("test-data/convert/input/v1/migration/hostendpoint.yaml", True,),
        ("test-data/convert/input/v1/migration/ippool.yaml", True,),
        ("test-data/convert/input/v1/migration/node.yaml", True,),
        ("test-data/convert/input/v1/migration/policy.yaml", False,),
        ("test-data/convert/input/v1/migration/profile.yaml", True,),
        ("test-data/convert/input/v1/migration/workloadendpoint.yaml", True,),
        ("test-data/convert/input/k8s/k8s-networkpolicy.yaml", True,),
        ("test-data/convert/input/k8s/k8s-networkpolicy-invalid.yaml", True,),
        ("test-data/convert/input/k8s/k8s-networkpolicy-multiple.yaml", False,),
        ("test-data/convert/input/k8s/k8s-networkpolicy-multiple-list.yaml", False,),
        ("test-data/convert/input/k8s/k8s-networkpolicy-multiple-invalid.yaml", False,),
    ]

class TestCalicoctlConvert(TestBase):
    """
    Test calicoctl convert
    """

    def _test_convert(self, filename, applySuccess, format="yaml"):
        """
        Test convert successfully
        """
        # Convert the file
        rc = calicoctl("convert -o %s -f %s" % (format, filename))

        # Get expected conversion output filename (file in output/ dir with
        # yaml or json extension)
        output_filename = (filename.replace("input", "output").split(".")[0]
                           + "." + format)

        # If expected conversion output exists then assert that the
        # conversion is successful, otherwise assert an error occurs
        if os.path.isfile(output_filename):
            rc.assert_no_error()
            with open(output_filename, 'r') as f:
                expected_output = f.read().rstrip()
                self.assertEqual(rc.output, expected_output)

            # With the converted data to a temp file
            with open("/tmp/converted", 'w') as f:
                f.write(rc.output)

            # Load the converted data
            rc = calicoctl("apply -f /tmp/converted")
            if applySuccess:
                rc.assert_no_error()
            else:
                rc.assert_error()
        else:
            rc.assert_error()

    @parameterized.expand(convert_files)
    def test_convert_yaml(self, filename, applySuccess):
        """
        Test convert with yaml output.
        """
        self._test_convert(filename, applySuccess, format="yaml")

    @parameterized.expand(convert_files)
    def test_convert_json(self, filename, applySuccess):
        """
        Test convert with json output.
        """
        self._test_convert(filename, applySuccess, format="json")
