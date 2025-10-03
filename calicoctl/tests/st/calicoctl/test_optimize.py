# Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

from tests.st.test_base import TestBase
from tests.st.utils.utils import calicoctl
from tests.st.utils.data import (
    ippool_name1_rev1_v4,
    ippool_name2_rev1_v6,
)

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)


class TestCalicoctlOptimize(TestBase):
    """
    Test calicoctl optimize (no-op transformation) behavior.
    We intentionally use IPPool (not GlobalNetworkPolicy) to validate pass-through.
    """

    def setUp(self):
        super(TestCalicoctlOptimize, self).setUp()

    def test_optimize_single_resource_yaml(self):
        # Optimize a single resource provided via file.
        rc = calicoctl("optimize", data=ippool_name1_rev1_v4)
        rc.assert_no_error()
        rc.assert_data(ippool_name1_rev1_v4, format="yaml")

    def test_optimize_single_resource_stdin(self):
        # Optimize a single resource provided via stdin.
        rc = calicoctl("optimize -f -", data=ippool_name2_rev1_v6, load_as_stdin=True)
        rc.assert_no_error()
        rc.assert_data(ippool_name2_rev1_v6, format="yaml")

    def test_optimize_list_yaml_array(self):
        # Optimize multiple resources provided as a YAML array; expect a YAML array back.
        resources = [ippool_name1_rev1_v4, ippool_name2_rev1_v6]
        rc = calicoctl("optimize", data=resources)
        rc.assert_no_error()
        rc.assert_data(resources, format="yaml")

    def test_optimize_multi_doc_file(self):
        # Optimize multiple resources provided as multi-document YAML; expect a YAML array back.
        path = "/code/calicoctl/tests/st/manifests/optimize-multidoc.yaml"
        rc = calicoctl("optimize -f %s" % path)
        rc.assert_no_error()
        expected = [ippool_name1_rev1_v4, ippool_name2_rev1_v6]
        rc.assert_data(expected, format="yaml")

