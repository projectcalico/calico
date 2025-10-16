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
        rc = calicoctl("optimize", data=ippool_name2_rev1_v6, load_as_stdin=True)
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
        path = "tests/st/manifests/optimize-multidoc.yaml"
        rc = calicoctl("optimize -f %s" % path)
        rc.assert_no_error()
        expected = [ippool_name1_rev1_v4, ippool_name2_rev1_v6]
        rc.assert_data(expected, format="yaml")

    def test_optimize_split_on_selectors(self):
        # Optimize multiple resources provided as multi-document YAML; expect a YAML array back.
        path = "tests/st/manifests/optimize-gnp-split.yaml"
        rc = calicoctl("optimize -f %s" % path)
        rc.assert_no_error()

        expected = [
            # 0th rule had destination selector 'app == "a"', which should be removed.
            {
                "apiVersion": "projectcalico.org/v3",
                "kind": "GlobalNetworkPolicy",
                "metadata": {
                    "name": "gnp-split-i-0",
                },
                "spec": {
                    "selector": '(has(bar) && app == "a")',
                    "namespaceSelector": 'name == "foo"',
                    "ingress": [
                        {
                            "action": "Allow",
                            "source": {"selector": 'app == "a"'},
                            "destination": {"ports": [80, 443]},
                            "protocol": "TCP",
                            "metadata": {"annotations": {"idx": "0"}},
                        }
                    ],
                    "types": ["Ingress"],
                },
            },
            # 1st and 2nd rules had destination selector 'app == "b"', which should be removed.
            {
                "apiVersion": "projectcalico.org/v3",
                "kind": "GlobalNetworkPolicy",
                "metadata": {
                    "name": "gnp-split-i-1",
                },
                "spec": {
                    "selector": '(has(bar) && app == "b")',
                    "namespaceSelector": 'name == "foo"',
                    "ingress": [
                        {
                            "action": "Allow",
                            "source": {"selector": 'app == "a"'},
                            "metadata": {"annotations": {"idx": "1"}},
                        },
                        {
                            "action": "Allow",
                            "metadata": {"annotations": {"idx": "2"}},
                        },
                    ],
                    "types": ["Ingress"],
                },
            },
            # 3rd-7th, 9th rules had namespaceSelector name == 'foo'.  Only 3rd rule
            # remains after unreachable rule elimination.
            {
                "apiVersion": "projectcalico.org/v3",
                "kind": "GlobalNetworkPolicy",
                "metadata": {
                    "name": "gnp-split-i-2",
                },
                "spec": {
                    "selector": 'has(bar)',
                    "namespaceSelector": 'name == "foo"',
                    "ingress": [
                        {
                            "action": "Allow",
                            "metadata": {"annotations": {"idx": "3"}},
                        }
                    ],
                    "types": ["Ingress"],
                },
            },
            # 8th rule had a different selector, so remains unchanged.
            {
                "apiVersion": "projectcalico.org/v3",
                "kind": "GlobalNetworkPolicy",
                "metadata": {
                    "name": "gnp-split-i-3",
                },
                "spec": {
                    "selector": '(has(bar) && app == "jazz")',
                    "namespaceSelector": 'name == "foo"',
                    "ingress": [
                        {
                            "action": "Allow",
                            "metadata": {"annotations": {"idx": "8"}},
                        }
                    ],
                    "types": ["Ingress"],
                },
            },
            # Egress rules pass through.
            {
                "apiVersion": "projectcalico.org/v3",
                "kind": "GlobalNetworkPolicy",
                "metadata": {
                    "name": "gnp-split-e",
                },
                "spec": {
                    "selector": 'has(bar)',
                    "namespaceSelector": 'name == "foo"',
                    "egress": [
                        {
                            "action": "Allow",
                            "destination": {"selector": 'app == "a"'},
                            "metadata": {"annotations": {"idx": "0"}},
                        }
                    ],
                    "types": ["Egress"],
                },
            },
        ]
        rc.assert_data(expected, format="yaml")

