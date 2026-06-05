# Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

from tests.k8st.test_base import TestBase
from tests.k8st.utils.utils import run_go_test

# The proxy ARP/NDP verification lives in a standalone Go test binary
# (node/tests/k8st/proxyneigh), built by `make -C node build-k8st-go-tests` into
# tests/k8st/bin/proxyneigh.test. We invoke it from here rather than
# reimplementing the L2 probing in Python: the test needs direct access to the
# local docker daemon to attach an L2-adjacent peer to the kind network


class TestProxyNeigh(TestBase):

    def test_proxy_neigh(self):
        run_go_test("proxyneigh.test")
