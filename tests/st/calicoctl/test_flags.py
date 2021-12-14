# Copyright (c) 2015-2019 Tigera, Inc. All rights reserved.
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

import re
from tests.st.test_base import TestBase
from tests.st.utils.data import node_name1_rev1
from tests.st.utils.utils import calicoctl, name, set_cluster_version

class TestCalicoctlCLIFlags(TestBase):
    """
    Test calicoctl command-line flags
    """

    def test_usage(self):
        """
        Test usage successfully
        """
        rc = calicoctl("-h")
        rc.assert_no_error()

    def test_bad_flags(self):
        """
        Test bad flags unsuccessfully
        """
        # no -m flag
        rc = calicoctl("-m")
        rc.assert_error(text="Invalid option: '--allow-version-mismatch -m'.")
        # no --unknown-flag flag
        rc = calicoctl("--unknown-flag")
        rc.assert_error(text="Invalid option: '--allow-version-mismatch --unknown-flag'.")

    def test_version_mismatch(self):
        """
        Test version mismatch verification
        """
        # Create a Node, this should also trigger auto-creation of a cluster info,
        # but without any CalicoVersion field.
        rc = calicoctl("create", data=node_name1_rev1)
        rc.assert_no_error()

        # The "datastore migrate import" command bypasses version mismatch checking
        rc = calicoctl("datastore migrate import -f a", allowVersionMismatch=False)
        # Assert that the error is not "version mismatch"
        rc.assert_error("Invalid datastore type")

        # CalicoVersion is unset in the cluster, expect no error
        rc = calicoctl("replace", data=node_name1_rev1, allowVersionMismatch=False)
        rc.assert_no_error()

        # Set the correct CalicoVersion in the cluster
        output = set_cluster_version()
        output.assert_no_error()

        # CalicoVersion is correct in the cluster, expect no error
        rc = calicoctl("replace", data=node_name1_rev1, allowVersionMismatch=False)
        output.assert_no_error()

        # Set an incorrect CalicoVersion in the cluster
        output = set_cluster_version("v0.0.0.1.2.3")
        output.assert_no_error()

        # CalicoVersion is incorrect in the cluster, expect error
        rc = calicoctl("replace", data=node_name1_rev1, allowVersionMismatch=False)
        rc.assert_error("Version mismatch.")
