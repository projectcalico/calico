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

from tests.st.test_base import TestBase
from tests.st.utils.utils import calicoctl

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
        rc.assert_error(text="Invalid option: 'calicoctl -m'.")
        # no --unknown-flag flag
        rc = calicoctl("--unknown-flag")
        rc.assert_error(text="Invalid option: 'calicoctl --unknown-flag'.")

