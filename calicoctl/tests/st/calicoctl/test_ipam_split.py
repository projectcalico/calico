# Copyright (c) 2022 Tigera, Inc. All rights reserved.
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
import copy
import os

from nose_parameterized import parameterized

from tests.st.test_base import TestBase
from tests.st.utils.utils import log_and_run, calicoctl, \
    API_VERSION, name, namespace, ERROR_CONFLICT, NOT_FOUND, NOT_NAMESPACED, \
    SET_DEFAULT, NOT_SUPPORTED, KUBERNETES_NP, NOT_LOCKED_SPLIT, \
    POOL_NOT_EXIST_CIDR, INVALID_SPLIT_NUM, POOL_TOO_SMALL, \
    NOT_KUBERNETES, NO_IPAM, writeyaml
from tests.st.utils.data import *

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

class TestCalicoctlIPAMSplit(TestBase):
    """
    Test splitting IPAM pools works
    1) Test splitting an ippool 10.0.1.0/24 into 4 ippools:
       10.0.1.128/26, 10.0.1.64/26, 10.0.1.0/26, and 10.0.1.192/26.
    """

    def test_ipam_split_by_cidr(self):
        """
        Test that splitting IP pools works properly by CIDR
        """

        # Create the ipv4 pool using calicoctl, and read it out using an
        # exact get and a list query.
        rc = calicoctl("create", data=ippool_name1_rev1_v4)
        rc.assert_no_error()
        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_v4))
        rc.assert_data(ippool_name1_rev1_v4)
        rc = calicoctl("get ippool -o yaml")
        rc.assert_list("IPPool", [ippool_name1_rev1_v4])

        # Create a Node, this should also trigger auto-creation of a cluster info
        rc = calicoctl("create", data=node_name4_rev1)
        rc.assert_no_error()
        rc = calicoctl("get node %s -o yaml" % name(node_name4_rev1))
        rc.assert_data(node_name4_rev1)
        rc = calicoctl("get clusterinfo %s -o yaml" % name(clusterinfo_name1_rev1))
        rc.assert_no_error()

        # Attempt to split the IP pool before locking the datastore
        rc = calicoctl("ipam split --cidr=10.0.1.0/24 4")
        rc.assert_error(text=NOT_LOCKED_SPLIT)

        # Lock the data
        rc = calicoctl("datastore migrate lock")
        rc.assert_no_error()

        # Attempt to split a non-existent IP pool
        rc = calicoctl("ipam split --cidr=10.0.2.0/24 4")
        rc.assert_error(text=POOL_NOT_EXIST_CIDR)

        # Attempt to split an IP pool into an invalid number of child pools
        rc = calicoctl("ipam split --cidr=10.0.1.0/24 3")
        rc.assert_error(text=INVALID_SPLIT_NUM)

        # Attempt to split an IP pool into more pools than possible given the size
        rc = calicoctl("ipam split --cidr=10.0.1.0/24 512")
        rc.assert_error(text=POOL_TOO_SMALL)

        # Split the IP pool
        rc = calicoctl("ipam split --cidr=10.0.1.0/24 4")
        rc.assert_no_error()

        # Check that the original IP pool no longer exists
        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_v4))
        rc.assert_error(text=NOT_FOUND)

        # Check that the split IP pools exist
        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_split1_v4))
        rc.assert_no_error()
        rc.assert_data(ippool_name1_rev1_split1_v4)

        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_split2_v4))
        rc.assert_no_error()
        rc.assert_data(ippool_name1_rev1_split2_v4)

        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_split3_v4))
        rc.assert_no_error()
        rc.assert_data(ippool_name1_rev1_split3_v4)

        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_split4_v4))
        rc.assert_no_error()
        rc.assert_data(ippool_name1_rev1_split4_v4)

        # Unlock the datastore
        rc = calicoctl("datastore migrate unlock")
        rc.assert_no_error()

        # Clean up
        rc = calicoctl("delete ippool %s" % name(ippool_name1_rev1_split1_v4))
        rc.assert_no_error()
        rc = calicoctl("delete ippool %s" % name(ippool_name1_rev1_split2_v4))
        rc.assert_no_error()
        rc = calicoctl("delete ippool %s" % name(ippool_name1_rev1_split3_v4))
        rc.assert_no_error()
        rc = calicoctl("delete ippool %s" % name(ippool_name1_rev1_split4_v4))
        rc.assert_no_error()
        rc = calicoctl("delete node %s" % name(node_name4_rev1))
        rc.assert_no_error()

    def test_ipam_split_by_name(self):
        """
        Test that splitting IP pools works properly by IP pool name
        """

        # Create the ipv4 pool using calicoctl, and read it out using an
        # exact get and a list query.
        rc = calicoctl("create", data=ippool_name1_rev1_v4)
        rc.assert_no_error()
        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_v4))
        rc.assert_data(ippool_name1_rev1_v4)
        rc = calicoctl("get ippool -o yaml")
        rc.assert_list("IPPool", [ippool_name1_rev1_v4])

        # Create a Node, this should also trigger auto-creation of a cluster info
        rc = calicoctl("create", data=node_name4_rev1)
        rc.assert_no_error()
        rc = calicoctl("get node %s -o yaml" % name(node_name4_rev1))
        rc.assert_data(node_name4_rev1)
        rc = calicoctl("get clusterinfo %s -o yaml" % name(clusterinfo_name1_rev1))
        rc.assert_no_error()

        # Attempt to split the IP pool before locking the datastore
        rc = calicoctl("ipam split --name=%s 4" % name(ippool_name1_rev1_v4))
        rc.assert_error(text=NOT_LOCKED_SPLIT)

        # Lock the data
        rc = calicoctl("datastore migrate lock")
        rc.assert_no_error()

        # Attempt to split a non-existent IP pool
        rc = calicoctl("ipam split --name=%s 4" % name(ippool_name2_rev1_v6))
        rc.assert_error(text=POOL_NOT_EXIST_CIDR)

        # Attempt to split an IP pool into an invalid number of child pools
        rc = calicoctl("ipam split --name=%s 3" % name(ippool_name1_rev1_v4))
        rc.assert_error(text=INVALID_SPLIT_NUM)

        # Attempt to split an IP pool into more pools than possible given the size
        rc = calicoctl("ipam split --name=%s 512" % name(ippool_name1_rev1_v4))
        rc.assert_error(text=POOL_TOO_SMALL)

        # Split the IP pool
        rc = calicoctl("ipam split --name=%s 4" % name(ippool_name1_rev1_v4))
        rc.assert_no_error()

        # Check that the original IP pool no longer exists
        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_v4))
        rc.assert_error(text=NOT_FOUND)

        # Check that the split IP pools exist
        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_split1_v4))
        rc.assert_no_error()
        rc.assert_data(ippool_name1_rev1_split1_v4)

        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_split2_v4))
        rc.assert_no_error()
        rc.assert_data(ippool_name1_rev1_split2_v4)

        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_split3_v4))
        rc.assert_no_error()
        rc.assert_data(ippool_name1_rev1_split3_v4)

        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_split4_v4))
        rc.assert_no_error()
        rc.assert_data(ippool_name1_rev1_split4_v4)

        # Unlock the datastore
        rc = calicoctl("datastore migrate unlock")
        rc.assert_no_error()

        # Clean up
        rc = calicoctl("delete ippool %s" % name(ippool_name1_rev1_split1_v4))
        rc.assert_no_error()
        rc = calicoctl("delete ippool %s" % name(ippool_name1_rev1_split2_v4))
        rc.assert_no_error()
        rc = calicoctl("delete ippool %s" % name(ippool_name1_rev1_split3_v4))
        rc.assert_no_error()
        rc = calicoctl("delete ippool %s" % name(ippool_name1_rev1_split4_v4))
        rc.assert_no_error()
        rc = calicoctl("delete node %s" % name(node_name4_rev1))
        rc.assert_no_error()
