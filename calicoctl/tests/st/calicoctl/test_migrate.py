# Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
    SET_DEFAULT, NOT_SUPPORTED, KUBERNETES_NP, NOT_LOCKED, \
    NOT_KUBERNETES, NO_IPAM, writeyaml
from tests.st.utils.data import *

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

class TestCalicoctlMigrate(TestBase):
    """
    Test calicoctl datastore migration works
    1) Test migration works for ippools and networkpolicies.
    """

    def test_datastore_migrate(self):
        """
        Test that migrating Calico resources works properly
        """

        # Create the ipv6 pool using calicoctl, and read it out using an
        # exact get and a list query.
        rc = calicoctl("create", data=ippool_name2_rev1_v6)
        rc.assert_no_error()
        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name2_rev1_v6))
        rc.assert_data(ippool_name2_rev1_v6)
        rc = calicoctl("get ippool -o yaml")
        rc.assert_list("IPPool", [ippool_name2_rev1_v6])

        # Create a BGP Config
        rc = calicoctl("create", data=bgpconfig_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl("get bgpconfig %s -o yaml" % name(bgpconfig_name1_rev1))
        rc.assert_data(bgpconfig_name1_rev1)
        rc = calicoctl("get bgpconfig -o yaml")
        rc.assert_list("BGPConfiguration", [bgpconfig_name1_rev1])

        # Create a BGP Config that should reference a node.
        # This node reference will change since the node's orchrefs reference a different node.
        rc = calicoctl("create", data=bgpconfig_name3_rev1)
        rc.assert_no_error()
        rc = calicoctl("get bgpconfig %s -o yaml" % name(bgpconfig_name3_rev1))
        rc.assert_data(bgpconfig_name3_rev1)
        rc = calicoctl("get bgpconfig -o yaml")
        rc.assert_list("BGPConfiguration", [bgpconfig_name1_rev1, bgpconfig_name3_rev1])

        # Create a BGP Peer
        rc = calicoctl("create", data=bgppeer_name1_rev1_v4)
        rc.assert_no_error()
        rc = calicoctl("get bgppeer %s -o yaml" % name(bgppeer_name1_rev1_v4))
        rc.assert_data(bgppeer_name1_rev1_v4)
        rc = calicoctl("get bgppeer -o yaml")
        rc.assert_list("BGPPeer", [bgppeer_name1_rev1_v4])

        # Create a Felix config
        rc = calicoctl("create", data=felixconfig_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl("get felixconfig %s -o yaml" % name(felixconfig_name1_rev1))
        rc.assert_no_error()

        # Create a Felix config that should reference a node.
        # This node reference will change since the node's orchrefs reference a different node.
        rc = calicoctl("create", data=felixconfig_name2_rev1)
        rc.assert_no_error()
        rc = calicoctl("get felixconfig %s -o yaml" % name(felixconfig_name2_rev1))
        rc.assert_no_error()

        # Create a Global Network policy
        rc = calicoctl("create", data=globalnetworkpolicy_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl("get globalnetworkpolicy %s -o yaml" % name(globalnetworkpolicy_name1_rev1))
        rc.assert_data(globalnetworkpolicy_name1_rev1)
        rc = calicoctl("get globalnetworkpolicy -o yaml")
        rc.assert_list("GlobalNetworkPolicy", [globalnetworkpolicy_name1_rev1])

        # Create a Global Network set
        rc = calicoctl("create", data=globalnetworkset_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl("get globalnetworkset %s -o yaml" % name(globalnetworkset_name1_rev1))
        rc.assert_data(globalnetworkset_name1_rev1)
        rc = calicoctl("get globalnetworkset -o yaml")
        rc.assert_list("GlobalNetworkSet", [globalnetworkset_name1_rev1])

        # Create a HostEndpoint
        rc = calicoctl("create", data=hostendpoint_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl("get hostendpoint %s -o yaml" % name(hostendpoint_name1_rev1))
        rc.assert_data(hostendpoint_name1_rev1)
        rc = calicoctl("get hostendpoint -o yaml")
        rc.assert_list("HostEndpoint", [hostendpoint_name1_rev1])

        # Create Network policy
        rc = calicoctl("create", data=networkpolicy_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl("get networkpolicy %s -o yaml" % name(networkpolicy_name1_rev1))
        rc.assert_data(networkpolicy_name1_rev1)
        rc.assert_no_error()

        # Create namespaced Network policy
        rc = calicoctl("create", data=networkpolicy_name3_rev1)
        rc.assert_no_error()
        rc = calicoctl("get networkpolicy %s -n %s -o yaml" % (name(networkpolicy_name3_rev1), namespace(networkpolicy_name3_rev1)))
        rc.assert_data(networkpolicy_name3_rev1)
        rc.assert_no_error()

        # Create NetworkSets
        rc = calicoctl("create", data=networkset_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl("get networkset %s -o yaml" % name(networkset_name1_rev1))
        rc.assert_no_error()

        # Create namespaced NetworkSet
        rc = calicoctl("create", data=networkset_name2_rev1)
        rc.assert_no_error()
        rc = calicoctl("get networkset %s -n %s -o yaml" % (name(networkset_name2_rev1), namespace(networkset_name2_rev1)))
        rc.assert_no_error()

        # Create a Node, this should also trigger auto-creation of a cluster info
        rc = calicoctl("create", data=node_name4_rev1)
        rc.assert_no_error()
        rc = calicoctl("get node %s -o yaml" % name(node_name4_rev1))
        rc.assert_data(node_name4_rev1)
        rc = calicoctl("get clusterinfo %s -o yaml" % name(clusterinfo_name1_rev1))
        rc.assert_no_error()

        # Create another Node, this node will not be imported because it does not
        # reference a real k8s node.
        rc = calicoctl("create", data=node_name5_rev1)
        rc.assert_no_error()
        rc = calicoctl("get node %s -o yaml" % name(node_name5_rev1))
        rc.assert_data(node_name5_rev1)

        # TODO: Pull code or modify tests to create IPAM objects for this test
        # since they cannot be created via calicoctl.

        # Export the data before locking the datastore
        rc = calicoctl("datastore migrate export > /tmp/test-migration")
        rc.assert_error(text=NOT_LOCKED)

        # Lock the data
        rc = calicoctl("datastore migrate lock")
        rc.assert_no_error()

        # Export the data after locking the datastore
        rc = calicoctl("datastore migrate export > /tmp/test-migration")
        rc.assert_no_error()

        # Delete the data
        rc = calicoctl("delete ippool %s" % name(ippool_name2_rev1_v6))
        rc.assert_no_error()
        rc = calicoctl("delete bgpconfig %s" % name(bgpconfig_name1_rev1))
        rc.assert_no_error()
        rc = calicoctl("delete bgpconfig %s" % name(bgpconfig_name3_rev1))
        rc.assert_no_error()
        rc = calicoctl("delete bgppeer %s" % name(bgppeer_name1_rev1_v4))
        rc.assert_no_error()
        rc = calicoctl("delete felixconfig %s" % name(felixconfig_name1_rev1))
        rc.assert_no_error()
        rc = calicoctl("delete felixconfig %s" % name(felixconfig_name2_rev1))
        rc.assert_no_error()
        rc = calicoctl("delete globalnetworkpolicy %s" % name(globalnetworkpolicy_name1_rev1))
        rc.assert_no_error()
        rc = calicoctl("delete globalnetworkset %s" % name(globalnetworkset_name1_rev1))
        rc.assert_no_error()
        rc = calicoctl("delete hostendpoint %s" % name(hostendpoint_name1_rev1))
        rc.assert_no_error()
        rc = calicoctl("delete networkpolicy %s" % name(networkpolicy_name1_rev1))
        rc.assert_no_error()
        rc = calicoctl("delete networkpolicy %s -n %s" % (name(networkpolicy_name3_rev1), namespace(networkpolicy_name3_rev1)))
        rc.assert_no_error()
        rc = calicoctl("delete networkset %s" % name(networkset_name1_rev1))
        rc.assert_no_error()
        rc = calicoctl("delete networkset %s -n %s" % (name(networkset_name2_rev1), namespace(networkset_name2_rev1)))
        rc.assert_no_error()
        rc = calicoctl("delete node %s" % name(node_name4_rev1))
        rc.assert_no_error()
        rc = calicoctl("delete node %s" % name(node_name5_rev1))
        rc.assert_no_error()

        # Attempt and fail to import the data into an etcd datastore
        rc = calicoctl("datastore migrate import -f /tmp/test-migration")
        rc.assert_error(text=NOT_KUBERNETES)

        # Import the data
        rc = calicoctl("datastore migrate import -f /tmp/test-migration", kdd=True)
        rc.assert_error(text=NO_IPAM)

        # Check that all the resources were imported properly
        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name2_rev1_v6), kdd=True)
        rc.assert_data(ippool_name2_rev1_v6)
        rc = calicoctl("get bgpconfig %s -o yaml" % name(bgpconfig_name1_rev1), kdd=True)
        rc.assert_data(bgpconfig_name1_rev1)
        # bgpconfig_name3_rev1 should be changed to bgpconfig_name4_rev1
        rc = calicoctl("get bgpconfig %s -o yaml" % name(bgpconfig_name3_rev1), kdd=True)
        rc.assert_error(text=NOT_FOUND)
        rc = calicoctl("get bgpconfig %s -o yaml" % name(bgpconfig_name4_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("get bgppeer %s -o yaml" % name(bgppeer_name1_rev1_v4), kdd=True)
        rc.assert_data(bgppeer_name1_rev1_v4)
        rc = calicoctl("get felixconfig %s -o yaml" % name(felixconfig_name1_rev1), kdd=True)
        rc.assert_no_error()
        # felixconfig_name2_rev1 should be changed to felixconfig_name3_rev1
        rc = calicoctl("get felixconfig %s -o yaml" % name(felixconfig_name2_rev1), kdd=True)
        rc.assert_error(text=NOT_FOUND)
        rc = calicoctl("get felixconfig %s -o yaml" % name(felixconfig_name3_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("get globalnetworkpolicy %s -o yaml" % name(globalnetworkpolicy_name1_rev1), kdd=True)
        rc.assert_data(globalnetworkpolicy_name1_rev1)
        rc = calicoctl("get globalnetworkset %s -o yaml" % name(globalnetworkset_name1_rev1), kdd=True)
        rc.assert_data(globalnetworkset_name1_rev1)
        rc = calicoctl("get hostendpoint %s -o yaml" % name(hostendpoint_name1_rev1), kdd=True)
        rc.assert_data(hostendpoint_name1_rev1)
        rc = calicoctl("get networkpolicy %s -o yaml" % name(networkpolicy_name1_rev1), kdd=True)
        rc.assert_data(networkpolicy_name1_rev1)
        rc = calicoctl("get networkpolicy %s -n %s -o yaml" % (name(networkpolicy_name3_rev1), namespace(networkpolicy_name3_rev1)), kdd=True)
        rc.assert_data(networkpolicy_name3_rev1)
        rc = calicoctl("get networkset %s -o yaml" % name(networkset_name1_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("get networkset %s -n %s -o yaml" % (name(networkset_name2_rev1), namespace(networkset_name2_rev1)), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("get node %s -o yaml" % name(node_name4_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("get node %s -o yaml" % name(node_name5_rev1), kdd=True)
        rc.assert_error(text=NOT_FOUND)
        rc = calicoctl("get clusterinfo %s -o yaml" % name(clusterinfo_name1_rev1), kdd=True)
        rc.assert_no_error()

        # Unlock the datastore
        rc = calicoctl("datastore migrate unlock", kdd=True)
        rc.assert_no_error()

        # Clean up
        rc = calicoctl("delete ippool %s" % name(ippool_name2_rev1_v6), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete bgpconfig %s" % name(bgpconfig_name1_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete bgpconfig %s" % name(bgpconfig_name4_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete bgppeer %s" % name(bgppeer_name1_rev1_v4), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete felixconfig %s" % name(felixconfig_name1_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete felixconfig %s" % name(felixconfig_name3_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete globalnetworkpolicy %s" % name(globalnetworkpolicy_name1_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete globalnetworkset %s" % name(globalnetworkset_name1_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete hostendpoint %s" % name(hostendpoint_name1_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete networkpolicy %s" % name(networkpolicy_name1_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete networkpolicy %s -n %s" % (name(networkpolicy_name3_rev1), namespace(networkpolicy_name3_rev1)), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete networkset %s" % name(networkset_name1_rev1), kdd=True)
        rc.assert_no_error()
        rc = calicoctl("delete networkset %s -n %s" % (name(networkset_name2_rev1), namespace(networkset_name2_rev1)), kdd=True)
        rc.assert_no_error()
