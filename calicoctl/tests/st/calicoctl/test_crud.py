# Copyright (c) 2015-2021 Tigera, Inc. All rights reserved.
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
    API_VERSION, name, ERROR_CONFLICT, NOT_FOUND, NOT_NAMESPACED, \
    SET_DEFAULT, NOT_SUPPORTED, KUBERNETES_NP, writeyaml
from tests.st.utils.data import *

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

class TestCalicoctlCommands(TestBase):
    """
    Test calicoctl pool
    1) Test the CRUD aspects of the pool commands.
    2) Test IP assignment from pool.
    BGP exported routes are hard to test and aren't expected to change much so
    write tests for them (yet)
    """

    def test_get(self):
        """
        Test that a basic CRUD flow for pool commands works.
        """

        # Create the ipv6 pool using calicoctl, and read it out using an
        # exact get and a list query.
        rc = calicoctl("create", data=ippool_name2_rev1_v6)
        rc.assert_no_error()
        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name2_rev1_v6))
        rc.assert_data(ippool_name2_rev1_v6)
        rc = calicoctl("get ippool -o yaml")
        rc.assert_list("IPPool", [ippool_name2_rev1_v6])

        # Add in the ipv4 network with calicoctl, and read out using an exact
        # get, and a list query.
        rc = calicoctl("create", data=ippool_name1_rev1_v4)
        rc.assert_no_error()
        rc = calicoctl("get ippool %s -o yaml" % name(ippool_name1_rev1_v4))
        rc.assert_data(ippool_name1_rev1_v4)
        rc = calicoctl("get ippool -o yaml")
        rc.assert_list("IPPool", [ippool_name1_rev1_v4, ippool_name2_rev1_v6])

        # Check correct rendering of the table format.
        rc = calicoctl("get ippool %s" % name(ippool_name1_rev1_v4))
        rc.assert_output_equals(ippool_name1_rev1_table)
        rc = calicoctl("get ippool %s -o wide" % name(ippool_name1_rev1_v4))
        rc.assert_output_equals(ippool_name1_rev1_wide_table)

        # Remove both the ipv4 pool and ipv6 pool by CLI options and by file.
        rc = calicoctl("delete ippool %s" % name(ippool_name1_rev1_v4))
        rc.assert_no_error()
        rc = calicoctl("delete", ippool_name2_rev1_v6)
        rc.assert_no_error()

        # Assert pools are now deleted
        rc = calicoctl("get ippool -o yaml")
        rc.assert_empty_list("IPPool")

        # Assert that deleting the pool again fails.
        rc = calicoctl("delete ippool %s" % name(ippool_name2_rev1_v6))
        rc.assert_error(text=NOT_FOUND)

    def test_no_config(self):
        """
        Test that broken store configuration does not crash
        """

        rc = calicoctl("get policy", no_config=True)
        rc.assert_error()

        rc = calicoctl("get policy x", no_config=True)
        rc.assert_error()

        rc = calicoctl("create", data=ippool_name2_rev1_v6, no_config=True)
        rc.assert_error()

        rc = calicoctl("apply", data=bgppeer_name1_rev2_v4, no_config=True)
        rc.assert_error()

        rc = calicoctl("replace", data=networkpolicy_name1_rev2, no_config=True)
        rc.assert_error()

        rc = calicoctl("label workloadendpoint node1-k8s-abcd-eth0 app=web --namespace=namespace1", no_config=True)
        rc.assert_error()

        rc = calicoctl("ipam show", no_config=True)
        rc.assert_error()

    def test_get_delete_multiple_names(self):
        """
        Test get/delete resource kind works with multiple names
        """
        # Create ipv6 and ipv4 pools (2 IPPool resources)
        rc = calicoctl("create", data=ippool_name2_rev1_v6)
        rc.assert_no_error()
        rc = calicoctl("create", data=ippool_name1_rev1_v4)
        rc.assert_no_error()

        # Get the 2 resources by name
        rc = calicoctl("get ippool %s %s" % (name(ippool_name1_rev1_v4), name(ippool_name2_rev1_v6)))
        rc.assert_no_error()
        rc.assert_output_equals(ippool_name1_rev1_table + "   \n\n" + ippool_name2_rev1_table)

        rcNoErr = rc

        # Get the 2 + one that does not exist
        rc = calicoctl("get ippool %s %s %s" % (name(ippool_name1_rev1_v4), "blah", name(ippool_name2_rev1_v6)))
        rc.assert_error()
        rc.assert_output_equals(ippool_name1_rev1_table +
                "   \n\n" +
                ippool_name2_rev1_table +
                "      \n\n" +
                "resource does not exist: IPPool(blah) with error: <nil>\n")

        rc = calicoctl("get ippool %s %s %s" % (name(ippool_name1_rev1_v4), "blah", name(ippool_name2_rev1_v6)),
                only_stdout=True)

        # Check that the output with no errors and with some errors equal for
        # the good cases (XXX some weird benign printer whitespaces at the end)
        rc.assert_output_equals(rcNoErr.output + "      \n\n")

        # Delete both by name
        rc = calicoctl("delete ippool %s %s" % (name(ippool_name1_rev1_v4), name(ippool_name2_rev1_v6)))
        rc.assert_no_error()

        # Assert pools are now deleted
        rc = calicoctl("get ippool -o yaml")
        rc.assert_empty_list("IPPool")

        # Create ipv6 and ipv4 pools (2 IPPool resources)
        rc = calicoctl("create", data=ippool_name2_rev1_v6)
        rc.assert_no_error()
        rc = calicoctl("create", data=ippool_name1_rev1_v4)
        rc.assert_no_error()

        # Delete the 2 + one that does not exist
        rc = calicoctl("delete ippool %s %s %s" %
                (name(ippool_name1_rev1_v4), "blah", name(ippool_name2_rev1_v6)))
        rc.assert_error()

        # Assert pools are now deleted
        rc = calicoctl("get ippool -o yaml")
        rc.assert_empty_list("IPPool")

        # Create ipv6 and ipv4 pools (2 IPPool resources)
        rc = calicoctl("create", data=ippool_name2_rev1_v6)
        rc.assert_no_error()
        rc = calicoctl("create", data=ippool_name1_rev1_v4)
        rc.assert_no_error()

        # Make sure that we do not delete anything unintentionally
        rcYaml= calicoctl("get ippool -o yaml")
        rcYaml.assert_no_error()

        rc = calicoctl("delete ippool x y z")
        rc.assert_error()

        rc= calicoctl("get ippool -o yaml")
        rc.assert_no_error()
        rc.assert_output_equals_ignore_res_version(rcYaml.output)

    def test_reject_unknown_resource(self):
        """
        Test that we error if a resource is not know
        """

        rc = calicoctl("get somekind somename")
        rc.assert_error()
        rc.assert_output_contains("Failed to get resources: resource type 'somekind' is not supported")

    def test_empty_name_is_ilegal(self):
        """
        Test that we error if empty name is provided
        """

        rc = calicoctl("get policy \"\"")
        rc.assert_error()

        rc = calicoctl("get policy x \"\" y")
        rc.assert_error()

        rc = calicoctl("get delete \"\"")
        rc.assert_error()

        rc = calicoctl("get delete x \"\" y")
        rc.assert_error()

        rc = calicoctl("get label \"\" key --remove")
        rc.assert_error()

    def test_delete_with_resource_version(self):
        """
        Test that resource version operates correctly with delete, i.e.
        calicoctl honors the resource version when it's specified.
        """

        # Create a new BGP Peer and get it to determine the current resource
        # version.
        rc = calicoctl("create", data=bgppeer_name1_rev1_v4)
        rc.assert_no_error()
        rc = calicoctl("get bgppeer %s -o yaml" % name(bgppeer_name1_rev1_v4))
        rc.assert_no_error()
        rev0 = rc.decoded

        # Update the BGP Peer and get it to assert the resource version is not
        # the same.
        rc = calicoctl("apply", data=bgppeer_name1_rev2_v4)
        rc.assert_no_error()
        rc = calicoctl("get bgppeer %s -o yaml" % name(bgppeer_name1_rev2_v4))
        rc.assert_no_error()
        rev1 = rc.decoded
        self.assertNotEqual(rev0['metadata']['resourceVersion'], rev1['metadata']['resourceVersion'])

        # Attempt to delete using the old revision (rev0).  This will fail.
        rc = calicoctl("delete", data=rev0)
        rc.assert_error(text=ERROR_CONFLICT)

        # Delete using the new revision (rev1).
        rc = calicoctl("delete", data=rev1)
        rc.assert_no_error()

    def test_replace_with_resource_version(self):
        """
        Test that resource version operates correctly with update, i.e.
        calicoctl honors the resource version when it's specified.
        """

        # Create a new Network Policy and get it to determine the current
        # resource version.
        rc = calicoctl("create", data=networkpolicy_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl(
            "get networkpolicy %s -o yaml" % name(networkpolicy_name1_rev1))
        rc.assert_no_error()
        rev0 = rc.decoded

        # Replace the Network Policy (with no resource version) and get it to
        # assert the resource version is not the same.
        rc = calicoctl("replace", data=networkpolicy_name1_rev2)
        rc.assert_no_error()
        rc = calicoctl(
            "get networkpolicy %s -o yaml" % name(networkpolicy_name1_rev2))
        rc.assert_no_error()
        rev1 = rc.decoded
        self.assertNotEqual(rev0['metadata']['resourceVersion'], rev1['metadata']['resourceVersion'])

        # Attempt to replace using the old revision (rev0).  This will fail.
        rc = calicoctl("replace", data=rev0)
        rc.assert_error(text=ERROR_CONFLICT)

        # Replace using the original data, but with the new resource version.
        rev0['metadata']['resourceVersion'] = rev1['metadata']['resourceVersion']
        rc = calicoctl("replace", data=rev0)
        rc.assert_no_error()

        # Delete the resource by name (i.e. without using a resource version).
        rc = calicoctl("delete networkpolicy %s" % name(rev0))
        rc.assert_no_error()

        # Attempt to replace the (now deleted) resource.
        rc = calicoctl("replace", data=networkpolicy_name1_rev2)
        rc.assert_error(text=NOT_FOUND)

    def test_create_single_invalid_resource(self):
        """
        Test that creating a single invalid resource returns an appropriate error
        """
        rc = calicoctl("create", data=bgppeer_invalid, format="json")
        rc.assert_error(text="error with field PeerIP = 'badpeerIP'")
        rc.assert_output_not_contains("Partial success")
        rc.assert_output_contains("Failed to create 'BGPPeer' resource")

    def test_create_all_invalid_resources(self):
        """
        Test that creating multiple invalid resources returns an appropriate error
        """
        rc = calicoctl("create", data=bgppeer_multiple_invalid, format="json")
        rc.assert_error(text="error with field PeerIP = 'badpeerIP'")
        rc.assert_output_not_contains("Partial success")
        rc.assert_output_contains("Failed to create any 'BGPPeer' resources")

    def test_apply_single_invalid_resource(self):
        """
        Test that applying a single invalid resource returns an appropriate error
        """
        rc = calicoctl("apply", data=bgppeer_invalid)
        rc.assert_error(text="error with field PeerIP = 'badpeerIP'")
        rc.assert_output_not_contains("Partial success")
        rc.assert_output_contains("Failed to apply 'BGPPeer' resource")

    def test_apply_all_invalid_resources(self):
        """
        Test that applying multiple invalid resources returns an appropriate error
        """
        rc = calicoctl("apply", data=bgppeer_multiple_invalid)
        rc.assert_error(text="error with field PeerIP = 'badpeerIP'")
        rc.assert_output_not_contains("Partial success")
        rc.assert_output_contains("Failed to apply any 'BGPPeer' resources")

    def test_apply_with_resource_version(self):
        """
        Test that resource version operates correctly with apply, i.e.
        calicoctl honors the resource version when it's specified.
        """

        # Use apply to create a new Host Endpoint and get it to determine the
        # current resource version (first checking that it doesn't exist).
        rc = calicoctl(
            "get hostendpoint %s -o yaml" % name(hostendpoint_name1_rev1))
        rc.assert_error(text=NOT_FOUND)

        rc = calicoctl("apply", data=hostendpoint_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl(
            "get hostendpoint %s -o yaml" % name(hostendpoint_name1_rev1))
        rc.assert_no_error()
        rev0 = rc.decoded

        # Apply the Host Endpoint (with no resource version) and get it to
        # assert the resource version is not the same.
        rc = calicoctl("apply", data=hostendpoint_name1_rev2)
        rc.assert_no_error()
        rc = calicoctl(
            "get hostendpoint %s -o yaml" % name(hostendpoint_name1_rev2))
        rc.assert_no_error()
        rev1 = rc.decoded
        self.assertNotEqual(rev0['metadata']['resourceVersion'], rev1['metadata']['resourceVersion'])

        # Attempt to apply using the old revision (rev0).  This will fail.
        rc = calicoctl("apply", data=rev0)
        rc.assert_error(text=ERROR_CONFLICT)

        # Apply using the original data, but with the new resource version.
        rev0['metadata']['resourceVersion'] = rev1['metadata']['resourceVersion']
        rc = calicoctl("apply", data=rev0)
        rc.assert_no_error()

        # Delete the resource without using a resource version.
        rc = calicoctl("delete hostendpoint %s" % name(rev0))
        rc.assert_no_error()

    def test_json(self):
        """
        Test mainline CRUD operations using JSON input and output.
        """
        # Use create to create a new profile and get the profile to check the
        # data was stored (using JSON input/output).
        rc = calicoctl("create", data=profile_name1_rev1, format="json")
        rc.assert_no_error()
        rc = calicoctl("get profile %s -o json" % name(profile_name1_rev1))
        rc.assert_data(profile_name1_rev1, format="json")

        # Use apply to update the profile and get the profile to check the
        # data was stored (using JSON input/output).
        rc = calicoctl("apply", data=profile_name1_rev2, format="json")
        rc.assert_no_error()
        rc = calicoctl("get profile %s -o json" % name(profile_name1_rev1))
        rc.assert_data(profile_name1_rev2, format="json")

        # Use replace to update the profile and get the profile to check the
        # data was stored (using JSON input/output).
        rc = calicoctl("replace", data=profile_name1_rev1, format="json")
        rc.assert_no_error()
        rc = calicoctl("get profile %s -o json" % name(profile_name1_rev1))
        rc.assert_data(profile_name1_rev1, format="json")

        # Use delete to delete the profile (using JSON input).
        rc = calicoctl("delete", data=profile_name1_rev1, format="json")
        rc.assert_no_error()

    def test_stdin(self):
        """
        Test mainline CRUD operations using stdin input and output (mixing
        JSON and YAML types).
        """
        # Use create to create a new GlobalNetworkPolicy and get the resource to check the
        # data was stored (using JSON input/output).
        rc = calicoctl("create", data=globalnetworkpolicy_name1_rev1, format="json", load_as_stdin=True)
        rc.assert_no_error()
        rc = calicoctl("get globalnetworkpolicy %s -o json" % name(globalnetworkpolicy_name1_rev1))
        rc.assert_data(globalnetworkpolicy_name1_rev1, format="json")

        # Use apply to update the GlobalNetworkPolicy and get the resource to check the
        # data was stored (using YAML input/output).
        rc = calicoctl("apply", data=globalnetworkpolicy_name1_rev2, format="yaml", load_as_stdin=True)
        rc.assert_no_error()
        rc = calicoctl("get globalnetworkpolicy %s -o yaml" % name(globalnetworkpolicy_name1_rev1))
        rc.assert_data(globalnetworkpolicy_name1_rev2, format="yaml")

        # Use replace to update the GlobalNetworkPolicy and get the resource to check the
        # data was stored (using JSON input/output).
        rc = calicoctl("replace", data=globalnetworkpolicy_name1_rev1, format="json", load_as_stdin=True)
        rc.assert_no_error()
        rc = calicoctl("get globalnetworkpolicy %s -o json" % name(globalnetworkpolicy_name1_rev1))
        rc.assert_data(globalnetworkpolicy_name1_rev1, format="json")

        # Use delete to delete the GlobalNetworkPolicy (using YAML input).
        rc = calicoctl("delete", data=globalnetworkpolicy_name1_rev1, format="yaml", load_as_stdin=True)
        rc.assert_no_error()

    def test_file_multi(self):
        """
        Test CRUD operations using a file containing multiple entries (a mix
        of non-List and List types).
        """
        # Since the file processing is the same for all commands, we only
        # need to test multi entries per file on a single command (in this case
        # we use delete).

        # Combine three different resources and create those in a single file-based command.
        resources = [globalnetworkpolicy_name1_rev1, workloadendpoint_name1_rev1, workloadendpoint_name2_rev1]
        rc = calicoctl("create", data=resources)
        rc.assert_no_error()

        # Get the resources using file based input.  It should return the
        # same results.
        rc = calicoctl("get -o yaml", data=resources)
        rc.assert_data(resources)

        # Use a get/list to get one of the resource types and an exact get to
        # get the other.  Join them together and use it to delete the resource.
        # This tests a mix of List and non-list types in the same file.
        # We use the data returned from the get since this should be able to
        # be used directly as input into the next command.
        rc = calicoctl("get globalnetworkpolicy %s -o yaml" % name(globalnetworkpolicy_name1_rev1))
        rc.assert_data(globalnetworkpolicy_name1_rev1)
        gnp = rc.decoded

        rc = calicoctl("get workloadendpoints -o yaml --all-namespaces")
        rc.assert_list("WorkloadEndpoint", [workloadendpoint_name1_rev1, workloadendpoint_name2_rev1])
        wepList = rc.decoded

        rc = calicoctl("delete", data=[gnp, wepList])
        rc.assert_no_error()

        # Finally do a  get to make sure nothing is returned.
        rc = calicoctl("get workloadendpoints -o yaml")
        rc.assert_empty_list("WorkloadEndpoint")

    def test_file_single_list(self):
        """
        Test CRUD operations using a file containing a single List.
        """
        # Create a couple of resources.
        resources = [workloadendpoint_name1_rev1, workloadendpoint_name2_rev1]
        rc = calicoctl("create", data=resources)
        rc.assert_no_error()

        # Get the resources using file based input.  It should return the
        # same results.
        rc = calicoctl("get workloadendpoints -o yaml --all-namespaces")
        rc.assert_list("WorkloadEndpoint", resources)
        wepList = rc.decoded

        # Use the returned list to perform a get.  Since the list is expanded
        # this query results in two exact gets - so we'll end up with a []
        # of resources rather than a resource List.
        rc = calicoctl("get -o yaml", wepList)
        rc.assert_data(resources)

        # Use the returned list to perform a delete.
        rc = calicoctl("delete", wepList)
        rc.assert_no_error()

        # Use the returned list to perform a delete.
        rc = calicoctl("get workloadendpoints -o yaml")
        rc.assert_empty_list("WorkloadEndpoint")

    @parameterized.expand([
        (ippool_name1_rev1_v4,),
        (ipresv_name1_rev1_v4,),
        (profile_name1_rev1,),
        (globalnetworkpolicy_name1_rev1,),
        (globalnetworkset_name1_rev1,),
        (globalnetworkset_name1_rev1_large,),
        (hostendpoint_name1_rev1,),
        (bgppeer_name1_rev1_v4,),
        (node_name1_rev1,),
    ])
    def test_non_namespaced(self, data):
        """
        Test namespace is handled as expected for each non-namespaced resource type.
        """
        # Clone the data so that we can modify the metadata parms.
        data1 = copy.deepcopy(data)
        kind = data['kind']

        rc = calicoctl("create", data=data1)
        rc.assert_no_error()

        # Get the resource type as normal.
        rc = calicoctl("get %s" % kind)
        rc.assert_no_error()
        rc = calicoctl("get %s -o wide" % kind)
        rc.assert_no_error()

        # Get the resource with name1 and namespace2.
        # For non-namespaced resources this will error.
        rc = calicoctl("get %s %s --namespace default -o yaml" % (kind, data1['metadata']['name']))
        rc.assert_error(NOT_NAMESPACED)

        # Get the resource type for all namespaces.
        # For non-namespaced resources this will error.
        rc = calicoctl("get %s --all-namespaces -o yaml" % kind)
        rc.assert_error(NOT_NAMESPACED)
        # Get the resource type for all namespaces.
        # For non-namespaced resources this will error.
        rc = calicoctl("get %s --all-namespaces -o yaml" % kind)
        rc.assert_error(NOT_NAMESPACED)

        # Delete the resource
        rc = calicoctl("delete", data=data1)
        rc.assert_no_error()

    def test_ip_reservation_no_truncation(self):
        """
        Test that the list of CIDRd is truncated if it's too long.
        """
        rc = calicoctl("create", ipresv_name1_rev1_v4)
        rc.assert_no_error()

        kind = ipresv_name1_rev1_v4['kind']
        rc = calicoctl("get %s -o wide" % kind)

        rc.assert_no_error()
        rc.assert_output_contains("10.0.1.0/24,11.0.0.1/32")

    def test_ip_reservation_truncation(self):
        """
        Test that the list of CIDRs is truncated if it's too long.
        """
        rc = calicoctl("create", ipresv_name1_rev1_v4_long)
        rc.assert_no_error()

        kind = ipresv_name1_rev1_v4['kind']
        rc = calicoctl("get %s -o wide" % kind)

        rc.assert_no_error()
        rc.assert_output_contains("10.0.0.0/28,10.0.1.0/28,10.0.2.0/28,10.0.3.0/28,10.0.4.0/28,10.0.5.0/28,10.0....")

    @parameterized.expand([
        (globalnetworkset_name1_rev1_large,),
        (networkset_name1_rev1_large,),
    ])
    def test_nets_truncation(self, data):
        """
        Test that the list of nets is truncated if it's too long.
        """
        rc = calicoctl("create", data)
        rc.assert_no_error()

        kind = data['kind']
        if kind == "GlobalNetworkSet":
            rc = calicoctl("get %s -o wide" % kind)
        else:
            rc = calicoctl("get %s -o wide -n %s" % (kind, data['metadata']['namespace']))

        rc.assert_no_error()
        rc.assert_output_contains("10.0.0.0/28,10.0.1.0/28,10.0.2.0/28,10.0.3.0/28,10.0.4.0/28,10.0.5.0/28,10.0....")

    @parameterized.expand([
        (globalnetworkset_name1_rev1,),
        (networkset_name1_rev1,),
    ])
    def test_nets_no_truncation(self, data):
        """
        Test that the list of nets is shown in full if not too long.
        """
        rc = calicoctl("create", data)
        rc.assert_no_error()

        rc = calicoctl("get %s -o wide" % data['kind'])
        rc.assert_no_error()
        rc.assert_output_contains("10.0.0.1,11.0.0.0/16,feed:beef::1,dead:beef::96")

    @parameterized.expand([
        (networkpolicy_name1_rev1,),
        (networkset_name1_rev1,),
        (workloadendpoint_name1_rev1,),
    ])
    def test_namespaced(self, data):
        """
        Tests namespace is handled as expected for each namespaced resource type.
        """
        # Clone the data so that we can modify the metadata parms.
        data1 = copy.deepcopy(data)
        data2 = copy.deepcopy(data)

        kind = data['kind']

        # Create resource with name1 and with name2.
        # Leave the first namespace blank and the second set to
        # namespace2 for the actual create request.
        if kind == "WorkloadEndpoint":
            # The validation in libcalico-go WorkloadEndpoint checks the
            # construction of the name so keep the name on the workloadendpoint.

            # Below namespace2 is searched for the WorkloadEndpoint data1
            # name so we need data2 to have a different name than data1 so we
            # change it to have eth1 instead of eth0

            # Strip off the last character (the zero in eth0) and replace it
            # with a 1
            data2['metadata']['name'] = data1['metadata']['name'][:len(data1['metadata']['name'])-1] + "1"
            # Change endpoint to eth1 so the validation works on the WEP
            data2['spec']['endpoint'] = "eth1"
        elif kind == "IPPool":
            data1['metadata']['name'] = "name1"
            data2['metadata']['name'] = "name2"
            data2['spec']['cidr'] = "10.10.1.0/24"
        else:
            data1['metadata']['name'] = "name1"
            data2['metadata']['name'] = "name2"

        data1['metadata']['namespace'] = ""
        data2['metadata']['namespace'] = "namespace2"

        rc = calicoctl("create", data=data1)
        rc.assert_no_error()
        rc = calicoctl("create", data=data2)
        rc.assert_no_error()

        # We expect the namespace to be defaulted to "default"
        # if not specified.  Tweak the namespace in data1 to be default so that
        # we can use it to compare against the calicoctl get output.
        data1['metadata']['namespace'] = "default"

        if kind == "WorkloadEndpoint":
            data1['metadata']['labels']['projectcalico.org/namespace'] = 'default'

        # Get the resource with name1 and default namespace.  For a namespaced
        # resource this should match the modified data to default the
        # namespace.
        rc = calicoctl("get %s %s --namespace default -o yaml" % (kind, data1['metadata']['name']))
        rc.assert_data(data1)

        if kind == "WorkloadEndpoint":
            data2['metadata']['labels']['projectcalico.org/namespace'] = 'namespace2'

        # Get the resource type for all namespaces.  For a namespaced resource
        # this will return everything.
        rc = calicoctl("get %s --all-namespaces -o yaml" % kind)
        rc.assert_list(kind, [data1, data2])

        # For namespaced resources, if you do a list without specifying the
        # namespace we'll just get the default namespace.
        rc = calicoctl("get %s -o yaml" % kind)
        rc.assert_list(kind, [data1])

        # For namespaced resources, if you do a list specifying a namespace
        # we'll get results for that namespace.
        rc = calicoctl("get %s -o yaml -n namespace2" % kind)
        rc.assert_list(kind, [data2])

        # Doing a get by file will use the namespace in the file.
        rc = calicoctl("get -o yaml", data1)
        rc.assert_data(data1)
        rc = calicoctl("get -o yaml", data2)
        rc.assert_data(data2)

        # Doing a get by file will use the default namespace if not specified
        # in the file or through the CLI args.
        data1_no_ns = copy.deepcopy(data1)
        del (data1_no_ns['metadata']['namespace'])
        rc = calicoctl("get -o yaml", data1_no_ns)
        rc.assert_data(data1)
        rc = calicoctl("get -o yaml -n namespace2", data1_no_ns)
        rc.assert_error(NOT_FOUND)

        data2_no_ns = copy.deepcopy(data2)
        del(data2_no_ns['metadata']['namespace'])
        rc = calicoctl("get -o yaml -n namespace2", data2_no_ns)
        rc.assert_data(data2)
        rc = calicoctl("get -o yaml", data2_no_ns)
        rc.assert_error(NOT_FOUND)

        # Deleting without a namespace will delete the default.
        rc = calicoctl("delete %s %s" % (kind, data1['metadata']['name']))
        rc.assert_no_error()

        rc = calicoctl("delete %s %s" % (kind, data2['metadata']['name']))
        rc.assert_error(NOT_FOUND)
        rc = calicoctl("delete", data2)
        rc.assert_no_error()

    def test_bgpconfig(self):
        """
        Test CRUD commands behave as expected on the BGP configuration resource:
        """
        # Create a new default BGPConfiguration and get it to determine the current
        # resource version.
        rc = calicoctl("create", data=bgpconfig_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl(
            "get bgpconfig %s -o yaml" % name(bgpconfig_name1_rev1))
        rc.assert_no_error()
        rev0 = rc.decoded

        # Replace the BGP Configuration (with no resource version) and get it to
        # assert the resource version is not the same.
        rc = calicoctl("replace", data=bgpconfig_name1_rev2)
        rc.assert_no_error()
        rc = calicoctl(
            "get bgpconfig %s -o yaml" % name(bgpconfig_name1_rev2))
        rc.assert_no_error()
        rev1 = rc.decoded
        self.assertNotEqual(rev0['metadata']['resourceVersion'], rev1['metadata']['resourceVersion'])

        # Attempt to delete the default resource by name (i.e. without using a resource version).
        # rc = calicoctl("delete bgpconfig %s" % name(rev0))
        # rc.assert_error(DELETE_DEFAULT)

        rc = calicoctl("create", data=bgpconfig_name2_rev1)
        rc.assert_no_error()
        rc = calicoctl(
            "get bgpconfig %s -o yaml" % name(bgpconfig_name2_rev1))
        rc.assert_no_error()
        rev2 = rc.decoded

        # Apply an update to the BGP Configuration and assert the resource version is not the same.
        rc = calicoctl("apply", data=bgpconfig_name2_rev2)
        rc.assert_no_error()
        rc = calicoctl(
            "get bgpconfig %s -o yaml" % name(bgpconfig_name2_rev2))
        rc.assert_no_error()
        rev3 = rc.decoded
        self.assertNotEqual(rev2['metadata']['resourceVersion'], rev3['metadata']['resourceVersion'])

        # Attempt to apply an update to change fields that are for default configs ONLY
        rc = calicoctl("apply", data=bgpconfig_name2_rev3)
        rc.assert_error(SET_DEFAULT)

        # Delete the resource by name (i.e. without using a resource version).
        rc = calicoctl("delete bgpconfig %s" % name(rev3))
        rc.assert_no_error()

    def test_felixconfig(self):
        """
        Test CRUD commands behave as expected on the felix configuration resource:
        """
        # Create a new default BGPConfiguration and get it to determine the current
        # resource version.
        rc = calicoctl("create", data=felixconfig_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl(
            "get felixconfig %s -o yaml" % name(felixconfig_name1_rev1))
        rc.assert_no_error()
        rev0 = rc.decoded

        # Replace the BGP Configuration (with no resource version) and get it to
        # assert the resource version is not the same.
        rc = calicoctl("replace", data=felixconfig_name1_rev2)
        rc.assert_no_error()
        rc = calicoctl(
            "get felixconfig %s -o yaml" % name(felixconfig_name1_rev2))
        rc.assert_no_error()
        rev1 = rc.decoded
        self.assertNotEqual(rev0['metadata']['resourceVersion'], rev1['metadata']['resourceVersion'])

        # Apply an update to the BGP Configuration and assert the resource version is not the same.
        rc = calicoctl("apply", data=felixconfig_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl(
            "get felixconfig %s -o yaml" % name(felixconfig_name1_rev1))
        rc.assert_no_error()
        rev2 = rc.decoded
        self.assertNotEqual(rev1['metadata']['resourceVersion'], rev2['metadata']['resourceVersion'])

        # Apply an update to the felix configuration with a large duration.
        rc = calicoctl("apply", data=felixconfig_name1_rev3)
        rc.assert_no_error()
        rc = calicoctl(
            "get felixconfig %s -o yaml" % name(felixconfig_name1_rev3))
        rc.assert_no_error()
        rev3 = rc.decoded
        self.assertEqual(rev3['spec']['netlinkTimeout'], '2m5s')
        self.assertEqual(rev3['spec']['reportingTTL'], '2h45m10s')

        # Delete the resource by name (i.e. without using a resource version).
        rc = calicoctl("delete felixconfig %s" % name(rev2))
        rc.assert_no_error()

    def test_clusterinfo(self):
        """
        Test CRUD commands behave as expected on the cluster information resource:
        """
        # Try to create a cluster info, should be rejected.
        rc = calicoctl("create", data=clusterinfo_name1_rev1)
        rc.assert_error(NOT_SUPPORTED)
        rc = calicoctl("get clusterinfo %s -o yaml" % name(clusterinfo_name1_rev1))
        rc.assert_error(NOT_FOUND)

        # Replace the cluster information (with no resource version) - assert not supported.
        rc = calicoctl("replace", data=clusterinfo_name1_rev2)
        rc.assert_error(NOT_FOUND)

        # Apply an update to the cluster information and assert not found (we need the node to
        # create it).
        rc = calicoctl("apply", data=clusterinfo_name1_rev2)
        rc.assert_error(NOT_SUPPORTED)

        # Delete the resource by name (i.e. without using a resource version) - assert not
        # supported.
        rc = calicoctl("delete clusterinfo %s" % name(clusterinfo_name1_rev1))
        rc.assert_error(NOT_SUPPORTED)

        # Create a node, this should trigger auto-creation of a cluster info.
        rc = calicoctl("create", data=node_name2_rev1)
        rc.assert_no_error()

        rc = calicoctl("get clusterinfo %s -o yaml" % name(clusterinfo_name1_rev1))
        rc.assert_no_error()
        # Check the GUID is populated.
        self.assertRegexpMatches(rc.decoded["spec"]["clusterGUID"], "^[a-f0-9]{32}$")
        # The GUID is unpredictable so tweak our test data to match it.
        ci = copy.deepcopy(clusterinfo_name1_rev1)
        ci["spec"]["clusterGUID"] = rc.decoded["spec"]["clusterGUID"]
        rc.assert_data(ci)

        # Create a second node, this should keep the existing cluster info.
        rc = calicoctl("create", data=node_name3_rev1)
        rc.assert_no_error()
        rc = calicoctl("get clusterinfo %s -o yaml" % name(clusterinfo_name1_rev1))
        rc.assert_no_error()
        rc.assert_data(ci)  # Implicitly checks the GUID is still the same.

    def test_kubecontrollersconfig(self):
        """
        Test CRUD commands behave as expected on the kube controllers configuration resource:
        """
        # Create a new default KubeControllersConfiguration and get it to determine the current
        # resource version.
        rc = calicoctl("create", data=kubecontrollersconfig_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl(
            "get kubecontrollersconfig %s -o yaml" % name(kubecontrollersconfig_name1_rev1))
        rc.assert_no_error()
        rev0 = rc.decoded

        # Replace the KubeControllersConfiguration (with no resource version) and get it to
        # assert the resource version is not the same.
        rc = calicoctl("replace", data=kubecontrollersconfig_name1_rev2)
        rc.assert_no_error()
        rc = calicoctl(
            "get kubecontrollersconfig %s -o yaml" % name(kubecontrollersconfig_name1_rev2))
        rc.assert_no_error()
        rev1 = rc.decoded
        self.assertNotEqual(rev0['metadata']['resourceVersion'], rev1['metadata']['resourceVersion'])

        # Apply an update to the KubeControllersConfiguration and assert the resource version is not the same.
        rc = calicoctl("apply", data=kubecontrollersconfig_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl(
            "get kubecontrollersconfig %s -o yaml" % name(kubecontrollersconfig_name1_rev1))
        rc.assert_no_error()
        rev2 = rc.decoded
        self.assertNotEqual(rev1['metadata']['resourceVersion'], rev2['metadata']['resourceVersion'])

        # Delete the resource by name (i.e. without using a resource version).
        rc = calicoctl("delete kubecontrollersconfig %s" % name(rev2))
        rc.assert_no_error()

    @parameterized.expand([
        ('create', 'replace'),
        ('apply', 'apply'),
    ])
    def test_metadata_unchanged(self, create_cmd, update_cmd):
        """
        Test that the metadata fields other than labels and annotations cannot be changed
        in create and update operations by applying a resource twice.
        """
        # Create a new Host Endpoint and get it to determine the
        # current resource version (first checking that it doesn't exist).
        rc = calicoctl(
            "get hostendpoint %s -o yaml" % name(hostendpoint_name1_rev2))
        rc.assert_error(text=NOT_FOUND)

        rc = calicoctl(create_cmd, data=hostendpoint_name1_rev2)
        rc.assert_no_error()
        rc = calicoctl(
            "get hostendpoint %s -o yaml" % name(hostendpoint_name1_rev2))
        rc.assert_no_error()
        rev0 = rc.decoded
        self.assertIn('uid', rev0['metadata'])
        self.assertIn('creationTimestamp', rev0['metadata'])

        # Update the Host Endpoint (with no resource version) and get it to
        # assert the resource version is not the same.
        rc = calicoctl(update_cmd, data=hostendpoint_name1_rev3)
        rc.assert_no_error()
        rc = calicoctl(
            "get hostendpoint %s -o yaml" % name(hostendpoint_name1_rev3))
        rc.assert_no_error()
        rev1 = rc.decoded
        self.assertNotEqual(rev0['metadata']['resourceVersion'], rev1['metadata']['resourceVersion'])

        # Validate that only annotations and labels were changed in the metadata
        self.assertNotIn('selfLink', rev1['metadata'])
        self.assertNotIn('generation', rev1['metadata'])
        self.assertNotIn('finalizers', rev1['metadata'])
        self.assertIn('uid', rev1['metadata'])
        self.assertIn('creationTimestamp', rev1['metadata'])
        self.assertNotEqual(rev1['metadata']['uid'], hostendpoint_name1_rev3['metadata']['uid'])
        self.assertNotEqual(rev1['metadata']['creationTimestamp'], hostendpoint_name1_rev3['metadata']['creationTimestamp'])
        self.assertEqual(rev1['metadata'].get('name', ''), hostendpoint_name1_rev2['metadata'].get('name', ''))
        self.assertEqual(rev1['metadata']['labels'], hostendpoint_name1_rev3['metadata']['labels'])
        self.assertNotEqual(rev1['metadata']['labels'], rev0['metadata']['labels'])
        self.assertEqual(rev1['metadata']['annotations'], hostendpoint_name1_rev3['metadata']['annotations'])
        self.assertNotEqual(rev1['metadata']['annotations'], rev0['metadata']['labels'])

        # Validate that creationTimestamp and UID are unchanged from when they were created
        self.assertEqual(rev1['metadata']['creationTimestamp'], rev0['metadata']['creationTimestamp'])
        self.assertEqual(rev1['metadata']['uid'], rev0['metadata']['uid'])

        # Delete the resource without using a resource version.
        rc = calicoctl("delete hostendpoint %s" % name(rev1))
        rc.assert_no_error()

    def test_export_flag(self):
        """
        Test that the cluster-specific information gets stripped
        out of a "get" request.
        """
        # Create a new Network Policy with all metadata specified
        rc = calicoctl('create', data=networkpolicy_name2_rev1)
        rc.assert_no_error()
        rc = calicoctl(
            "get networkpolicy %s -o yaml" % name(networkpolicy_name2_rev1))
        rc.assert_no_error()
        rev0 = rc.decoded
        self.assertIn('uid', rev0['metadata'])
        self.assertIn('creationTimestamp', rev0['metadata'])
        self.assertEqual(rev0['metadata']['name'], networkpolicy_name2_rev1['metadata']['name'])
        self.assertEqual(rev0['metadata']['namespace'], networkpolicy_name2_rev1['metadata']['namespace'])
        self.assertIn('resourceVersion', rev0['metadata'])

        # Retrieve the Network Policy with the export flag and
        # Verify that cluster-specific information is not present
        rc = calicoctl(
            "get networkpolicy %s -o yaml --export" % name(networkpolicy_name2_rev1))
        rc.assert_no_error()
        rev1 = rc.decoded
        self.assertNotIn('uid', rev1['metadata'])
        self.assertIsNone(rev1['metadata']['creationTimestamp'])
        self.assertNotIn('namespace', rev1['metadata'])
        self.assertNotIn('resourceVersion', rev1['metadata'])
        self.assertEqual(rev1['metadata']['name'], rev0['metadata']['name'])

        # Write the output to yaml so that it can be applied later
        rev1['spec']['order'] = 100
        writeyaml('/tmp/export_data.yaml', rev1)

        # Verify that the cluster-specific information IS present if
        # the export flag is used without specifying a specific resource.
        rc = calicoctl(
            "get networkpolicy -o yaml --export")
        rc.assert_no_error()
        rev2 = rc.decoded
        self.assertEqual(len(rev2['items']), 1)
        self.assertIn('uid', rev2['items'][0]['metadata'])
        self.assertIsNotNone(rev2['items'][0]['metadata']['creationTimestamp'])
        self.assertIn('namespace', rev2['items'][0]['metadata'])
        self.assertIn('resourceVersion', rev2['items'][0]['metadata'])
        self.assertEqual(rev2['items'][0]['metadata']['name'], rev0['metadata']['name'])

        # Apply the output and verify that it did not error out
        rc = calicoctl(
            "apply -f %s" % '/tmp/export_data.yaml')
        rc.assert_no_error()
        rc = calicoctl(
            "get networkpolicy %s -o yaml" % name(networkpolicy_name2_rev1))
        rc.assert_no_error()
        rev3 = rc.decoded
        self.assertEqual(rev3['metadata']['name'], rev1['metadata']['name'])
        self.assertEqual(rev3['spec']['order'], 100)

        # Delete the resource without using a resource version.
        rc = calicoctl("delete networkpolicy %s" % name(rev3))
        rc.assert_no_error()

    def test_disallow_crud_on_knp_defaults(self):
        """
        Test that we disallow CRUD on a knp.default prefixed NetworkPolicy.
        """
        k8s_np = copy.deepcopy(networkpolicy_name1_rev1)
        k8s_np['metadata']['name'] = 'knp.default.foobarfizz'

        rc = calicoctl("create", data=k8s_np)
        rc.assert_error(text=NOT_SUPPORTED)
        rc.assert_error(text=KUBERNETES_NP)

        rc = calicoctl("apply", data=k8s_np)
        rc.assert_error(text=NOT_FOUND)

        rc = calicoctl("replace", data=k8s_np)
        rc.assert_error(text=NOT_FOUND)

        rc = calicoctl("delete", data=k8s_np)
        rc.assert_error(text=NOT_SUPPORTED)
        rc.assert_error(text=KUBERNETES_NP)

    @parameterized.expand([
        ('replace'),
        ('apply'),
    ])
    def test_disallow_update_old_resource_version(self, update_cmd):
        """
        Test that we disallow updates on resources with old resource versions.
        """
        rc = calicoctl("create", data=ippool_name1_rev1_v4)
        rc.assert_no_error()

        rc = calicoctl(
                "get ippool %s -o yaml" % name(ippool_name1_rev1_v4))
        rc.assert_no_error()
        rev1 = rc.decoded

        rc = calicoctl(update_cmd, data=rev1)
        rc.assert_no_error()

        rc = calicoctl(
                "get ippool %s -o yaml" % name(ippool_name1_rev1_v4))
        rc.assert_no_error()
        rev2 = rc.decoded
        self.assertNotEqual(rev1['metadata']['resourceVersion'], rev2['metadata']['resourceVersion'])

        rc = calicoctl(update_cmd, data=rev1)
        rc.assert_error(text=ERROR_CONFLICT)

        # Delete the resource
        rc = calicoctl("delete ippool %s" % name(ippool_name1_rev1_v4))
        rc.assert_no_error()

    def test_bgppeer_node_selector(self):
        rc = calicoctl("create", data={
            'apiVersion': API_VERSION,
            'kind': 'BGPPeer',
            'metadata': {
                'name': 'bp1'
            },
            'spec': {
                'nodeSelector': "has(rr)",
                'peerSelector': "has(rr)",
            },
        })
        rc.assert_no_error()

        rc = calicoctl("get bgpp")
        rc.assert_no_error()
        rc.assert_output_contains("bp1")
        rc.assert_output_contains("has(rr)")
        assert "global" not in rc.output

    def test_bgppeer_password(self):
        rc = calicoctl("create", data={
            'apiVersion': API_VERSION,
            'kind': 'BGPPeer',
            'metadata': {
                'name': 'bp1'
            },
            'spec': {
                'password': {'secretKeyRef': {'name': 'bgp-passwords', 'key': 'bp1p'}},
                'peerSelector': "has(rr)",
            },
        })
        rc.assert_no_error()

        rc = calicoctl("get bgpp")
        rc.assert_no_error()
        rc.assert_output_contains("bp1")
        rc.assert_output_contains("global")

    def test_label_command(self):
        """
        Test calicoctl label command.
        """
        rc = calicoctl("create",data=workloadendpoint_name1_rev1)
        rev1_labels = workloadendpoint_name1_rev1['metadata']['labels']
        rc.assert_no_error()

        rc = calicoctl("label workloadendpoint node1-k8s-abcd-eth0 app=web --namespace=namespace1")
        rc.assert_no_error()

        rc = calicoctl("get workloadendpoint node1-k8s-abcd-eth0 --namespace=namespace1 -o yaml")
        rc.assert_no_error()
        rev2 = rc.decoded
        self.assertEqual("web",rev2['metadata']['labels']['app'])

        rc = calicoctl("label workloadendpoint node1-k8s-abcd-eth0 app=order --namespace=namespace1")
        rc.assert_error(text="key app is already present")

        rc = calicoctl("label workloadendpoint node1-k8s-abcd-eth0 app=order --namespace=namespace1 --overwrite")
        rc.assert_no_error()

        rc = calicoctl("get workloadendpoint node1-k8s-abcd-eth0 --namespace=namespace1 -o yaml")
        rc.assert_no_error()
        rev3 = rc.decoded
        self.assertEqual("order",rev3['metadata']['labels']['app'])

        rc = calicoctl("label workloadendpoint node1-k8s-abcd-eth0 app --namespace=namespace1 --remove")
        rc.assert_no_error()

        rc = calicoctl("get workloadendpoint node1-k8s-abcd-eth0 --namespace=namespace1 -o yaml")
        rc.assert_no_error()
        rev4 = rc.decoded
        self.assertEqual(rev1_labels,rev4['metadata']['labels'])

        # test adding label for resources with no labels.
        rc = calicoctl("create",data=node_name1_rev1)
        rc.assert_no_error()

        rc = calicoctl("label nodes node1 cluster=frontend")
        rc.assert_no_error()

        rc = calicoctl("get nodes node1 -o yaml")
        rc.assert_no_error()
        node1_rev2 = rc.decoded
        self.assertEqual("frontend",node1_rev2['metadata']['labels']['cluster'])

        # test removing labels on resources with no labels
        rc = calicoctl("apply",data=node_name1_rev1)
        rc.assert_no_error()
        rc = calicoctl("label nodes node1 cluster --remove")
        rc.assert_error("can not remove label")

    def test_patch(self):
        """
        Test that a basic CRUD flow for patch command works.
        """

        # test patching a node
        rc = calicoctl("create", data=node_name1_rev1)
        rc.assert_no_error()

        rc = calicoctl("patch nodes node1 -p '{\"spec\":{\"bgp\": {\"routeReflectorClusterID\": \"192.168.0.1\"}}}'")
        rc.assert_no_error()

        rc = calicoctl("get nodes node1 -o yaml")
        rc.assert_no_error()
        node1_rev1 = rc.decoded
        self.assertEqual("192.168.0.1",node1_rev1['spec']['bgp']['routeReflectorClusterID'])

        # test patching an ippool
        rc = calicoctl("create", data=ippool_name1_rev4_v4)
        rc.assert_no_error()

        rc = calicoctl(
                "patch ippool %s -p '{\"spec\":{\"natOutgoing\": true}}'" % name(ippool_name1_rev4_v4))
        rc.assert_no_error()

        rc = calicoctl(
                "get ippool %s -o yaml" % name(ippool_name1_rev1_v4))
        rc.assert_no_error()
        ippool1_rev1 = rc.decoded
        self.assertEqual(True,ippool1_rev1['spec']['natOutgoing'])
        # Ensure that labels and annotations were merged properly
        self.assertEqual('label-1',ippool1_rev1['metadata']['labels']['test-label'])
        self.assertEqual('annotation-1',ippool1_rev1['metadata']['annotations']['test-annotation'])

        # test patching invalid networkpolicy
        rc = calicoctl('create', data=networkpolicy_name2_rev1)
        rc.assert_no_error()

        rc = calicoctl(
                "patch networkpolicy %s -p '{\"http\": {\"exact\": \"path/to/match\"}}'" % name(networkpolicy_name2_rev1))
        rc.assert_error()

#
# class TestCreateFromFile(TestBase):
#     """
#     Test calicoctl create command
#     Test data is a pair of different resource objects of each type.
#     Test creates one using json and the other using yaml, then we retrieve
#     them and check the output objects are the same as we input when retrieved
#     in both yaml and json formats.
#     """
#
#     testdata = [
#         ("bgpPeer1", {
#             'apiVersion': API_VERSION,
#             'kind': 'BGPPeer',
#             'metadata': { 'name': 'bgppeer-123'},
#             'spec':  {'node': 'node1',
#                       'peerIP': '192.168.0.250',
#                       'asNumber': 64514},
#         }),
#         ("bgpPeer2", {
#             'apiVersion': API_VERSION,
#             'kind': 'BGPPeer',
#             'metadata': { 'name': 'bgppeer-456'},
#             'spec': {'node': 'node2',
#                      'peerIP': 'fd5f::6:ee',
#                      'asNumber': 64590},
#         }),
#         ("hostEndpoint1", {
#             'apiVersion': API_VERSION,
#             'kind': 'HostEndpoint',
#             'metadata': { 'name': 'endpoint1', 'labels': {'type': 'database'}},
#             'spec': {'interfaceName': 'eth0',
#                      'profiles': ['prof1',
#                                   'prof2'],
#                      'node': 'host1'}
#         }),
#         ("hostEndpoint2", {
#             'apiVersion': API_VERSION,
#             'kind': 'HostEndpoint',
#             'metadata': { 'name': 'endpoint2', 'labels': {'type': 'frontend'}},
#             'spec': {'interfaceName': 'cali7',
#                      'profiles': ['prof1',
#                                   'prof2'],
#                      'node': 'host2',
#                      'ports': [{"name": "tcp-port",
#                                 "port": 1234,
#                                 "protocol": "tcp"},
#                                {"name": "udp-port",
#                                 "port": 5000,
#                                 "protocol": "udp"}]}}
#         }),
#         ("workloadEndpoint1", {
#             'apiVersion': API_VERSION,
#             'kind': 'WorkloadEndpoint',
#             'metadata': {'name': 'endpoint2',
#                          'labels': {'type': 'frontend'}},
#             'spec': {'interfaceName': 'cali7',
#                      'profiles': ['prof1',
#                                   'prof2'],
#                      'node': 'host2',
#                      'orchestrator': 'orch',
#                      'workload': 'workl',
#                      'ipNetworks': ['10.0.0.1/32'],
#                      'ports': [{"name": "tcp-port",
#                                 "port": 1234,
#                                 "protocol": "tcp"},
#                                {"name": "udp-port",
#                                 "port": 5000,
#                                 "protocol": "udp"}]}
#         }),
#         ("networkPolicy1", {'apiVersion': API_VERSION,
#                      'kind': 'NetworkPolicy',
#                      'metadata': {'name': 'policy1',
#                                   'namespace': 'default'},
#                      'spec': {'egress': [{'action': 'allow',
#                                           'source': {
#                                               'selector':
#                                                   "type=='application'"},
#                                           'destination': {},
#                                           }],
#                               'ingress': [{'notICMP': {'type': 19, 'code': 255},
#                                            'ipVersion': 4,
#                                            'action': 'deny',
#                                            'destination': {
#                                                'notNets': ['10.3.0.0/16'],
#                                                'notPorts': ['110:1050'],
#                                                'notSelector': "type=='apples'",
#                                                'notTag': "bananas",
#                                                'nets': ['10.2.0.0/16'],
#                                                'ports': ['100:200'],
#                                                'selector':
#                                                    "type=='application'",
#                                                'tag': 'alphatag'},
#                                            'icmp': {'type': 10, 'code': 6},
#                                            'protocol': 'tcp',
#                                            'source': {
#                                                'notNets': ['10.1.0.0/16'],
#                                                'notPorts': [1050],
#                                                'notSelector': "type=='database'",
#                                                'notTag': 'bartag',
#                                                'nets': ['10.0.0.0/16'],
#                                                'ports': [1234,
#                                                          '10:1024',
#                                                          'named-port'],
#                                                'selector':
#                                                    "type=='application'",
#                                                'tag': 'footag'}}],
#                               'order': 100,
#                               'selector': "type=='database'",
#                               'types': ['ingress', 'egress']}
#         }),
#         ("networkPolicy2", {'apiVersion': API_VERSION,
#                      'kind': 'NetworkPolicy',
#                      'metadata': {'name': 'policy2',
#                                   'namespace': 'default'},
#                      'spec': {'egress': [{'action': 'deny',
#                                           'destination': {},
#                                           'protocol': 'tcp',
#                                           'source': {}}],
#                               'ingress': [{'action': 'allow',
#                                            'destination': {},
#                                            'protocol': 'udp',
#                                            'source': {}}],
#                               'order': 100000,
#                               'applyOnForward': True,
#                               'doNotTrack': True,
#                               'types': ['ingress', 'egress']}
#         }),
#         ("networkPolicy3", {'apiVersion': API_VERSION,
#                      'kind': 'NetworkPolicy',
#                      'metadata': {'name': 'policy2',
#                                   'namespace': 'default'},
#                      'spec': {'egress': [{'action': 'allow',
#                                           'destination': {
#                                               'ports': ['http-port']},
#                                           'protocol': 'tcp',
#                                           'source': {}}],
#                               'selector': "type=='application'",
#                               'types': ['egress']}
#         }),
#         ("networkPolicy4", {'apiVersion': API_VERSION,
#                      'kind': 'NetworkPolicy',
#                      'metadata': {'name': 'policy2',
#                                   'namespace': 'default'},
#                      'spec': {
#                          'egress': [{
#                              'action': 'allow',
#                              'destination': {'ports': ['Telnet']},
#                              'protocol': 'udp',
#                              'source': {},
#                          }],
#                          'ingress': [{
#                              'action': 'allow',
#                              'destination': {
#                                  'ports': ['echo', 53, 17, 'Quote']
#                              },
#                              'protocol': 'udp',
#                              'source': {},
#                          }],
#                          'selector': "type=='application'",
#                          'types': ['egress', 'ingress']
#                    }}),
#         ("pool1", {'apiVersion': API_VERSION,
#                    'kind': 'IPPool',
#                    'metadata': {'name': 'ippool1'},
#                    'spec': {'ipip': {'mode': "Always"},
#                             'cidr': "10.0.1.0/24"}
#                    }),
#         ("pool2", {'apiVersion': API_VERSION,
#                    'kind': 'IPPool',
#                    'metadata': {'name': 'ippool2'},
#                    'spec': {'ipip': {'mode': 'CrossSubnet'},
#                             'cidr': "10.0.2.0/24"}
#                    }),
#         ("profile1", {'apiVersion': API_VERSION,
#                       'kind': 'Profile',
#                       'metadata': {
#                           'labels': {'foo': 'bar'},
#                           'name': 'profile1'
#                       },
#                       'spec': {
#                           'egress': [{'action': 'allow',
#                                       'destination': {},
#                                       'source': {
#                                           'selector': "type=='application'"}}],
#                           'ingress': [{'notICMP': {'type': 19, 'code': 255},
#                                        'ipVersion': 4,
#                                        'action': 'deny',
#                                        'destination': {
#                                            'notNets': ['10.3.0.0/16'],
#                                            'notPorts': ['110:1050'],
#                                            'notSelector': "type=='apples'",
#                                            'notTag': "bananas",
#                                            'nets': ['10.2.0.0/16'],
#                                            'ports': ['100:200'],
#                                            'selector': "type=='application'",
#                                            'tag': 'alphatag'},
#                                        'icmp': {'type': 10, 'code': 6},
#                                        'protocol': 'tcp',
#                                        'source': {
#                                            'notNets': ['10.1.0.0/16'],
#                                            'notPorts': [1050],
#                                            'notSelector': "type=='database'",
#                                            'notTag': 'bartag',
#                                            'nets': ['10.0.0.0/16'],
#                                            'ports': [1234, '10:20'],
#                                            'selector': "type=='application'",
#                                            'tag': "production"}}],
#                       }}),
#         ("profile2", {'apiVersion': API_VERSION,
#                       'kind': 'Profile',
#                       'metadata': {
#                           'name': 'profile2',
#                       },
#                       'spec': {
#                           'egress': [{'action': 'allow',
#                                       'destination': {},
#                                       'source': {}}],
#                           'ingress': [{'ipVersion': 6,
#                                        'action': 'deny',
#                                        'destination': {},
#                                        'source': {}}],
#                       }}),
#     ]
#
#     @parameterized.expand(testdata)
#     def test_create_from_file_yaml(self, name, data):
#         self._check_data_save_load(data)
#         res_type = data['kind']
#         logger.debug("Testing %s" % res_type)
#         # Write out the files to load later
#         self.writeyaml('/tmp/%s-1.yaml' % res_type, data)
#
#         calicoctl("create", "/tmp/%s-1.yaml" % res_type)
#
#         # Check both come out OK in yaml:
#         self.check_data_in_datastore([data], res_type)
#
#         # Check both come out OK in json:
#         self.check_data_in_datastore([data], res_type, yaml_format=False)
#
#         # Tidy up
#         calicoctl("delete", "/tmp/%s-1.yaml" % res_type)
#
#         # Check it deleted
#         self.check_data_in_datastore([], res_type)
#
#     @parameterized.expand(testdata)
#     def test_create_from_file_json(self, name, data):
#         self._check_data_save_load(data)
#         res_type = data['kind']
#         logger.debug("Testing %s" % res_type)
#         # Write out the files to load later
#         self.writejson('/tmp/%s-1.json' % res_type, data)
#
#         calicoctl("create", "/tmp/%s-1.json" % res_type)
#
#         # Check both come out OK in yaml:
#         self.check_data_in_datastore([data], res_type)
#
#         # Check both come out OK in json:
#         self.check_data_in_datastore([data], res_type, yaml_format=False)
#
#         # Tidy up
#         calicoctl("delete", "/tmp/%s-1.json" % res_type)
#
#         # Check it deleted
#         self.check_data_in_datastore([], res_type)
#
#     @parameterized.expand(testdata)
#     def test_create_from_stdin_json(self, name, data):
#         self._check_data_save_load(data)
#         res_type = data['kind']
#         logger.debug("Testing %s" % res_type)
#         # Write out the files to load later
#         self.writejson('/tmp/%s-1.json' % res_type, data)
#
#         # Test use of create with stdin
#         calicoctl("create", "/tmp/%s-1.json" % res_type, True)
#
#         # Check both come out OK in yaml:
#         self.check_data_in_datastore([data], res_type)
#
#         # Check both come out OK in json:
#         self.check_data_in_datastore([data], res_type, yaml_format=False)
#
#         # Tidy up
#         calicoctl("delete", "/tmp/%s-1.json" % res_type)
#
#         # Check it deleted
#         self.check_data_in_datastore([], res_type)
#
#     @parameterized.expand(testdata)
#     def test_create_from_stdin_yaml(self, name, data):
#         self._check_data_save_load(data)
#         res_type = data['kind']
#         logger.debug("Testing %s" % res_type)
#         # Write out the files to load later
#         self.writeyaml('/tmp/%s-1.yaml' % res_type, data)
#
#         # Test use of create with stdin
#         calicoctl("create", "/tmp/%s-1.yaml"  % res_type, True)
#
#         # Check both come out OK in yaml:
#         self.check_data_in_datastore([data], res_type)
#
#         # Check both come out OK in yaml:
#         self.check_data_in_datastore([data], res_type, yaml_format=False)
#
#         # Tidy up
#         calicoctl("delete", "/tmp/%s-1.yaml" % res_type)
#
#         # Check it deleted
#         self.check_data_in_datastore([], res_type)
#
#     @parameterized.expand([
#         ("bgpPeer",
#          {
#              'apiVersion': API_VERSION,
#              'kind': 'BGPPeer',
#              'metadata': {'name': 'bgppeer-abc'},
#              'spec': {'asNumber': 64514,
#                       'peerIP': '192.168.0.250',
#                       'node': 'Node1'}
#          },
#          {
#              'apiVersion': API_VERSION,
#              'kind': 'BGPPeer',
#              'metadata': {'name': 'bgppeer-def'},
#              'spec': {'asNumber': 64590,
#                       'peerIP': 'fd5f::6:ee',
#                       'node': 'node2'}
#          }
#          ),
#         ("hostEndpoint",
#          {
#              'apiVersion': API_VERSION,
#              'kind': 'HostEndpoint',
#              'metadata': {'labels': {'type': 'database'},
#                           'name': 'endpoint3'},
#              'spec': {'interfaceName': 'eth0',
#                       'profiles': ['prof1',
#                                    'prof2'],
#                       'node': 'host1',}
#          },
#          {
#              'apiVersion': API_VERSION,
#              'kind': 'HostEndpoint',
#              'metadata': {'labels': {'type': 'frontend'},
#                           'name': 'endpoint4'},
#              'spec': {'interfaceName': 'cali7',
#                       'profiles': ['prof1',
#                                    'prof2'],
#                       'node': 'host2',}
#          },
#          ),
#         ("policy",
#          {'apiVersion': API_VERSION,
#           'kind': 'NetworkPolicy',
#           'metadata': {'name': 'policy-123',
#                        'namespace': 'default' },
#           'spec': {'egress': [{'action': 'allow',
#                                'source': {
#                                    'selector': "type=='application'"},
#                                'destination': {},
#                                }],
#                    'ingress': [{'notICMP': {'type': 19, 'code': 255},
#                                 'ipVersion': 4,
#                                 'action': 'deny',
#                                 'destination': {
#                                     'notNets': ['10.3.0.0/16'],
#                                     'notPorts': ['110:1050'],
#                                     'notSelector': "type=='apples'",
#                                     'notTag': "bananas",
#                                     'nets': ['10.2.0.0/16'],
#                                     'ports': ['100:200'],
#                                     'selector': "type=='application'",
#                                     'tag': 'alphatag'},
#                                 'icmp': {'type': 10, 'code': 6},
#                                 'protocol': 'tcp',
#                                 'source': {'notNets': ['10.1.0.0/16'],
#                                            'notPorts': [1050],
#                                            'notSelector': "type=='database'",
#                                            'notTag': 'bartag',
#                                            'nets': ['10.0.0.0/16'],
#                                            'ports': [1234, '10:1024'],
#                                            'selector': "type=='application'",
#                                            'tag': 'footag'}}],
#                    'order': 100,
#                    'selector': "type=='database'",
#                    'types': ['ingress', 'egress']}},
#          {'apiVersion': API_VERSION,
#           'kind': 'NetworkPolicy',
#           'metadata': {'name': 'policy-456',
#                        'namespace': 'default' },
#           'spec': {'egress': [{'action': 'deny',
#                                'destination': {},
#                                'protocol': 'tcp',
#                                'source': {}}],
#                    'ingress': [{'action': 'allow',
#                                 'destination': {},
#                                 'protocol': 'udp',
#                                 'source': {}}],
#                    'order': 100000,
#                    'types': ['ingress', 'egress']}},
#          ),
#         ("ipPool",
#          {'apiVersion': API_VERSION,
#           'kind': 'IPPool',
#           'metadata': {'name': 'ippool-3'},
#           'spec': {'ipip': {'mode': 'Always'},
#                    'cidr': "10.0.1.0/24"}
#           },
#          {'apiVersion': API_VERSION,
#           'kind': 'IPPool',
#           'metadata':  {'name': 'ippool-4'},
#           'spec': {'ipip': {'mode': 'Always'},
#                    'cidr': "10.0.2.0/24"}
#           },
#          ),
#         ("profile",
#          {'apiVersion': API_VERSION,
#           'kind': 'Profile',
#           'metadata': {
#               'labels': {'foo': 'bar'},
#               'name': 'profile-2',
#           },
#           'spec': {
#               'egress': [{'action': 'allow',
#                           'destination': {},
#                           'source': {
#                               'selector': "type=='application'"}}],
#               'ingress': [{'notICMP': {'type': 19, 'code': 255},
#                            'ipVersion': 4,
#                            'action': 'deny',
#                            'destination': {
#                                'notNets': ['10.3.0.0/16'],
#                                'notPorts': ['110:1050'],
#                                'notSelector': "type=='apples'",
#                                'notTag': "bananas",
#                                'nets': ['10.2.0.0/16'],
#                                'ports': ['100:200'],
#                                'selector': "type=='application'",
#                                'tag': 'alphatag'},
#                            'icmp': {'type': 10, 'code': 6},
#                            'protocol': 'tcp',
#                            'source': {'notNets': ['10.1.0.0/16'],
#                                       'notPorts': [1050],
#                                       'notSelector': "type=='database'",
#                                       'notTag': 'bartag',
#                                       'nets': ['10.0.0.0/16'],
#                                       'ports': [1234, '10:20'],
#                                       'selector': "type=='application'",
#                                       'tag': "production"}}],
#               }},
#          {'apiVersion': API_VERSION,
#           'kind': 'Profile',
#           'metadata': {
#               'name': 'profile-3',
#           },
#           'spec': {
#               'egress': [{'action': 'allow',
#                           'destination': {},
#                           'source': {}}],
#               'ingress': [{'ipVersion': 6,
#                            'action': 'deny',
#                            'destination': {},
#                            'source': {}}],
#               }},
#          )
#     ])
#     def test_create_from_file(self, res, data1, data2):
#         self._check_data_save_load(data1)
#         self._check_data_save_load(data2)
#         logger.debug("Testing %s" % res)
#         # Write out the files to load later
#         self.writeyaml('/tmp/%s-1.yaml' % res, data1)
#         self.writejson('/tmp/%s-2.json' % res, data2)
#
#         calicoctl("create", "/tmp/%s-1.yaml" % res)
#         # Test use of create with stdin
#         #TODO - There shouldn't be a hardcoded path here
#         calicoctl("create", "/tmp/%s-2.json" % res,  True)
#
#         # Check both come out OK in yaml:
#         self.check_data_in_datastore([data1, data2], res)
#
#         # Check both come out OK in json:
#         self.check_data_in_datastore([data1, data2], res, yaml_format=False)
#
#         # Tidy up
#         calicoctl("delete", "/tmp/%s-1.yaml" % res)
#         calicoctl("delete", "/tmp/%s-2.json" % res)
#
#         # Check it deleted
#         self.check_data_in_datastore([], res)
#
#     @parameterized.expand([
#         ("bgpPeer",
#          {
#              'apiVersion': API_VERSION,
#              'kind': 'BGPPeer',
#              'metadata': {'name': 'bgppeer-5'},
#              'spec': {'asNumber': 64514,
#                       'node': 'Node1',
#                       'peerIP': '192.168.0.250'}
#          },
#          {
#              'apiVersion': API_VERSION,
#              'kind': 'BGPPeer',
#              'metadata': {'name': 'bgppeer-6'},
#              'spec': {'asNumber': 64590,
#                       'node': 'Node1',
#                       'peerIP': '192.168.0.250'}
#          }
#          ),
#         ("hostEndpoint",
#          {
#              'apiVersion': API_VERSION,
#              'kind': 'HostEndpoint',
#              'metadata': {'labels': {'type': 'database'},
#                           'name': 'endpoint-7'},
#              'spec': {'interfaceName': 'eth0',
#                       'profiles': ['prof1',
#                                    'prof2'],
#                       'node': 'host1'}
#          },
#          {
#              'apiVersion': API_VERSION,
#              'kind': 'HostEndpoint',
#              'metadata': {'labels': {'type': 'frontend'},
#                           'name': 'endpoint-8'},
#              'spec': {'node': 'host1',
#                       'interfaceName': 'cali7',
#                       'profiles': ['prof1',
#                                    'prof2']}
#          },
#          ),
#         ("policy",
#          {'apiVersion': API_VERSION,
#           'kind': 'NetworkPolicy',
#           'metadata': {'name': 'policy3',
#                        'namespace': 'default' },
#           'spec': {'egress': [{'action': 'deny',
#                                'protocol': 'tcp',
#                                'destination': {},
#                                'source': {
#                                    'notNets': ['aa:bb:cc:ff::/100', 'aa:bb:cc:fe::/100'],
#                                    'notPorts': [100],
#                                    'notTag': 'abcd'}}],
#                    'ingress': [{'action': 'allow',
#                                 'destination': {
#                                     'nets': ['10.20.30.40/32'],
#                                     'tag': 'database'},
#                                 'icmp': {'code': 100,
#                                          'type': 10},
#                                 'protocol': 'udp',
#                                 'source': {
#                                     'nets': ['1.2.0.0/16'],
#                                     'ports': [1, 2, 3, 4],
#                                     'tag': 'web'}}],
#                    'order': 6543215.5,
#                    'types': ['ingress', 'egress']}},
#          {'apiVersion': API_VERSION,
#           'kind': 'NetworkPolicy',
#           'metadata': {'name': 'policy4',
#                        'namespace': 'default'},
#           'spec': {'egress': [{'action': 'deny',
#                                'protocol': 'tcp',
#                                'destination': {},
#                                'source': {
#                                    'notNets': ['aa:bb:cc::/100'],
#                                    'notPorts': [100],
#                                    'notTag': 'abcd'}}],
#                    'ingress': [{'action': 'allow',
#                                 'destination': {
#                                     'nets': ['10.20.30.40/32'],
#                                     'tag': 'database'},
#                                 'icmp': {'code': 100,
#                                          'type': 10},
#                                 'protocol': 'udp',
#                                 'source': {
#                                     'nets': ['1.2.3.0/24'],
#                                     'ports': [1, 2, 3, 4],
#                                     'tag': 'web'}}],
#                    'order': 100000,
#                    'types': ['ingress', 'egress']}},
#          ),
#         #  https://github.com/projectcalico/libcalico-go/issues/230
#         ("policy",
#           {'apiVersion': API_VERSION,
#            'kind': 'NetworkPolicy',
#            'metadata': {'name': 'policy5',
#                         'namespace': 'default' },
#            'spec': {'egress': [{'action': 'deny',
#                                 'protocol': 'tcp',
#                                 'destination': {},
#                                 'source': {
#                                     'notNets': ['aa:bb:cc:ff::/100'],
#                                     'notPorts': [100],
#                                     'notTag': 'abcd'}}],
#                     'ingress': [{'action': 'allow',
#                                  'destination': {
#                                      'nets': ['10.20.30.40/32'],
#                                      'tag': 'database'},
#                                  'icmp': {'code': 100,
#                                           'type': 10},
#                                  'protocol': 'udp',
#                                  'source': {
#                                      'nets': ['1.2.0.0/16'],
#                                      'ports': [1, 2, 3, 4],
#                                      'tag': 'web'}}],
#                     'order': 6543215.321,
#                     'types': ['ingress', 'egress']}},
#           {'apiVersion': API_VERSION,
#            'kind': 'NetworkPolicy',
#            'metadata': {'name': 'policy6',
#                         'namespace': 'default'},
#            'spec': {'egress': [{'action': 'deny',
#                                 'protocol': 'tcp',
#                                 'destination': {},
#                                 'source': {
#                                     'notNets': ['aa:bb:cc::/100'],
#                                     'notPorts': [100],
#                                     'notTag': 'abcd'}}],
#                     'ingress': [{'action': 'allow',
#                                  'destination': {
#                                      'nets': ['10.20.30.40/32'],
#                                      'tag': 'database'},
#                                  'icmp': {'code': 100,
#                                           'type': 10},
#                                  'protocol': 'udp',
#                                  'source': {
#                                      'nets': ['1.2.3.0/24'],
#                                      'ports': [1, 2, 3, 4],
#                                      'tag': 'web'}}],
#                     'order': 100000,
#                     'types': ['ingress', 'egress']}},
#         ),
#         ("ipPool",
#          {'apiVersion': API_VERSION,
#           'kind': 'IPPool',
#           'metadata': {'name': 'ippool-5'},
#           'spec': {'cidr': "10.0.1.0/24"}
#           },
#          {'apiVersion': API_VERSION,
#           'kind': 'IPPool',
#           'metadata': {'name': 'ippool-6'},
#           'spec': {'ipip': {'mode': 'Always'},
#                    'cidr': "10.0.1.0/24"}
#           },
#          ),
#         ("profile",
#          {'apiVersion': API_VERSION,
#           'kind': 'Profile',
#           'metadata': {
#               'name': 'profile-9',
#               'labels': {'type': 'database'},
#           },
#           'spec': {
#               'egress': [{
#                   'source': {},
#                   'destination': {},
#                   'action': 'deny'}],
#               'ingress': [{
#                   'source': {},
#                   'destination': {},
#                   'action': 'deny'}],
#           }, },
#          {'apiVersion': API_VERSION,
#           'kind': 'Profile',
#           'metadata': {
#               'labels': {'type': 'frontend'},
#               'name': 'profile-10',
#           },
#           'spec': {
#               'egress': [{
#                   'source': {},
#                   'destination': {},
#                   'action': 'deny'}],
#               'ingress': [{
#                   'source': {},
#                   'destination': {},
#                   'action': 'deny'}],
#               }},
#          )
#     ])
#     def test_apply_create_replace(self, res, data1, data2):
#         """
#         Test calicoctl create/apply/replace/delete commands.
#         Test data is a pair of resource objects - both are the same object,
#         but the details differ in some way to simulate a user updating the
#         object.
#         """
#         self._check_data_save_load(data1)
#         self._check_data_save_load(data2)
#         logger.debug("Testing %s" % res)
#
#         # Write test data files for loading later
#         self.writeyaml('/tmp/data1.yaml', data1)
#         self.writejson('/tmp/data2.json', data2)
#
#         # apply - create when not present
#         calicoctl("apply", "/tmp/data1.yaml")
#         # Check it went in OK
#         self.check_data_in_datastore([data1], res)
#
#         # create - skip overwrite with data2
#         calicoctl("create", "/tmp/data2.json --skip-exists")
#         # Check that nothing's changed
#         self.check_data_in_datastore([data1], res)
#
#         # replace - overwrite with data2
#         calicoctl("replace", "/tmp/data2.json")
#         # Check that we now have data2 in the datastore
#         self.check_data_in_datastore([data2], res)
#
#         # apply - overwrite with data1
#         calicoctl("apply", "/tmp/data1.yaml")
#         # Check that we now have data1 in the datastore
#         self.check_data_in_datastore([data1], res)
#
#         # delete
#         calicoctl("delete --filename=/tmp/data1.yaml")
#         # Check it deleted
#         self.check_data_in_datastore([], res)
#
#     def _check_data_save_load(self, data):
#         """
#         Confirms that round tripping the data via json and yaml format works
#         OK so that we can be sure any errors the tests find are due to the
#         calicoctl code under test
#         :param data: The dictionary of test data to check
#         :return: None.
#         """
#         exp_data=data #['kind']+"List"
#
#         # Do yaml first
#         self.writeyaml('/tmp/test', data)
#         with open('/tmp/test', 'r') as f:
#             output = yaml.safe_load(f.read())
#         self.assert_same(exp_data, output)
#         # Now check json
#         self.writejson('/tmp/test', data)
#         with open('/tmp/test', 'r') as f:
#             output = json.loads(f.read())
#         self.assert_same(exp_data, output)
#


class InvalidData(TestBase):
    testdata = [
                   ("bgpPeer-invalidASnum", {
                       'apiVersion': API_VERSION,
                       'kind': 'BGPPeer',
                       'metadata': {'name': 'bgppeer2'},
                       'spec': {'asNumber': 4294967296,  # Valid numbers are <=4294967295
                                'node': 'node1',
                                'peerIP': '192.168.0.250',
                                'scope': 'node'}
                   }, 'cannot unmarshal number into Go value of type string'),
                   ("bgpPeer-invalidIP", {
                       'apiVersion': API_VERSION,
                       'kind': 'BGPPeer',
                       'metadata': {'name': 'bgppeer3'},
                       'spec': {'asNumber': 64513,
                                'node': 'node1',
                                'peerIP': '192.168.0.256',
                                }
                   }, "error with field PeerIP = '192.168.0.256'"),
                   ("bgpPeer-apiversion", {
                       'apiVersion': 'v7',
                       'kind': 'BGPPeer',
                       'metadata': {'name': 'bgppeer4'},
                       'spec': {'asNumber': 64513,
                                'node': 'node1',
                                'peerIP': '192.168.0.250',
                                }
                   }, 'Unknown resource type (BGPPeer) and/or version (v7)'),
                   ("bgpPeer-invalidIpv6", {
                       'apiVersion': API_VERSION,
                       'kind': 'BGPPeer',
                       'metadata': {'name': 'bgppeer5'},
                       'spec': {'asNumber': 64590,
                                'node': 'node2',
                                'peerIP': 'fd5f::6::ee',
                                }
                   }, "error with field PeerIP = 'fd5f::6::ee'"),
                   ("bgpPeer-invalidnodename", {
                       'apiVersion': API_VERSION,
                       'kind': 'BGPPeer',
                       'metadata': {'name': 'bgppeer6'},
                       'spec': {'asNumber': 64590,
                                'node': 'node 2',
                                'peerIP': 'fd5f::6:ee',
                                }
                   }, "error with field Node = 'node 2'"),
                   # See issue https://github.com/projectcalico/libcalico-go/issues/248
                   ("bgpPeer-unrecognisedfield", {
                       'apiVersion': API_VERSION,
                       'kind': 'BGPPeer',
                       'metadata': {'name': 'bgppeer7'},
                       'spec': {'asNumber': 64590,
                                'unknown': 'thing',
                                'node': 'node2',
                                'peerIP': 'fd5f::6:ee',
                                }
                   }, 'field in document is not recognized or is in the wrong location: unknown'),
                   # See issue https://github.com/projectcalico/libcalico-go/issues/222
                   # ("bgpPeer-longname", {
                   #     'apiVersion': API_VERSION,
                   #     'kind': 'BGPPeer',
                   #     'metadata': {'name': 'bgppeer8'},
                   #     'spec': {'asNumber': 64590,
                   #              'node':
                   #                  'testtesttesttesttesttesttesttesttesttesttest'
                   #                  'testtesttesttesttesttesttesttesttesttesttest'
                   #                  'testtesttesttesttesttesttesttesttesttesttest'
                   #                  'testtesttesttesttesttesttesttesttesttesttest'
                   #                  'testtesttesttesttesttesttesttesttesttesttest'
                   #                  'testtesttesttesttesttesttesttesttesttesttest'
                   #                  'testtesttesttesttesttesttesttesttesttesttest'
                   #                  'testtesttesttesttesttesttesttesttesttesttest'
                   #                  'testtesttesttesttesttesttesttesttesttesttest'
                   #                  'testtesttesttesttesttesttesttesttesttesttest'
                   #                  'testtesttesttesttesttesttesttesttesttesttest',
                   #              'peerIP': 'fd5f::6:ee',
                   #              }
                   # }),
                   ("hostEndpoint-invalidInterface", {
                       'apiVersion': API_VERSION,
                       'kind': 'HostEndpoint',
                       'metadata': {'labels': {'type': 'database'},
                                    'name': 'endpoint1'},
                       'spec': {'interfaceName': 'wibblywobblyeth0',  # overlength interface name
                                'profiles': ['prof1',
                                             'prof2'],
                                'node': 'host1',
                                }
                   }, "error with field InterfaceName = 'wibblywobblyeth0'"),
                   # https://github.com/projectcalico/libcalico-go/pull/236/files
                   ("policy-invalidHighPortinList", {
                       'apiVersion': API_VERSION,
                       'kind': 'NetworkPolicy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'Egress': [{'action': 'Deny',
                                            'destination': {},
                                            'source': {
                                                'protocol': 'TCP',
                                                'ports': [10, 90, 65536]  # Max port is 65535
                                            },
                                            }],
                                'Ingress': [{'action': 'Allow',
                                             'destination': {},
                                             'protocol': 'UDP',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}
                   }, 'cannot unmarshal number 65536 into Go value of type uint16'),
                   # https://github.com/projectcalico/libcalico-go/issues/248
                   ("policy-invalidHighPortinRange", {
                       'apiVersion': API_VERSION,
                       'kind': 'NetworkPolicy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'Egress': [{'action': 'Deny',
                                            'destination': {},
                                            'source': {
                                                'protocol': 'TCP',
                                                'ports': ['1:65536']  # Max port is 65535
                                            },
                                            }],
                                'Ingress': [{'action': 'Allow',
                                             'destination': {},
                                             'protocol': 'UDP',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}
                   }, 'invalid maximum port number in range (1:65536)'),
                   ("policy-invalidLowPortinRange", {
                       'apiVersion': API_VERSION,
                       'kind': 'NetworkPolicy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'Egress': [{'action': 'Deny',
                                            'destination': {},
                                            'protocol': 'TCP',
                                            'source': {
                                                'ports': ['0:65535'],  # Min port is 1
                                            },
                                            }],
                                'Ingress': [{'action': 'Allow',
                                             'destination': {},
                                             'protocol': 'UDP',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}
                   }, "error with field Port = '0' (port range invalid, port number must be between 1 and 65535)"),
                   ("policy-invalidLowPortinList", {
                       'apiVersion': API_VERSION,
                       'kind': 'NetworkPolicy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'Egress': [{'action': 'Deny',
                                            'destination': {},
                                            'protocol': 'TCP',
                                            'source': {
                                                'ports': [0, 10, 80]  # Min port is 1
                                            },
                                            }],
                                'Ingress': [{'action': 'Allow',
                                             'destination': {},
                                             'protocol': 'UDP',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}
                   }, "error with field Port = '0' (port range invalid, port number must be between 1 and 65535)"),
                   ("policy-invalidReversedRange", {
                       'apiVersion': API_VERSION,
                       'kind': 'NetworkPolicy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'Egress': [{'action': 'Deny',
                                            'destination': {},
                                            'protocol': 'TCP',
                                            'source': {
                                                'ports': ['65535:1']  # range should be low-high
                                            },
                                            }],
                                'Ingress': [{'action': 'Allow',
                                             'destination': {},
                                             'protocol': 'UDP',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}
                   }, 'minimum port number (65535) is greater than maximum port number (1) in port range'),
                   ("policy-invalidAction", {
                       'apiVersion': API_VERSION,
                       'kind': 'NetworkPolicy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'Egress': [{'action': 'jumpupanddown',  # invalid action
                                            'destination': {},
                                            'protocol': 'TCP',
                                            'source': {},
                                            }],
                                'Ingress': [{'action': 'Allow',
                                             'destination': {},
                                             'protocol': 'UDP',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}
                   }, "error with field Action = 'jumpupanddown'"),
                   ("policy-NetworkPolicyNameRejected", {
                       'apiVersion': API_VERSION,
                       'kind': 'NetworkPolicy',
                       'metadata': {'name': 'knp.default.rejectmeplease',
                                    'namespace': 'default'},
                       'spec': {'Egress': [{'action': 'Allow',
                                            'destination': {},
                                            'protocol': 'TCP',
                                            'source': {},
                                            }],
                                'Ingress': [{'action': 'Allow',
                                             'destination': {},
                                             'protocol': 'UDP',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}
                   }, 'kubernetes network policies must be managed through the kubernetes API'),
                   ("pool-invalidNet1", {
                       'apiVersion': API_VERSION,
                       'kind': 'IPPool',
                       'metadata': {'name': 'pool-invalid-net-1'},
                       'spec': {
                           'ipipMode': 'Always',
                           'cidr': "10.0.1.0/33"}  # impossible mask
                   }, "CIDR = '10.0.1.0/33'"),
                   ("pool-invalidNet2", {
                       'apiVersion': API_VERSION,
                       'kind': 'IPPool',
                       'metadata': {'name': 'pool-invalid-net-1'},
                       'spec': {
                           'ipipMode': 'Always',
                           'cidr': "10.0.256.0/24"}  # invalid octet
                   }, "CIDR = '10.0.256.0/24'"),
                   ("pool-invalidNet3", {
                       'apiVersion': API_VERSION,
                       'kind': 'IPPool',
                       'metadata': {'name': 'pool-invalid-net-1'},
                       'spec': {
                           'ipipMode': 'Always',
                           'cidr': "10.0.250.0/32"}  # no mask
                   }, "error with field IPPool.Spec.CIDR = '10.0.250.0/32' "
                      "(IP pool size is too small for use with Calico IPAM. It must be equal to or greater than the block size.)"),
                   ("pool-invalidNet4", {
                       'apiVersion': API_VERSION,
                       'kind': 'IPPool',
                       'metadata': {'name': 'pool-invalid-net-1'},
                       'spec': {
                           'ipipMode': 'Never',
                           'cidr': "fd5f::2::1/32"}  # too many ::
                   }, "CIDR = 'fd5f::2::1/32'"),
                   #  https://github.com/projectcalico/libcalico-go/issues/224
                   # ("pool-invalidNet5a", {'apiVersion': API_VERSION,
                   #                       'kind': 'IPPool',
                   #                       'metadata': {'cidr': "::/0"},  # HUGE pool
                   #                       }),
                   # ("pool-invalidNet5b", {'apiVersion': API_VERSION,
                   #                       'kind': 'IPPool',
                   #                       'metadata': {'cidr': "1.1.1.1/0"},  # BIG pool
                   #                       }),
                   ("pool-invalidNet6", {
                       'apiVersion': API_VERSION,
                       'kind': 'IPPool',
                       'metadata': {'name': 'invalid-net-6'},
                       'spec': {
                           'ipipMode': 'Never',
                           'vxlanMode': 'Never',
                           'cidr': "::/128",
                       }
                       # nothing
                   }, "error with field IPPool.Spec.CIDR = '::/128' "
                      "(IP pool size is too small for use with Calico IPAM. It must be equal to or greater than the block size.)"),
                   ("pool-invalidNet7", {
                       'apiVersion': API_VERSION,
                       'kind': 'IPPool',
                       'metadata': {'name': 'invalid-net-7'},
                       'spec': {
                           'cidr': "192.168.0.0/27"}  # invalid mask
                   }, "error with field IPPool.Spec.CIDR = '192.168.0.0/27' "
                      "(IP pool size is too small for use with Calico IPAM. It must be equal to or greater than the block size.)"),
                   ("pool-invalidNet8", {
                       'apiVersion': API_VERSION,
                       'kind': 'IPPool',
                       'metadata': {'name': 'invalid-net-8'},
                       'spec': {
                           'ipipMode': 'Never',
                           'cidr': "fd5f::1/123",
                       }  # invalid mask
                   }, "IPPool.Spec.CIDR = 'fd5f::/123'"),
                   ("pool-invalidIpIp1", {
                       'apiVersion': API_VERSION,
                       'kind': 'IPPool',
                       'metadata': {'name': 'invalid-ipip-1'},
                       'spec': {'disabled': 'True',  # disabled value must be a bool
                                'cidr': "10.0.1.0/24"}
                   }, "cannot parse string 'True' into field IPPoolSpec.disabled of type bool"),
                   ("pool-invalidIpIp2", {
                       'apiVersion': API_VERSION,
                       'kind': 'IPPool',
                       'metadata': {'name': 'invalid-ipip-2'},
                       'spec': {
                           'disabled': 'Maybe',
                           'cidr': "10.0.1.0/24"}
                   }, "cannot parse string 'Maybe' into field IPPoolSpec.disabled of type bool"),
                   ("profile-ICMPtype", {
                       'apiVersion': API_VERSION,
                       'kind': 'Profile',
                       'metadata': {
                           'name': 'profile2',
                       },
                       'spec': {
                           'Egress': [{'action': 'Allow',
                                       'destination': {},
                                       'source': {}}],
                           'Ingress': [{'ipVersion': 4,
                                        'ICMP': {'type': 256,  # max value 255
                                                 'code': 255},
                                        'action': 'Deny',
                                        'protocol': 'ICMP',
                                        'destination': {},
                                        'source': {}}],
                       }
                   }, "error with field Type = '256'"),
                   ("profile-ICMPcode", {
                       'apiVersion': API_VERSION,
                       'kind': 'Profile',
                       'metadata': {
                           'name': 'profile2',
                       },
                       'spec': {
                           'Egress': [{'action': 'Allow',
                                       'destination': {},
                                       'source': {}}],
                           'Ingress': [{'ipVersion': 4,
                                        'ICMP': {'type': 19,
                                                 'code': 256},  # max value 255
                                        'action': 'Deny',
                                        'protocol': 'ICMP',
                                        'destination': {},
                                        'source': {}}],
                       }
                   }, "error with field Code = '256'"),
               ]

    compound_test_data = [("compound-config", [{
        'apiVersion': API_VERSION,
        'kind': 'BGPPeer',
        'metadata': {
            'name': "compound-config",
        },
        'spec': {
            'node': 'node1',
            'peerIP': '192.168.0.250',
            'asNumber': 64513
        }
    },
        {
            'apiVersion': API_VERSION,
            'kind': 'Profile',
            'metadata': {
                'name': 'profile2',
            },
            'spec': {
                'Egress': [{'action': 'Allow',
                            'destination': {},
                            'source': {}}],
                'Ingress': [{'ipVersion': 4,
                             'ICMP': {'type': 256,  # 1-byte field
                                      'code': 255},
                             'action': 'Deny',
                             'protocol': 'ICMP',
                             'destination': {},
                             'source': {}}],
            },
        }],{"profile2": "error with field Type = '256'"})]

    def check_no_data_in_store(self, testdata):
        out = calicoctl("get %s --output=yaml" % testdata['kind'])
        out.assert_output_contains(
        'apiVersion: %s\n'
        'items: []\n'
        'kind: %sList\n'
        'metadata:\n'
        '  resourceVersion: ' % (API_VERSION, testdata['kind'])
    )

    def check_only_default_profile_returned(self, testdata):
        out = calicoctl("get %s --output=yaml" % testdata['kind'])
        out.assert_output_contains(
        'apiVersion: %s\n'
        'items:\n'
        '- apiVersion: %s\n'
        '  kind: %s\n'
        '  metadata:\n'
        '    creationTimestamp: null\n'
        '    name: projectcalico-default-allow\n'
        '    resourceVersion: "0"\n'
        '  spec:\n'
        '    egress:\n'
        '    - action: Allow\n'
        '      destination: {}\n'
        '      source: {}\n'
        '    ingress:\n'
        '    - action: Allow\n'
        '      destination: {}\n'
        '      source: {}\n'
        'kind: %sList\n'
        'metadata:\n'
        '  resourceVersion: ' % (API_VERSION, API_VERSION, testdata['kind'], testdata['kind'])
    )

    @parameterized.expand(testdata)
    def test_invalid_profiles_rejected(self, name, testdata, error):

        log_and_run("cat << EOF > %s\n%s" % ("/tmp/testfile.yaml", testdata))
        ctl = calicoctl("create", testdata)

        # Profiles are a special case. Getting profiles
        # always returns the default-allow profile.
        if testdata['kind'] == 'Profile':
            self.check_only_default_profile_returned(testdata)
        else:
            self.check_no_data_in_store(testdata)

        # Assert that we saw the correct error being reported
        ctl.assert_error(error)

    @parameterized.expand(compound_test_data)
    def test_invalid_compound_profiles_rejected(self, name, testdata, errors):

        log_and_run("cat << EOF > %s\n%s" % ("/tmp/testfile.yaml", testdata))
        ctl = calicoctl("create", testdata)

        for data in testdata:
            if data['metadata']['name'] in errors:
                if data['kind'] == 'Profile':
                    self.check_only_default_profile_returned(data)
                else:
                    self.check_no_data_in_store(data)


        # Assert that we saw the correct error being reported
        for value in errors.values():
            ctl.assert_error(value)

# TODO: uncomment this once we have default field handling in libcalico
# class TestTypes(TestBase):
#     """
#     Test calicoctl types field. Confirm that for a policy with:
#     1) both ingress and egress rules, the types:ingress,egress
#        field is appended.
#     2) neither an ingress rule nor an egress rule, the
#        types:ingress field is appended.
#     3) only an ingress rule, the types:ingress field is appended.
#     4) only an egress rule, the types:egress field is appended.
#     """
#     def test_types_both_egress_and_ingress(self):
#         """
#         Test that a simple policy with both ingress and egress
#         rules will have the types:ingress,egress field appended.
#         """
#         # Set up simple ingress/egress policy
#         policy1_dict = {'apiVersion': API_VERSION,
#                         'kind': 'NetworkPolicy',
#                         'metadata': {'name': 'policy-9',
#                                      'namespace': 'default'},
#                         'spec': {
#                             'egress': [{
#                                 'action': 'deny',
#                                 'destination': {},
#                                 'source': {},
#                             }],
#                             'ingress': [{
#                                 'action': 'allow',
#                                 'destination': {},
#                                 'source': {},
#                             }],
#                             'selector': "type=='application'"
#                         }
#         }
#         self.writeyaml('/tmp/policy1.yaml', policy1_dict)
#
#         # append types: 'ingress', 'egress'
#         policy1_types_dict = policy1_dict
#         policy1_types_dict['spec'].update({'types': ['ingress', 'egress']})
#
#         # Create the policy using calicoctl
#         calicoctl("create", "/tmp/policy1.yaml")
#
#         # Now read it out (yaml format) with calicoctl and verify it matches:
#         self.check_data_in_datastore([policy1_types_dict], "policy")
#
#         # Remove policy1
#         calicoctl("delete", "/tmp/policy1.yaml")
#
#     def test_types_no_ingress_or_egress(self):
#         """
#         Test that a simple policy with neither an ingress nor an
#         egress rule will have the types:ingress field appended.
#         """
#         # Set up simple policy without ingress or egress rules
#         policy2_dict = {'apiVersion': API_VERSION,
#                         'kind': 'NetworkPolicy',
#                         'metadata': {'name': 'policy-10',
#                                      'namespace': 'default'},
#                         'spec': {
#                             'selector': "type=='application'"
#                         }
#         }
#
#         self.writeyaml('/tmp/policy2.yaml', policy2_dict)
#
#         # Create the policy using calicoctl
#         calicoctl("create", "/tmp/policy2.yaml")
#
#         # append types: 'ingress'
#         policy2_types_dict = policy2_dict
#         policy2_types_dict['spec'].update({'types': ['ingress']})
#
#         # Now read it out (yaml format) with calicoctl and verify it matches:
#         self.check_data_in_datastore([policy2_types_dict], "policy")
#
#         # Remove policy2
#         calicoctl("delete", "/tmp/policy2.yaml")
#
#     def test_types_ingress_only(self):
#         """
#         Test that a simple policy with only an ingress
#         rule will have the types:ingress field appended.
#         """
#         # Set up simple ingress-only policy
#         policy2_dict = {'apiVersion': API_VERSION,
#                         'kind': 'NetworkPolicy',
#                         'metadata': {'name': 'policy-11',
#                                      'namespace': 'default'},
#                         'spec': {
#                             'ingress': [{
#                                 'action': 'allow',
#                                 'destination': {},
#                                 'source': {},
#                             }],
#                             'selector': "type=='application'"
#                         }
#         }
#
#         self.writeyaml('/tmp/policy2.yaml', policy2_dict)
#
#         # Create the policy using calicoctl
#         calicoctl("create", "/tmp/policy2.yaml")
#
#         # append types: 'ingress'
#         policy2_types_dict = policy2_dict
#         policy2_types_dict['spec'].update({'types': ['ingress']})
#
#         # Now read it out (yaml format) with calicoctl and verify it matches:
#         self.check_data_in_datastore([policy2_types_dict], "policy")
#
#         # Remove policy2
#         calicoctl("delete", "/tmp/policy2.yaml")
#
#     def test_types_egress_only(self):
#         """
#         Test that a simple policy with only an egress
#         rule will have the types:egress field appended.
#         """
#         # Set up simple egress-only policy
#         policy2_dict = {'apiVersion': API_VERSION,
#                         'kind': 'NetworkPolicy',
#                         'metadata': {'name': 'policy-12',
#                                      'namespace': 'default'},
#                         'spec': {
#                             'egress': [{
#                                 'action': 'allow',
#                                 'destination': {},
#                                 'source': {},
#                             }],
#                             'selector': "type=='application'"
#                         }
#         }
#
#         self.writeyaml('/tmp/policy2.yaml', policy2_dict)
#
#         # Create the policy using calicoctl
#         calicoctl("create", "/tmp/policy2.yaml")
#
#         # append types: 'egress'
#         policy2_types_dict = policy2_dict
#         policy2_types_dict['spec'].update({'types': ['egress']})
#
#         # Now read it out (yaml format) with calicoctl and verify it matches:
#         self.check_data_in_datastore([policy2_types_dict], "policy")
#
#         # Remove policy2
#         calicoctl("delete", "/tmp/policy2.yaml")
#
