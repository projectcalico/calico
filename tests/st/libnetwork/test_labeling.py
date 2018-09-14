# Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

from unittest import skip

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost
from tests.st.utils.network import NETWORKING_LIBNETWORK
from tests.st.utils.utils import ETCD_CA, ETCD_CERT, \
    ETCD_KEY, ETCD_HOSTNAME_SSL, ETCD_SCHEME, get_ip, \
    retry_until_success, wipe_etcd

POST_DOCKER_COMMANDS = [
    "docker load -q -i /code/calico-node.tar",
    "docker load -q -i /code/busybox.tar",
    "docker load -q -i /code/workload.tar",
]

if ETCD_SCHEME == "https":
    ADDITIONAL_DOCKER_OPTIONS = "--cluster-store=etcd://%s:2379 " \
                                "--cluster-store-opt kv.cacertfile=%s " \
                                "--cluster-store-opt kv.certfile=%s " \
                                "--cluster-store-opt kv.keyfile=%s " % \
                                (ETCD_HOSTNAME_SSL, ETCD_CA, ETCD_CERT,
                                 ETCD_KEY)
else:
    ADDITIONAL_DOCKER_OPTIONS = "--cluster-store=etcd://%s:2379 " % \
                                get_ip()

# TODO: Re-enable
@skip("Disabled until libnetwork is updated for libcalico-go v3")
class TestLibnetworkLabeling(TestBase):
    """
    Tests that labeling is correctly implemented in libnetwork.  Setup
    multiple networks and then run containers with labels and see that
    policy will allow and block traffic.
    """
    hosts = None
    host = None

    @classmethod
    def setUpClass(cls):
        wipe_etcd(get_ip())

        # Rough idea for setup
        #
        #    Network1                  Network2
        #
        #   container1                 container2
        #    foo = bar                  baz = bop
        #
        #   container3                 container4
        #    foo = bing                 foo = bar

        cls.hosts = []
        cls.host1 = DockerHost(
                "host1",
                additional_docker_options=ADDITIONAL_DOCKER_OPTIONS,
                post_docker_commands=POST_DOCKER_COMMANDS,
                start_calico=False,
                networking=NETWORKING_LIBNETWORK)
        cls.host1_hostname = cls.host1.execute("hostname")
        cls.hosts.append(cls.host1)
        cls.host2 = DockerHost(
                "host2",
                additional_docker_options=ADDITIONAL_DOCKER_OPTIONS,
                post_docker_commands=POST_DOCKER_COMMANDS,
                start_calico=False,
                networking=NETWORKING_LIBNETWORK)
        cls.host2_hostname = cls.host1.execute("hostname")
        cls.hosts.append(cls.host2)

        for host in cls.hosts:
            host.start_calico_node(options='--use-docker-networking-container-labels')

        cls.network1 = cls.host1.create_network("network1")
        cls.network2 = cls.host1.create_network("network2")

        cls.workload1_nw1_foo_bar = cls.host1.create_workload(
                "workload1", network=cls.network1,
                labels=["org.projectcalico.label.foo=bar"])
        cls.workload2_nw2_baz_bop = cls.host1.create_workload(
                "workload2", network=cls.network2,
                labels=["org.projectcalico.label.baz=bop"])
        cls.workload3_nw1_foo_bing = cls.host2.create_workload(
                "workload3", network=cls.network1,
                labels=["org.projectcalico.label.foo=bing"])
        cls.workload4_nw2_foo_bar = cls.host2.create_workload(
                "workload4", network=cls.network2,
                labels=["org.projectcalico.label.foo=bar"])

    def setUp(self):
        # Override the per-test setUp to avoid wiping etcd; instead only
        # clean up the data we added.
        self.host1.delete_all_resource("policy")

    def tearDown(self):
        self.host1.delete_all_resource("policy")
        super(TestLibnetworkLabeling, self).tearDown()

    @classmethod
    def tearDownClass(cls):
        # Tidy up
        for host in cls.hosts:
            host.remove_workloads()
        for host in cls.hosts:
            host.cleanup()
            del host

    def test_policy_only_selectors_allow_traffic(self):
        self.host1.add_resource([
            {
                'apiVersion': 'projectcalico.org/v3',
                'kind': 'NetworkPolicy',
                'metadata': {'name': 'allowFooBarToBazBop'},
                'spec': {
                    'ingress': [
                        {
                            'source': {'selector': 'foo == "bar"'},
                            'action': 'Allow',
                        },
                    ],
                    'egress': [{'action': 'Deny'}],
                    'selector': 'baz == "bop"'
                }
            }, {
                'apiVersion': 'projectcalico.org/v3',
                'kind': 'NetworkPolicy',
                'metadata': {'name': 'allowFooBarEgress'},
                'spec': {
                    'selector': 'foo == "bar"',
                    'egress': [{'action': 'Allow'}]
                }
            }
        ])

        retry_until_success(lambda: self.assert_ip_connectivity(
            workload_list=[self.workload1_nw1_foo_bar,
                           self.workload4_nw2_foo_bar],
            ip_pass_list=[self.workload2_nw2_baz_bop.ip],
            ip_fail_list=[self.workload3_nw1_foo_bing.ip]), 3)

    def test_no_policy_allows_no_traffic(self):
        retry_until_success(lambda: self.assert_ip_connectivity(
            workload_list=[self.workload1_nw1_foo_bar,
                           self.workload2_nw2_baz_bop,
                           self.workload3_nw1_foo_bing],
            ip_pass_list=[],
            ip_fail_list=[self.workload4_nw2_foo_bar.ip]), 2)
        retry_until_success(lambda: self.assert_ip_connectivity(
            workload_list=[self.workload2_nw2_baz_bop,
                           self.workload3_nw1_foo_bing,
                           self.workload4_nw2_foo_bar],
            ip_pass_list=[],
            ip_fail_list=[self.workload1_nw1_foo_bar.ip]), 2)
        retry_until_success(lambda: self.assert_ip_connectivity(
            workload_list=[self.workload1_nw1_foo_bar,
                           self.workload3_nw1_foo_bing,
                           self.workload4_nw2_foo_bar],
            ip_pass_list=[],
            ip_fail_list=[self.workload2_nw2_baz_bop.ip]), 2)
        retry_until_success(lambda: self.assert_ip_connectivity(
            workload_list=[self.workload1_nw1_foo_bar,
                           self.workload2_nw2_baz_bop,
                           self.workload4_nw2_foo_bar],
            ip_pass_list=[],
            ip_fail_list=[self.workload3_nw1_foo_bing.ip]), 2)
