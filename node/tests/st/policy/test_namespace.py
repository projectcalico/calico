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

import json
import logging
import subprocess

from tests.st.test_base import TestBase, HOST_IPV4
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.utils import get_ip, log_and_run, retry_until_success, \
    ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_HOSTNAME_SSL, ETCD_SCHEME, \
    handle_failure, clear_on_failures, add_on_failure, wipe_etcd

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)

POST_DOCKER_COMMANDS = [
    "docker load -q -i /code/calico-node.tar",
    "docker load -q -i /code/workload.tar",
]
NAMESPACE_PREFIX = "pcns"

class TestNamespace(TestBase):
    """
    Tests that global network policy and namespaced network policy is correctly
    implemented on namespaced workload endpoints.
    """
    hosts = None

    @classmethod
    def setUpClass(cls):
        # Wipe etcd once before any test in this class runs.
        _log.debug("Wiping etcd")
        wipe_etcd(HOST_IPV4)

        # We set up 2 hosts on top of which running nine workloads in three namespaces.
        # Host1 has 5 workloads.
        #     2 in namespace nsa: [nsa_h1_wl0] [nsa_h1_wl1]
        #     1 in namespace nsb: [nsb_h1_wl0]
        #     2 in default namespace: [default_h1_wl0] [omit_h1_wl0]
        # *omit* means 'namespace' field is not specified during workload setup.
        #
        # Host2 has 4 workloads.
        #     1 in namespace nsa: [nsa_h2_wl0]
        #     2 in namespace nsb: [nsb_h2_wl0] [nsb_h2_wl1]
        #     1 in namespace default: [default_h2_wl0]
        #
        # Global network policies and network policies then apply on namespaced
        # workload endpoints with mixed orders. The test checks connectivity of
        # 4 workloads [nsa_h1_wl0, nsb_h2_wl0, default_h1_wl0, omit_h1_wl0] from
        # other workloads.

        # Create two hosts.
        cls.hosts = []
        cls.host1 = DockerHost("cali-host1",
                               additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                               post_docker_commands=POST_DOCKER_COMMANDS,
                               start_calico=False)
        cls.host1_hostname = cls.host1.execute("hostname")
        cls.host2 = DockerHost("cali-host2",
                               additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                               post_docker_commands=POST_DOCKER_COMMANDS,
                               start_calico=False)
        cls.host2_hostname = cls.host2.execute("hostname")
        cls.hosts.append(cls.host1)
        cls.hosts.append(cls.host2)

        # Start calico node on hosts.
        for host in cls.hosts:
            host.start_calico_node(env_options=" -e FELIX_HEALTHENABLED=true ")

        handle_failure(lambda: retry_until_success(cls.host1.assert_is_ready, retries=30))
        handle_failure(lambda: retry_until_success(cls.host2.assert_is_ready, retries=30))

        # Prepare namespace profile so that we can use namespaceSelector for non-k8s deployment.
        # CNI will use the existing profile which is setup here instead of creating its own.
        cls.add_ns_profile('nsa')
        cls.add_ns_profile('nsb')
        cls.add_ns_profile('default')

        # Create calico network.
        cls.calinet = cls.host1.create_network("calinet")

        # Create workloads for host1
        # For CNI, network is used for cni_name but nothing else.
        # We set network to same value as namespace name to let cni program a
        # namespace profile for us.
        cls.nsa_wl = cls.host1.create_workload(
            "nsa_h1_wl0",
            image="workload",
            network="nsa",
            labels=["wep=nsa_h1_wl0"],
            namespace="nsa")

        cls.host1.create_workload(
            "nsa_h1_wl1",
            image="workload",
            network="nsa",
            labels=["wep=nsa_h1_wl1"],
            namespace="nsa")

        cls.host1.create_workload(
            "nsb_h1_wl0",
            image="workload",
            network="nsb",
            labels=["wep=nsb_h1_wl0"],
            namespace="nsb")

        cls.default_wl = cls.host1.create_workload(
            "default_h1_wl0",
            image="workload",
            network="default",
            labels=["wep=default_h1_wl0"],
            namespace="default")

        cls.omit_wl = cls.host1.create_workload(
            "omit_h1_wl0",
            image="workload",
            network="default",
            labels=["wep=omit_h1_wl0"],
            namespace=None)

        # Create workloads for host2
        cls.nsb_wl = cls.host2.create_workload(
            "nsb_h2_wl0",
            image="workload",
            network="nsb",
            labels=["wep=nsb_h2_wl0"],
            namespace="nsb")

        cls.host2.create_workload(
            "nsb_h2_wl1",
            image="workload",
            network="nsb",
            labels=["wep=nsb_h2_wl1"],
            namespace="nsb")

        cls.host2.create_workload(
            "nsa_h2_wl0",
            image="workload",
            network="nsa",
            labels=["wep=nsa_h2_wl0"],
            namespace="nsa")

        cls.host2.create_workload(
            "default_h2_wl0",
            image="workload",
            network="default",
            labels=["wep=default_h2_wl0"],
            namespace="default")

        # Work out workload set for different namespaces.
        cls.all_workloads = cls.host1.workloads.union(cls.host2.workloads)
        cls.wl_nsa = filter(lambda x: x.namespace == "nsa", cls.all_workloads)
        cls.wl_nsb = filter(lambda x: x.namespace == "nsb", cls.all_workloads)
        cls.wl_default = filter(lambda x: x.namespace == "default" or x.namespace is None, cls.all_workloads)

        clear_on_failures()
        add_on_failure(cls.host1.log_extra_diags)
        add_on_failure(cls.host2.log_extra_diags)

    @handle_failure
    def test_can_access_without_policy(self):
        """
        Test all workload can be accessed without policy.
        """

        self.check_namespace_access(self.nsa_wl, True, True, True)
        self.check_namespace_access(self.nsb_wl, True, True, True)
        self.check_namespace_access(self.default_wl, True, True, True)
        self.check_namespace_access(self.omit_wl, True, True, True)

    @handle_failure
    def test_global_policy(self):
        """
        Test global network policy with different order.
        """
        self.add_global_ingress(500, 'Deny', 'default')
        self.add_global_ingress(200, 'Allow', 'nsa')
        self.add_global_ingress(100, 'Deny', 'nsb')

        self.check_namespace_access(self.nsa_wl, True, False, False)
        self.check_namespace_access(self.nsb_wl, True, False, False)
        self.check_namespace_access(self.default_wl, True, False, False)
        self.check_namespace_access(self.omit_wl, True, False, False)

    @handle_failure
    def test_deny_nsa(self):
        """
        Test network policy for namespace nsa.
        """
        self.add_global_ingress(200, 'Allow')
        self.add_namespace_ingress('nsa', 100, 'Deny', 'nsb')

        self.check_namespace_access(self.nsa_wl, True, False, True)
        self.check_namespace_access(self.nsb_wl, True, True, True)
        self.check_namespace_access(self.default_wl, True, True, True)
        self.check_namespace_access(self.omit_wl, True, True, True)

    @handle_failure
    def test_deny_nsa_with_two_policy(self):
        """
        Test deny network policy for namespace nsa with two orders mixed with global network policy.
        """
        self.add_global_ingress(200, 'Allow')
        self.add_namespace_ingress('nsa', 300, 'Deny', 'nsb')
        self.add_namespace_ingress('nsa', 100, 'Deny', 'default')

        self.check_namespace_access(self.nsa_wl, True, True, False)
        self.check_namespace_access(self.nsb_wl, True, True, True)
        self.check_namespace_access(self.default_wl, True, True, True)
        self.check_namespace_access(self.omit_wl, True, True, True)

    @handle_failure
    def test_deny_default_with_two_policy(self):
        """
        Test deny network policy for namespace default with two orders mixed with global network policy.
        """
        self.add_global_ingress(200, 'Allow')
        self.add_namespace_ingress('default', 300, 'Deny', 'nsb')
        self.add_namespace_ingress('default', 100, 'Deny', 'nsa')

        self.check_namespace_access(self.nsa_wl, True, True, True)
        self.check_namespace_access(self.nsb_wl, True, True, True)
        self.check_namespace_access(self.default_wl, False, True, True)
        self.check_namespace_access(self.omit_wl, False, True, True)

    @handle_failure
    def test_allow_nsb_with_two_policy(self):
        """
        Test deny network policy for namespace nsb with two orders mixed with global network policy.
        """
        self.add_global_ingress(200, 'Deny')
        self.add_namespace_ingress('nsb', 300, 'Allow', 'nsa')
        self.add_namespace_ingress('nsb', 100, 'Allow', 'default')

        self.check_namespace_access(self.nsa_wl, False, False, False)
        self.check_namespace_access(self.nsb_wl, False, False, True)
        self.check_namespace_access(self.default_wl, False, False, False)
        self.check_namespace_access(self.omit_wl, False, False, False)

    @handle_failure
    def test_allow_default_with_two_policy(self):
        """
        Test deny network policy for namespace default with two orders mixed with global network policy.
        """
        self.add_global_ingress(200, 'Deny')
        self.add_namespace_ingress('default', 300, 'Allow', 'nsb')
        self.add_namespace_ingress('default', 100, 'Allow', 'nsa')

        self.check_namespace_access(self.nsa_wl, False, False, False)
        self.check_namespace_access(self.nsb_wl, False, False, False)
        self.check_namespace_access(self.default_wl, True, False, False)
        self.check_namespace_access(self.omit_wl, True, False, False)

    @handle_failure
    def test_mixed_deny(self):
        """
        Test mixed deny network policy for namespaces mixed with global network policy.
        """
        self.add_global_ingress(200, 'Allow')
        self.add_namespace_ingress('nsa', 300, 'Deny', 'default')
        self.add_namespace_ingress('nsa', 100, 'Deny', 'nsb')
        self.add_namespace_ingress('nsb', 300, 'Deny', 'default')
        self.add_namespace_ingress('nsb', 100, 'Deny', 'nsa')
        self.add_namespace_ingress('default', 300, 'Deny', 'nsa')
        self.add_namespace_ingress('default', 100, 'Deny', 'default')

        self.check_namespace_access(self.nsa_wl, True, False, True)
        self.check_namespace_access(self.nsb_wl, False, True, True)
        self.check_namespace_access(self.default_wl, True, True, False)
        self.check_namespace_access(self.omit_wl, True, True, False)

    def setUp(self):
        # Override the per-test setUp to avoid wiping etcd; instead only clean up the data we
        # added.
        self.remove_policy()

    def tearDown(self):
        self.remove_policy()
        super(TestNamespace, self).tearDown()

    @classmethod
    def tearDownClass(cls):
        cls.delete_all("profile")

        # Tidy up
        for host in cls.hosts:
            host.remove_workloads()
        for host in cls.hosts:
            host.cleanup()
            del host
        cls.calinet.delete()

        clear_on_failures()

    def add_namespace_ingress(self, ns, order, action, from_ns):
        ns_selector = "ns_profile == '%s'" % from_ns

        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'NetworkPolicy',
            'metadata': {
                'name': '%s-%s-%s-from-%s' % (ns, order, action.lower(), from_ns),
                'namespace': ns
            },
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'TCP',
                        'source': {
                            'namespaceSelector': ns_selector,
                        },
                        'action': action.capitalize(),
                    },
                ],
                'egress': [],
            }
        })

    def add_global_ingress(self, order, action, from_ns='all'):
        if from_ns != 'all':
            ingress_map = {
                'source': {
                    'selector': "%s.ns_profile == '%s'" % (NAMESPACE_PREFIX, from_ns)
                },
                'action': action.capitalize(),
            }
        else:
            ingress_map = {
                'action': action.capitalize(),
            }

        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {
                'name': 'global-%s-%s-from-%s' % (order, action.lower(), from_ns),
            },
            'spec': {
                'order': order,
                'ingress': [
                    ingress_map,
                ],
                'egress': [],
            }
        })

    @classmethod
    def add_ns_profile(cls, ns):
        profile_data = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'Profile',
            'metadata': {
                'name': ns,
            },
            'spec': {
                'labelsToApply': {
                    '%s.ns_profile' % NAMESPACE_PREFIX: ns
                },
                'ingress': [
                    {
                        'action': 'Allow',
                    },
                ],
                'egress': [
                    {
                        'action': 'Allow',
                    },
                ],
            }
        }
        cls.host1._apply_resources(profile_data)

    def add_policy(self, policy_data):
        self.host1._apply_resources(policy_data)

    def check_namespace_access(self, target, nsa_can, nsb_can, default_can):
        assert_func = {
            True: self.assert_workload_can_access_workload,
            False: self.assert_workload_can_not_access_workload
        }

        for src in self.wl_nsa:
            if not src == target:
                assert_func[nsa_can](src, target)

        for src in self.wl_nsb:
            if not src == target:
                assert_func[nsb_can](src, target)

        for src in self.wl_default:
            if not src == target:
                assert_func[default_can](src, target)

    def assert_workload_can_access_workload(self, src_workload, target_workload):
        _log.info("Can access test from %s to %s", src_workload.name, target_workload.name)

        if src_workload.check_can_tcp(target_workload.ip, 1):
            return
        _log.exception("workload %s with IP:%s failed to access workload %s on IP:%s",
                       src_workload.name, src_workload.ip, target_workload.name, target_workload.ip)
        msg = ("workload %s with IP:%s failed to access workload %s on IP:%s" %
               (src_workload.name, src_workload.ip, target_workload.name, target_workload.ip))

        self.fail(msg)

    def assert_workload_can_not_access_workload(self, src_workload, target_workload):
        _log.info("Cannot access test from %s to %s", src_workload.name, target_workload.name)

        if src_workload.check_cant_tcp(target_workload.ip, 1):
            return
        _log.exception("workload %s with IP:%s can access workload %s on IP:%s",
                       src_workload.name, src_workload.ip, target_workload.name, target_workload.ip)
        msg = ("workload %s with IP:%s can access workload %s on IP:%s" %
               (src_workload.name, src_workload.ip, target_workload.name, target_workload.ip))

        self.fail(msg)

    def remove_policy(self):
        self.delete_all("globalnetworkpolicy")
        self.delete_all("networkpolicy --all-namespaces")

    @classmethod
    def delete_all(cls, resource):
        cls.hosts[0].delete_all_resource(resource)

    @classmethod
    def get_container_ip(cls, container_name):
        ip = log_and_run(
            "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s" %
            container_name)
        return ip.strip()
