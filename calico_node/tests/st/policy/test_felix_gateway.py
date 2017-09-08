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

import yaml
from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.utils import get_ip, log_and_run, retry_until_success, \
    ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_HOSTNAME_SSL, ETCD_SCHEME

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)

POST_DOCKER_COMMANDS = [
    "docker load -i /code/calico-node.tar",
    "docker load -i /code/busybox.tar",
    "docker load -i /code/workload.tar",
]


class TestFelixOnGateway(TestBase):
    """
    Tests that policy is correctly implemented when using Calico
    on a gateway or router.  In that scenario, Calico should
    police forwarded (possibly NATted) traffic using the host endpoint
    policy.
    """
    hosts = None
    gateway = None
    host = None

    @classmethod
    def setUpClass(cls):
        # Wipe etcd once before any test in this class runs.
        wipe_etcd()

        # We set up an additional docker network to act as the external
        # network.  The Gateway container is connected to both networks.
        # and we configure it as a NAT gateway.
        #
        #  "cali-st-ext" host
        #   container
        #      |
        #  "cali-st-ext" docker
        #    bridge
        #      |
        #  Gateway           Host
        #  container         container
        #         \          /
        #        default docker
        #            bridge

        # We are testing two host endpoints including
        # gw_int connecting gateway with host through internal network.
        # gw_ext connecting gateway with external server.
        #
        # We are testing five access patterns.
        # Host to external server through gateway.
        # Host -> gw_int(untracked ingress, preDNAT) -> gw_int(forward ingress) ->
        # gw_ext(forward egress) -> gw_ext(untracked egress) -> external server.
        #
        # Host to workload running on gateway.
        # Host -> gw_int(untracked ingress, preDNAT) -> gw_int(forward ingress) ->
        # workload (workload ingress)
        #
        # Host to process running on gateway.
        # Host -> gw_int(untracked ingress, preDNAT) -> gw_int(normal ingress)
        #
        # Process running on gateway to external server.
        # Process -> gw_ext(normal egress) -> gw_ext(untracked egress)
        #
        # Workload running on gateway to external server.
        # Workload (workload egress) -> gw_ext(forward egress) -> gw_ext(untracked egress)

        # First, create the hosts and the gateway.
        cls.hosts = []
        cls.gateway = DockerHost("cali-st-gw",
                                 additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                                 post_docker_commands=POST_DOCKER_COMMANDS,
                                 start_calico=False)
        cls.gateway_hostname = cls.gateway.execute("hostname")
        cls.host = DockerHost("cali-st-host",
                              additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                              post_docker_commands=POST_DOCKER_COMMANDS,
                              start_calico=False)
        cls.host_hostname = cls.host.execute("hostname")
        cls.hosts.append(cls.gateway)
        cls.hosts.append(cls.host)

        # Delete the nginx container if it still exists.  We need to do this
        # before we try to remove the network.
        log_and_run("docker rm -f cali-st-ext-nginx || true")

        # Create the external network.
        log_and_run("docker network rm cali-st-ext || true")
        # Use 172.19.0.0 to avoid clash with normal docker subnet and
        # docker-in-docker subnet
        log_and_run("docker network create --driver bridge --subnet 172.19.0.0/16 cali-st-ext")

        # And an nginx server on the external network only.
        log_and_run("docker run"
                    " --network=cali-st-ext"
                    " -d"
                    " --name=cali-st-ext-nginx"
                    " nginx")

        for host in cls.hosts:
            host.start_calico_node()

        # Run local httpd server on gateway.
        cls.gateway.execute(
            "echo '<HTML> Local process </HTML>' > $HOME/index.html && httpd -p 80 -h $HOME")

        # Get the internal IP of the gateway.  We do this before we add the second
        # network since it means we don't have to figure out which IP is which.
        int_ip = str(cls.gateway.ip)
        cls.gateway_int_ip = int_ip
        _log.info("Gateway internal IP: %s", cls.gateway_int_ip)

        # Add the gateway to the external network.
        log_and_run("docker network connect cali-st-ext cali-st-gw")

        # Get the external IP of the gateway.
        ext_ip = log_and_run("docker inspect --format "
                             "'{{with index .NetworkSettings.Networks"
                             " \"cali-st-ext\"}}{{.IPAddress}}{{end}}' cali-st-gw")
        cls.gateway_ext_ip = ext_ip
        _log.info("Gateway external IP: %s", cls.gateway_ext_ip)

        # Get the IP of the external server.
        ext_ip = cls.get_container_ip("cali-st-ext-nginx")
        cls.ext_server_ip = ext_ip
        _log.info("External workload IP: %s", cls.ext_server_ip)

        # Configure the internal host to use the gateway for the external IP.
        cls.host.execute("ip route add %s via %s" %
                         (cls.ext_server_ip, cls.gateway_int_ip))

        # Configure the gateway to forward and NAT.
        cls.gateway.execute("sysctl -w net.ipv4.ip_forward=1")
        cls.gateway.execute("iptables -t nat -A POSTROUTING --destination %s -j MASQUERADE" %
                            cls.ext_server_ip)

        cls.calinet = cls.gateway.create_network("calinet")
        cls.gateway_workload = cls.gateway.create_workload(
            "gw-wl",
            image="workload",
            network=cls.calinet,
            labels=["org.projectcalico.label.wep=gateway"])

        cls.host_workload = cls.host.create_workload(
            "host-wl",
            image="workload",
            network=cls.calinet,
            labels=["org.projectcalico.label.wep=host"])

    def setUp(self):
        # Override the per-test setUp to avoid wiping etcd; instead only clean up the data we
        # added.
        self.remove_pol_and_endpoints()

    def tearDown(self):
        self.remove_pol_and_endpoints()
        super(TestFelixOnGateway, self).tearDown()

    @classmethod
    def tearDownClass(cls):
        # Tidy up
        for host in cls.hosts:
            host.remove_workloads()
        for host in cls.hosts:
            host.cleanup()
            del host
        cls.calinet.delete()

        log_and_run("docker rm -f cali-st-ext-nginx || true")

    def test_can_connect_by_default(self):
        """
        Test if traffic is allowed with no policy setup.
        """
        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        self.add_host_iface()

        # Adding the host endpoints should break connectivity until we add policy back in.
        # Add allow policy for host, make sure it applies to forward and has order lower than
        # empty forward.
        self.add_policy({
            'apiVersion': 'v1',
            'kind': 'policy',
            'metadata': {'name': 'host-out'},
            'spec': {
                'order': 100,
                'selector': 'nodeEth == "host"',
                'egress': [{'action': 'allow'}],
                'ingress': [{'action': 'allow'}],
                'applyOnForward': True,
            }
        })
        retry_until_success(self.assert_host_can_curl_ext, 3)

    def test_default_deny_for_local_traffic(self):
        """
        Test default deny for local traffic after host endpoint been created.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

    def test_empty_policy_for_forward_traffic(self):
        """
        Test empty policy deny local and forward traffic.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Add empty policy forward, but only to host endpoint.
        self.add_policy({
            'apiVersion': 'v1',
            'kind': 'policy',
            'metadata': {'name': 'empty-forward'},
            'spec': {
                'order': 500,
                'selector': 'has(nodeEth)',
                'ingress': [],
                'egress': [],
                'applyOnForward': True,
                'types': ['ingress', 'egress']
            }
        })

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

    def test_local_allow_with_forward_empty(self):
        """
        Test local allow does not affect forward traffic with empty policy.
        """
        self.test_empty_policy_for_forward_traffic()

        # Add local ingress/egress allow.
        self.add_ingress_policy(200, 'allow', False)
        self.add_egress_policy(200, 'allow', False)

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

        # Add local&forward ingress/egress allow.
        self.add_ingress_policy(200, 'allow', True)
        self.add_egress_policy(200, 'allow', True)

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

    def test_local_deny_with_lower_forward_allow(self):
        """
        Test local deny with lower order does not affect forward allow policy.
        """
        self.test_empty_policy_for_forward_traffic()  # setup a deny for all traffic

        # Add local&forward ingress/egress allow.
        self.add_ingress_policy(300, 'allow', True)
        self.add_egress_policy(300, 'allow', True)

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        # Add local ingress/egress deny.
        self.add_ingress_policy(200, 'deny', False)
        self.add_egress_policy(200, 'deny', False)

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

    def test_local_ingress_allow_with_lower_ingress_forward_deny(self):
        """
        Test local ingress allow does not affect forward ingress deny with lower order.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Add local ingress allow and forward ingress deny
        self.add_ingress_policy(200, 'allow', False)
        self.add_ingress_policy(500, 'deny', True)

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        # Add workload egress deny
        self.add_workload_egress(800, 'deny')

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

    def test_local_egress_allow_with_lower_egress_forward_deny(self):
        """
        Test local egress allow does not affect forward egress deny with lower order.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Add local egress allow and forward egress deny
        self.add_egress_policy(200, 'allow', False)
        self.add_egress_policy(500, 'deny', True)

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

        # Add workload ingress deny
        self.add_workload_ingress(800, 'deny')

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

    def test_local_forward_opposite_policy_0(self):
        """
        Test local and forward got opposite allow/deny rules.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Add local ingress allow, egress deny and lower forward ingress deny, forward egress allow
        self.add_ingress_policy(200, 'allow', False)
        self.add_ingress_policy(500, 'deny', True)
        self.add_egress_policy(200, 'deny', False)
        self.add_egress_policy(500, 'allow', True)

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

    def test_local_forward_opposite_policy_1(self):
        """
        Test local and forward got opposite allow/deny rules.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Add local ingress deny, egress allow and lower forward ingress allow, forward egress deny
        self.add_ingress_policy(200, 'deny', False)
        self.add_ingress_policy(500, 'allow', True)
        self.add_egress_policy(200, 'allow', False)
        self.add_egress_policy(500, 'deny', True)

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

    def test_host_endpoint_combinations(self):
        """
        Test combinations of untracked, preDNAT, normal and forward policies.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Test untracked policy.
        self.add_untrack_gw_int(500, 'allow')
        self.add_untrack_gw_ext(500, 'allow')

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)

        # Untracked packets skip masquerade rule for packet from host
        # via gateway to ext server.
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        # Conntrack state invalid, default workload policy will drop packet.
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        # Packet from workload will be masqueraded by cali-nat-outgoing. It
        # can reach external server but return packet will be dropped by not having
        # a conntrack entry to do a reverse SNAT.
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

        # Configure external server to use gateway as default gateway.
        # So we dont need to masquerade internal ip.
        # External server sees internal ip and knows how to send response
        # back.
        self.set_ext_container_default_route("cali-st-ext-nginx")
        retry_until_success(self.assert_host_can_curl_ext, 3)

        self.del_untrack_gw_int()
        self.del_untrack_gw_ext()

        # Deny host endpoint ingress.
        # Ingress packet dropped. Egress packet accepted.
        self.add_ingress_policy(200, 'deny', True)
        self.add_egress_policy(200, 'allow', True)
        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)

        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        # Skip normal and forward policy if preDNAT policy accept packet.
        self.add_prednat_ingress(500, 'allow')
        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_host_can_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)

        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        self.add_prednat_ingress(200, 'deny')
        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)

        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        # Skip preDNAT, normal and forward policy if untracked policy accept packet.
        self.add_untrack_gw_int(500, 'allow')
        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        # We need to add egress allow because if host send request to external server,
        # return traffic will not match any conntrack entry hence been dropped by
        # cali-fhfw-eth1. An untracked egress allow skips normal forward policy.
        self.add_untrack_gw_ext(500, 'allow')
        # Traffic to/from workload will be dropped by workload default policy
        # since conntrack entry is invalid.
        retry_until_success(self.assert_host_can_curl_ext, 3)
        # Traffic to/from workload will be dropped by workload default policy
        # since conntrack entry is invalid.
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

    def add_workload_ingress(self, order, action):
        self.add_policy({
            'apiVersion': 'v1',
            'kind': 'policy',
            'metadata': {'name': 'workload-ingress'},
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'tcp',
                        'destination': {
                            'ports': [80]
                        },
                        'action': action,
                    },
                ],
                'egress': [],
                'selector': '!has(nodeEth)'
            }
        })

    def add_workload_egress(self, order, action):
        self.add_policy({
            'apiVersion': 'v1',
            'kind': 'policy',
            'metadata': {'name': 'workload-egress'},
            'spec': {
                'order': order,
                'ingress': [],
                'egress': [
                    {
                        'protocol': 'tcp',
                        'destination': {
                            'ports': [80],
                            'net': self.ext_server_ip + "/32",
                        },
                        'action': action
                    },
                ],
                'selector': '!has(nodeEth)'
            }
        })

    def add_prednat_ingress(self, order, action):
        self.add_policy({
            'apiVersion': 'v1',
            'kind': 'policy',
            'metadata': {'name': 'prednat'},
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'tcp',
                        'destination': {
                            'ports': [80]
                        },
                        'action': action
                    },
                ],
                'egress': [],
                'selector': 'nodeEth == "gateway-int"',
                'applyOnForward': True,
                'preDNAT': True
            }
        })

    def del_prednat_ingress(self):
        self.delete_all("pol prednat")

    def add_untrack_gw_int(self, order, action):
        self.add_policy({
            'apiVersion': 'v1',
            'kind': 'policy',
            'metadata': {'name': 'untrack-ingress'},
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'tcp',
                        'destination': {
                            'ports': [80]
                        },
                        'action': action
                    },
                ],
                'egress': [
                    {
                        'protocol': 'tcp',
                        'source': {
                            'ports': [80]
                        },
                        'action': action
                    },
                ],
                'selector': 'nodeEth == "gateway-int"',
                'applyOnForward': True,
                'doNotTrack': True
            }
        })

    def del_untrack_gw_int(self):
        self.delete_all("pol untrack-ingress")

    def add_untrack_gw_ext(self, order, action):
        self.add_policy({
            'apiVersion': 'v1',
            'kind': 'policy',
            'metadata': {'name': 'untrack-egress'},
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'tcp',
                        'source': {
                            'ports': [80],
                            'net': self.ext_server_ip + "/32",
                        },
                        'action': action
                    },
                ],
                'egress': [
                    {
                        'protocol': 'tcp',
                        'destination': {
                            'ports': [80],
                            'net': self.ext_server_ip + "/32",
                        },
                        'action': action
                    },
                ],
                'selector': 'nodeEth == "gateway-ext"',
                'applyOnForward': True,
                'doNotTrack': True
            }
        })

    def del_untrack_gw_ext(self):
        self.delete_all("pol untrack-egress")

    def add_ingress_policy(self, order, action, forward):
        self.add_policy({
            'apiVersion': 'v1',
            'kind': 'policy',
            'metadata': {'name': 'port80-int-%s' % str(forward)},
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'tcp',
                        'destination': {
                            'ports': [80]
                        },
                        'action': action
                    },
                ],
                'egress': [],
                'selector': 'nodeEth == "gateway-int"',
                'applyOnForward': forward
            }
        })

    def add_egress_policy(self, order, action, forward):
        self.add_policy({
            'apiVersion': 'v1',
            'kind': 'policy',
            'metadata': {'name': 'port80-ext-%s' % str(forward)},
            'spec': {
                'order': order,
                'ingress': [],
                'egress': [
                    {
                        'protocol': 'tcp',
                        'destination': {
                            'ports': [80],
                            'net': self.ext_server_ip + "/32",
                        },
                        'action': action
                    },
                ],
                'selector': 'nodeEth == "gateway-ext"',
                'applyOnForward': forward
            }
        })

    def add_policy(self, policy_data):
        self._apply_resources(policy_data, self.gateway)

    def add_gateway_internal_iface(self):
        host_endpoint_data = {
            'apiVersion': 'v1',
            'kind': 'hostEndpoint',
            'metadata': {
                'name': 'gw-int',
                'node': self.gateway_hostname,
                'labels': {'nodeEth': 'gateway-int'}
            },
            'spec': {
                'interfaceName': 'eth0'
            }
        }
        self._apply_resources(host_endpoint_data, self.gateway)

    def add_gateway_external_iface(self):
        host_endpoint_data = {
            'apiVersion': 'v1',
            'kind': 'hostEndpoint',
            'metadata': {
                'name': 'gw-ext',
                'node': self.gateway_hostname,
                'labels': {'nodeEth': 'gateway-ext'}
            },
            'spec': {
                'interfaceName': 'eth1'
            }
        }
        self._apply_resources(host_endpoint_data, self.gateway)

    def add_host_iface(self):
        host_endpoint_data = {
            'apiVersion': 'v1',
            'kind': 'hostEndpoint',
            'metadata': {
                'name': 'host-int',
                'node': self.host_hostname,
                'labels': {'nodeEth': 'host'}
            },
            'spec': {
                'interfaceName': 'eth0',
                'expectedIPs': [str(self.host.ip)],
            }
        }
        self._apply_resources(host_endpoint_data, self.gateway)

    def assert_host_can_curl_local(self):
        try:
            self.host.execute("curl --fail -m 1 -o /tmp/local-index.html %s" % self.gateway_int_ip)
        except subprocess.CalledProcessError:
            _log.exception("Internal host failed to curl gateway internal IP: %s",
                           self.gateway_int_ip)
            self.fail("Internal host failed to curl gateway internal IP: %s" % self.gateway_int_ip)

    def assert_host_can_not_curl_local(self):
        try:
            self.host.execute("curl --fail -m 1 -o /tmp/local-index.html %s" % self.gateway_int_ip)
        except subprocess.CalledProcessError:
            return
        else:
            self.fail("Internal host can curl gateway internal IP: %s" % self.gateway_int_ip)

    def assert_hostwl_can_access_workload(self):
        if self.host_workload.check_can_tcp(self.gateway_workload.ip, 1):
            return
        _log.exception("Internal host workload failed to access gateway internal workload IP: %s",
                       self.gateway_workload.ip)
        self.fail(
            "Internal host workload failed to access gateway internal workload IP: %s" %
            self.gateway_workload.ip)

    def assert_hostwl_can_not_access_workload(self):
        if self.host_workload.check_cant_tcp(self.gateway_workload.ip, 1):
            return
        _log.exception("Internal host workload can access gateway internal workload IP: %s",
                       self.gateway_workload.ip)
        self.fail(
            "Internal host workload can access gateway internal workload IP: %s" %
            self.gateway_workload.ip)

    def assert_workload_can_curl_ext(self):
        try:
            self.gateway_workload.execute("wget -q -T 1 %s -O /dev/null" % self.ext_server_ip)
        except subprocess.CalledProcessError:
            _log.exception("Gateway workload failed to curl external server IP: %s",
                           self.ext_server_ip)
            self.fail("Gateway workload failed to curl external server IP: %s" % self.ext_server_ip)

    def assert_workload_can_not_curl_ext(self):
        try:
            self.gateway_workload.execute("wget -q -T 1 %s -O /dev/null" % self.ext_server_ip)
        except subprocess.CalledProcessError:
            return
        else:
            self.fail("Gateway workload can curl external server IP: %s" % self.ext_server_ip)

    def assert_gateway_can_curl_ext(self):
        try:
            self.gateway.execute(
                "curl --fail -m 1 -o /tmp/nginx-index.html %s" % self.ext_server_ip)
        except subprocess.CalledProcessError:
            _log.exception("Gateway failed to curl external server IP: %s",
                           self.ext_server_ip)
            self.fail("Gateway failed to curl external server IP: %s" % self.ext_server_ip)

    def assert_gateway_can_not_curl_ext(self):
        try:
            self.gateway.execute(
                "curl --fail -m 1 -o /tmp/nginx-index.html %s" % self.ext_server_ip)
        except subprocess.CalledProcessError:
            return
        else:
            self.fail("Gateway can curl external server IP: %s" % self.ext_server_ip)

    def assert_host_can_curl_ext(self):
        try:
            self.host.execute("curl --fail -m 1 -o /tmp/nginx-index.html %s" % self.ext_server_ip)
        except subprocess.CalledProcessError:
            _log.exception("Internal host failed to curl external server IP: %s",
                           self.ext_server_ip)
            self.fail("Internal host failed to curl external server IP: %s" % self.ext_server_ip)

    def assert_host_can_not_curl_ext(self):
        try:
            self.host.execute("curl --fail -m 1 -o /tmp/nginx-index.html %s" % self.ext_server_ip)
        except subprocess.CalledProcessError:
            return
        else:
            self.fail("Internal host can curl external server IP: %s" % self.ext_server_ip)

    def remove_pol_and_endpoints(self):
        self.delete_all("pol")
        self.delete_all("hostEndpoint")
        # Wait for felix to remove the policy and allow traffic through the gateway.
        retry_until_success(self.assert_host_can_curl_ext)

    def delete_all(self, resource):
        # Grab all objects of a resource type
        objects = yaml.load(self.hosts[0].calicoctl("get %s -o yaml" % resource))
        # and delete them (if there are any)
        if len(objects) > 0:
            self._delete_data(objects, self.hosts[0])

    def _delete_data(self, data, host):
        _log.debug("Deleting data with calicoctl: %s", data)
        self._exec_calicoctl("delete", data, host)

    @classmethod
    def _apply_resources(cls, resources, host):
        cls._exec_calicoctl("apply", resources, host)

    @staticmethod
    def _exec_calicoctl(action, data, host):
        # use calicoctl with data
        host.writefile("new_data",
                       yaml.dump(data, default_flow_style=False))
        host.calicoctl("%s -f new_data" % action)

    @classmethod
    def get_container_ip(cls, container_name):
        ip = log_and_run(
            "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s" %
            container_name)
        return ip.strip()

    @classmethod
    def set_ext_container_default_route(cls, container_name):
        pid = log_and_run("docker inspect -f '{{.State.Pid}}' %s" %
                          container_name)
        _log.info("pid is %s", pid)
        log_and_run("mkdir -p /var/run/netns; "
                    "ln -s /proc/%s/ns/net /var/run/netns/%s; "
                    "ip netns exec %s ip route del default; "
                    "ip netns exec %s ip route add default via %s" %
                    (pid, pid, pid, pid, cls.gateway_ext_ip))


def wipe_etcd():
    _log.debug("Wiping etcd")
    # Delete /calico if it exists. This ensures each test has an empty data
    # store at start of day.
    curl_etcd(get_ip(), "calico", options=["-XDELETE"])

    # Disable Usage Reporting to usage.projectcalico.org
    # We want to avoid polluting analytics data with unit test noise
    curl_etcd(get_ip(),
              "calico/v1/config/UsageReportingEnabled",
              options=["-XPUT -d value=False"])
    curl_etcd(get_ip(),
              "calico/v1/config/LogSeverityScreen",
              options=["-XPUT -d value=debug"])


def curl_etcd(ip, path, options=None, recursive=True):
    """
    Perform a curl to etcd, returning JSON decoded response.
    :param ip: IP address of etcd server
    :param path:  The key path to query
    :param options:  Additional options to include in the curl
    :param recursive:  Whether we want recursive query or not
    :return:  The JSON decoded response.
    """
    if options is None:
        options = []
    if ETCD_SCHEME == "https":
        # Etcd is running with SSL/TLS, require key/certificates
        command = "curl --cacert %s --cert %s --key %s " \
                  "-sL https://%s:2379/v2/keys/%s?recursive=%s %s" % \
                  (ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_HOSTNAME_SSL, path,
                   str(recursive).lower(), " ".join(options))
    else:
        command = "curl -sL http://%s:2379/v2/keys/%s?recursive=%s %s" % \
                  (ip, path, str(recursive).lower(), " ".join(options))
    _log.debug("Running: %s", command)
    rc = subprocess.check_output(command, shell=True)
    return json.loads(rc.strip())
