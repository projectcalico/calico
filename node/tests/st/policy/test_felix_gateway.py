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
    "docker load -q -i /code/busybox.tar",
    "docker load -q -i /code/workload.tar",
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
        _log.debug("Wiping etcd")
        wipe_etcd(HOST_IPV4)

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
        _log.info("External server IP: %s", cls.ext_server_ip)

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

        clear_on_failures()
        add_on_failure(cls.host.log_extra_diags)
        add_on_failure(cls.gateway.log_extra_diags)

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

        clear_on_failures()

    @handle_failure
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
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {
                'name': 'host-out',
            },
            'spec': {
                'order': 100,
                'selector': 'nodeEth == "host"',
                'egress': [{'action': 'Allow'}],
                'ingress': [{'action': 'Allow'}],
                'applyOnForward': True,
            }
        })
        retry_until_success(self.assert_host_can_curl_ext, 3)

    @handle_failure
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

    @handle_failure
    def test_empty_policy_for_forward_traffic(self):
        """
        Test empty policy deny local and forward traffic.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Add empty policy forward, but only to host endpoint.
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {
                'name': 'empty-forward',
            },
            'spec': {
                'order': 500,
                'selector': 'has(nodeEth)',
                'ingress': [],
                'egress': [],
                'applyOnForward': True,
                'types': ['Ingress', 'Egress']
            }
        })

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

    @handle_failure
    def test_local_allow_with_forward_empty(self):
        """
        Test local allow does not affect forward traffic with empty policy.
        """
        self.test_empty_policy_for_forward_traffic()

        # Add local ingress/egress allow.
        self.add_ingress_policy(200, 'Allow', False)
        self.add_egress_policy(200, 'Allow', False)

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

        # Add local&forward ingress/egress allow.
        self.add_ingress_policy(200, 'Allow', True)
        self.add_egress_policy(200, 'Allow', True)

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

    @handle_failure
    def test_local_deny_with_lower_forward_allow(self):
        """
        Test local deny with lower order does not affect forward allow policy.
        """
        self.test_empty_policy_for_forward_traffic()  # setup a deny for all traffic

        # Add local&forward ingress/egress allow.
        self.add_ingress_policy(300, 'Allow', True)
        self.add_egress_policy(300, 'Allow', True)

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        # Add local ingress/egress deny.
        self.add_ingress_policy(200, 'Deny', False)
        self.add_egress_policy(200, 'Deny', False)

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

    @handle_failure
    def test_local_ingress_allow_with_lower_ingress_forward_deny(self):
        """
        Test local ingress allow does not affect forward ingress deny with lower order.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Add local ingress allow and forward ingress deny
        self.add_ingress_policy(200, 'Allow', False)
        self.add_ingress_policy(500, 'Deny', True)

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        # Add workload egress deny
        self.add_workload_egress(800, 'Deny')

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

    @handle_failure
    def test_local_egress_allow_with_lower_egress_forward_deny(self):
        """
        Test local egress allow does not affect forward egress deny with lower order.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Add local egress allow and forward egress deny
        self.add_egress_policy(200, 'Allow', False)
        self.add_egress_policy(500, 'Deny', True)

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

        # Add workload ingress deny
        self.add_workload_ingress(800, 'Deny')

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

    @handle_failure
    def test_local_forward_opposite_policy_0(self):
        """
        Test local and forward got opposite allow/deny rules.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Add local ingress allow, egress deny and lower forward ingress deny, forward egress allow
        self.add_ingress_policy(200, 'Allow', False)
        self.add_ingress_policy(500, 'Deny', True)
        self.add_egress_policy(200, 'Deny', False)
        self.add_egress_policy(500, 'Allow', True)

        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_not_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

    @handle_failure
    def test_local_forward_opposite_policy_1(self):
        """
        Test local and forward got opposite allow/deny rules.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Add local ingress deny, egress allow and lower forward ingress allow, forward egress deny
        self.add_ingress_policy(200, 'Deny', False)
        self.add_ingress_policy(500, 'Allow', True)
        self.add_egress_policy(200, 'Allow', False)
        self.add_egress_policy(500, 'Deny', True)

        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

    @handle_failure
    def test_host_endpoint_combinations(self):
        """
        Test combinations of untracked, preDNAT, normal and forward policies.
        """
        self.test_can_connect_by_default()

        self.add_gateway_external_iface()
        self.add_gateway_internal_iface()

        # Test untracked policy.
        self.add_untrack_gw_int(500, 'Allow')
        self.add_untrack_gw_ext(500, 'Allow')

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
        self.add_ingress_policy(200, 'Deny', True)
        self.add_egress_policy(200, 'Allow', True)
        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)

        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        # Skip normal and forward policy if preDNAT policy accept packet.
        self.add_prednat_ingress(500, 'Allow')
        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_host_can_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_access_workload, 3)

        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        self.add_prednat_ingress(200, 'Deny')
        retry_until_success(self.assert_host_can_not_curl_local, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)

        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_workload_can_curl_ext, 3)

        # Skip preDNAT, normal and forward policy if untracked policy accept packet.
        self.add_untrack_gw_int(500, 'Allow')
        retry_until_success(self.assert_host_can_curl_local, 3)
        retry_until_success(self.assert_gateway_can_curl_ext, 3)
        retry_until_success(self.assert_host_can_not_curl_ext, 3)
        # We need to add egress allow because if host send request to external server,
        # return traffic will not match any conntrack entry hence been dropped by
        # cali-fhfw-eth1. An untracked egress allow skips normal forward policy.
        self.add_untrack_gw_ext(500, 'Allow')
        # Traffic to/from workload will be dropped by workload default policy
        # since conntrack entry is invalid.
        retry_until_success(self.assert_host_can_curl_ext, 3)
        # Traffic to/from workload will be dropped by workload default policy
        # since conntrack entry is invalid.
        retry_until_success(self.assert_hostwl_can_not_access_workload, 3)
        retry_until_success(self.assert_workload_can_not_curl_ext, 3)

    def add_workload_ingress(self, order, action):
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {
                'name': 'workload-ingress',
            },
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'TCP',
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
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {
                'name': 'workload-egress',
            },
            'spec': {
                'order': order,
                'ingress': [],
                'egress': [
                    {
                        'protocol': 'TCP',
                        'destination': {
                            'ports': [80],
                            'nets': [self.ext_server_ip + "/32"],
                        },
                        'action': action
                    },
                ],
                'selector': '!has(nodeEth)'
            }
        })

    def add_prednat_ingress(self, order, action):
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {
                'name': 'prednat',
            },
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'TCP',
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
        self.delete_all("globalnetworkpolicy prednat")

    def add_untrack_gw_int(self, order, action):
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {
                'name': 'untrack-ingress',
            },
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'TCP',
                        'destination': {
                            'ports': [80]
                        },
                        'action': action
                    },
                ],
                'egress': [
                    {
                        'protocol': 'TCP',
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
        self.delete_all("globalnetworkpolicy untrack-ingress")

    def add_untrack_gw_ext(self, order, action):
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {
                'name': 'untrack-egress',
            },
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'TCP',
                        'source': {
                            'ports': [80],
                            'nets': [self.ext_server_ip + "/32"],
                        },
                        'action': action
                    },
                ],
                'egress': [
                    {
                        'protocol': 'TCP',
                        'destination': {
                            'ports': [80],
                            'nets': [self.ext_server_ip + "/32"],
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
        self.delete_all("globalnetworkpolicy untrack-egress")

    def add_ingress_policy(self, order, action, forward):
        self.add_policy({
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {
                'name': 'port80-int-%s' % str(forward).lower(),
            },
            'spec': {
                'order': order,
                'ingress': [
                    {
                        'protocol': 'TCP',
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
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {
                'name': 'port80-ext-%s' % str(forward).lower(),
             },
            'spec': {
                'order': order,
                'ingress': [],
                'egress': [
                    {
                        'protocol': 'TCP',
                        'destination': {
                            'ports': [80],
                            'nets': [self.ext_server_ip + "/32"],
                        },
                        'action': action
                    },
                ],
                'selector': 'nodeEth == "gateway-ext"',
                'applyOnForward': forward
            }
        })

    def add_policy(self, policy_data):
        self.gateway._apply_resources(policy_data)

    def add_gateway_internal_iface(self):
        host_endpoint_data = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'HostEndpoint',
            'metadata': {
                'name': 'gw-int',
                'labels': {'nodeEth': 'gateway-int'}
            },
            'spec': {
                'node': '%s' % self.gateway_hostname,
                'interfaceName': 'eth0'
            }
        }
        self.gateway._apply_resources(host_endpoint_data)

    def add_gateway_external_iface(self):
        host_endpoint_data = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'HostEndpoint',
            'metadata': {
                'name': 'gw-ext',
                'labels': {'nodeEth': 'gateway-ext'}
            },
            'spec': {
                'node': '%s' % self.gateway_hostname,
                'interfaceName': 'eth1'
            }
        }
        self.gateway._apply_resources(host_endpoint_data)

    def add_host_iface(self):
        host_endpoint_data = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'HostEndpoint',
            'metadata': {
                'name': 'host-int',
                'labels': {'nodeEth': 'host'}
            },
            'spec': {
                'node': '%s' % self.host_hostname,
                'interfaceName': 'eth0',
                'expectedIPs': [str(self.host.ip)],
            }
        }
        self.gateway._apply_resources(host_endpoint_data)

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
        self.delete_all("globalnetworkpolicy")
        self.delete_all("hostEndpoint")
        # Wait for felix to remove the policy and allow traffic through the gateway.
        retry_until_success(self.assert_host_can_curl_ext)

    def delete_all(self, resource):
        self.hosts[0].delete_all_resource(resource)

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
