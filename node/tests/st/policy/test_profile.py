# Copyright 2015 Tigera, Inc
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
import copy
import netaddr
import logging
import yaml

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS
from tests.st.utils.utils import assert_profile, \
    assert_number_endpoints, get_profile_name

POST_DOCKER_COMMANDS = ["docker load -q -i /code/calico-node.tar",
                        "docker load -q -i /code/busybox.tar",
                        "docker load -q -i /code/workload.tar"]


_log = logging.getLogger(__name__)


class MultiHostMainline(TestBase):
    host1 = None
    host2 = None

    @classmethod
    def setUpClass(cls):
        super(MultiHostMainline, cls).setUpClass()
        cls.host1 = DockerHost("host1",
                               additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                               post_docker_commands=POST_DOCKER_COMMANDS)
        cls.host2 = DockerHost("host2",
                               additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                               post_docker_commands=POST_DOCKER_COMMANDS)

    @classmethod
    def tearDownClass(cls):
        cls.host1.cleanup()
        cls.host2.cleanup()
        super(MultiHostMainline, cls).tearDownClass()

    def setUp(self):
        super(MultiHostMainline, self).setUp(clear_etcd=False)
        host1 = self.host1
        host2 = self.host2

        (self.n1_workloads, self.n2_workloads, self.networks) = \
            self._setup_workloads(host1, host2)

        # Get the original profiles:
        output = host1.calicoctl("get profile -o yaml")
        self.original_profiles = yaml.safe_load(output)['items']

        # Filter out the default-allow profile
        temp = []
        for profile in self.original_profiles:
            if profile['metadata']['name'] != "projectcalico-default-allow":
                temp.append(profile)
                    
        self.original_profiles = temp   

        # Make a copy of the profiles to mess about with.
        self.new_profiles = copy.deepcopy(self.original_profiles)

    def tearDown(self):
        # Remove the network sets, if present
        self.host1.calicoctl("delete globalnetworkset netset-1", raise_exception_on_failure=False)
        self.host1.calicoctl("delete globalnetworkset netset-2", raise_exception_on_failure=False)

        # Delete conntrack state for UDP connections to the workloads.
        # Otherwise a new UDP connection may be allowed where it should be
        # denied.
        self.host1.delete_conntrack_state_to_workloads("udp")
        self.host2.delete_conntrack_state_to_workloads("udp")

        # Now restore the original profile and check it all works as before
        self._apply_new_profile(self.original_profiles, self.host1)
        self.host1.calicoctl("get profile -o yaml")
        try:
            self._check_original_connectivity(self.n1_workloads, self.n2_workloads)
        finally:
            # Tidy up
            self.host1.remove_workloads()
            self.host2.remove_workloads()
            for network in self.networks:
                network.delete()

            super(MultiHostMainline, self).tearDown()

    def test_tags(self):
        # Update profiles so that they each include each other's labelsToApply.
        _log.info("Profile 0 labelsToApply = %r", self.new_profiles[0]['spec']['labelsToApply'])
        _log.info("Profile 1 labelsToApply = %r", self.new_profiles[1]['spec']['labelsToApply'])
        self.new_profiles[0]['spec']['labelsToApply'].update(self.new_profiles[1]['spec']['labelsToApply'])
        self.new_profiles[1]['spec']['labelsToApply'].update(self.new_profiles[0]['spec']['labelsToApply'])
        _log.info("Merged profile 0 labelsToApply = %r", self.new_profiles[0]['spec']['labelsToApply'])
        _log.info("Merged profile 1 labelsToApply = %r", self.new_profiles[1]['spec']['labelsToApply'])
        self._apply_new_profile(self.new_profiles, self.host1)
        # Check everything can contact everything else now
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads + self.n2_workloads)
    test_tags.batchnumber = 5

    def test_rules_protocol_icmp(self):
        rule = {'action': 'Allow',
                'protocol': 'ICMP'}
        # The copy.deepcopy(rule) is needed to ensure that we don't
        # end up with a yaml document with a reference to the same
        # rule.  While this is probably legal, it isn't main line.
        self.new_profiles[0]['spec']['ingress'].append(rule)
        self.new_profiles[1]['spec']['ingress'].append(copy.deepcopy(rule))
        self._apply_new_profile(self.new_profiles, self.host1)
        # Check everything can contact everything else now
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads + self.n2_workloads,
                                 type_list=["icmp"])
    test_rules_protocol_icmp.batchnumber = 1

    def test_rules_ip_addr(self):
        prof_n1, prof_n2 = self._get_profiles(self.new_profiles)
        for workload in self.n1_workloads:
            ip = workload.ip
            rule = {'action': 'Allow',
                    'source':
                        {'nets': ['%s/32' % ip]}}
            prof_n2['spec']['ingress'].append(rule)
        for workload in self.n2_workloads:
            ip = workload.ip
            rule = {'action': 'Allow',
                    'source':
                        {'nets': ['%s/32' % ip]}}
            prof_n1['spec']['ingress'].append(rule)
        self._apply_new_profile(self.new_profiles, self.host1)
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads + self.n2_workloads)
    test_rules_ip_addr.batchnumber = 1

    def test_rules_ip_net(self):
        prof_n1, prof_n2 = self._get_profiles(self.new_profiles)
        n1_ips = [workload.ip for workload in self.n1_workloads]
        n2_ips = [workload.ip for workload in self.n2_workloads]
        n1_subnet = netaddr.spanning_cidr(n1_ips)
        n2_subnet = netaddr.spanning_cidr(n2_ips)
        rule = {'action': 'Allow',
                'source':
                    {'nets': [str(n1_subnet)]}}
        prof_n2['spec']['ingress'].append(rule)
        rule = {'action': 'Allow',
                'source':
                    {'nets': [str(n2_subnet)]}}
        prof_n1['spec']['ingress'].append(rule)
        self._apply_new_profile(self.new_profiles, self.host1)
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads + self.n2_workloads)
    test_rules_ip_net.batchnumber = 1

    def test_rules_source_ip_nets(self):
        # Add a rule to each profile that allows traffic from all the workloads in the *other*
        # network (which would normally be blocked).
        prof_n1, prof_n2 = self._get_profiles(self.new_profiles)
        n1_ips = [str(workload.ip) + "/32" for workload in self.n1_workloads]
        n2_ips = [str(workload.ip) + "/32" for workload in self.n2_workloads]
        rule = {'action': 'Allow',
                'source': {'nets': n1_ips}}
        prof_n2['spec']['ingress'].append(rule)
        rule = {'action': 'Allow',
                'source': {'nets': n2_ips}}
        prof_n1['spec']['ingress'].append(rule)
        self._apply_new_profile(self.new_profiles, self.host1)
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads + self.n2_workloads)
    test_rules_source_ip_nets.batchnumber = 4

    def test_rules_source_ip_sets(self):
        """Test global network sets end-to-end"""
        # Add a rule to each profile that allows traffic from all the workloads in the *other*
        # network by means of a network set (which would normally be blocked).
        prof_n1, prof_n2 = self._get_profiles(self.new_profiles)
        n1_ips = [str(workload.ip) + "/32" for workload in self.n1_workloads]
        n2_ips = [str(workload.ip) + "/32" for workload in self.n2_workloads]

        netset = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkSet',
            'metadata': {
                'name': "netset-1",
                'labels': {"group": "n1"},
            },
            'spec': {
                'nets': n1_ips,
            }
        }
        self.host1.writejson("netset.json", netset)
        self.host1.calicoctl("create -f netset.json")
        netset = {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkSet',
            'metadata': {
                'name': "netset-2",
                'labels': {"group": "n2"},
            },
            'spec': {
                'nets': n2_ips,
            }
        }
        self.host1.writejson("netset.json", netset)
        self.host1.calicoctl("create -f netset.json")

        # Check initial connectivity before we update the rules to reference the
        # network sets.
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads,
                                 fail_list=self.n2_workloads)
        self.assert_connectivity(retries=2,
                                 pass_list=self.n2_workloads,
                                 fail_list=self.n1_workloads)

        rule = {'action': 'Allow',
                'source': {'selector': 'group=="n1"'}}
        prof_n2['spec']['ingress'].append(rule)
        rule = {'action': 'Allow',
                'source': {'selector': 'group=="n2"'}}
        prof_n1['spec']['ingress'].append(rule)
        self._apply_new_profile(self.new_profiles, self.host1)

        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads + self.n2_workloads)
    test_rules_source_ip_sets.batchnumber = 2

    def test_rules_source_ip_nets_2(self):
        # Adjust each profile to allow traffic from all IPs in the other group but then exclude
        # one of the IPs using a notNets match.  The end result is that the first workload in
        # each group should be blocked but the other should be allowed.
        prof_n1, prof_n2 = self._get_profiles(self.new_profiles)
        n1_ips = [str(workload.ip) + "/32" for workload in self.n1_workloads]
        n1_denied_ips = n1_ips[:1]
        _log.info("Network 1 IPs: %s; Denied IPs: %s", n1_ips, n1_denied_ips)

        n2_ips = [str(workload.ip) + "/32" for workload in self.n2_workloads]
        rule = {'action': 'Allow',
                'source': {'nets': n1_ips,
                           'notNets': n1_denied_ips}}
        prof_n2['spec']['ingress'].append(rule)
        _log.info("Profile for network 2: %s", prof_n2)

        rule = {'action': 'Allow',
                'source': {'nets': n2_ips,
                           'notNets': n2_ips[:1]}}
        prof_n1['spec']['ingress'].append(rule)
        self._apply_new_profile(self.new_profiles, self.host1)

        # Check first workload in each group cannot ping the other group.
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads[:1],
                                 fail_list=self.n2_workloads)
        self.assert_connectivity(retries=2,
                                 pass_list=self.n2_workloads[:1],
                                 fail_list=self.n1_workloads)

        # Check non-excluded workloads can all ping each other.
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads[1:] + self.n2_workloads[1:])
        self.assert_connectivity(retries=2,
                                 pass_list=self.n2_workloads[1:] + self.n1_workloads[1:])
    test_rules_source_ip_nets_2.batchnumber = 4

    def test_rules_dest_ip_nets(self):
        # Adjust the egress policies to drop all traffic
        prof_n1, prof_n2 = self._get_profiles(self.new_profiles)
        prof_n2['spec']['egress'] = []
        prof_n1['spec']['egress'] = []
        self._apply_new_profile(self.new_profiles, self.host1)
        self.assert_connectivity(retries=2,
                                 pass_list=self.n2_workloads[:1],
                                 fail_list=self.n1_workloads + self.n2_workloads[1:])

        # Add a destination whitelist to n2 that allows pods within it to reach other pods in n2.
        n2_ips = [str(workload.ip) + "/32" for workload in self.n2_workloads]
        rule = {'action': 'Allow',
                'destination': {'nets': n2_ips}}
        prof_n2['spec']['egress'] = [rule]
        self._apply_new_profile(self.new_profiles, self.host1)
        self.assert_connectivity(retries=2,
                                 pass_list=self.n2_workloads,
                                 fail_list=self.n1_workloads)

        # Add some rules that have a single nets entry and multiple notNets entries.  These are
        # rendered a bit differently in Felix.
        n1_ips = [str(workload.ip) + "/32" for workload in self.n1_workloads]
        rule1 = {'action': 'Allow',
                 'destination': {'nets': n1_ips[0:1],
                                 'notNets': n1_ips[1:]}}
        rule2 = {'action': 'Allow',
                 'destination': {'nets': n1_ips[1:2],
                                 'notNets': n1_ips[:1]}}
        prof_n1['spec']['egress'] = [rule1, rule2]
        self._apply_new_profile(self.new_profiles, self.host1)
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads[:2],
                                 fail_list=self.n1_workloads[2:])
    test_rules_dest_ip_nets.batchnumber = 5

    def test_rules_selector(self):
        self.new_profiles[0]['spec']['labelsToApply']['net'] = 'n1'
        self.new_profiles[1]['spec']['labelsToApply']['net'] = 'n2'
        rule = {'action': 'Allow',
                'source':
                    {'selector': 'net=="n2"'}}
        self.new_profiles[0]['spec']['ingress'].append(rule)
        rule = {'action': 'Allow',
                'source':
                    {'selector': "net=='n1'"}}
        self.new_profiles[1]['spec']['ingress'].append(rule)
        self._apply_new_profile(self.new_profiles, self.host1)
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads + self.n2_workloads)
    test_rules_selector.batchnumber = 5

    def test_rules_tcp_port(self):
        rule = {'action': 'Allow',
                'protocol': 'TCP',
                'destination':
                    {'ports': [80]}}
        # The copy.deepcopy(rule) is needed to ensure that we don't
        # end up with a yaml document with a reference to the same
        # rule.  While this is probably legal, it isn't main line.
        self.new_profiles[0]['spec']['ingress'].append(rule)
        self.new_profiles[1]['spec']['ingress'].append(copy.deepcopy(rule))
        self._apply_new_profile(self.new_profiles, self.host1)
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads + self.n2_workloads,
                                 type_list=['tcp'])
        self.assert_connectivity(retries=2,
                                 pass_list=self.n1_workloads,
                                 fail_list=self.n2_workloads,
                                 type_list=['icmp', 'udp'])
    test_rules_tcp_port.batchnumber = 5

    def test_rules_udp_port(self):
            rule = {'action': 'Allow',
                    'protocol': 'UDP',
                    'destination':
                        {'ports': [69]}}
            # The copy.deepcopy(rule) is needed to ensure that we don't
            # end up with a yaml document with a reference to the same
            # rule.  While this is probably legal, it isn't main line.
            self.new_profiles[0]['spec']['ingress'].append(rule)
            self.new_profiles[1]['spec']['ingress'].append(copy.deepcopy(rule))
            self._apply_new_profile(self.new_profiles, self.host1)
            self.assert_connectivity(retries=2,
                                     pass_list=self.n1_workloads + self.n2_workloads,
                                     type_list=['udp'])
            self.assert_connectivity(retries=2,
                                     pass_list=self.n1_workloads,
                                     fail_list=self.n2_workloads,
                                     type_list=['icmp', 'tcp'])
    test_rules_udp_port.batchnumber = 5

    @staticmethod
    def _get_profiles(profiles):
        """
        Sorts and returns the profiles for the networks.
        :param profiles: the list of profiles
        :return: tuple: profile for network1, profile for network2
        """
        prof_n1 = None
        prof_n2 = None
        for profile in profiles:
            if profile['metadata']['name'] == "testnet1":
                prof_n1 = profile
            elif profile['metadata']['name'] == "testnet2":
                prof_n2 = profile
        assert prof_n1 is not None, "Could not find testnet1 profile"
        assert prof_n2 is not None, "Could not find testnet2 profile"
        return prof_n1, prof_n2

    @staticmethod
    def _apply_new_profile(new_profiles, host):
        # Get profiles now, so we have up to date resource versions.
        output = host.calicoctl("get profile -o yaml")
        profiles_now = yaml.safe_load(output)['items']
        resource_version_map = {
            p['metadata']['name']: p['metadata']['resourceVersion']
            for p in profiles_now
        }
        _log.info("resource_version_map = %r", resource_version_map)

        # Set current resource versions in the profiles we are about to apply.
        for p in new_profiles:
            p['metadata']['resourceVersion'] = resource_version_map[p['metadata']['name']]
            if 'creationTimestamp' in p['metadata']:
                del p['metadata']['creationTimestamp']

        # Apply new profiles
        host.writejson("new_profiles", new_profiles)
        host.calicoctl("apply -f new_profiles")

    def _setup_workloads(self, host1, host2):
        # Create the networks on host1, but they should be usable from all
        # hosts.
        network1 = host1.create_network("testnet1")
        network2 = host1.create_network("testnet2")
        networks = [network1, network2]

        n1_workloads = []
        n2_workloads = []

        # Create two workloads on host1 and one on host2 all in network 1.
        n1_workloads.append(host2.create_workload("workload_h2n1_1",
                                                  image="workload",
                                                  network=network1))
        n1_workloads.append(host1.create_workload("workload_h1n1_1",
                                                  image="workload",
                                                  network=network1))
        n1_workloads.append(host1.create_workload("workload_h1n1_2",
                                                  image="workload",
                                                  network=network1))

        # Create similar workloads in network 2.
        n2_workloads.append(host1.create_workload("workload_h1n2_1",
                                                  image="workload",
                                                  network=network2))
        n2_workloads.append(host1.create_workload("workload_h1n2_2",
                                                  image="workload",
                                                  network=network2))
        n2_workloads.append(host2.create_workload("workload_h2n2_1",
                                                  image="workload",
                                                  network=network2))
        print "*******************"
        print "Network1 is:\n%s\n%s" % (
            [x.ip for x in n1_workloads],
            [x.name for x in n1_workloads])
        print "Network2 is:\n%s\n%s" % (
            [x.ip for x in n2_workloads],
            [x.name for x in n2_workloads])
        print "*******************"

        # Assert that endpoints are in Calico
        assert_number_endpoints(host1, 4)
        assert_number_endpoints(host2, 2)

        try:
            self._check_original_connectivity(n1_workloads, n2_workloads)
        except Exception as e:
            _log.exception(e)
            host1.log_extra_diags()
            host2.log_extra_diags()
            raise

        return n1_workloads, n2_workloads, networks

    def _check_original_connectivity(self, n1_workloads, n2_workloads,
                                     types=None):
        # Assert that workloads can communicate with each other on network
        # 1, and not those on network 2.  Ping using IP for all workloads,
        # and by hostname for workloads on the same network (note that
        # a workloads own hostname does not work).
        if types is None:
            types = ['icmp', 'tcp', 'udp']
        self.assert_connectivity(retries=10,
                                 pass_list=n1_workloads,
                                 fail_list=n2_workloads,
                                 type_list=types)

        # Repeat with network 2.
        self.assert_connectivity(pass_list=n2_workloads,
                                 fail_list=n1_workloads,
                                 type_list=types)
