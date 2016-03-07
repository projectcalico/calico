# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import unittest

from mock import patch, MagicMock, ANY, call
from nose.tools import assert_equal, assert_false, assert_raises
from nose_parameterized import parameterized
from pycalico.datastore_datatypes import Rule, Rules

from policy_parser import *

"""
Specifications for NetworkPolicies and the expected set of 
Calico rules that should be generated as a result.
"""
# An empty NetworkPolicy.
network_policy_empty = {"kind": "networkpolicy",
                        "apiversion": "net.alpha.kubernetes.io",
                        "metadata": {"namespace": "ns",
                                     "name": "test-policy"},
                        "spec": {}}
network_policy_empty_result = []

# NetworkPolicy with only ports defined.
ports = [{"port": 80, "protocol": "TCP"}, 
         {"port": 443, "protocol": "UDP"}]
spec = {"ingress": [{"ports": ports}]}
network_policy_ports = {"kind": "networkpolicy",
                        "apiversion": "net.alpha.kubernetes.io",
                        "metadata": {"namespace": "ns",
                                     "name": "test-policy"},
                        "spec": spec}
network_policy_ports_result = [
        Rule(action="allow", dst_ports=[80], protocol="tcp"),
        Rule(action="allow", dst_ports=[443], protocol="udp")
]

# NetworkPolicy with only pods defined.
froms = [{"pods": {"role": "diags"}}, 
         {"pods": {"tier": "db"}}]
spec = {"ingress": [{"from": froms}]}
network_policy_froms = {"kind": "networkpolicy",
                        "apiversion": "net.alpha.kubernetes.io",
                        "metadata": {"namespace": "ns",
                                     "name": "test-policy"},
                        "spec": spec}
network_policy_froms_result = [
        Rule(action="allow", src_selector="role == 'diags' && calico/k8s_ns == 'ns'"),
        Rule(action="allow", src_selector="tier == 'db' && calico/k8s_ns == 'ns'")
]

# NetworkPolicy with ports and pods defined.
froms = [{"pods": {"role": "diags"}}, 
         {"pods": {"tier": "db"}}]
ports = [{"port": 80, "protocol": "TCP"}, 
         {"port": 443, "protocol": "UDP"}]
spec = {"ingress": [{"from": froms, "ports": ports}]}
network_policy_both = {"kind": "networkpolicy",
                        "apiversion": "net.alpha.kubernetes.io",
                        "metadata": {"namespace": "ns",
                                     "name": "test-policy"},
                        "spec": spec}
network_policy_both_result = [
        Rule(action="allow", 
             src_selector="role == 'diags' && calico/k8s_ns == 'ns'", 
             dst_ports=[80], protocol="tcp"),
        Rule(action="allow", 
             src_selector="tier == 'db' && calico/k8s_ns == 'ns'", 
             dst_ports=[80], protocol="tcp"),
        Rule(action="allow", 
             src_selector="role == 'diags' && calico/k8s_ns == 'ns'", 
             dst_ports=[443], protocol="udp"),
        Rule(action="allow", 
             src_selector="tier == 'db' && calico/k8s_ns == 'ns'", 
             dst_ports=[443], protocol="udp")
]

# NetworkPolicy with pods and namespaces defined.
froms = [{"namespaces": {"role": "prod"}}, 
         {"pods": {"tier": "db"}}]
spec = {"ingress": [{"from": froms}]}
network_policy_from_pods_ns = {"kind": "networkpolicy",
                        "apiversion": "net.alpha.kubernetes.io",
                        "metadata": {"namespace": "ns",
                                     "name": "test-policy"},
                        "spec": spec}
network_policy_from_pods_ns_result = [
        Rule(action="allow", src_selector="k8s_ns/label/role == 'prod'"),
        Rule(action="allow", src_selector="tier == 'db' && calico/k8s_ns == 'ns'")
]

# NetworkPolicy all pods and all namespaces.
froms = [{"namespaces": None}, 
         {"pods": None}]
spec = {"ingress": [{"from": froms}]}
network_policy_from_all = {"kind": "networkpolicy",
                        "apiversion": "net.alpha.kubernetes.io",
                        "metadata": {"namespace": "ns",
                                     "name": "test-policy"},
                        "spec": spec}
network_policy_from_all_result = [
        Rule(action="allow", src_selector="has(calico/k8s_ns)"),
        Rule(action="allow", src_selector="calico/k8s_ns == 'ns'")
]

# Invalid: Cannot declare both namespaces and pods in same from. 
froms = [{"namespaces": None, "pods": None}] 
spec = {"ingress": [{"from": froms}]}
network_policy_invalid_both = {"kind": "networkpolicy",
                        "apiversion": "net.alpha.kubernetes.io",
                        "metadata": {"namespace": "ns",
                                     "name": "test-policy"},
                        "spec": spec}
network_policy_invalid_both_result =  PolicyError

# No ingress rules - should allow all. 
spec = {"ingress": [None]}
network_policy_empty_rule = {"kind": "networkpolicy",
                        "apiversion": "net.alpha.kubernetes.io",
                        "metadata": {"namespace": "ns",
                                     "name": "test-policy"},
                        "spec": spec}
network_policy_empty_rule_result = [Rule(action="allow")] 


class PolicyParserTest(unittest.TestCase):
    """
    Test class for PolicyParser class.
    """
    @parameterized.expand([
        (network_policy_empty, network_policy_empty_result),
        (network_policy_ports, network_policy_ports_result),
        (network_policy_froms, network_policy_froms_result),
        (network_policy_both, network_policy_both_result),
        (network_policy_from_pods_ns, network_policy_from_pods_ns_result),
        (network_policy_from_all, network_policy_from_all_result),
        (network_policy_invalid_both, network_policy_invalid_both_result),
        (network_policy_empty_rule, network_policy_empty_rule_result),
    ])
    def test_parse_policy(self, policy, expected):
        # Parse it.
        self.parser = PolicyParser(policy)

        # If expected result is an exception, try to catch it.
        try:
            rules = self.parser.calculate_inbound_rules()
        except Exception, e:
            if isinstance(e, expected): 
                pass
            else:
                raise
        else:
            assert_equal(sorted(rules), sorted(expected))
