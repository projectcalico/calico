# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
import yaml

from netaddr import IPNetwork
from nose_parameterized import parameterized

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost
from tests.st.utils.exceptions import CommandExecError

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)


class TestPool(TestBase):
    """
    Test calicoctl pool
    1) Test the CRUD aspects of the pool commands.
    2) Test IP assignment from pool.
    BGP exported routes are hard to test and aren't expected to change much so
    write tests for them (yet)
    """

    def test_pool_crud(self):
        """
        Test that a basic CRUD flow for pool commands works.
        """
        with DockerHost('host', dind=False, start_calico=False) as host:
            # Set up the ipv4 and ipv6 pools to use
            ipv4_net = IPNetwork("10.0.1.0/24")
            ipv6_net = IPNetwork("fed0:8001::/64")

            ipv4_pool_dict = {'apiVersion': 'v1',
                              'kind': 'ipPool',
                              'metadata': {'cidr': str(ipv4_net.cidr)},
                              'spec': {'ipip': {'enabled': True}}
                              }

            ipv6_pool_dict = {'apiVersion': 'v1',
                              'kind': 'ipPool',
                              'metadata': {'cidr': str(ipv6_net.cidr)},
                              'spec': {}
                              }

            # Write out some yaml files to load in through calicoctl-go
            # We could have sent these via stdout into calicoctl, but this
            # seemed easier.
            self.writeyaml('/tmp/ipv4.yaml', ipv4_pool_dict)
            self.writeyaml('/tmp/ipv6.yaml', ipv6_pool_dict)

            # Create the ipv6 network using calicoctl
            host.calicoctl("create -f /tmp/ipv6.yaml")
            # Now read it out (yaml format) with calicoctl:
            self.check_data_in_datastore(host, [ipv6_pool_dict], "ipPool")

            # Add in the ipv4 network with calicoctl
            host.calicoctl("create -f /tmp/ipv4.yaml")
            # Now read it out with the calicoctl:
            self.check_data_in_datastore(
                host, [ipv4_pool_dict, ipv6_pool_dict], "ipPool")

            # Remove both the ipv4 pool and ipv6 pool
            host.calicoctl("delete -f /tmp/ipv6.yaml")
            host.calicoctl("delete -f /tmp/ipv4.yaml")
            # Assert output contains neither network
            self.check_data_in_datastore(host, [], "ipPool")

            # Assert that deleting the pool again fails.
            self.assertRaises(CommandExecError,
                              host.calicoctl, "delete -f /tmp/ipv4.yaml")


class TestCreateFromFile(TestBase):
    """
    Test calicoctl create command
    Test data is a pair of different resource objects of each type.
    Test creates one using json and the other using yaml, then we retrieve
    them and check the output objects are the same as we input when retrieved
    in both yaml and json formats.
    """

    testdata = [
        ("bgpPeer1", {
            'apiVersion': 'v1',
            'kind': 'bgpPeer',
            'metadata': {'node': 'Node1',
                         'peerIP': '192.168.0.250',
                         'scope': 'node'},
            'spec': {'asNumber': 64514}
        }),
        ("bgpPeer2", {
            'apiVersion': 'v1',
            'kind': 'bgpPeer',
            'metadata': {'node': 'Node2',
                         'peerIP': 'fd5f::6:ee',
                         'scope': 'node'},
            'spec': {'asNumber': 64590}
        }),
        ("hostEndpoint1", {
            'apiVersion': 'v1',
            'kind': 'hostEndpoint',
            'metadata': {'node': 'host1',
                         'labels': {'type': 'database'},
                         'name': 'endpoint1'},
            'spec': {'interfaceName': 'eth0',
                     'profiles': ['prof1',
                                  'prof2']}
        }),
        ("hostEndpoint2", {
            'apiVersion': 'v1',
            'kind': 'hostEndpoint',
            'metadata': {'node': 'host2',
                         'labels': {'type': 'frontend'},
                         'name': 'endpoint2'},
            'spec': {'interfaceName': 'cali7',
                     'profiles': ['prof1',
                                  'prof2']}
        }),
        ("policy1", {'apiVersion': 'v1',
                     'kind': 'policy',
                     'metadata': {'name': 'policy1'},
                     'spec': {'egress': [{'action': 'allow',
                                          'source': {
                                              'selector':
                                                  "type=='application'"},
                                          'destination': {},
                                          }],
                              'ingress': [{'notICMP': {'type': 19, 'code': 255},
                                           'ipVersion': 4,
                                           'action': 'deny',
                                           'destination': {
                                               'notNet': '10.3.0.0/16',
                                               'notPorts': ['110:1050'],
                                               'notSelector': "type=='apples'",
                                               'notTag': "bananas",
                                               'net': '10.2.0.0/16',
                                               'ports': ['100:200'],
                                               'selector':
                                                   "type=='application'",
                                               'tag': 'alphatag'},
                                           'icmp': {'type': 10, 'code': 6},
                                           'protocol': 'tcp',
                                           'source': {
                                               'notNet': '10.1.0.0/16',
                                               'notPorts': [1050],
                                               'notSelector': "type=='database'",
                                               'notTag': 'bartag',
                                               'net': '10.0.0.0/16',
                                               'ports': [1234,
                                                         '10:1024'],
                                               'selector':
                                                   "type=='application'",
                                               'tag': 'footag'}}],
                              'order': 100,
                              'selector': "type=='database'"}}),
        ("policy2", {'apiVersion': 'v1',
                     'kind': 'policy',
                     'metadata': {'name': 'policy2'},
                     'spec': {'egress': [{'action': 'deny',
                                          'destination': {},
                                          'protocol': 'tcp',
                                          'source': {}}],
                              'ingress': [{'action': 'allow',
                                           'destination': {},
                                           'protocol': 'udp',
                                           'source': {}}],
                              'order': 100000,
                              'selector': "",
                              'doNotTrack': True}}),
        ("pool1", {'apiVersion': 'v1',
                   'kind': 'ipPool',
                   'metadata': {'cidr': "10.0.1.0/24"},
                   'spec': {'ipip': {'enabled': True}}
                   }),
        ("pool2", {'apiVersion': 'v1',
                   'kind': 'ipPool',
                   'metadata': {'cidr': "10.0.2.0/24"},
                   'spec': {'ipip': {'enabled': True}}
                   }),
        ("profile1", {'apiVersion': 'v1',
                      'kind': 'profile',
                      'metadata': {
                          'labels': {'foo': 'bar'},
                          'tags': ['tag1', 'tag2s'],
                          'name': 'profile1'
                      },
                      'spec': {
                          'egress': [{'action': 'allow',
                                      'destination': {},
                                      'source': {
                                          'selector': "type=='application'"}}],
                          'ingress': [{'notICMP': {'type': 19, 'code': 255},
                                       'ipVersion': 4,
                                       'action': 'deny',
                                       'destination': {
                                           'notNet': '10.3.0.0/16',
                                           'notPorts': ['110:1050'],
                                           'notSelector': "type=='apples'",
                                           'notTag': "bananas",
                                           'net': '10.2.0.0/16',
                                           'ports': ['100:200'],
                                           'selector': "type=='application'",
                                           'tag': 'alphatag'},
                                       'icmp': {'type': 10, 'code': 6},
                                       'protocol': 'tcp',
                                       'source': {
                                           'notNet': '10.1.0.0/16',
                                           'notPorts': [1050],
                                           'notSelector': "type=='database'",
                                           'notTag': 'bartag',
                                           'net': '10.0.0.0/16',
                                           'ports': [1234, '10:20'],
                                           'selector': "type=='application'",
                                           'tag': "production"}}],
                      }}),
        ("profile2", {'apiVersion': 'v1',
                      'kind': 'profile',
                      'metadata': {
                          'name': 'profile2',
                          'tags': ['tag1', 'tag2s']
                      },
                      'spec': {
                          'egress': [{'action': 'allow',
                                      'destination': {},
                                      'source': {}}],
                          'ingress': [{'ipVersion': 6,
                                       'action': 'deny',
                                       'destination': {},
                                       'source': {}}],
                      }}),
    ]

    @parameterized.expand(testdata)
    def test_create_from_file_yaml(self, name, data):
        self._check_data_save_load(data)
        with DockerHost('host', dind=False, start_calico=False) as host:
            res_type = data['kind']
            logger.debug("Testing %s" % res_type)
            # Write out the files to load later
            self.writeyaml('/tmp/%s-1.yaml' % res_type, data)

            host.calicoctl("create -f /tmp/%s-1.yaml" % res_type)
            # Test use of create with stdin

            # Check both come out OK in yaml:
            self.check_data_in_datastore(
                host, [data], res_type)

            # Check both come out OK in json:
            self.check_data_in_datastore(
                host, [data], res_type, yaml_format=False)

            # Tidy up
            host.calicoctl("delete -f /tmp/%s-1.yaml" % res_type)

            # Check it deleted
            self.check_data_in_datastore(host, [], res_type)

    @parameterized.expand(testdata)
    def test_create_from_file_json(self, name, data):
        self._check_data_save_load(data)
        with DockerHost('host', dind=False, start_calico=False) as host:
            res_type = data['kind']
            logger.debug("Testing %s" % res_type)
            # Write out the files to load later
            self.writejson('/tmp/%s-1.json' % res_type, data)

            host.calicoctl("create -f /tmp/%s-1.json" % res_type)
            # Test use of create with stdin

            # Check both come out OK in yaml:
            self.check_data_in_datastore(
                host, [data], res_type)

            # Check both come out OK in json:
            self.check_data_in_datastore(
                host, [data], res_type, yaml_format=False)

            # Tidy up
            host.calicoctl("delete -f /tmp/%s-1.json" % res_type)

            # Check it deleted
            self.check_data_in_datastore(host, [], res_type)

    @parameterized.expand(testdata)
    def test_create_from_stdin_json(self, name, data):
        self._check_data_save_load(data)
        with DockerHost('host', dind=False, start_calico=False) as host:
            res_type = data['kind']
            logger.debug("Testing %s" % res_type)
            # Write out the files to load later
            self.writejson('/tmp/%s-1.json' % res_type, data)

            # Test use of create with stdin
            host.execute(
                "cat /tmp/%s-1.json | /code/dist/calicoctl create -f -" %
                res_type)

            # Check both come out OK in yaml:
            self.check_data_in_datastore(
                host, [data], res_type)

            # Check both come out OK in json:
            self.check_data_in_datastore(
                host, [data], res_type, yaml_format=False)

            # Tidy up
            host.calicoctl("delete -f /tmp/%s-1.json" % res_type)

            # Check it deleted
            self.check_data_in_datastore(host, [], res_type)

    @parameterized.expand(testdata)
    def test_create_from_stdin_yaml(self, name, data):
        self._check_data_save_load(data)
        with DockerHost('host', dind=False, start_calico=False) as host:
            res_type = data['kind']
            logger.debug("Testing %s" % res_type)
            # Write out the files to load later
            self.writeyaml('/tmp/%s-1.yaml' % res_type, data)

            # Test use of create with stdin
            host.execute(
                "cat /tmp/%s-1.yaml | /code/dist/calicoctl create -f -" %
                res_type)

            # Check both come out OK in yaml:
            self.check_data_in_datastore(
                host, [data], res_type)

            # Check both come out OK in yaml:
            self.check_data_in_datastore(
                host, [data], res_type, yaml_format=False)

            # Tidy up
            host.calicoctl("delete -f /tmp/%s-1.yaml" % res_type)

            # Check it deleted
            self.check_data_in_datastore(host, [], res_type)

    @parameterized.expand([
        ("bgpPeer",
         {
             'apiVersion': 'v1',
             'kind': 'bgpPeer',
             'metadata': {'node': 'Node1',
                          'peerIP': '192.168.0.250',
                          'scope': 'node'},
             'spec': {'asNumber': 64514}
         },
         {
             'apiVersion': 'v1',
             'kind': 'bgpPeer',
             'metadata': {'node': 'Node2',
                          'peerIP': 'fd5f::6:ee',
                          'scope': 'node'},
             'spec': {'asNumber': 64590}
         }
         ),
        ("hostEndpoint",
         {
             'apiVersion': 'v1',
             'kind': 'hostEndpoint',
             'metadata': {'node': 'host1',
                          'labels': {'type': 'database'},
                          'name': 'endpoint1'},
             'spec': {'interfaceName': 'eth0',
                      'profiles': ['prof1',
                                   'prof2']}
         },
         {
             'apiVersion': 'v1',
             'kind': 'hostEndpoint',
             'metadata': {'node': 'host2',
                          'labels': {'type': 'frontend'},
                          'name': 'endpoint2'},
             'spec': {'interfaceName': 'cali7',
                      'profiles': ['prof1',
                                   'prof2']}
         },
         ),
        ("policy",
         {'apiVersion': 'v1',
          'kind': 'policy',
          'metadata': {'name': 'policy1', },
          'spec': {'egress': [{'action': 'allow',
                               'source': {
                                   'selector': "type=='application'"},
                               'destination': {},
                               }],
                   'ingress': [{'notICMP': {'type': 19, 'code': 255},
                                'ipVersion': 4,
                                'action': 'deny',
                                'destination': {
                                    'notNet': '10.3.0.0/16',
                                    'notPorts': ['110:1050'],
                                    'notSelector': "type=='apples'",
                                    'notTag': "bananas",
                                    'net': '10.2.0.0/16',
                                    'ports': ['100:200'],
                                    'selector': "type=='application'",
                                    'tag': 'alphatag'},
                                'icmp': {'type': 10, 'code': 6},
                                'protocol': 'tcp',
                                'source': {'notNet': '10.1.0.0/16',
                                           'notPorts': [1050],
                                           'notSelector': "type=='database'",
                                           'notTag': 'bartag',
                                           'net': '10.0.0.0/16',
                                           'ports': [1234, '10:1024'],
                                           'selector': "type=='application'",
                                           'tag': 'footag'}}],
                   'order': 100,
                   'selector': "type=='database'"}},
         {'apiVersion': 'v1',
          'kind': 'policy',
          'metadata': {'name': 'policy2',

                       },
          'spec': {'egress': [{'action': 'deny',
                               'destination': {},
                               'protocol': 'tcp',
                               'source': {}}],
                   'ingress': [{'action': 'allow',
                                'destination': {},
                                'protocol': 'udp',
                                'source': {}}],
                   'order': 100000,
                   'selector': ""}},
         ),
        ("ipPool",
         {'apiVersion': 'v1',
          'kind': 'ipPool',
          'metadata': {'cidr': "10.0.1.0/24"},
          'spec': {'ipip': {'enabled': True}}
          },
         {'apiVersion': 'v1',
          'kind': 'ipPool',
          'metadata': {'cidr': "10.0.2.0/24"},
          'spec': {'ipip': {'enabled': True}}
          },
         ),
        ("profile",
         {'apiVersion': 'v1',
          'kind': 'profile',
          'metadata': {
              'labels': {'foo': 'bar'},
              'name': 'profile1',
              'tags': ['tag1', 'tag2s']
          },
          'spec': {
              'egress': [{'action': 'allow',
                          'destination': {},
                          'source': {
                              'selector': "type=='application'"}}],
              'ingress': [{'notICMP': {'type': 19, 'code': 255},
                           'ipVersion': 4,
                           'action': 'deny',
                           'destination': {
                               'notNet': '10.3.0.0/16',
                               'notPorts': ['110:1050'],
                               'notSelector': "type=='apples'",
                               'notTag': "bananas",
                               'net': '10.2.0.0/16',
                               'ports': ['100:200'],
                               'selector': "type=='application'",
                               'tag': 'alphatag'},
                           'icmp': {'type': 10, 'code': 6},
                           'protocol': 'tcp',
                           'source': {'notNet': '10.1.0.0/16',
                                      'notPorts': [1050],
                                      'notSelector': "type=='database'",
                                      'notTag': 'bartag',
                                      'net': '10.0.0.0/16',
                                      'ports': [1234, '10:20'],
                                      'selector': "type=='application'",
                                      'tag': "production"}}],
              }},
         {'apiVersion': 'v1',
          'kind': 'profile',
          'metadata': {
              'name': 'profile2',
              'tags': ['tag1', 'tag2s']
          },
          'spec': {
              'egress': [{'action': 'allow',
                          'destination': {},
                          'source': {}}],
              'ingress': [{'ipVersion': 6,
                           'action': 'deny',
                           'destination': {},
                           'source': {}}],
              }},
         )
    ])
    def test_create_from_file(self, res, data1, data2):
        self._check_data_save_load(data1)
        self._check_data_save_load(data2)
        with DockerHost('host', dind=False, start_calico=False) as host:
            logger.debug("Testing %s" % res)
            # Write out the files to load later
            self.writeyaml('/tmp/%s-1.yaml' % res, data1)
            self.writejson('/tmp/%s-2.json' % res, data2)

            host.calicoctl("create -f /tmp/%s-1.yaml" % res)
            # Test use of create with stdin
            host.execute(
                "cat /tmp/%s-2.json | /code/dist/calicoctl create -f -" % res)

            # Check both come out OK in yaml:
            self.check_data_in_datastore(
                host, [data1, data2], res)

            # Check both come out OK in json:
            self.check_data_in_datastore(
                host, [data1, data2], res, yaml_format=False)

            # Tidy up
            host.calicoctl("delete -f /tmp/%s-1.yaml" % res)
            host.calicoctl("delete -f /tmp/%s-2.json" % res)

            # Check it deleted
            self.check_data_in_datastore(host, [], res)

    @parameterized.expand([
        ("bgpPeer",
         {
             'apiVersion': 'v1',
             'kind': 'bgpPeer',
             'metadata': {'node': 'Node1',
                          'peerIP': '192.168.0.250',
                          'scope': 'node'},
             'spec': {'asNumber': 64514}
         },
         {
             'apiVersion': 'v1',
             'kind': 'bgpPeer',
             'metadata': {'node': 'Node1',
                          'peerIP': '192.168.0.250',
                          'scope': 'node'},
             'spec': {'asNumber': 64590}
         }
         ),
        ("hostEndpoint",
         {
             'apiVersion': 'v1',
             'kind': 'hostEndpoint',
             'metadata': {'node': 'host1',
                          'labels': {'type': 'database'},
                          'name': 'endpoint1'},
             'spec': {'interfaceName': 'eth0',
                      'profiles': ['prof1',
                                   'prof2']}
         },
         {
             'apiVersion': 'v1',
             'kind': 'hostEndpoint',
             'metadata': {'node': 'host1',
                          'labels': {'type': 'frontend'},
                          'name': 'endpoint1'},
             'spec': {'interfaceName': 'cali7',
                      'profiles': ['prof1',
                                   'prof2']}
         },
         ),
        ("policy",
         {'apiVersion': 'v1',
          'kind': 'policy',
          'metadata': {'name': 'policy1', },
          'spec': {'egress': [{'action': 'deny',
                               'protocol': 'tcp',
                               'destination': {},
                               'source': {
                                   'notNet': 'aa:bb:cc:ff::/100',
                                   'notPorts': [100],
                                   'notTag': 'abcd'}}],
                   'ingress': [{'action': 'allow',
                                'destination': {
                                    'net': '10.20.30.40/32',
                                    'tag': 'database'},
                                'icmp': {'code': 100,
                                         'type': 10},
                                'protocol': 'udp',
                                'source': {
                                    'net': '1.2.0.0/16',
                                    'ports': [1, 2, 3, 4],
                                    'tag': 'web'}}],
                   'order': 6543215.5,
                   'selector': ''}},
         {'apiVersion': 'v1',
          'kind': 'policy',
          'metadata': {'name': 'policy1'},
          'spec': {'egress': [{'action': 'deny',
                               'protocol': 'tcp',
                               'destination': {},
                               'source': {
                                   'notNet': 'aa:bb:cc::/100',
                                   'notPorts': [100],
                                   'notTag': 'abcd'}}],
                   'ingress': [{'action': 'allow',
                                'destination': {
                                    'net': '10.20.30.40/32',
                                    'tag': 'database'},
                                'icmp': {'code': 100,
                                         'type': 10},
                                'protocol': 'udp',
                                'source': {
                                    'net': '1.2.3.0/24',
                                    'ports': [1, 2, 3, 4],
                                    'tag': 'web'}}],
                   'order': 100000,
                   'selector': ""}},
         ),
        #  https://github.com/projectcalico/libcalico-go/issues/230
        ("policy",
          {'apiVersion': 'v1',
           'kind': 'policy',
           'metadata': {'name': 'policy1', },
           'spec': {'egress': [{'action': 'deny',
                                'protocol': 'tcp',
                                'destination': {},
                                'source': {
                                    'notNet': 'aa:bb:cc:ff::/100',
                                    'notPorts': [100],
                                    'notTag': 'abcd'}}],
                    'ingress': [{'action': 'allow',
                                 'destination': {
                                     'net': '10.20.30.40/32',
                                     'tag': 'database'},
                                 'icmp': {'code': 100,
                                          'type': 10},
                                 'protocol': 'udp',
                                 'source': {
                                     'net': '1.2.0.0/16',
                                     'ports': [1, 2, 3, 4],
                                     'tag': 'web'}}],
                    'order': 6543215.321,
                    'selector': ''}},
          {'apiVersion': 'v1',
           'kind': 'policy',
           'metadata': {'name': 'policy1'},
           'spec': {'egress': [{'action': 'deny',
                                'protocol': 'tcp',
                                'destination': {},
                                'source': {
                                    'notNet': 'aa:bb:cc::/100',
                                    'notPorts': [100],
                                    'notTag': 'abcd'}}],
                    'ingress': [{'action': 'allow',
                                 'destination': {
                                     'net': '10.20.30.40/32',
                                     'tag': 'database'},
                                 'icmp': {'code': 100,
                                          'type': 10},
                                 'protocol': 'udp',
                                 'source': {
                                     'net': '1.2.3.0/24',
                                     'ports': [1, 2, 3, 4],
                                     'tag': 'web'}}],
                    'order': 100000,
                    'selector': ""}},
        ),
        ("ipPool",
         {'apiVersion': 'v1',
          'kind': 'ipPool',
          'metadata': {'cidr': "10.0.1.0/24"},
          'spec': {}
          },
         {'apiVersion': 'v1',
          'kind': 'ipPool',
          'metadata': {'cidr': "10.0.1.0/24"},
          'spec': {'ipip': {'enabled': True}}
          },
         ),
        ("profile",
         {'apiVersion': 'v1',
          'kind': 'profile',
          'metadata': {
              'name': 'profile1',
              'labels': {'type': 'database'},
              'tags': ['tag1', 'tag2s']
          },
          'spec': {
              'egress': [{
                  'source': {},
                  'destination': {},
                  'action': 'deny'}],
              'ingress': [{
                  'source': {},
                  'destination': {},
                  'action': 'deny'}],
          }, },
         {'apiVersion': 'v1',
          'kind': 'profile',
          'metadata': {
              'labels': {'type': 'frontend'},
              'name': 'profile1',
              'tags': ['d', 'e', 'f', 'a1']
          },
          'spec': {
              'egress': [{
                  'source': {},
                  'destination': {},
                  'action': 'deny'}],
              'ingress': [{
                  'source': {},
                  'destination': {},
                  'action': 'deny'}],
              }},
         )
    ])
    def test_apply_create_replace(self, res, data1, data2):
        """
        Test calicoctl create/apply/replace/delete commands.
        Test data is a pair of resource objects - both are the same object,
        but the details differ in some way to simulate a user updating the
        object.
        """
        self._check_data_save_load(data1)
        self._check_data_save_load(data2)
        with DockerHost('host', dind=False, start_calico=False) as host:
            logger.debug("Testing %s" % res)

            # Write test data files for loading later
            self.writeyaml('/tmp/data1.yaml', data1)
            self.writejson('/tmp/data2.json', data2)

            # apply - create when not present
            host.calicoctl("apply -f /tmp/data1.yaml")
            # Check it went in OK
            self.check_data_in_datastore(host, [data1], res)

            # create - skip overwrite with data2
            host.calicoctl("create -f /tmp/data2.json --skip-exists")
            # Check that nothing's changed
            self.check_data_in_datastore(host, [data1], res)

            # replace - overwrite with data2
            host.calicoctl("replace -f /tmp/data2.json")
            # Check that we now have data2 in the datastore
            self.check_data_in_datastore(host, [data2], res)

            # apply - overwrite with data1
            host.calicoctl("apply -f /tmp/data1.yaml")
            # Check that we now have data1 in the datastore
            self.check_data_in_datastore(host, [data1], res)

            # delete
            host.calicoctl("delete --filename=/tmp/data1.yaml")
            # Check it deleted
            self.check_data_in_datastore(host, [], res)

    def _check_data_save_load(self, data):
        """
        Confirms that round tripping the data via json and yaml format works
        OK so that we can be sure any errors the tests find are due to the
        calicoctl code under test
        :param data: The dictionary of test data to check
        :return: None.
        """
        # Do yaml first
        self.writeyaml('/tmp/test', data)
        with open('/tmp/test', 'r') as f:
            output = yaml.safe_load(f.read())
        self.assert_same(data, output)
        # Now check json
        self.writejson('/tmp/test', data)
        with open('/tmp/test', 'r') as f:
            output = json.loads(f.read())
        self.assert_same(data, output)


class InvalidData(TestBase):
    testdata = [
                   ("bgpPeer-invalidkind", {
                       'apiVersion': 'v1',
                       'kind': 'bgppeer',
                       'metadata': {'node': 'Node1',
                                    'peerIP': '192.168.0.250',
                                    'scope': 'node'},
                       'spec': {'asNumber': 64513}
                   }),
                   ("bgpPeer-invalidASnum", {
                       'apiVersion': 'v1',
                       'kind': 'bgpPeer',
                       'metadata': {'node': 'Node1',
                                    'peerIP': '192.168.0.250',
                                    'scope': 'node'},
                       'spec': {'asNumber': 4294967296}
                       # Valid numbers are <=4294967295
                   }),
                   ("bgpPeer-invalidIP", {
                       'apiVersion': 'v1',
                       'kind': 'bgpPeer',
                       'metadata': {'node': 'Node1',
                                    'peerIP': '192.168.0.256',
                                    'scope': 'node'},
                       'spec': {'asNumber': 64513}
                   }),
                   ("bgpPeer-apiversion", {
                       'apiVersion': 'v7',
                       'kind': 'bgpPeer',
                       'metadata': {'node': 'Node1',
                                    'peerIP': '192.168.0.250',
                                    'scope': 'node'},
                       'spec': {'asNumber': 64513}
                   }),
                   ("bgpPeer-invalidIpv6", {
                       'apiVersion': 'v1',
                       'kind': 'bgpPeer',
                       'metadata': {'node': 'Node2',
                                    'peerIP': 'fd5f::6::ee',
                                    'scope': 'node'},
                       'spec': {'asNumber': 64590}
                   }),
                   ("bgpPeer-invalidname", {
                       'apiVersion': 'v1',
                       'kind': 'bgpPeer',
                       'metadata': {'node': 'Node 2',
                                    'peerIP': 'fd5f::6:ee',
                                    'scope': 'node'},
                       'spec': {'asNumber': 64590}
                   }),
                   # See issue https://github.com/projectcalico/libcalico-go/issues/248
                   ("bgpPeer-unrecognisedfield", {
                       'apiVersion': 'v1',
                       'kind': 'bgpPeer',
                       'metadata': {'node': 'Node2',
                                    'peerIP': 'fd5f::6:ee',
                                    'scope': 'node'},
                       'spec': {'asNumber': 64590,
                                'unknown': 'thing'}
                   }),
                   # See issue https://github.com/projectcalico/libcalico-go/issues/222
                   ("bgpPeer-longname", {
                       'apiVersion': 'v1',
                       'kind': 'bgpPeer',
                       'metadata': {'node':
                                        'TestTestTestTestTestTestTestTestTestTestTest'
                                        'TestTestTestTestTestTestTestTestTestTestTest'
                                        'TestTestTestTestTestTestTestTestTestTestTest'
                                        'TestTestTestTestTestTestTestTestTestTestTest'
                                        'TestTestTestTestTestTestTestTestTestTestTest'
                                        'TestTestTestTestTestTestTestTestTestTestTest'
                                        'TestTestTestTestTestTestTestTestTestTestTest'
                                        'TestTestTestTestTestTestTestTestTestTestTest'
                                        'TestTestTestTestTestTestTestTestTestTestTest'
                                        'TestTestTestTestTestTestTestTestTestTestTest'
                                        'TestTestTestTestTestTestTestTestTestTestTest',
                                    'peerIP': 'fd5f::6:ee',
                                    'scope': 'node'},
                       'spec': {'asNumber': 64590}
                   }),
                   ("hostEndpoint-invalidInterface", {
                       'apiVersion': 'v1',
                       'kind': 'hostEndpoint',
                       'metadata': {'node': 'host1',
                                    'labels': {'type': 'database'},
                                    'name': 'endpoint1'},
                       'spec': {'interfaceName': 'wibblywobblyeth0',  # overlength interface name
                                'profiles': ['prof1',
                                             'prof2']}
                   }),
                   # https://github.com/projectcalico/libcalico-go/pull/236/files
                   ("policy-invalidHighPortinList", {
                       'apiVersion': 'v1',
                       'kind': 'policy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'egress': [{'action': 'deny',
                                            'destination': {},
                                            'source': {
                                                'protocol': 'tcp',
                                                'ports': [10, 90, 65536]  # Max port is 65535
                                            },
                                            }],
                                'ingress': [{'action': 'allow',
                                             'destination': {},
                                             'protocol': 'udp',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}}),
                   # https://github.com/projectcalico/libcalico-go/issues/248
                   ("policy-invalidHighPortinRange", {
                       'apiVersion': 'v1',
                       'kind': 'policy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'egress': [{'action': 'deny',
                                            'destination': {},
                                            'source': {
                                                'protocol': 'tcp',
                                                'ports': [1-65536]  # Max port is 65535
                                            },
                                            }],
                                'ingress': [{'action': 'allow',
                                             'destination': {},
                                             'protocol': 'udp',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}}),
                   ("policy-invalidLowPortinRange", {
                       'apiVersion': 'v1',
                       'kind': 'policy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'egress': [{'action': 'deny',
                                            'destination': {},
                                            'source': {
                                                'ports': [0-65535],  # Min port is 1
                                                'protocol': 'tcp',
                                            },
                                            }],
                                'ingress': [{'action': 'allow',
                                             'destination': {},
                                             'protocol': 'udp',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}}),
                   ("policy-invalidLowPortinList", {
                       'apiVersion': 'v1',
                       'kind': 'policy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'egress': [{'action': 'deny',
                                            'destination': {},
                                            'source': {
                                                'protocol': 'tcp',
                                                'ports': [0, 10, 80]  # Min port is 1
                                            },
                                            }],
                                'ingress': [{'action': 'allow',
                                             'destination': {},
                                             'protocol': 'udp',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}}),
                   ("policy-invalidReversedRange", {
                       'apiVersion': 'v1',
                       'kind': 'policy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'egress': [{'action': 'deny',
                                            'destination': {},
                                            'source': {
                                                'protocol': 'tcp',
                                                'ports': [65535-1]  # range should be low-high
                                            },
                                            }],
                                'ingress': [{'action': 'allow',
                                             'destination': {},
                                             'protocol': 'udp',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}}),
                   ("policy-invalidAction", {
                       'apiVersion': 'v1',
                       'kind': 'policy',
                       'metadata': {'name': 'policy2'},
                       'spec': {'egress': [{'action': 'jumpupanddown',  # invalid action
                                            'destination': {},
                                            'protocol': 'tcp',
                                            'source': {},
                                            }],
                                'ingress': [{'action': 'allow',
                                             'destination': {},
                                             'protocol': 'udp',
                                             'source': {}}],
                                'order': 100000,
                                'selector': ""}}),
                   ("pool-invalidNet1", {'apiVersion': 'v1',
                                         'kind': 'ipPool',
                                         'metadata': {'cidr': "10.0.1.0/33"},  # impossible mask
                                         'spec': {'ipip': {'enabled': True}}
                                         }),
                   ("pool-invalidNet2", {'apiVersion': 'v1',
                                         'kind': 'ipPool',
                                         'metadata': {'cidr': "10.0.256.0/24"},  # invalid octet
                                         'spec': {'ipip': {'enabled': True}}
                                         }),
                   ("pool-invalidNet3", {'apiVersion': 'v1',
                                         'kind': 'ipPool',
                                         'metadata': {'cidr': "10.0.250.0"},  # no mask
                                         'spec': {'ipip': {'enabled': True}}
                                         }),
                   ("pool-invalidNet4", {'apiVersion': 'v1',
                                         'kind': 'ipPool',
                                         'metadata': {'cidr': "fd5f::2::1/32"},  # too many ::
                                         'spec': {'ipip': {'enabled': True}}
                                         }),
                   #  https://github.com/projectcalico/libcalico-go/issues/224
                   # ("pool-invalidNet5a", {'apiVersion': 'v1',
                   #                       'kind': 'ipPool',
                   #                       'metadata': {'cidr': "::/0"},  # HUGE pool
                   #                       }),
                   # ("pool-invalidNet5b", {'apiVersion': 'v1',
                   #                       'kind': 'ipPool',
                   #                       'metadata': {'cidr': "1.1.1.1/0"},  # BIG pool
                   #                       }),
                   ("pool-invalidNet6", {'apiVersion': 'v1',
                                         'kind': 'ipPool',
                                         'metadata': {'cidr': "::/128"},
                                         # nothing
                                         }),
                   ("pool-invalidNet7", {'apiVersion': 'v1',
                                         'kind': 'ipPool',
                                         'metadata': {'cidr': "192.168.0.0/27"},  # invalid mask
                                         }),
                   ("pool-invalidNet8", {'apiVersion': 'v1',
                                         'kind': 'ipPool',
                                         'metadata': {'cidr': "fd5f::1/123"}, # invalid mask
                                         }),

                   ("pool-invalidIpIp1", {'apiVersion': 'v1',
                                          'kind': 'ipPool',
                                          'metadata': {'cidr': "10.0.1.0/24"},
                                          'spec': {'ipip': {'enabled': 'True'}}  # enabled value must be a bool
                                          }),
                   ("pool-invalidIpIp2", {'apiVersion': 'v1',
                                          'kind': 'ipPool',
                                          'metadata': {'cidr': "10.0.1.0/24"},
                                          'spec': {'ipip': {'enabled': 'Maybe'}}
                                          }),
                   ("profile-icmptype", {'apiVersion': 'v1',
                                         'kind': 'profile',
                                         'metadata': {
                                             'name': 'profile2',
                                             'tags': ['tag1', 'tag2s']
                                         },
                                         'spec': {
                                             'egress': [{'action': 'allow',
                                                         'destination': {},
                                                         'source': {}}],
                                             'ingress': [{'ipVersion': 6,
                                                          'icmp': {'type': 256,  # max value 255
                                                                   'code': 255},
                                                          'action': 'deny',
                                                          'destination': {},
                                                          'source': {}}],
                                             }}),
                   ("profile-icmpcode", {'apiVersion': 'v1',
                                         'kind': 'profile',
                                         'metadata': {
                                             'name': 'profile2',
                                             'tags': ['tag1', 'tag2s']
                                         },
                                         'spec': {
                                             'egress': [{'action': 'allow',
                                                         'destination': {},
                                                         'source': {}}],
                                             'ingress': [{'ipVersion': 6,
                                                          'icmp': {'type': 19,
                                                                   'code': 256},  # max value 255
                                                          'action': 'deny',
                                                          'destination': {},
                                                          'source': {}}],
                                             }}),
                   ("compound-config", [{
                       'apiVersion': 'v1',
                       'kind': 'bgpPeer',
                       'metadata': {'node': 'Node1',
                                    'peerIP': '192.168.0.250',
                                    'scope': 'node'},
                       'spec': {'asNumber': 64513}},
                       {'apiVersion': 'v1',
                        'kind': 'profile',
                        'metadata': {
                            'name': 'profile2',
                            'tags': ['tag1', 'tag2s']
                        },
                        'spec': {
                            'egress': [{'action': 'allow',
                                        'destination': {},
                                        'source': {}}],
                            'ingress': [{'ipVersion': 6,
                                         'icmp': {'type': 256,  # 1-byte field
                                                  'code': 255},
                                         'action': 'deny',
                                         'destination': {},
                                         'source': {}}],
                            },
                        }],
                    ),
               ]

    @parameterized.expand(testdata)
    def test_invalid_profiles_rejected(self, name, testdata):

        with DockerHost('host', dind=False, start_calico=False) as host:
            commanderror = False
            def check_no_data_in_store(testdata):
                out = host.calicoctl(
                    "get %s --output=yaml" % testdata['kind'])
                output = yaml.safe_load(out)
                assert output == [], "Testdata has left data in datastore " \
                                     "instead of being completely " \
                                     "rejected:\n" \
                                     "Injected: %s\n" \
                                     "Got back: %s" % (testdata, output)

            host.writefile("/tmp/testfile.yaml", testdata)
            try:
                host.calicoctl("create -f /tmp/testfile.yaml")
            except CommandExecError:
                logger.debug("calicoctl error hit, as expected")
                commanderror = True

            if name.startswith('compound'):
                for data in testdata:
                    check_no_data_in_store(data)
            else:
                check_no_data_in_store(testdata)

            # Cover the case where no data got stored, but calicoctl didn't fail:
            assert commanderror is True, "Failed - calicoctl did not fail to add invalid config"
