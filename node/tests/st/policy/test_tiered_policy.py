# Copyright 2024 Tigera, Inc

import copy
import functools
import json
import logging
import subprocess
import time
import yaml
from nose_parameterized import parameterized
from multiprocessing.dummy import Pool

from tests.st.test_base import TestBase, HOST_IPV4
from tests.st.utils.docker_host import DockerHost
from tests.st.utils.utils import assert_number_endpoints, get_ip, \
    ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_HOSTNAME_SSL, ETCD_SCHEME, \
    wipe_etcd

_log = logging.getLogger(__name__)
_log.setLevel(logging.DEBUG)

POST_DOCKER_COMMANDS = ["docker load -i /code/calico-node.tar",
                        "docker load -i /code/busybox.tar",
                        "docker load -i /code/workload.tar"]

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


def parallel_host_setup(num_hosts):
    makehost = functools.partial(DockerHost,
                                 additional_docker_options=ADDITIONAL_DOCKER_OPTIONS,
                                 post_docker_commands=POST_DOCKER_COMMANDS,
                                 start_calico=False)
    hostnames = []
    for i in range(num_hosts):
        hostnames.append("host%s" % i)
    pool = Pool(num_hosts)
    hosts = pool.map(makehost, hostnames)
    pool.close()
    pool.join()
    return hosts


gnp_next_all = {
    "apiVersion": "projectcalico.org/v3",
    "kind": "GlobalNetworkPolicy",
    "metadata": {"name": "gnp_next_all"},
    "spec": {
        "order": 10,
        "ingress": [{"action": "Pass"}],
        "egress": [{"action": "Pass"}]
    }
}

gnp_allow_all = {
    "apiVersion": "projectcalico.org/v3",
    "kind": "GlobalNetworkPolicy",
    "metadata": {"name": "gnp_allow_all"},
    "spec": {
        "order": 10,
        "ingress": [{"action": "Allow"}],
        "egress": [{"action": "Allow"}]
    }
}

gnp_deny_all = {
    "apiVersion": "projectcalico.org/v3",
    "kind": "GlobalNetworkPolicy",
    "metadata": {"name": "gnp_deny_all"},
    "spec": {
        "order": 10,
        "ingress": [{"action": "Deny"}],
        "egress": [{"action": "Deny"}]}
}
gnp_none_all = {
    "apiVersion": "projectcalico.org/v3",
    "kind": "GlobalNetworkPolicy",
    "metadata": {"name": "gnp_none_all"},
    "spec": {
        "selector": "all()",
        "order": 10,
        "ingress": [],
        "egress": []}
}


class TieredPolicyWorkloads(TestBase):
    def setUp(self):
        _log.debug("Override the TestBase setUp() method which wipes etcd. Do nothing.")
        # Wipe policies and tiers before each test
        self.delete_all("gnp")
        self.delete_all("tier")

    def delete_all(self, resource):
        # Grab all objects of a resource type
        objects = yaml.load(self.hosts[0].calicoctl("get %s -o yaml" % resource))
        # and delete them (if there are any)
        if len(objects) > 0:
            _log.info("objects: %s", objects)
            if 'items' in objects:
                # Filter out object(s) representing the default tier.
                objects['items'] = [x for x in objects['items']
                                    if (x.get('kind', '') != 'Tier' or
                                        'metadata' not in x or
                                        x['metadata'].get('name', '') != 'default')]
            if 'items' in objects and len(objects['items']) == 0:
                pass
            else:
                self._delete_data(objects, self.hosts[0])

    @staticmethod
    def sleep(length):
        _log.debug("Sleeping for %s" % length)
        time.sleep(length)

    @classmethod
    def setUpClass(cls):
        _log.debug("Wiping etcd")
        wipe_etcd(HOST_IPV4)

        cls.policy_tier_name = "default"
        cls.next_tier_allowed = False
        cls.hosts = []
        cls.hosts.append(DockerHost("host1",
                                    additional_docker_options=ADDITIONAL_DOCKER_OPTIONS,
                                    post_docker_commands=POST_DOCKER_COMMANDS,
                                    start_calico=False))
        cls.hosts.append(DockerHost("host2",
                                    additional_docker_options=ADDITIONAL_DOCKER_OPTIONS,
                                    post_docker_commands=POST_DOCKER_COMMANDS,
                                    start_calico=False))

        for host in cls.hosts:
            host.start_calico_node()
        # Allow time for calico-node to load
        time.sleep(10)

        cls.networks = []
        cls.networks.append(cls.hosts[0].create_network("testnet2"))
        cls.sleep(10)

        cls.n1_workloads = []
        # Create two workloads on cls.hosts[0] and one on cls.hosts[1] all in network 1.
        cls.n1_workloads.append(cls.hosts[1].create_workload("workload_h2n1_1",
                                                             image="workload",
                                                             network=cls.networks[0]))
        cls.sleep(2)
        cls.n1_workloads.append(cls.hosts[0].create_workload("workload_h1n1_1",
                                                             image="workload",
                                                             network=cls.networks[0]))
        # Assert that endpoints are in Calico
        assert_number_endpoints(cls.hosts[0], 1)
        assert_number_endpoints(cls.hosts[1], 1)

    @classmethod
    def tearDownClass(cls):
        # Tidy up
        for host in cls.hosts:
            host.remove_workloads()
        for network in cls.networks:
            network.delete()
        for host in cls.hosts:
            host.cleanup()
            del host

    def test_tier_ordering_explicit(self):
        """Check correct ordering of tiers by their explicit order field."""
        self.policy_tier_name = "the-tier"
        self.next_tier_allowed = True
        self._do_tier_order_test("tier-c", 1,
                                 "tier-b", 2,
                                 "tier-a", 3)

    def test_tier_ordering_implicit(self):
        """Check correct ordering of tiers by name as tie-breaker."""
        self.policy_tier_name = "the-tier"
        self.next_tier_allowed = True
        self._do_tier_order_test("tier-1", 1,
                                 "tier-2", 1,
                                 "tier-3", 1)

    def set_tier(self, name=None, order=10):
        _log.debug("Setting tier data: \n"
                   "name : %s\norder : %s",
                   name, order)
        if name is None:
            name = self.policy_tier_name
        tier = {"apiVersion": "projectcalico.org/v3",
                "kind": "Tier",
                "metadata": {"name": name},
                "spec": {"order": order}
                }
        self._apply_data(tier, self.hosts[0])

    def _do_tier_order_test(self, first_tier, first_tier_order, second_tier,
                            second_tier_order, third_tier, third_tier_order):
        # Note that the following tests need to check that connectivity to
        # the rpcbind service alternates between succeeding and failing so
        # that we spot if felix hasn't actually changed anything.
        # Check we start with connectivity.
        _log.info("Starting tier order test %s (%s); %s (%s); %s (%s)",
                  first_tier, first_tier_order, second_tier,
                  second_tier_order, third_tier, third_tier_order)

        self.assert_connectivity(self.n1_workloads)

        # Create tiers and endpoints.
        _log.info("Configuring tiers.")
        self.set_tier(name=first_tier, order=first_tier_order)
        self.set_tier(name=second_tier, order=second_tier_order)
        self.set_tier(name=third_tier, order=third_tier_order)

        # Slip a deny into the third tier, just to alternate DENY/ALLOW.
        self.set_policy(third_tier, "pol-1", gnp_deny_all)
        # Check that access is blocked.
        self.assert_no_connectivity(self.n1_workloads)

        # Allow in first tier only, should allow.
        _log.info("Allow in first tier only, should allow.")
        self.set_policy(first_tier, "pol-1", gnp_allow_all)
        self.set_policy(second_tier, "pol-1", gnp_deny_all)
        self.set_policy(third_tier, "pol-1", gnp_deny_all)
        self.assert_connectivity(self.n1_workloads)

        # Deny in all tiers, should drop.
        _log.info("Deny in all tiers, should drop.")
        # Fix up second tier
        self.set_policy(second_tier, "pol-1", gnp_deny_all)
        self.set_policy(first_tier, "pol-1", gnp_deny_all)
        self.assert_no_connectivity(self.n1_workloads)

        # Allow in first tier, should allow.
        self.set_policy(first_tier, "pol-1", gnp_allow_all)
        self.assert_connectivity(self.n1_workloads)

        # Switch, now the first tier drops but the later ones allow.
        _log.info("Switch, now the first tier drops but the later ones "
                  "allow.")
        self.set_policy(first_tier, "pol-1", gnp_deny_all)
        self.set_policy(second_tier, "pol-1", gnp_allow_all)
        self.set_policy(third_tier, "pol-1", gnp_allow_all)
        self.assert_no_connectivity(self.n1_workloads)

        # Fall through via a next-tier policy in the first tier.
        _log.info("Fall through via a next-tier policy in the first "
                  "tier.")
        self.set_policy(first_tier, "pol-1", gnp_next_all)
        self.assert_connectivity(self.n1_workloads)

        # Swap the second tier for a drop.
        _log.info("Swap the second tier for a drop.")
        self.set_policy(second_tier, "pol-1", gnp_deny_all)
        self.assert_no_connectivity(self.n1_workloads)

    def _apply_data(self, data, host):
        _log.debug("Applying data with calicoctl: %s", data)
        self._use_calicoctl("apply", data, host)

    def _delete_data(self, data, host):
        _log.debug("Deleting data with calicoctl: %s", data)
        self._use_calicoctl("delete", data, host)

    @staticmethod
    def _use_calicoctl(action, data, host):
        # Delete creationTimestamp fields from the data that we're going to
        # write.
        _log.debug("Use calicoctl: %s", data)
        if type(data) == list:
            for d in data:
                for obj in d.get('items', []):
                    if 'creationTimestamp' in obj['metadata']:
                        del obj['metadata']['creationTimestamp']
                if 'metadata' in data and 'creationTimestamp' in data['metadata']:
                    del data['metadata']['creationTimestamp']
        else:
            for obj in data.get('items', []):
                if 'creationTimestamp' in obj['metadata']:
                    del obj['metadata']['creationTimestamp']
            if 'metadata' in data and 'creationTimestamp' in data['metadata']:
                del data['metadata']['creationTimestamp']

        # use calicoctl with data
        host.writefile("new_data",
                       yaml.dump(data, default_flow_style=False))
        host.calicoctl("%s -f new_data" % action)

    def set_policy(self, tier, policy_name, data, order=None):
        data = copy.deepcopy(data)
        if order is not None:
            data["spec"]["order"] = order

        if not self.next_tier_allowed:
            for dirn in ["ingress", "egress"]:
                if dirn in data:
                    def f(rule):
                        return rule != {"action": "Pass"}
                    data[dirn] = filter(f, data[dirn])

        data["metadata"]["name"] = policy_name
        if tier != "default":
            data["spec"]["tier"] = tier
            data["metadata"]["name"] = "{tier}.{policy}".format(tier=tier,
                                                                policy=data["metadata"]["name"])
        elif tier == "default":
            # TODO(doublek): This elif can be removed when proper tier
            # validation has been added.
            data["spec"]["tier"] = "default"
            data["metadata"]["name"] = "default.{policy}".format(policy=data["metadata"]["name"])

        self._apply_data(data, self.hosts[0])

    def assert_no_connectivity(self, workload_list, retries=0, type_list=None):
        """
        Checks that none of the workloads passed in can contact any of the others.
        :param workload_list:
        :param retries:
        :param type_list:
        :return:
        """
        for workload in workload_list:
            the_rest = [wl for wl in workload_list if wl is not workload]
            self.assert_connectivity([workload], fail_list=the_rest,
                                     retries=retries, type_list=type_list)

    def test_policy_ordering_explicit(self):
        """Check correct ordering of policies by their explicit order
        field."""
        self.policy_tier_name = "default"
        self.next_tier_allowed = False
        self._do_policy_order_test("pol-c", 1,
                                   "pol-b", 2,
                                   "pol-a", 3)

    def test_policy_ordering_implicit(self):
        """Check correct ordering of policies by name as tie-breaker."""
        self.policy_tier_name = "default"
        self.next_tier_allowed = False
        self._do_policy_order_test("pol-1", 1,
                                   "pol-2", 1,
                                   "pol-3", 1)

    def _do_policy_order_test(self,
                              first_pol, first_pol_order,
                              second_pol, second_pol_order,
                              third_pol, third_pol_order):
        """Checks that policies are ordered correctly."""
        # Note that the following tests need to check that connectivity to
        # the rpcbind service alternates between succeeding and failing so
        # that we spot if felix hasn't actually changed anything.

        _log.info("Check we start with connectivity.")
        self.assert_connectivity(self.n1_workloads)
        _log.info("Apply a single deny policy")
        self.set_policy(self.policy_tier_name, first_pol, gnp_deny_all,
                        order=first_pol_order)
        _log.info("Check we now cannot access tcp service")
        self.assert_no_connectivity(self.n1_workloads)
        _log.info("Allow in first tier only, should allow.")
        self.set_policy(self.policy_tier_name, first_pol, gnp_allow_all,
                        order=first_pol_order)
        self.set_policy(self.policy_tier_name, second_pol, gnp_deny_all,
                        order=second_pol_order)
        self.set_policy(self.policy_tier_name, third_pol, gnp_deny_all,
                        order=third_pol_order)
        self.assert_connectivity(self.n1_workloads)

        # Fix up second tier
        self.set_policy(self.policy_tier_name, second_pol, gnp_deny_all,
                        order=second_pol_order)

        # Deny in all tiers, should drop.
        _log.info("Deny in all tiers, should drop.")
        self.set_policy(self.policy_tier_name, first_pol, gnp_deny_all,
                        order=first_pol_order)
        self.assert_no_connectivity(self.n1_workloads)

        # Allow in first tier, should allow.
        _log.info("Allow in first tier, should allow.")
        self.set_policy(self.policy_tier_name, first_pol, gnp_allow_all,
                        order=first_pol_order)
        self.assert_connectivity(self.n1_workloads)

        # Switch, now the first policy drops but the later ones allow.
        _log.info("Switch, now the first tier drops but the later ones "
                  "allow.")
        self.set_policy(self.policy_tier_name, first_pol, gnp_deny_all,
                        order=first_pol_order)
        self.set_policy(self.policy_tier_name, second_pol, gnp_allow_all,
                        order=second_pol_order)
        self.set_policy(self.policy_tier_name, third_pol, gnp_allow_all,
                        order=third_pol_order)
        self.assert_no_connectivity(self.n1_workloads)

        # Fall through to second policy.
        _log.info("Fall through to second policy.")
        self.set_policy(self.policy_tier_name, first_pol, gnp_none_all,
                        order=first_pol_order)
        self.assert_connectivity(self.n1_workloads)

        # Swap the second tier for a drop.
        _log.info("Swap the second tier for a drop.")
        self.set_policy(self.policy_tier_name, second_pol,  gnp_deny_all,
                        order=second_pol_order)
        self.assert_no_connectivity(self.n1_workloads)

    @parameterized.expand([
        ({"apiVersion": "projectcalico.org/v3",
          "kind": "GlobalNetworkPolicy",
          "metadata": {"name": "default.deny-test-true1"},
          "spec": {
              "tier": "default",
              "ingress": [{
                  "action": "Deny",
                  "source": {"selector": "test == 'True'"},
              },
                  {"action": "Allow"}
              ],
              "egress": [
                  {"action": "Deny",
                   "destination": {"selector": "test == 'True'"}},
                  {"action": "Allow"}
              ]},
          },
         {"test": "True"},
         True
         ),

        ({"apiVersion": "projectcalico.org/v3",
          "kind": "GlobalNetworkPolicy",
          "metadata": {"name": "default.deny-test-true2"},
          "spec": {
              "tier": "default",
              "ingress": [{
                  "action": "Deny",
                  "source": {"selector": "test != 'True'"},
              },
                  {"action": "Allow"}
              ],
              "egress": [
                  {"action": "Deny",
                   "destination": {"selector": "test != 'True'"}},
                  {"action": "Allow"}
              ]},
          },
         {"test": "False"},
         False
         ),

        ({"apiVersion": "projectcalico.org/v3",
          "kind": "GlobalNetworkPolicy",
          "metadata": {"name": "default.deny-test-true3"},
          "spec": {
              "tier": "default",
              "ingress": [{
                  "action": "Deny",
                  "source": {"selector": "has(test)"},
              },
                  {"action": "Allow"}
              ],
              "egress": [
                  {"action": "Deny",
                   "destination": {"selector": "has(test)"}},
                  {"action": "Allow"}
              ]},
          },
         {"test": "any_old_value"},
         True
         ),

        ({"apiVersion": "projectcalico.org/v3",
          "kind": "GlobalNetworkPolicy",
          "metadata": {"name": "default.deny-test-true4"},
          "spec": {
              "tier": "default",
              "ingress": [{
                  "action": "Deny",
                  "source": {"selector": "!has(test)"},
              },
                  {"action": "Allow"}
              ],
              "egress": [
                  {"action": "Deny",
                   "destination": {"selector": "!has(test)"}},
                  {"action": "Allow"}
              ]},
          },
         {"test": "no_one_cares"},
         False
         ),

        ({"apiVersion": "projectcalico.org/v3",
          "kind": "GlobalNetworkPolicy",
          "metadata": {"name": "default.deny-test-true5"},
          "spec": {
              "tier": "default",
              "ingress": [{
                  "action": "Deny",
                  "source": {"selector": "test in {'true', 'false'}"},
              },
                  {"action": "Allow"}
              ],
              "egress": [
                  {"action": "Deny",
                   "destination": {"selector": "test in {'true', 'false'}"}},
                  {"action": "Allow"}
              ]},
          },
         {"test": "true"},
         True
         ),

        ({"apiVersion": "projectcalico.org/v3",
          "kind": "GlobalNetworkPolicy",
          "metadata": {"name": "default.deny-test-true6"},
          "spec": {
              "tier": "default",
              "ingress": [{
                  "action": "Deny",
                  "source": {"selector": "test in {'true', 'false'}"},
              },
                  {"action": "Allow"}
              ],
              "egress": [
                  {"action": "Deny",
                   "destination": {"selector": "test in {'true', 'false'}"}},
                  {"action": "Allow"}
              ]},
          },
         {"test": "false"},
         True
         ),

        ({"apiVersion": "projectcalico.org/v3",
          "kind": "GlobalNetworkPolicy",
          "metadata": {"name": "default.deny-test-true7"},
          "spec": {
              "tier": "default",
              "ingress": [{
                  "action": "Deny",
                  "source": {"selector": "test not in {'true', 'false'}"},
              },
                  {"action": "Allow"}
              ],
              "egress": [
                  {"action": "Deny",
                   "destination": {"selector": "test not in {'true', 'false'}"}},
                  {"action": "Allow"}
              ]},
          },
         {"test": "neither"},
         False
         ),

        ([{"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true8a"},
           "spec":
               {
                   "tier": "default",
                   "selector": "test == 'true'",
                   "ingress": [
                       {"action": "Deny"},
                   ],
                   "egress": [
                       {"action": "Deny"},
                   ]
               }
           },
          {"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true8b"},
           "spec":
               {
                   "tier": "default",
                   "ingress": [
                       {"action": "Allow"},
                   ],
                   "egress": [
                       {"action": "Allow"},
                   ]
               }
           }
          ],
         {"test": "true"},
         True
         ),

        ([{"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true9a"},
           "spec":
               {
                   "tier": "default",
                   "selector": "test != 'true'",
                   "ingress": [
                       {"action": "Deny"},
                   ],
                   "egress": [
                       {"action": "Deny"},
                   ]
               }
           },
          {"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true9b"},
           "spec":
               {
                   "tier": "default",
                   "ingress": [
                       {"action": "Allow"},
                   ],
                   "egress": [
                       {"action": "Allow"},
                   ]
               }
           }
          ],
         {"test": "true"},
         False
         ),

        ([{"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true10a"},
           "spec":
               {
                   "tier": "default",
                   "selector": "has(test)",
                   "ingress": [
                       {"action": "Deny"},
                   ],
                   "egress": [
                       {"action": "Deny"},
                   ]
               }
           },
          {"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true10b"},
           "spec":
               {
                   "tier": "default",
                   "ingress": [
                       {"action": "Allow"},
                   ],
                   "egress": [
                       {"action": "Allow"},
                   ]
               }
           }
          ],
         {"test": "true"},
         True
         ),

        ([{"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true11a"},
           "spec":
               {
                   "tier": "default",
                   "selector": "!has(test)",
                   "ingress": [
                       {"action": "Deny"},
                   ],
                   "egress": [
                       {"action": "Deny"},
                   ]
               }
           },
          {"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true11b"},
           "spec":
               {
                   "tier": "default",
                   "ingress": [
                       {"action": "Allow"},
                   ],
                   "egress": [
                       {"action": "Allow"},
                   ]
               }
           }
          ],
         {"test": "true"},
         False
         ),

        ([{"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true12a"},
           "spec":
               {
                   "tier": "default",
                   "selector": "test in {'true', 'false'}",
                   "ingress": [
                       {"action": "Deny"},
                   ],
                   "egress": [
                       {"action": "Deny"},
                   ]
               }
           },
          {"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true12b"},
           "spec":
               {
                   "tier": "default",
                   "ingress": [
                       {"action": "Allow"},
                   ],
                   "egress": [
                       {"action": "Allow"},
                   ]
               }
           }
          ],
         {"test": "true"},
         True
         ),

        ([{"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true13a"},
           "spec":
               {
                   "tier": "default",
                   "selector": "test in {'true', 'false'}",
                   "ingress": [
                       {"action": "Deny"},
                   ],
                   "egress": [
                       {"action": "Deny"},
                   ]
               }
           },
          {"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true13b"},
           "spec":
               {
                   "tier": "default",
                   "ingress": [
                       {"action": "Allow"},
                   ],
                   "egress": [
                       {"action": "Allow"},
                   ]
               }
           }
          ],
         {"test": "false"},
         True
         ),

        ([{"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true14a"},
           "spec":
               {
                   "tier": "default",
                   "selector": "test not in {'true', 'false'}",
                   "ingress": [
                       {"action": "Deny"},
                   ],
                   "egress": [
                       {"action": "Deny"},
                   ]
               }
           },
          {"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true14b"},
           "spec":
               {
                   "tier": "default",
                   "ingress": [
                       {"action": "Allow"},
                   ],
                   "egress": [
                       {"action": "Allow"},
                   ]
               }
           }
          ],
         {"test": "neither"},
         False
         ),

        ([{"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true15a"},
           "spec":
               {
                   "tier": "default",
                   "selector": "has(test) && test in {'true', 'false'} && test == 'true'",
                   "ingress": [
                       {"action": "Deny"},
                   ],
                   "egress": [
                       {"action": "Deny"},
                   ]
               }
           },
          {"apiVersion": "projectcalico.org/v3",
           "kind": "GlobalNetworkPolicy",
           "metadata": {"name": "default.deny-test-true15b"},
           "spec":
               {
                   "tier": "default",
                   "ingress": [
                       {"action": "Allow"},
                   ],
                   "egress": [
                       {"action": "Allow"},
                   ]
               }
           }
          ],
         {"test": "true"},
         True
         ),

        ({"apiVersion": "projectcalico.org/v3",
          "kind": "GlobalNetworkPolicy",
          "metadata": {"name": "default.deny-test-true16"},
          "spec": {
              "tier": "default",
              "ingress": [{
                  "action": "Deny",
                  "source":
                      {"selector": "has(test) && test in {'True', 'False'} && test == 'True'"},
              },
                  {"action": "Allow"}
              ],
              "egress": [
                  {"action": "Deny",
                   "destination":
                       {"selector": "has(test) && test in {'True', 'False'} && test == 'True'"}},
                  {"action": "Allow"}
              ]},
          },
         {"test": "True"},
         True
         ),

        ({"apiVersion": "projectcalico.org/v3",
          "kind": "GlobalNetworkPolicy",
          "metadata": {"name": "default.deny-test-true17"},
          "spec": {
              "tier": "default",
              "ingress": [{
                  "action": "Deny",
                  "source":
                      {"selector":
                           "has(test) && test not in {'True', 'False'} && test == 'Sausage'"},
              },
                  {"action": "Allow"}
              ],
              "egress": [
                  {"action": "Deny",
                   "destination":
                       {"selector":
                            "has(test) && test not in {'True', 'False'} && test == 'Sausage'"}},
                  {"action": "Allow"}
              ]},
          },
         {"test": "Sausage"},
         True
         ),
    ])
    def test_selectors(self, policy, workload_label, no_label_expected_result):
        """
        Tests selectors in policy.
        :param policy: The policy to apply
        :param workload_label: The label to add to one of the workload endpoints
        :param no_label_expected_result: Whether we'd expect the policy to block connectivity if
        the workloads do not have the label.
        :return:
        """
        # set workload config
        host = self.hosts[0]
        weps = yaml.safe_load(host.calicoctl("get wep -o yaml"))
        _log.info("n1_workloads 0 %s", self.n1_workloads[0].__dict__)
        _log.info("n1_workloads 1 %s", self.n1_workloads[1].__dict__)
        wep_old = weps['items'][0]
        #for w in weps['items']:
        #    if w['spec']['ipNetworks'][0] == self.n1_workloads[1].ip + '/32':
        #        _log.info("Set wep_old to %s", w)
        #        wep_old = w
        wep = copy.deepcopy(wep_old)
        _log.info("Set new label %s", workload_label)
        wep['metadata']['labels'] = workload_label
        self._apply_data(wep, host)
        updated_weps = yaml.safe_load(host.calicoctl("get workloadEndpoint -o yaml"))
        # check connectivity OK
        self.assert_connectivity(self.n1_workloads)
        # set up policy
        _log.info("Set up policy %s", policy)
        self._apply_data(policy, host)
        # check connectivity not OK - use retries to allow time to apply new policy
        self.assert_no_connectivity(self.n1_workloads, retries=3)
        # Restore workload config (i.e. remove the label)
        wep_old['metadata']['resourceVersion'] = updated_weps['items'][0]['metadata']['resourceVersion']
        _log.info("Restore workload config %s", wep_old)
        self._apply_data(wep_old, host)
        updated_weps = yaml.safe_load(host.calicoctl("get workloadEndpoint -o yaml"))
        if no_label_expected_result:
            # check connectivity OK again - use retries to allow time to apply new policy
            self.assert_connectivity(self.n1_workloads, retries=3)
        else:
            self.assert_no_connectivity(self.n1_workloads)


class IpNotFound(Exception):
    pass
