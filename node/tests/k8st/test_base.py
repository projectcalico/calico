# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
import os
import subprocess
import time
from pprint import pformat
from unittest import TestCase

from deepdiff import DeepDiff
from kubernetes import client, config

from utils.utils import retry_until_success, run, kubectl, calicoctl

logger = logging.getLogger(__name__)


first_log_time = None


class TestBase(TestCase):

    """
    Base class for test-wide methods.
    """

    def setUp(self):
        """
        Set up before every test.
        """
        super(TestBase, self).setUp()
        self.cluster = self.k8s_client()
        self.cleanups = []
        self.orig_vxlan_mode = None
        self.orig_ipip_mode = None

        # Log a newline to ensure that the first log appears on its own line.
        logger.info("")

    def tearDown(self):
        for cleanup in reversed(self.cleanups):
            try:
                cleanup()
            except Exception:
                logger.exception("Cleanup function failed %s", cleanup)
                raise
        super(TestBase, self).tearDown()

    def add_cleanup(self, cleanup):
        self.cleanups.append(cleanup)

    @staticmethod
    def assert_same(thing1, thing2):
        """
        Compares two things.  Debug logs the differences between them before
        asserting that they are the same.
        """
        assert cmp(thing1, thing2) == 0, \
            "Items are not the same.  Difference is:\n %s" % \
            pformat(DeepDiff(thing1, thing2), indent=2)

    @staticmethod
    def writejson(filename, data):
        """
        Converts a python dict to json and outputs to a file.
        :param filename: filename to write
        :param data: dictionary to write out as json
        """
        with open(filename, 'w') as f:
            text = json.dumps(data,
                              sort_keys=True,
                              indent=2,
                              separators=(',', ': '))
            logger.debug("Writing %s: \n%s" % (filename, text))
            f.write(text)

    @staticmethod
    def log_banner(msg, *args, **kwargs):
        global first_log_time
        time_now = time.time()
        if first_log_time is None:
            first_log_time = time_now
        time_now -= first_log_time
        elapsed_hms = "%02d:%02d:%02d " % (time_now / 3600,
                                           (time_now % 3600) / 60,
                                           time_now % 60)

        level = kwargs.pop("level", logging.INFO)
        msg = elapsed_hms + str(msg) % args
        banner = "+" + ("-" * (len(msg) + 2)) + "+"
        logger.log(level, "\n" +
                   banner + "\n"
                            "| " + msg + " |\n" +
                   banner)

    @staticmethod
    def k8s_client():
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        return client.CoreV1Api()

    def check_pod_status(self, ns):
        pods = self.cluster.list_namespaced_pod(ns)

        for pod in pods.items:
            logger.info("%s\t%s\t%s", pod.metadata.name, pod.metadata.namespace, pod.status.phase)
            if pod.status.phase != 'Running':
                kubectl("describe po %s -n %s" % (pod.metadata.name, pod.metadata.namespace))
            assert pod.status.phase == 'Running'

    def create_namespace(self, ns_name, labels=None, annotations=None):
        self.cluster.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=ns_name, labels=labels, annotations=annotations)))
        self.add_cleanup(lambda: self.delete_and_confirm(ns_name, "ns"))

    def deploy(self, image, name, ns, port, replicas=1, svc_type="NodePort", traffic_policy="Local", cluster_ip=None, ipv6=False):
        """
        Creates a deployment and corresponding service with the given
        parameters.
        """
        # Use a pod anti-affinity so that the scheduler prefers deploying the
        # pods on different nodes. This makes our tests more reliable, since
        # some tests expect pods to be scheduled to different nodes.
        selector = {'matchLabels': {'app': name}}
        terms = [client.V1WeightedPodAffinityTerm(
            pod_affinity_term=client.V1PodAffinityTerm(
                label_selector=selector,
                topology_key="kubernetes.io/hostname"),
            weight=100,
            )]
        anti_aff = client.V1PodAntiAffinity(
                preferred_during_scheduling_ignored_during_execution=terms)

        # Run a deployment with <replicas> copies of <image>, with the
        # pods labelled with "app": <name>.
        deployment = client.V1Deployment(
            api_version="apps/v1",
            kind="Deployment",
            metadata=client.V1ObjectMeta(name=name),
            spec=client.V1DeploymentSpec(
                replicas=replicas,
                selector=selector,
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(labels={"app": name}),
                    spec=client.V1PodSpec(
                        affinity=client.V1Affinity(pod_anti_affinity=anti_aff),
                        containers=[
                          client.V1Container(name=name,
                                             image=image,
                                             ports=[client.V1ContainerPort(container_port=port)]),
                    ]))))

        # Create the deployment.
        api_response = client.AppsV1Api().create_namespaced_deployment(
            body=deployment,
            namespace=ns)
        logger.debug("Deployment created. status='%s'" % str(api_response.status))

        # Create a service called <name> whose endpoints are the pods
        # with "app": <name>; i.e. those just created above.
        self.create_service(name, name, ns, port, svc_type, traffic_policy, ipv6=ipv6)

    def wait_for_deployment(self, name, ns):
        """
        Waits for the given deployment to have the desired number of replicas.
        """
        logger.info("Checking status for deployment %s/%s" % (ns, name))
        kubectl("-n %s rollout status deployment/%s" % (ns, name))
        kubectl("get pods -n %s -o wide" % ns)

    def create_service(self, name, app, ns, port, svc_type="NodePort", traffic_policy="Local", cluster_ip=None, ipv6=False):
        service = client.V1Service(
            metadata=client.V1ObjectMeta(
                name=name,
                labels={"name": name},
            ),
            spec={
                "ports": [{"port": port}],
                "selector": {"app": app},
                "type": svc_type,
            }
        )
        if traffic_policy:
            service.spec["externalTrafficPolicy"] = traffic_policy
        if cluster_ip:
          service.spec["clusterIP"] = cluster_ip
        if ipv6:
          service.spec["ipFamilies"] = ["IPv6"]

        api_response = self.cluster.create_namespaced_service(
            body=service,
            namespace=ns,
        )
        logger.debug("Additional Service created. status='%s'" % str(api_response.status))

    def wait_until_exists(self, name, resource_type, ns="default"):
        retry_until_success(kubectl, function_args=["get %s %s -n%s" %
                                                    (resource_type, name, ns)])

    def delete(self, name, resource_type, ns="default", wait="true"):
        try:
            kubectl("delete %s %s -n %s --wait=%s" % (resource_type, name, ns, wait))
        except subprocess.CalledProcessError:
            pass

    def confirm_deletion(self, name, resource_type, ns="default"):
        def is_it_gone_yet(res_name, res_type):
            try:
                kubectl("get %s %s -n %s" % (res_type, res_name, ns),
                        logerr=False)
                raise self.StillThere
            except subprocess.CalledProcessError:
                # Success
                pass

        retry_until_success(is_it_gone_yet, retries=10, wait_time=10, function_args=[name, resource_type])

    def delete_and_confirm(self, name, resource_type, ns="default", wait="true"):
        self.delete(name, resource_type, ns, wait)
        self.confirm_deletion(name, resource_type, ns)

    class StillThere(Exception):
        pass

    def get_routes(self):
        return run("docker exec kube-node-extra ip r")

    def annotate_resource(self, res_type, res_name, ns, k, v):
        return run("kubectl annotate %s %s -n %s %s=%s" % (res_type, res_name, ns, k, v)).strip()

    def get_node_ips_with_local_pods(self, ns, label_selector):
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        api = client.CoreV1Api(client.ApiClient())
        pods = api.list_namespaced_pod(ns, label_selector=label_selector)
        node_names = map(lambda x: x.spec.node_name, pods.items)
        node_ips = []
        for n in node_names:
            addrs = api.read_node(n).status.addresses
            for a in addrs:
                if a.type == 'InternalIP':
                    node_ips.append(a.address)
        return node_ips

    def patch_ippool(self, name, vxlan_mode=None, ipip_mode=None, undo_at_teardown=True):
        assert vxlan_mode is not None
        assert ipip_mode is not None
        json_str = calicoctl("get ippool %s -o json" % name)
        node_dict = json.loads(json_str)
        old_ipip_mode = node_dict['spec']['ipipMode']
        old_vxlan_mode = node_dict['spec']['vxlanMode']

        calicoctl("""patch ippool %s --patch '{"spec":{"vxlanMode": "%s", "ipipMode": "%s"}}'""" % (
            name,
            vxlan_mode,
            ipip_mode,
        ))
        logger.info("Updated vxlanMode of %s from %s to %s, ipipMode from %s to %s",
                  name, old_vxlan_mode, vxlan_mode, old_ipip_mode, ipip_mode)
        if undo_at_teardown:
            self.add_cleanup(lambda: self.patch_ippool(name, old_vxlan_mode, old_ipip_mode, undo_at_teardown=False))
        return old_vxlan_mode, old_ipip_mode

    def get_ds_env(self, ds, ns, key):
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        api = client.AppsV1Api(client.ApiClient())
        node_ds = api.read_namespaced_daemon_set(ds, ns, exact=True, export=False)
        for container in node_ds.spec.template.spec.containers:
            if container.name == ds:
                for env in container.env:
                    if env.name == key:
                        return env.value
        return None

    def update_ds_env(self, ds, ns, env_vars, undo_at_teardown=True):
        orig_env = {}
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        api = client.AppsV1Api(client.ApiClient())
        node_ds = api.read_namespaced_daemon_set(ds, ns, exact=True, export=False)
        for container in node_ds.spec.template.spec.containers:
            if container.name == ds:
                for k, v in env_vars.items():
                    logger.info("Set %s=%s", k, v)
                    env_present = False
                    orig_env[k] = None
                    for env in container.env:
                        if env.name == k:
                            orig_env[k] = env.value
                            if env.value == v:
                                env_present = True
                            else:
                                container.env.remove(env)

                    if not env_present and v is not None:
                        v1_ev = client.V1EnvVar(name=k, value=v, value_from=None)
                        container.env.append(v1_ev)
        api.replace_namespaced_daemon_set(ds, ns, node_ds)

        if undo_at_teardown:
            self.add_cleanup(lambda: self.update_ds_env(ds, ns, orig_env, undo_at_teardown=False))

        # Wait until the DaemonSet reports that all nodes have been updated.
        # In the past we've seen that the calico-node on kind-control-plane can
        # hang, in a not Ready state, for about 15 minutes.  Here we want to
        # detect in case that happens again, and fail the test case if so.  We
        # do that by querying the number of nodes that have been updated, every
        # 10s, and failing the test if that number does not change for 4 cycles
        # i.e. for 40s.
        last_number = 0
        iterations_with_no_change = 0
        while True:
            time.sleep(10)
            node_ds = api.read_namespaced_daemon_set_status("calico-node", "kube-system")
            logger.info("%d/%d nodes updated",
                      node_ds.status.updated_number_scheduled,
                      node_ds.status.desired_number_scheduled)
            if node_ds.status.updated_number_scheduled == node_ds.status.desired_number_scheduled:
                break
            if node_ds.status.updated_number_scheduled == last_number:
                iterations_with_no_change += 1
                if iterations_with_no_change == 4:
                    run("docker exec kind-control-plane conntrack -L", allow_fail=True)
                    self.fail("calico-node DaemonSet update failed to make progress for 40s")
            else:
                last_number = node_ds.status.updated_number_scheduled
                iterations_with_no_change = 0

        # Wait until all calico-node pods are ready.
        kubectl("wait pod --for=condition=Ready -l k8s-app=calico-node -n kube-system --timeout=300s")

        # After restarting felixes, wait to ensure Felix is past its route-cleanup grace period.
        time.sleep(30)

        return orig_env

    def scale_deployment(self, deployment, ns, replicas):
        return kubectl("scale deployment %s -n %s --replicas %s" %
                       (deployment, ns, replicas)).strip()

class TestBaseV6(TestBase):

    def get_routes(self):
        return run("docker exec kube-node-extra ip -6 r")
