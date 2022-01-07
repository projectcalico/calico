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

from utils.utils import retry_until_success, run, kubectl

logger = logging.getLogger(__name__)


first_log_time = None


class TestBase(TestCase):

    """
    Base class for test-wide methods.
    """

    def setUp(self):
        """
        Clean up before every test.
        """
        self.cluster = self.k8s_client()

        # Log a newline to ensure that the first log appears on its own line.
        logger.info("")

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

    def create_namespace(self, ns_name):
        self.cluster.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=ns_name)))

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
                "externalTrafficPolicy": traffic_policy,
            }
        )
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

    def delete_and_confirm(self, name, resource_type, ns="default"):
        try:
            kubectl("delete %s %s -n%s" % (resource_type, name, ns))
        except subprocess.CalledProcessError:
            pass

        def is_it_gone_yet(res_name, res_type):
            try:
                kubectl("get %s %s -n%s" % (res_type, res_name, ns),
                        logerr=False)
                raise self.StillThere
            except subprocess.CalledProcessError:
                # Success
                pass

        retry_until_success(is_it_gone_yet, retries=10, wait_time=10, function_args=[name, resource_type])

    class StillThere(Exception):
        pass

    def get_routes(self):
        return run("docker exec kube-node-extra ip r")

    def update_ds_env(self, ds, ns, env_vars):
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        api = client.AppsV1Api(client.ApiClient())
        node_ds = api.read_namespaced_daemon_set(ds, ns, exact=True, export=False)
        for container in node_ds.spec.template.spec.containers:
            if container.name == ds:
                for k, v in env_vars.items():
                    logger.info("Set %s=%s", k, v)
                    env_present = False
                    for env in container.env:
                        if env.name == k:
                            env_present = True
                    if not env_present:
                        v1_ev = client.V1EnvVar(name=k, value=v, value_from=None)
                        container.env.append(v1_ev)
        api.replace_namespaced_daemon_set(ds, ns, node_ds)

        # Wait until the DaemonSet reports that all nodes have been updated.
        while True:
            time.sleep(10)
            node_ds = api.read_namespaced_daemon_set_status("calico-node", "kube-system")
            logger.info("%d/%d nodes updated",
                      node_ds.status.updated_number_scheduled,
                      node_ds.status.desired_number_scheduled)
            if node_ds.status.updated_number_scheduled == node_ds.status.desired_number_scheduled:
                break

    def scale_deployment(self, deployment, ns, replicas):
        return kubectl("scale deployment %s -n %s --replicas %s" %
                       (deployment, ns, replicas)).strip()


class TestBaseV6(TestBase):

    def get_routes(self):
        return run("docker exec kube-node-extra ip -6 r")
