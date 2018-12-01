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

from utils.utils import retry_until_success, run

logger = logging.getLogger(__name__)


first_log_time = None


class TestBase(TestCase):

    """
    Base class for test-wide methods.
    """
    @classmethod
    def setUpClass(cls):
        cls.check_calico_version()

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
                run("kubectl describe po %s -n %s" % (pod.metadata.name, pod.metadata.namespace))
            assert pod.status.phase == 'Running'

    def create_namespace(self, ns_name):
        self.cluster.create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=ns_name)))

    def create_service(self, image, name, ns, port, replicas=1, svc_type="NodePort", traffic_policy="Local", cluster_ip=None):
        # Run a deployment with <replicas> copies of <image>, with the
        # pods labelled with "app": <name>.
        deployment = client.ExtensionsV1beta1Deployment(
            api_version="extensions/v1beta1",
            kind="Deployment",
            metadata=client.V1ObjectMeta(name=name),
            spec=client.ExtensionsV1beta1DeploymentSpec(
                replicas=replicas,
                template=client.V1PodTemplateSpec(
                    metadata=client.V1ObjectMeta(labels={"app": name}),
                    spec=client.V1PodSpec(containers=[
                        client.V1Container(name=name,
                                           image=image,
                                           ports=[client.V1ContainerPort(container_port=port)]),
                    ]))))
        api_response = client.ExtensionsV1beta1Api().create_namespaced_deployment(
            body=deployment,
            namespace=ns)
        logger.debug("Deployment created. status='%s'" % str(api_response.status))

        # Create a service called <name> whose endpoints are the pods
        # with "app": <name>; i.e. those just created above.
        service = client.V1Service(
            metadata=client.V1ObjectMeta(
                name=name,
                labels={"name": name},
            ),
            spec={
                "ports": [{"port": port}],
                "selector": {"app": name},
                "type": svc_type,
                "externalTrafficPolicy": traffic_policy,
            }
        )
        if cluster_ip:
          service.spec["clusterIP"] = cluster_ip
        api_response = self.cluster.create_namespaced_service(
            body=service,
            namespace=ns,
        )
        logger.debug("Service created. status='%s'" % str(api_response.status))

    @classmethod
    def check_calico_version(cls):
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        api = client.AppsV1Api(client.ApiClient())
        node_ds = api.read_namespaced_daemon_set("calico-node", "kube-system", exact=True, export=True)
        for container in node_ds.spec.template.spec.containers:
            if container.name == "calico-node":
                if container.image != "calico/node:latest-amd64":
                    container.image = "calico/node:latest-amd64"
                    api.replace_namespaced_daemon_set("calico-node", "kube-system", node_ds)
                    time.sleep(3)
                    retry_until_success(cls.check_pod_status, retries=20, wait_time=3, function_args=["kube-system"])

    def wait_until_exists(self, name, resource_type, ns="default"):
        retry_until_success(run, function_args=["kubectl get %s %s -n%s" % (resource_type, name, ns)])

    def delete_and_confirm(self, name, resource_type, ns="default"):
        try:
            run("kubectl delete %s %s -n%s" % (resource_type, name, ns))
        except subprocess.CalledProcessError:
            pass

        def is_it_gone_yet(res_name, res_type):
            try:
                run("kubectl get %s %s -n%s" % (res_type, res_name, ns), logerr=False)
                raise self.StillThere
            except subprocess.CalledProcessError:
                # Success
                pass

        retry_until_success(is_it_gone_yet, retries=10, wait_time=10, function_args=[name, resource_type])

    class StillThere(Exception):
        pass

    def get_routes(self):
        return run("docker exec kube-node-extra ip r")

    def update_ds_env(self, ds, ns, k, v):
        config.load_kube_config(os.environ.get('KUBECONFIG'))
        api = client.AppsV1Api(client.ApiClient())
        node_ds = api.read_namespaced_daemon_set(ds, ns, exact=True, export=True)
        for container in node_ds.spec.template.spec.containers:
            if container.name == ds:
                env_present = False
                for env in container.env:
                    if env.name == k:
                        env_present = True
                if not env_present:
                    container.env.append({"name": k, "value": v, "value_from": None})
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
        return run("kubectl scale deployment %s -n %s --replicas %s" % (deployment, ns, replicas)).strip()
