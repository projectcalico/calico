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
        self.cleanups = []

        # Log a newline to ensure that the first log appears on its own line.
        logger.info("")

    def tearDown(self):
        for cleanup in reversed(self.cleanups):
            cleanup()
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

    def get_calico_node_pod(self, nodeName):
        """Get the calico-node pod name for a given kind node"""
        def fn():
            calicoPod = kubectl("-n kube-system get pods -o wide | grep calico-node | grep '%s '| cut -d' ' -f1" % nodeName)
            if calicoPod is None:
                raise Exception('calicoPod is None')
            return calicoPod.strip()
        calicoPod = retry_until_success(fn)
        return calicoPod

class Container(object):

    def __init__(self, image, args, flags=""):
        self.id = run("docker run --rm -d --net=kind %s %s %s" % (
            flags,
            image,
            args)).strip().split("\n")[-1].strip()
        self._ip = None

    def kill(self):
        run("docker rm -f %s" % self.id)

    def inspect(self, template):
        return run("docker inspect -f '%s' %s" % (template, self.id))

    def running(self):
        return self.inspect("{{.State.Running}}").strip()

    def assert_running(self):
        assert self.running() == "true"

    def wait_running(self):
        retry_until_success(self.assert_running)

    @property
    def ip(self):
        if not self._ip:
            self._ip = self.inspect(
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
            ).strip()
        return self._ip

    def logs(self):
        return run("docker logs %s 2>&1" % self.id)

    def execute(self, cmd):
        return run("docker exec %s %s" % (self.id, cmd))


class Pod(object):

    def __init__(self, ns, name, node=None, image=None, labels=None, annotations=None, yaml=None, cmd=None):
        if yaml:
            # Caller has provided the complete pod YAML.
            kubectl("""apply -f - <<'EOF'
%s
EOF
""" % yaml)
        else:
            # Build YAML with specified namespace, name and image.
            pod = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": name,
                    "namespace": ns,
                },
                "spec": {
                    "containers": [
                        {
                            "name": name,
                            "image": image,
                        },
                    ],
                    "terminationGracePeriodSeconds": 0,
                },
            }
            if node:
                pod["spec"]["nodeName"] = node
            if annotations:
                pod["metadata"]["annotations"] = annotations
            if labels:
                pod["metadata"]["labels"] = labels
            if cmd:
                pod["spec"]["containers"][0]["command"] = cmd
            kubectl("""apply -f - <<'EOF'
%s
EOF
""" % json.dumps(pod))

        self.name = name
        self.ns = ns
        self._ip = None
        self._hostip = None
        self._nodename = None

    def delete(self):
        kubectl("delete pod/%s -n %s" % (self.name, self.ns))

    def wait_ready(self):
        kubectl("wait --for=condition=ready pod/%s -n %s --timeout=300s" % (self.name, self.ns))

    def wait_not_ready(self):
        kubectl("wait --for=condition=Ready=false pod/%s -n %s --timeout=300s" % (self.name, self.ns))

    @property
    def ip(self):
        start_time = time.time()
        while not self._ip:
            assert time.time() - start_time < 30, "Pod failed to get IP address within 30s"
            ip = run("kubectl get po %s -n %s -o json | jq '.status.podIP'" % (self.name, self.ns)).strip().strip('"')
            if ip != "null":
                self._ip = ip
                break
            time.sleep(0.1)
        return self._ip

    @property
    def hostip(self):
        if not self._hostip:
            self._hostip = run("kubectl get po %s -n %s -o json | jq '.status.hostIP'" %
                           (self.name, self.ns)).strip().strip('"')
        return self._hostip

    @property
    def nodename(self):
        if not self._nodename:
            # spec.nodeName will be populated for a running pod regardless of being specified or not on pod creation.
            self._nodename = run("kubectl get po %s -n %s -o json | jq '.spec.nodeName'" %
                               (self.name, self.ns)).strip().strip('"')
        return self._nodename

    @property
    def annotations(self):
        return json.loads(run("kubectl get po %s -n %s -o json | jq '.metadata.annotations'" %
                           (self.name, self.ns)).strip().strip('"'))

    def execute(self, cmd, timeout=0):
        return kubectl("exec %s -n %s -- %s" % (self.name, self.ns, cmd), timeout=timeout)

class TestBaseV6(TestBase):

    def get_routes(self):
        return run("docker exec kube-node-extra ip -6 r")
