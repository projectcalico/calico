#!/bin/python
import json
import os
import socket
import sys
from subprocess import check_output, CalledProcessError, check_call
import requests
import sh

# Append to existing env, to avoid losing PATH etc.
# Need to edit the path here since calicoctl loads client on import.
ETCD_AUTHORITY_ENV = "ETCD_AUTHORITY"
if ETCD_AUTHORITY_ENV not in os.environ:
    os.environ[ETCD_AUTHORITY_ENV] = 'kubernetes-master:6666'
print("Using ETCD_AUTHORITY=%s" % os.environ[ETCD_AUTHORITY_ENV])

from calico_ctl.container import container_add
from pycalico.datastore import IF_PREFIX
from pycalico.util import generate_cali_interface_name

CALICOCTL_PATH = os.environ.get('CALICOCTL_PATH', '/usr/bin/calicoctl')
print("Using CALICOCTL_PATH=%s" % CALICOCTL_PATH)
calicoctl = sh.Command(CALICOCTL_PATH).bake(_env=os.environ)

KUBE_API_ROOT = os.environ.get('KUBE_API_ROOT',
                               'http://kubernetes-master:8080/api/v1/')
print("Using KUBE_API_ROOT=%s" % KUBE_API_ROOT)


class NetworkPlugin(object):
    def __init__(self):
        self.pod_name = None
        self.docker_id = None

    def create(self, pod_name, docker_id):
        """"Create a pod."""
        # Calicoctl does not support the '-' character in iptables rule names.
        # TODO: fix Felix to support '-' characters.
        self.pod_name = pod_name
        self.docker_id = docker_id

        print('Configuring docker container %s' % self.docker_id)

        try:
            endpoint = self._configure_interface()
            self._configure_profile(endpoint)
        except CalledProcessError as e:
            print('Error code %d creating pod networking: %s\n%s' % (
                e.returncode, e.output, e))
            sys.exit(1)

    def delete(self, pod_name, docker_id):
        """Cleanup after a pod."""
        self.pod_name = pod_name
        self.docker_id = docker_id

        # Remove the profile for the workload.
        calicoctl('container', 'remove', self.docker_id)
        calicoctl('profile', 'remove', self.pod_name)

    def _configure_interface(self):
        """Configure the Calico interface for a pod.

        This involves the following steps:
        1) Determine the IP that docker assigned to the interface inside the
           container
        2) Delete the docker-assigned veth pair that's attached to the docker
           bridge
        3) Create a new calico veth pair, using the docker-assigned IP for the
           end in the container's namespace
        4) Assign the node's IP to the host end of the veth pair (required for
           compatibility with kube-proxy REDIRECT iptables rules).
        """
        container_ip = self._read_docker_ip()
        self._delete_docker_interface()
        print('Configuring Calico networking.')
        ep = container_add(self.docker_id, container_ip, 'eth0')
        interface_name = generate_cali_interface_name(IF_PREFIX, ep.endpoint_id)
        node_ip = self._get_node_ip()
        print('Adding IP %s to interface %s' % (node_ip, interface_name))

        # This is slightly tricky. Since the kube-proxy sometimes
        # programs REDIRECT iptables rules, we MUST have an IP on the host end
        # of the caliXXX veth pairs. This is because the REDIRECT rule
        # rewrites the destination ip/port of traffic from a pod to a service
        # VIP. The destination port is rewriten to an arbitrary high-numbered
        # port, and the destination IP is rewritten to one of the IPs allocated
        # to the interface. This fails if the interface doesn't have an IP,
        # so we allocate an IP which is already allocated to the node. We set
        # the subnet to /32 so that the routing table is not affected;
        # no traffic for the node_ip's subnet will use the /32 route.
        check_call(['ip', 'addr', 'add', node_ip + '/32',
                    'dev', interface_name])
        print('Finished configuring network interface')
        return ep

    def _get_node_ip(self):
        """Determine the IP for the host node.

        This hits a well-known IP (the Google public DNS).
        """
        # We'd like to use the k8s API here, but it doesn't work in the Vagrant
        # case since the node's name is set to its IP (so we have no way of
        # getting from hostname=>IP).
        # TODO: do this more reliably by parsing 'ip
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def _read_docker_ip(self):
        """Get the IP for the pod's infra container."""
        ip = check_output([
            'docker', 'inspect', '-format', '{{ .NetworkSettings.IPAddress }}',
            self.docker_id
        ])
        # Clean trailing whitespace (expect a '\n' at least).
        ip = ip.strip()

        print('Docker-assigned IP was %s' % ip)
        return ip

    def _delete_docker_interface(self):
        """Delete the existing veth connecting to the docker bridge."""
        print('Deleting eth0')

        # Get the PID of the container.
        pid = check_output([
            'docker', 'inspect', '-format', '{{ .State.Pid }}',
            self.docker_id
        ])
        # Clean trailing whitespace (expect a '\n' at least).
        pid = pid.strip()

        # Set up a link to the container's netns.
        print(check_output(['mkdir', '-p', '/var/run/netns']))
        netns_file = '/var/run/netns/' + pid
        if not os.path.isfile(netns_file):
            print(check_output(['ln', '-s', '/proc/' + pid + '/ns/net',
                                netns_file]))

        # Reach into the netns and delete the docker-allocated interface.
        print(check_output(['ip', 'netns', 'exec', pid,
                            'ip', 'link', 'del', 'eth0']))

        # Clean up after ourselves (don't want to leak netns files)
        print(check_output(['rm', netns_file]))

    def _configure_profile(self, endpoint):
        """
        Configure the calico profile for a pod.

        Currently assumes one pod with each name.
        """
        profile_name = self.pod_name
        calicoctl('profile', 'add', profile_name)
        pod = self._get_pod_config()

        self._apply_rules(profile_name)

        self._apply_tags(profile_name, pod)

        # Also set the profile for the workload.
        print('Setting profile %s on endpoint %s' %
              (profile_name, endpoint.endpoint_id))
        calicoctl('endpoint', endpoint.endpoint_id,
                  'profile', 'set', profile_name)
        print('Finished configuring profile.')

    def _get_pod_ports(self, pod):
        """
        Get the list of ports on containers in the Pod.

        :return list ports: the Kubernetes ContainerPort objects for the pod.
        """
        ports = []
        for container in pod['spec']['containers']:
            try:
                more_ports = container['ports']
                print('Adding ports %s' % more_ports)
                ports.extend(more_ports)
            except KeyError:
                pass
        return ports

    def _get_pod_config(self):
        """Get the list of pods from the Kube API server."""
        pods = self._get_api_path('pods')
        print('Got pods %s' % pods)

        for pod in pods:
            print('Processing pod %s' % pod)
            if pod['metadata']['name'].replace('/', '_') == self.pod_name:
                this_pod = pod
                break
        else:
            raise KeyError('Pod not found: ' + self.pod_name)
        print('Got pod data %s' % this_pod)
        return this_pod

    def _get_api_path(self, path):
        """Get a resource from the API specified API path.

        e.g.
        _get_api_path('pods')

        :param path: The relative path to an API endpoint.
        :return: A list of JSON API objects
        :rtype list
        """
        bearer_token = self._get_api_token()
        session = requests.Session()
        session.headers.update({'Authorization': 'Bearer ' + bearer_token})
        response = session.get(KUBE_API_ROOT + path, verify=False)
        response_body = response.text

        # The response body contains some metadata, and the pods themselves
        # under the 'items' key.
        return json.loads(response_body)['items']

    def _get_api_token(self):
        """
        Get the kubelet Bearer token for this node, used for HTTPS auth.
        If no token exists, this method will return an empty string.
        :return: The token.
        :rtype: str
        """
        try:
            with open('/var/lib/kubelet/kubernetes_auth') as f:
                json_string = f.read()
        except IOError, e:
            print("Failed to open auth_file (%s), assuming insecure mode" % e)
            return ""

        print('Using kubernetes_auth: ' + json_string)

        auth_data = json.loads(json_string)
        return auth_data['BearerToken']

    def _generate_rules(self):
        """
        Generate the Profile rules that have been specified on the Pod's ports.

        We only create a Rule for a port if it has 'allowFrom' specified.

        The Rule is structured to match the Calico etcd format.

        :return list() rules: the rules to be added to the Profile.
        """
        inbound_rules = [
            {
                'action': 'allow',
            },
        ]

        outbound_rules = [
            {
                'action': 'allow',
            },
        ]
        return inbound_rules, outbound_rules

    def _generate_profile_json(self, profile_name, rules):
        """
        Given a list of of Calico rules, generate a Calico Profile JSON blob
        implementing those rules.

        :param profile_name: The name of the Calico profile
        :type profile_name: string
        :param rules: A tuple of (inbound, outbound) Calico rules
        :type rules: tuple
        :return: A JSON blob ready to be loaded by calicoctl
        :rtype: str
        """
        inbound, outbound = rules
        profile = {
            'id': profile_name,
            'inbound_rules': inbound,
            'outbound_rules': outbound,
        }
        profile_json = json.dumps(profile, indent=2)
        print('Final profile "%s": %s' % (profile_name, profile_json))
        return profile_json

    def _apply_rules(self, profile_name):
        """
        Generate a new profile with the default 'allow all' rules.

        :param profile_name: The profile to update
        :type profile_name: string
        :return:
        """
        rules = self._generate_rules()
        profile_json = self._generate_profile_json(profile_name, rules)

        # Pipe the Profile JSON into the calicoctl command to update the rule.
        calicoctl('profile', profile_name, 'rule', 'update', _in=profile_json)
        print('Finished applying rules.')

    def _apply_tags(self, profile_name, pod):
        """
        Extract the label KV pairs from the pod config, and apply each as a
        tag in the pod's profile.

        :param profile_name: The name of the Calico profile.
        :type profile_name: string
        :param pod: The config dictionary for the pod being created.
        :type pod: dict
        :return:
        """
        try:
            labels = pod['metadata']['labels']
        except KeyError:
            # If there are no labels, there's no more work to do.
            print('No labels found in pod %s' % pod)
            return

        for k, v in labels.iteritems():
            tag = '%s_%s' % (k, v)
            tag = tag.replace('/', '_')
            print('Adding tag ' + tag)
            try:
                calicoctl('profile', profile_name, 'tag', 'add', tag)
            except sh.ErrorReturnCode as e:
                print('Could not create tag %s.\n%s' % (tag, e))
        print('Finished applying tags.')

if __name__ == '__main__':
    print('Args: %s' % sys.argv)
    mode = sys.argv[1]

    if mode == 'init':
        print('No initialization work to perform')
    else:
        # These args only present for setup/teardown.
        pod_name = sys.argv[3].replace('/', '_')
        docker_id = sys.argv[4]
        if mode == 'setup':
            print('Executing Calico pod-creation hook')
            NetworkPlugin().create(pod_name, docker_id)
        elif mode == 'teardown':
            print('Executing Calico pod-deletion hook')
            NetworkPlugin().delete(pod_name, docker_id)
