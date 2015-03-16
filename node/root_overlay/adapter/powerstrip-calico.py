# Copyright (c) 2015 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from twisted.internet import reactor
from twisted.web import server, resource
import json
import logging
import logging.handlers
import sys
from docker import Client
import netns
import calico_etcd
import socket
from netaddr import IPAddress, AddrFormatError

_log = logging.getLogger(__name__)

ENV_IP = "CALICO_IP"
ENV_GROUP = "CALICO_GROUP"

hostname = socket.gethostname()

LISTEN_PORT = 2378


def setup_logging(logfile):
    _log.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(filename)s.%(name)s %(lineno)d: '
                                  '%(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    handler.setFormatter(formatter)
    _log.addHandler(handler)
    handler = logging.handlers.TimedRotatingFileHandler(logfile,
                                                        when='D',
                                                        backupCount=10)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    _log.addHandler(handler)

    # Propagate to loaded modules
    calico_etcd.setup_logging(logfile)
    netns.setup_logging(logfile)


class AdapterResource(resource.Resource):
    isLeaf = True

    def __init__(self):
        resource.Resource.__init__(self)

        # Init a Docker client, to save having to do so every time a request comes in.
        self.docker = Client(base_url='unix://var/run/docker.sock',
                             version="1.16")

        # Init an etcd client.
        self.etcd = calico_etcd.CalicoEtcdClient()

    def render_POST(self, request):
        """
        Handle a pre-hook.
        """
        _log.info("render_POST called with %s", request)
        try:
            request_content = json.loads(request.content.read())
            if request_content["Type"] == "pre-hook":
                result = self._handle_pre_hook(request, request_content)
            elif request_content["Type"] == "post-hook":
                result = self._handle_post_hook(request, request_content)
            else:
                _log.error("Unsupported hook type: %s", request_content["Type"])
                raise Exception("unsupported hook type %s" %
                                (request_content["Type"],))
            _log.debug("Result: %s", result)
            return result
        except:
            _log.exception("Failed to process POST")
            raise

    def _handle_pre_hook(self, request, request_content):
        _log.info("Handling pre-hook")
        client_request = request_content["ClientRequest"]

        # Only one action at this point, so just plumb directly
        _client_request_net_none(client_request)

        return json.dumps({"PowerstripProtocolVersion": 1,
                           "ModifiedClientRequest": client_request})

    def _handle_post_hook(self, request, request_content):
        _log.debug("Post-hook response: %s", request_content)

        # Extract ip, group, master, docker_options
        client_request = request_content["ClientRequest"]
        server_response = request_content["ServerResponse"]

        # Only one action at this point, so just plumb directly.
        self._install_endpoint(client_request)

        return json.dumps({"PowerstripProtocolVersion": 1,
                           "ModifiedServerResponse": server_response})

    def _install_endpoint(self, client_request):
        """
        Install a Calico endpoint (veth) in the container referenced in the client request object.
        :param client_request: Powerstrip ClientRequest object as dictionary from JSON.
        :returns: None
        """
        try:
            uri = client_request["Request"]
            _log.info("Intercepted %s, starting network.", uri)

            # Get the container ID
            # TODO better URI parsing
            # /*/containers/*/start
            (_, version, _, cid, _) = uri.split("/", 4)
            _log.debug("cid %s", cid)

            # Grab the running pid from Docker
            cont = self.docker.inspect_container(cid)
            _log.debug("Container info: %s", cont)
            pid = cont["State"]["Pid"]
            _log.debug(pid)

            # Attempt to parse out environment variables
            env_list = cont["Config"]["Env"]
            env_dict = env_to_dictionary(env_list)
            ip_str = env_dict[ENV_IP]
            # TODO: process groups
            group = env_dict.get(ENV_GROUP, None)
        except KeyError as e:
            _log.warning("Key error %s, request: %s", e, client_request)
            return

        try:
            ip = IPAddress(ip_str)
        except AddrFormatError:
            _log.warning("IP address %s could not be parsed" % ip_str)
            return

        next_hop_ips = self.etcd.get_default_next_hops(hostname)
        endpoint = netns.set_up_endpoint(ip=ip, cpid=pid, next_hop_ips=next_hop_ips)
        self.etcd.create_container(hostname=hostname,
                                   container_id=cid,
                                   endpoint=endpoint)
        _log.info("Finished network for container %s, IP=%s", cid, ip)

        return


def _client_request_net_none(client_request):
    """
    Modify the client_request in place to set net=None Docker option.

    :param client_request: Powerstrip ClientRequest object as dictionary from JSON
    :return: None
    """
    try:
        # Body is passed as a string, so deserialize it to JSON.
        body = json.loads(client_request["Body"])

        host_config = body["HostConfig"]
        _log.debug("Original NetworkMode: %s", host_config.get("NetworkMode", "<unset>"))
        host_config["NetworkMode"] = "none"

        # Re-serialize the updated body.
        client_request["Body"] = json.dumps(body)
    except KeyError as e:
        _log.warning("Error setting net=none: %s, request was %s", e, client_request)


def get_adapter():
    root = resource.Resource()
    root.putChild("calico-adapter", AdapterResource())
    site = server.Site(root)
    return site


def env_to_dictionary(env_list):
    """
    Parse the environment variables into a dictionary for easy access.
    :param env_list: list of strings in the form "var=value"
    :return: a dictionary {"var": "value"}
    """
    env_dict = {}
    for pair in env_list:
        (var, value) = pair.split("=", 1)
        env_dict[var] = value
    return env_dict


if __name__ == "__main__":
    setup_logging("/var/log/calico/powerstrip-calico.log")
    # Listen only on the loopback so we don't expose the adapter outside the host.
    reactor.listenTCP(LISTEN_PORT, get_adapter(), interface="127.0.0.1")
    reactor.run()

