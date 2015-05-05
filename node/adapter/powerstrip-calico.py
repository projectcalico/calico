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
import socket

from docker import Client
from netaddr import IPAddress, AddrFormatError

import netns
from ipam import SequentialAssignment, IPAMClient

_log = logging.getLogger(__name__)

ENV_IP = "CALICO_IP"
ENV_PROFILE = "CALICO_PROFILE"

hostname = socket.gethostname()

LISTEN_PORT = 2378


def setup_logging(logfile):
    _log.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(filename)s.%(name)s %(lineno)d: '
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
    netns.setup_logging(logfile)


class AdapterResource(resource.Resource):
    isLeaf = True

    def __init__(self):
        resource.Resource.__init__(self)

        # Init a Docker client, to save having to do so every time a request
        # comes in.
        self.docker = Client(base_url='unix://host-var-run/docker.sock',
                             version="1.16")

        # Init an etcd client.
        self.datastore = IPAMClient()

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
                _log.error("Unsupported hook type: %s",
                           request_content["Type"])
                raise Exception("unsupported hook type %s" %
                                (request_content["Type"],))
            _log.debug("Result: %s", result)
            return result
        except:
            _log.exception("Failed to process POST")
            raise

    def _handle_pre_hook(self, request, request_content):
        _log.info("Handling pre-hook")

        # Exceptions hang the Reactor, so ensure we handle all exceptions.
        client_request = {}
        try:
            client_request = request_content["ClientRequest"]

            if _calico_ip_in_request(client_request):
                # Calico IP was defined in the request, so override the net
                # portion of the HostConfig
                _client_request_net_none(client_request)
        except BaseException:
            _log.exception("Unexpected error handling pre-hook")
        finally:
            return json.dumps({"PowerstripProtocolVersion": 1,
                               "ModifiedClientRequest": client_request})

    def _handle_post_hook(self, request, request_content):
        _log.debug("Post-hook response: %s", request_content)

        # Exceptions hang the Reactor, so ensure we handle all exceptions.
        server_response = {}
        try:
            # Extract ip, profile, master, docker_options
            client_request = request_content["ClientRequest"]
            server_response = request_content["ServerResponse"]

            request_uri = client_request['Request']
            request_path = request_uri.split('/')

            # Extract the container ID and request type.
            # TODO better URI parsing
            (_, version, _, cid, ctype) = request_uri.split("/", 4)
            _log.info("Request parameters: version:%s; cid:%s; ctype:%s",
                      version, cid, ctype)
            if ctype == u'start':
                # /version/containers/id/start
                _log.debug('Intercepted container start request')
                self._install_endpoint(client_request, cid)
            elif ctype== 'json':
                # /version/containers/*/json
                _log.debug('Intercepted container json request')
                self._update_container_info(cid, server_response)
            else:
                _log.debug('Unrecognized path: %s', request_path)
        except BaseException:
            _log.exception('Unexpected error handling post-hook.')
        finally:
            output = json.dumps({
                "PowerstripProtocolVersion": 1,
                "ModifiedServerResponse": server_response
            })
            _log.debug("Returning output:\n%s", output)
            return output

    def _install_endpoint(self, client_request, cid):
        """
        Install a Calico endpoint (veth) in the container referenced in the
        client request object.
-       :param client_request: Powerstrip ClientRequest object as dictionary
                               from JSON.
        :param cid: The ID of the container to install an endpoint in.
        :returns: None
        """
        try:
            _log.debug("Installing endpoint for cid %s", cid)

            # Grab the running pid from Docker
            cont = self.docker.inspect_container(cid)
            _log.debug("Container info: %s", cont)
            pid = cont["State"]["Pid"]
            _log.debug('Container PID: %s', pid)

            # Attempt to parse out environment variables
            env_list = cont["Config"]["Env"]
            env_list = env_list if env_list is not None else []
            env_dict = env_to_dictionary(env_list)
            ip_str = env_dict[ENV_IP]
            profile = env_dict.get(ENV_PROFILE, None)
        except KeyError as e:
            # This error is benign for missing ENV_IP, since it means not to
            # set up Calico networking for this container.
            _log.info("Key error %s, request: %s", e, client_request)
            return

        # Just auto assign ipv4 addresses for now.
        if ip_str.lower() == "auto":
            ip = self.assign_ipv4()
        else:
            try:
                ip = IPAddress(ip_str)
            except AddrFormatError:
                _log.warning("IP address %s could not be parsed" % ip_str)
                return
            else:
                version = "v%s" % ip.version
                _log.debug('Attempting to assign IP%s address %s', version, ip)
                pools = self.datastore.get_ip_pools(version)
                pool = None
                for candidate_pool in pools:
                    if ip in candidate_pool:
                        pool = candidate_pool
                        _log.debug('Using IP pool %s', pool)
                        break
                if not pool:
                    _log.warning("Requested IP %s isn't in any configured "
                                 "pool. Container %s", ip, cid)
                    return
                if not self.datastore.assign_address(pool, ip):
                    _log.warning("IP address couldn't be assigned for "
                                 "container %s, IP=%s", cid, ip)

        next_hop_ips = self.datastore.get_default_next_hops(hostname)
        endpoint = netns.set_up_endpoint(ip=ip,
                                         cpid=pid,
                                         next_hop_ips=next_hop_ips)
        if profile is not None:
            if not self.datastore.profile_exists(profile):
                _log.info("Autocreating profile %s", profile)
                self.datastore.create_profile(profile)
            _log.info("Adding container %s to profile %s", cid, profile)
            endpoint.profile_id = profile
            _log.info("Finished adding container %s to profile %s",
                      cid, profile)

        self.datastore.set_endpoint(hostname, cid, endpoint)
        _log.info("Finished network for container %s, IP=%s", cid, ip)

        return

    def _update_container_info(self, cid_or_name, server_response):
        """
        Update the response for a */container/*/json (docker inspect) request.

        Since we've patched the docker networking using --net=none,
        docker inspect calls will not return any IP information. This is
        required for some orchestrators (such as Kubernetes).

        Insert the IP for this container into the config dict.

        :param str cid_or_name: The name or ID of the container to update.
        :param dict server_response: The response from the Docker API, to be
                                     be updated.
        """
        _log.debug('Getting container config from etcd')

        try:
            cont = self.docker.inspect_container(cid_or_name)
            _log.debug("Container info: %s", cont)
            cid = cont["Id"]
            _log.debug("Container ID: %s", cid)

            # Get a single endpoint ID from the container, and use this to
            # get the Endpoint.
            ep_id = self.datastore.get_ep_id_from_cont(hostname, cid)
            ep = self.datastore.get_endpoint(hostname, cid, ep_id)
        except KeyError:
            _log.info('No workload found for container %s, '
                      'returning request unmodified.', cid)
            return

        _log.debug('Pre-load body:\n%s', server_response["Body"])

        # Tweak the contents of the NetworkSettings dictionary in the request
        # body.  We use an arbitrary IPv4 / IPv6 address from the endpoint
        # network sets to fill in the IP information since the dictionary only
        # allows a single value for each.
        body = json.loads(server_response["Body"])
        net_settings = body['NetworkSettings']
        for ipv4_net in ep.ipv4_nets:
            if ipv4_net.prefixlen == 32:
                net_settings['IPAddress'] = str(ipv4_net.ip)
                break
        for ipv6_net in ep.ipv6_nets:
            if ipv6_net.prefixlen == 128:
                net_settings['GlobalIPv6Address'] = str(ipv6_net.ip)
                break
        net_settings["MacAddress"] = str(ep.mac)
        server_response['Body'] = json.dumps(body, separators=(',', ':'))

        _log.debug('Post-load body:\n%s', server_response["Body"])

    def assign_ipv4(self):
        """
        Assign a IPv4 address from the configured pools.
        :return: An IPAddress, or None if an IP couldn't be
                 assigned
        """
        ip = None

        # For each configured pool, attempt to assign an IP before giving up.
        for pool in self.datastore.get_ip_pools("v4"):
            assigner = SequentialAssignment()
            ip = assigner.allocate(pool)
            if ip is not None:
                ip = IPAddress(ip)
                break
        return ip


def _calico_ip_in_request(client_request):
    """
    Examine a ClientRequest object to determine whether the ENV_IP environment
    variable is present.

    We don't set up Calico networking for container requests if the ENV_IP
    variable is absent.

    :param client_request:
    :return: True if ENV_IP variable is defined, False otherwise.
    """
    try:
        # Body is passed as a string, so deserialize it to JSON.
        body = json.loads(client_request["Body"])

        env = body["Env"]
    except KeyError:
        _log.warning("Client request object had no 'Env' in 'Body': %s",
                     client_request)
        return False

    _log.info("Request Env: %s", env)

    # env is a list of strings of the form 'VAR=value'.  We want an exact match
    # on our VAR, so search for it including the = sign at the beginning of the
    # string.  (Should be faster than compiling a regex and avoids the
    # dependency).
    search = ENV_IP + "="
    for line in env:
        if line.startswith(search):
            return True
    return False


def _client_request_net_none(client_request):
    """
    Modify the client_request in place to set net=None Docker option.

    :param client_request: Powerstrip ClientRequest object as dictionary from
    JSON
    :return: None
    """
    try:
        # Body is passed as a string, so deserialize it to JSON.
        body = json.loads(client_request["Body"])

        host_config = body["HostConfig"]
        _log.debug("Original NetworkMode: %s",
                   host_config.get("NetworkMode", "<unset>"))
        host_config["NetworkMode"] = "none"

        # Re-serialize the updated body.
        client_request["Body"] = json.dumps(body)
    except KeyError as e:
        _log.warning("Error setting net=none: %s, request was %s",
                     e, client_request)


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
    # Listen only on the loopback so we don't expose the adapter outside the
    # host.
    reactor.listenTCP(LISTEN_PORT, get_adapter(), interface="127.0.0.1")
    reactor.run()

