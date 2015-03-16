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
"""
etcd operations for the /calico namespace.  Provides high level functions for adding and removing
workloads on a node.
"""
import etcd
from collections import namedtuple
import json
import sys
import os
import logging
import logging.handlers
from netaddr import IPNetwork, IPAddress, AddrFormatError

_log = logging.getLogger(__name__)

class Endpoint(object):

    def __init__(self, ep_id, state, mac, felix_host):
        self.ep_id = ep_id
        self.state = state
        self.mac = mac

        self.profile_id = None
        self.ipv4_nets = set()
        self.ipv6_nets = set()
        self.ipv4_gateway = None
        self.ipv6_gateway = None

    def to_json(self):
        json_dict = {"state": "active" if self.state == "enabled" else "inactive",
                     "mac": self.mac,
                     "name": self.ep_id[:11],
                     "profile_id": self.profile_id,
                     "ipv4_nets": [str(net) for net in self.ipv4_nets],
                     "ipv6_nets": [str(net) for net in self.ipv6_nets],
                     "ipv4_gateway": str(self.ipv4_gateway) if
                                     self.ipv4_gateway else None,
                     "ipv6_gateway": str(self.ipv6_gateway) if
                                     self.ipv6_gateway else None}
        return json.dumps(json_dict)

    @classmethod
    def from_json(cls, ep_id, json_str):
        json_dict = json.loads(json_str)
        ep = cls(ep_id=ep_id,
                 state=json_dict["state"],
                 mac=json_dict["mac"],
                 felix_host=["hostname"])
        for net in json_dict["ipv4_nets"]:
            ep.ipv4_nets.add(IPNetwork(net))
        for net in json_dict["ipv6_nets"]:
            ep.ipv6_nets.add(IPNetwork(net))
        ipv4_gw = json_dict["ipv4_gateway"]
        if ipv4_gw:
            ep.ipv4_gateway = IPAddress(ipv4_gw)
        ipv6_gw = json_dict["ipv6_gateway"]
        if ipv6_gw:
            ep.ipv6_gateway = IPAddress(ipv6_gw)
        ep.profile_id = json_dict["profile_id"]
        return ep


HOST_PATH = "/calico/host/%(hostname)s/"
CONTAINER_PATH = HOST_PATH + "workload/docker/%(container_id)s/"
ENDPOINT_PATH = CONTAINER_PATH + "endpoint/%(endpoint_id)s/"

ENV_ETCD = "ETCD_AUTHORITY"
"""The environment variable that locates etcd service."""


def setup_logging(logfile):
    _log.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s %(lineno)d: %(message)s')
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


class CalicoEtcdClient(object):
    """
    An Etcd Client that exposes Calico specific operations on the etcd database.
    """

    def __init__(self):
        etcd_authority = os.getenv(ENV_ETCD, None)
        if not etcd_authority:
            self.client = etcd.Client()
        else:
            # TODO: Error handling
            (host, port) = etcd_authority.split(":", 1)
            self.client = etcd.Client(host=host, port=int(port))

    def create_container(self, hostname, container_id, endpoint):
        """
        Set up a container in the /calico/ namespace.  This function assumes 1
        container, with 1 endpoint.

        :param hostname: The hostname for the Docker hosting this container.
        :param container_id: The Docker container ID.
        :param endpoint: The Endpoint to add to the container.
        :return: Nothing
        """

        endpoint_path = ENDPOINT_PATH % {"hostname": hostname,
                                         "container_id": container_id,
                                         "endpoint_id": endpoint.ep_id}

        _log.info("Creating endpoint at %s", endpoint_path)
        try:
            self.client.write(endpoint_path, endpoint.to_json())
        except etcd.EtcdException as e:
            _log.exception("Hit Exception %s writing to etcd.", e)
            pass

    def get_default_next_hops(self, hostname):
        """
        Get the next hop IP addresses for default routes on the given host.

        :param hostname: The hostname for which to get default route next hops.
        :return: Dict of {ip_version: IPAddress}
        """

        host_path = HOST_PATH % {"hostname": hostname}
        ipv4 = self.client.read(host_path + "bird_ip").value
        ipv6 = self.client.read(host_path + "bird6_ip").value

        next_hops = {}

        # The IP addresses read from etcd could be blank. Only store them if
        # they can be parsed by IPAddress
        try:
            next_hops[4] = IPAddress(ipv4)
        except AddrFormatError:
            pass

        try:
            next_hops[6] = IPAddress(ipv6)
        except AddrFormatError:
            pass

        _log.info(next_hops)
        return next_hops
