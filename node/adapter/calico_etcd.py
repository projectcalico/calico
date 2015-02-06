# Copyright Metaswitch Networks 2015

"""
etcd operations for the /calico namespace.  Provides high level functions for adding and removing
workloads on a node.
"""
import etcd
from collections import namedtuple
import json
import sys
import logging
import logging.handlers

_log = logging.getLogger(__name__)

Endpoint = namedtuple("Endpoint", ["id", "addrs", "mac", "state"])

HOST_PATH = "/calico/host/%(hostname)s/"
CONTAINER_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/"
ENDPOINT_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/" + \
                "endpoint/%(endpoint_id)s/"


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
        self.client = etcd.Client()

    def create_container(self, hostname, container_id, endpoint):
        """
        Set up a container in the /calico/ namespace.  This function assumes 1 container, with 1
        endpoint.

        :param hostname: The hostname for the Docker hosting this container.
        :param container_id: The Docker container ID.
        :param endpoint: The Endpoint to add to the container.
        :return: Nothing
        """

        endpoint_path = ENDPOINT_PATH % {"hostname": hostname,
                                         "container_id": container_id,
                                         "endpoint_id": endpoint.id}

        _log.info("Creating endpoint at %s", endpoint_path)
        try:
            self.client.write(endpoint_path + "addrs", json.dumps(endpoint.addrs))
            self.client.write(endpoint_path + "mac", endpoint.mac)
            self.client.write(endpoint_path + "state", endpoint.state)
        except etcd.EtcdException as e:
            _log.exception("Hit Exception %s writing to etcd.", e)
            pass

