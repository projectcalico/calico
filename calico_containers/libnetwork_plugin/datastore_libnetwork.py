from etcd import EtcdKeyNotFound
import json
from pycalico.ipam import IPAMClient

PREFIX = "/calico/docker/v1/"


class LibnetworkDatastoreClient(IPAMClient):
    def cnm_endpoint_exists(self, ep_id):
        """
        Check if a Container Network Model (cnm) endpoint exists.
        :param ep_id: The endpoint ID to check.
        :return: True if it exists, false otherwise.
        """
        endpoint_path = PREFIX + ep_id
        try:
            self.etcd_client.read(endpoint_path)
        except EtcdKeyNotFound:
            return False
        else:
            return True

    def read_cnm_endpoint(self, ep_id):
        """
        Read a CNM endpoint.
        :param ep_id: The endpoint ID to read.
        :return: A dict representing the endpoint.
        """
        try:
            endpoint = self.etcd_client.read(PREFIX + ep_id)
            return json.loads(endpoint.value)
        except EtcdKeyNotFound:
            return None

    def write_cnm_endpoint(self, ep_id, ep):
        """
        Write a CNM endpoint.
        :param ep_id: The endpoint ID to write.
        :param ep: A dict representing the endpoint.
        :return: Nothing
        """
        self.etcd_client.write(PREFIX + ep_id, json.dumps(ep))

    def delete_cnm_endpoint(self, ep_id):
        """
        Delete a CNM endpoint.
        :param ep_id: The endpoint ID to delete.
        :return: True if the delete was successful, false if the ep_id
        didn't exist.
        """
        try:
            self.etcd_client.delete(PREFIX + ep_id)
        except EtcdKeyNotFound:
            return False
        else:
            return True
