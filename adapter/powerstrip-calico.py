# Inspired by https://github.com/ClusterHQ/powerstrip-slowreq
# Copyright Metaswitch Networks 2015  See LICENSE file for details.


from twisted.internet import reactor
from twisted.internet.task import deferLater
from twisted.web import server, resource
import calico
import json
import logging
import time
from docker import Client

_log = logging.getLogger(__name__)
_log.addHandler(logging.StreamHandler())
_log.setLevel(logging.INFO)

ENV_IP = "CALICO_IP_ADDR"
ENV_MASTER = "CALICO_MASTER"
ENV_GROUP = "CALICO_GROUP"

class AdapterResource(resource.Resource):

    isLeaf = True
    def render_POST(self, request):
        """
        Handle a pre-hook.
        """
        requestJson = json.loads(request.content.read())
        if requestJson["Type"] == "pre-hook":
            return self._handlePreHook(request, requestJson)
        elif requestJson["Type"] == "post-hook":
            return self._handlePostHook(request, requestJson)
        else:
            raise Exception("unsupported hook type %s" %
                (requestJson["Type"],))

    def _handlePreHook(self, request, requestJson):

        # Modify the request to set net to None.

        return json.dumps({"PowerstripProtocolVersion": 1,
                           "ModifiedClientRequest":
                           requestJson["ClientRequest"]})

    def _handlePostHook(self, request, requestJson):
        # The desired response is the entire client request
        # payload, unmodified.
        _log.debug("response: %s", requestJson)

        # Extract ip, group, master, docker_options
        client_request = requestJson["ClientRequest"]
        server_response = requestJson["ServerResponse"]
        try:
            _log.info("Intercepted %s, starting network.", client_request["Request"])
            # TODO better URI parsing
            # /*/containers/*/start
            (_, version, _, cid, _) = client_request["Request"].split("/", 4)
            _log.debug("cid %s", cid)

            # Grab the running pid
            docker = Client(base_url='unix://var/run/docker.sock')
            cont = docker.inspect_container(cid)
            _log.debug("Container info: %s", cont)
            cpid = cont["State"]["Pid"]
            _log.debug(cpid)

            # Attempt to parse out environment variables
            env_list = cont["Config"]["Env"]
            env_dict = env_to_dictionary(env_list)
            ip = env_dict[ENV_IP]
            master = env_dict[ENV_MASTER]
            group = env_dict.get(ENV_GROUP, None)

            calico.set_up_endpoint(ip=ip,
                                   master=master,
                                   group=group,
                                   cid=cid,
                                   cpid=cpid)
        except KeyError as e:
            _log.warning("Key error %s, requestJson: %s", e, requestJson)

        _log.info("Finished network for container %s, IP=%s", cid, ip)

        return json.dumps({
                "PowerstripProtocolVersion": 1,
                "ModifiedServerResponse":
                    requestJson["ServerResponse"]})


def getAdapter():
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
    reactor.listenTCP(80, getAdapter())
    reactor.run()

