# Copyright 2015 Metaswitch Networks
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
"""
Usage:
  calicoctl status

Description:
  Print current status information regarding calico-node container
  and the BIRD routing daemon.
"""
import re
from utils import docker_client


def status(arguments):
    """
    Main dispatcher for status commands. Calls the corresponding helper
    function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    calico_node_info = filter(lambda container: "/calico-node" in
                              container["Names"],
                              docker_client.containers())
    if len(calico_node_info) == 0:
        print "calico-node container not running"
    else:
        print "calico-node container is running. Status: %s" % \
              calico_node_info[0]["Status"]

        apt_cmd = docker_client.exec_create("calico-node", ["/bin/bash", "-c",
                                           "apt-cache policy calico-felix"])
        result = re.search(r"Installed: (.*?)\s", docker_client.exec_start(apt_cmd))
        if result is not None:
            print "Running felix version %s" % result.group(1)

        print "IPv4 Bird (BGP) status"
        bird_cmd = docker_client.exec_create("calico-node",
                                    ["/bin/bash", "-c",
                                     "echo show protocols | "
                                     "birdc -s /etc/service/bird/bird.ctl"])
        print docker_client.exec_start(bird_cmd)
        print "IPv6 Bird (BGP) status"
        bird6_cmd = docker_client.exec_create("calico-node",
                                    ["/bin/bash", "-c",
                                     "echo show protocols | "
                                     "birdc6 -s "
                                     "/etc/service/bird6/bird6.ctl"])
        print docker_client.exec_start(bird6_cmd)
