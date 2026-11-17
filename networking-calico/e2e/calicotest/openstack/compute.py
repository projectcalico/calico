# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
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

from calicotest.common.node import Node


class Compute(Node):
    """
    A representation of a compute node.
    """

    def __init__(
        self,
        vmname,
        fqdn,
        username,
        password,
        keyfile=None,
        ip=None,
        region=None,
    ):
        super(Compute, self).__init__(
            vmname,
            fqdn,
            username,
            password,
            keyfile=keyfile,
            ip=ip,
            region=region,
        )

    def stop_felix(self):
        """
        Stops the calico-felix service on the compute host
        :return:
        """
        self.execute("sudo service calico-felix stop")

    def start_felix(self):
        """
        Starts the calico-felix service on the compute host.
        :return:
        """
        self.execute("sudo service calico-felix start")

    def get_number_of_rules(self):
        """
        Returns the number of iptables rules on the compute host
        :return:
        """
        command = "sudo iptables --list | grep -cvE '^$|^Chain|^target'"
        return int(self.execute(command).stdout)
