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


class Control(Node):
    """
    A representation of a control node.
    """

    def __init__(
        self,
        vmname,
        fqdn,
        username,
        password,
        admin_password,
        keyfile=None,
        ip=None,
        region=None,
    ):
        self.admin_password = admin_password
        super(Control, self).__init__(
            vmname,
            fqdn,
            username,
            password,
            keyfile=keyfile,
            ip=ip,
            region=region,
        )
