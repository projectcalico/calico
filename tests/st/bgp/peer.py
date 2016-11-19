# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
from tests.st.utils.utils import assert_network, assert_profile, \
    assert_number_endpoints, get_profile_name, ETCD_CA, ETCD_CERT, \
    ETCD_KEY, ETCD_HOSTNAME_SSL, ETCD_SCHEME, get_ip, check_bird_status

if ETCD_SCHEME == "https":
    ADDITIONAL_DOCKER_OPTIONS = "--cluster-store=etcd://%s:2379 " \
                                "--cluster-store-opt kv.cacertfile=%s " \
                                "--cluster-store-opt kv.certfile=%s " \
                                "--cluster-store-opt kv.keyfile=%s " % \
                                (ETCD_HOSTNAME_SSL, ETCD_CA, ETCD_CERT,
                                 ETCD_KEY)
else:
    ADDITIONAL_DOCKER_OPTIONS = "--cluster-store=etcd://%s:2379 " % \
                                get_ip()

def create_bgp_peer(host, scope, ip, asNum):
    assert scope in ('node', 'global')
    node = host.name if scope == 'node' else ""
    testdata = {
        'apiVersion': 'v1',
        'kind': 'bgpPeer',
        'metadata': {
            'scope': scope,
            'node': node,
            'peerIP': ip,
        },
        'spec': {
            'asNumber': asNum
        }
    }
    host.writefile("testfile.yaml", testdata)
    host.calicoctl("create -f testfile.yaml")
